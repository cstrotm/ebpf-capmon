// capmon: eBPF Linux capabilities monitor.
//
// Loads the embedded BPF programs (capmon.bpf.c), attaches them to process
// creation, credential-change and file-capability (setcap) hooks, and writes
// every event to a file, syslog, or the systemd journal.
package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-strip -target amd64 -cc clang -cflags "-O2 -g -Wall -Wno-missing-declarations" capmon bpf/capmon.bpf.c

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/syslog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	sdjournal "github.com/coreos/go-systemd/v22/journal"
)

const (
	evFork       uint32 = 1
	evExec       uint32 = 2
	evCapChange  uint32 = 3
	evFileCapSet uint32 = 4
	evFileCapDel uint32 = 5

	compN   = 8
	compLen = 64
)

type caps struct {
	Eff, Perm, Inh, Bnd, Amb uint64
}

// event mirrors struct event in capmon.h — field order and sizes must match.
type event struct {
	Ts                    uint64
	Type                  uint32
	Pid, Tid, Ppid        uint32
	Uid, Gid, Euid, Egid  uint32
	Prev, Cur             caps
	CmdlineLen, Depth     uint32
	FileMagic, FileRootid uint32
	FilePerm, FileInh     uint64
	FileIno               uint64
	FileDev, FileValid    uint32
	Comm                  [16]byte
	Cmdline               [256]byte
	Raw                   [compN * compLen]byte // path (exec) or components (filecap)
}

var typeNames = map[uint32]string{
	evFork: "FORK", evExec: "EXEC", evCapChange: "CAPCHANGE",
	evFileCapSet: "FILECAP_SET", evFileCapDel: "FILECAP_DEL",
}

// typeFilter maps -events names to event types.
var typeFilter = map[string][]uint32{
	"fork":   {evFork},
	"exec":   {evExec},
	"capset": {evCapChange},
	"setcap": {evFileCapSet, evFileCapDel},
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func (e *event) cmdline() string {
	n := int(e.CmdlineLen)
	if n > len(e.Cmdline) {
		n = len(e.Cmdline)
	}
	b := bytes.TrimRight(e.Cmdline[:n], "\x00")
	s := strings.ReplaceAll(string(b), "\x00", " ")
	if e.CmdlineLen >= uint32(len(e.Cmdline)-1) {
		s += " …"
	}
	return s
}

// target reconstructs the setcap target path from the leaf-first components.
// The chain ends at the filesystem root, so the path is mount-relative.
func (e *event) target() string {
	n := int(e.Depth)
	if n > compN {
		n = compN
	}
	parts := make([]string, 0, n)
	complete := false
	for i := 0; i < n; i++ {
		c := cstr(e.Raw[i*compLen : (i+1)*compLen])
		if c == "/" {
			complete = true
			break
		}
		parts = append(parts, c)
	}
	if !complete && n == compN {
		parts = append(parts, "…") // path deeper than compN components
	}
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return "/" + strings.Join(parts, "/")
}

func (e *event) dev() string {
	return fmt.Sprintf("%d:%d", e.FileDev>>20, e.FileDev&0xfffff)
}

// fileCapFlags describes the vfs_cap_data magic_etc word.
func (e *event) fileCapVersion() int    { return int(e.FileMagic >> 24) }
func (e *event) fileCapEffective() bool { return e.FileMagic&1 != 0 }

type capSetJSON struct {
	Effective   []string `json:"effective"`
	Permitted   []string `json:"permitted"`
	Inheritable []string `json:"inheritable"`
	Bounding    []string `json:"bounding"`
	Ambient     []string `json:"ambient"`
}

func toJSONCaps(c caps) capSetJSON {
	nz := func(m uint64) []string {
		l := capList(m)
		if l == nil {
			l = []string{}
		}
		return l
	}
	return capSetJSON{nz(c.Eff), nz(c.Perm), nz(c.Inh), nz(c.Bnd), nz(c.Amb)}
}

func capsText(c caps) string {
	return fmt.Sprintf("eff=%s perm=%s inh=%s bnd=%s amb=%s",
		capString(c.Eff), capString(c.Perm), capString(c.Inh), capString(c.Bnd), capString(c.Amb))
}

// gainedCaps / removedCaps return, per set, the capabilities added / dropped.
func gainedCaps(p, c caps) caps {
	return caps{c.Eff &^ p.Eff, c.Perm &^ p.Perm, c.Inh &^ p.Inh, c.Bnd &^ p.Bnd, c.Amb &^ p.Amb}
}

func removedCaps(p, c caps) caps { return gainedCaps(c, p) }

// capsDiffText renders the non-empty sets of a diff, or "-" if none.
func capsDiffText(d caps) string {
	var parts []string
	for _, s := range []struct {
		n string
		m uint64
	}{{"eff", d.Eff}, {"perm", d.Perm}, {"inh", d.Inh}, {"bnd", d.Bnd}, {"amb", d.Amb}} {
		if s.m != 0 {
			parts = append(parts, s.n+"="+capString(s.m))
		}
	}
	if len(parts) == 0 {
		return "-"
	}
	return strings.Join(parts, " ")
}

// hasDiff reports whether the event kind carries a prev/cur comparison.
func (e *event) hasDiff() bool { return e.Type == evCapChange || e.Type == evExec }

// text renders the event as a single human readable line.
func (e *event) text() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s pid=%d tid=%d ppid=%d uid=%d gid=%d euid=%d egid=%d comm=%s cmdline=%s",
		typeNames[e.Type], e.Pid, e.Tid, e.Ppid, e.Uid, e.Gid, e.Euid, e.Egid,
		strconv.Quote(cstr(e.Comm[:])), strconv.Quote(e.cmdline()))
	switch e.Type {
	case evExec:
		fmt.Fprintf(&b, " exe=%s", strconv.Quote(cstr(e.Raw[:])))
	case evFileCapSet, evFileCapDel:
		fmt.Fprintf(&b, " target=%s dev=%s ino=%d", strconv.Quote(e.target()), e.dev(), e.FileIno)
	}
	if e.Type == evFileCapSet {
		if e.FileValid != 0 {
			fmt.Fprintf(&b, " file_caps{permitted=%s inheritable=%s effective_bit=%t version=%d",
				capString(e.FilePerm), capString(e.FileInh), e.fileCapEffective(), e.fileCapVersion())
			if e.fileCapVersion() == 3 {
				fmt.Fprintf(&b, " rootid=%d", e.FileRootid)
			}
			b.WriteString("}")
		} else {
			b.WriteString(" file_caps{unparsed}")
		}
		return b.String()
	}
	if e.Type == evFileCapDel {
		b.WriteString(" file_caps{removed}")
		return b.String()
	}
	fmt.Fprintf(&b, " prev{%s} cur{%s}", capsText(e.Prev), capsText(e.Cur))
	if e.hasDiff() {
		fmt.Fprintf(&b, " gained{%s} removed{%s}",
			capsDiffText(gainedCaps(e.Prev, e.Cur)), capsDiffText(removedCaps(e.Prev, e.Cur)))
	}
	return b.String()
}

type jsonEvent struct {
	Time     string      `json:"time"`
	Event    string      `json:"event"`
	Pid      uint32      `json:"pid"`
	Tid      uint32      `json:"tid"`
	Ppid     uint32      `json:"ppid"`
	Uid      uint32      `json:"uid"`
	Gid      uint32      `json:"gid"`
	Euid     uint32      `json:"euid"`
	Egid     uint32      `json:"egid"`
	Comm     string      `json:"comm"`
	Cmdline  string      `json:"cmdline"`
	Exe      string      `json:"exe,omitempty"`
	Prev     *capSetJSON `json:"prev_caps,omitempty"`
	Cur      *capSetJSON `json:"cur_caps,omitempty"`
	Gained   *capSetJSON `json:"gained_caps,omitempty"`
	Removed  *capSetJSON `json:"removed_caps,omitempty"`
	Target   string      `json:"target,omitempty"`
	Dev      string      `json:"dev,omitempty"`
	Ino      uint64      `json:"ino,omitempty"`
	FileCaps *struct {
		Permitted   []string `json:"permitted"`
		Inheritable []string `json:"inheritable"`
		Effective   bool     `json:"effective_bit"`
		Version     int      `json:"version"`
		RootID      uint32   `json:"rootid,omitempty"`
	} `json:"file_caps,omitempty"`
}

func (e *event) json(now time.Time) string {
	j := jsonEvent{
		Time: now.Format(time.RFC3339Nano), Event: typeNames[e.Type],
		Pid: e.Pid, Tid: e.Tid, Ppid: e.Ppid,
		Uid: e.Uid, Gid: e.Gid, Euid: e.Euid, Egid: e.Egid,
		Comm: cstr(e.Comm[:]), Cmdline: e.cmdline(),
	}
	switch e.Type {
	case evExec:
		j.Exe = cstr(e.Raw[:])
	case evFileCapSet, evFileCapDel:
		j.Target, j.Dev, j.Ino = e.target(), e.dev(), e.FileIno
		if e.Type == evFileCapSet && e.FileValid != 0 {
			fc := &struct {
				Permitted   []string `json:"permitted"`
				Inheritable []string `json:"inheritable"`
				Effective   bool     `json:"effective_bit"`
				Version     int      `json:"version"`
				RootID      uint32   `json:"rootid,omitempty"`
			}{capList(e.FilePerm), capList(e.FileInh), e.fileCapEffective(), e.fileCapVersion(), e.FileRootid}
			if fc.Permitted == nil {
				fc.Permitted = []string{}
			}
			if fc.Inheritable == nil {
				fc.Inheritable = []string{}
			}
			j.FileCaps = fc
		}
	}
	if e.Type != evFileCapSet && e.Type != evFileCapDel {
		p, c := toJSONCaps(e.Prev), toJSONCaps(e.Cur)
		j.Prev, j.Cur = &p, &c
		if e.hasDiff() {
			g, r := toJSONCaps(gainedCaps(e.Prev, e.Cur)), toJSONCaps(removedCaps(e.Prev, e.Cur))
			j.Gained, j.Removed = &g, &r
		}
	}
	out, _ := json.Marshal(j)
	return string(out)
}

// journalFields returns structured journal fields for the event.
func (e *event) journalFields() map[string]string {
	f := map[string]string{
		"SYSLOG_IDENTIFIER": "ebpf-capmon",
		"CAPMON_EVENT":      typeNames[e.Type],
		"CAPMON_PID":        strconv.Itoa(int(e.Pid)),
		"CAPMON_PPID":       strconv.Itoa(int(e.Ppid)),
		"CAPMON_UID":        strconv.Itoa(int(e.Uid)),
		"CAPMON_GID":        strconv.Itoa(int(e.Gid)),
		"CAPMON_COMM":       cstr(e.Comm[:]),
		"CAPMON_CMDLINE":    e.cmdline(),
	}
	if e.Type != evFileCapSet && e.Type != evFileCapDel {
		f["CAPMON_PREV_CAPS"] = capsText(e.Prev)
		f["CAPMON_CUR_CAPS"] = capsText(e.Cur)
		if e.hasDiff() {
			f["CAPMON_GAINED"] = capsDiffText(gainedCaps(e.Prev, e.Cur))
			f["CAPMON_REMOVED"] = capsDiffText(removedCaps(e.Prev, e.Cur))
		}
	} else {
		f["CAPMON_TARGET"] = e.target()
	}
	return f
}

func (e *event) priority() sdjournal.Priority {
	switch e.Type {
	case evFileCapSet, evFileCapDel:
		return sdjournal.PriWarning
	case evCapChange:
		return sdjournal.PriNotice
	}
	return sdjournal.PriInfo
}

type sink struct {
	write func(e *event, line string)
	info  func(msg string) // daemon messages (drops, etc.)
	close func()
}

func makeSink(mode, filePath string) sink {
	switch mode {
	case "file":
		f, err := os.OpenFile(filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			log.Fatalf("open log file %s: %v", filePath, err)
		}
		l := log.New(f, "", 0)
		w := func(msg string) { l.Println(time.Now().Format(time.RFC3339), msg) }
		return sink{
			write: func(_ *event, line string) { w(line) },
			info:  func(msg string) { w("CAPMON " + msg) },
			close: func() { f.Close() },
		}

	case "syslog":
		w, err := syslog.New(syslog.LOG_INFO|syslog.LOG_AUTHPRIV, "ebpf-capmon")
		if err != nil {
			log.Fatalf("connect to syslog: %v", err)
		}
		return sink{
			write: func(e *event, line string) {
				var err error
				switch e.priority() {
				case sdjournal.PriWarning:
					err = w.Warning(line)
				case sdjournal.PriNotice:
					err = w.Notice(line)
				default:
					err = w.Info(line)
				}
				if err != nil {
					log.Printf("syslog write: %v", err)
				}
			},
			info:  func(msg string) { _ = w.Warning("CAPMON " + msg) },
			close: func() { w.Close() },
		}

	case "journal":
		if !sdjournal.Enabled() {
			log.Fatal("systemd journal not available on this system")
		}
		return sink{
			write: func(e *event, line string) {
				_ = sdjournal.Send(line, e.priority(), e.journalFields())
			},
			info: func(msg string) {
				_ = sdjournal.Send("CAPMON "+msg, sdjournal.PriWarning,
					map[string]string{"SYSLOG_IDENTIFIER": "ebpf-capmon"})
			},
			close: func() {},
		}
	}
	log.Fatalf("unknown output mode %q; use file, syslog, or journal", mode)
	return sink{}
}

func parseEvents(spec string) map[uint32]bool {
	want := map[uint32]bool{}
	for _, n := range strings.Split(spec, ",") {
		n = strings.TrimSpace(strings.ToLower(n))
		if n == "all" {
			for _, ts := range typeFilter {
				for _, t := range ts {
					want[t] = true
				}
			}
			continue
		}
		ts, ok := typeFilter[n]
		if !ok {
			log.Fatalf("unknown event class %q; use fork, exec, capset, setcap, all", n)
		}
		for _, t := range ts {
			want[t] = true
		}
	}
	return want
}

func run(output, logFile, format, events string) error {
	want := parseEvents(events)
	if format != "text" && format != "json" {
		return fmt.Errorf("unknown format %q; use text or json", format)
	}
	if want := binary.Size(event{}); want <= 0 {
		return errors.New("event struct has variable size")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	var objs capmonObjects
	if err := loadCapmonObjects(&objs, nil); err != nil {
		return fmt.Errorf("load BPF objects: %w", err)
	}
	defer objs.Close()

	// All hooks are BTF-based tracing programs (tp_btf / fentry).
	var links []link.Link
	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()
	attach := func(name string, on bool, opts link.TracingOptions) error {
		if !on {
			return nil
		}
		l, err := link.AttachTracing(opts)
		if err != nil {
			return fmt.Errorf("attach %s: %w", name, err)
		}
		links = append(links, l)
		return nil
	}
	for _, h := range []struct {
		name string
		on   bool
		opts link.TracingOptions
	}{
		{"sched_process_fork", want[evFork], link.TracingOptions{Program: objs.OnFork}},
		{"sched_process_exec", want[evExec], link.TracingOptions{Program: objs.OnExec}},
		// exec needs commit_creds to learn the pre-exec capabilities
		{"commit_creds", want[evCapChange] || want[evExec], link.TracingOptions{Program: objs.OnCommitCreds}},
		{"security_inode_setxattr", want[evFileCapSet], link.TracingOptions{Program: objs.OnSetxattr}},
		{"security_inode_removexattr", want[evFileCapDel], link.TracingOptions{Program: objs.OnRemovexattr}},
	} {
		if err := attach(h.name, h.on, h.opts); err != nil {
			return err
		}
	}

	s := makeSink(output, logFile)
	defer s.close()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		return fmt.Errorf("create ring buffer reader: %w", err)
	}
	defer rd.Close()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	// Report events the kernel had to drop because the ring buffer was full.
	go func() {
		var last uint64
		for range time.Tick(10 * time.Second) {
			var per []uint64
			if err := objs.Drops.Lookup(uint32(0), &per); err != nil {
				continue
			}
			var total uint64
			for _, v := range per {
				total += v
			}
			if total > last {
				s.info(fmt.Sprintf("dropped %d events (ring buffer full), %d total", total-last, total))
				last = total
			}
		}
	}()

	s.info("started, events=" + events)
	var ev event
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				break
			}
			log.Printf("ring buffer read: %v", err)
			continue
		}
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &ev); err != nil {
			log.Printf("decode event (%d bytes): %v", len(rec.RawSample), err)
			continue
		}
		if !want[ev.Type] {
			continue // e.g. EV_CAPCHANGE enabled only to support exec
		}
		line := ""
		if format == "json" {
			line = ev.json(time.Now())
		} else {
			line = ev.text()
		}
		s.write(&ev, line)
	}
	s.info("stopped")
	return nil
}

func main() {
	output := flag.String("output", "journal", "Log output: file, syslog, journal")
	logFile := flag.String("logfile", "/var/log/ebpf-capmon.log", "Log file path (with -output file)")
	format := flag.String("format", "text", "Line format: text or json")
	events := flag.String("events", "all", "Comma separated event classes: fork, exec, capset, setcap, all")
	flag.Parse()

	if err := run(*output, *logFile, *format, *events); err != nil {
		log.Fatal(err)
	}
}
