package main

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Must equal sizeof(struct event) in bpf/capmon.h.
func TestEventSize(t *testing.T) {
	if got := binary.Size(event{}); got != 952 {
		t.Fatalf("event size %d, want 952", got)
	}
}

func TestFormat(t *testing.T) {
	var e event
	e.Type, e.Pid, e.Ppid, e.Uid = evCapChange, 10, 1, 1000
	copy(e.Comm[:], "ping")
	copy(e.Cmdline[:], "ping\x00-c\x001")
	e.CmdlineLen = 10
	e.Prev.Eff = 1 << 13
	e.Cur.Eff = 0
	got := e.text()
	for _, w := range []string{`cmdline="ping -c 1"`, "prev{eff=CAP_NET_RAW", "gained{-} removed{eff=CAP_NET_RAW}"} {
		if !strings.Contains(got, w) {
			t.Errorf("%q missing %q", got, w)
		}
	}
	e = event{Type: evFileCapSet, Depth: 3}
	copy(e.Raw[0:], "ping")
	copy(e.Raw[64:], "bin")
	copy(e.Raw[128:], "/")
	if e.target() != "/bin/ping" {
		t.Errorf("target %q", e.target())
	}
}
