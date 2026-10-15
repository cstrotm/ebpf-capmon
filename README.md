# ebpf-capmon

eBPF Linux capabilities monitor. Logs the capabilities of every new process and
every later change to a running process's capabilities, plus `setcap` changes
to file capabilities. Output goes to a file, syslog, or the systemd journal

## Hooks

| Event | Hook | Covers |
|---|---|---|
| `FORK` | `tp_btf/sched_process_fork` | fork, vfork, clone (threads are skipped) |
| `EXEC` | `tp_btf/sched_process_exec` | every execve/execveat; prev = pre-exec caps |
| `CAPCHANGE` | `fentry/commit_creds` | capset(2), prctl (ambient / bounding set / keepcaps), setuid & friends, user namespaces |
| `FILECAP_SET` | `fentry/security_inode_setxattr` | `setcap`, `setxattr(security.capability)` |
| `FILECAP_DEL` | `fentry/security_inode_removexattr` | `setcap -r` |

`commit_creds` is the single place every credential change passes through, and
the hook runs before the switch, so old and new sets can be compared. Changes
made by execve are folded into the `EXEC` event.

## Logged fields

pid (tgid), tid, ppid, uid, gid (plus euid/egid), comm, command line,
previous and current capabilities (effective, permitted, inheritable,
bounding, ambient). `CAPCHANGE` and `EXEC` add `gained{...}` and
`removed{...}` per capability set (`-` when empty); JSON has
`gained_caps`/`removed_caps`, the journal
`CAPMON_GAINED`/`CAPMON_REMOVED`. `EXEC` adds the executed
file. `FILECAP_*` log the target (mount-relative path, device, inode)
and the file capabilities being written.

Notes and limits:

- For `FORK` the previous caps are the parent's; for `FILECAP_*` there are no
  previous *file* caps (not readable from a non-sleepable hook); the process
  caps are logged as `cur`.
- Command line is read from the process (first 255 bytes, `…` if truncated).
- Paths are resolved from the dentry chain, so they are relative to the
  filesystem's mount point (up to 8 components).
- If the ring buffer fills, events are lost and a `dropped N events`
  line is logged.

## Build

Requires Go 1.22+, clang, and `bpftool` (only to regenerate `bpf/vmlinux.h`).
Kernel needs BTF (`/sys/kernel/btf/vmlinux`), BPF trampolines (fentry) and 5.8+.

```
make            # go generate (bpf2go) + go build
make test
sudo make install
```

The generated `capmon_x86_bpfel.*` files embed the BPF object; the
binary is self-contained.

## Usage

```
ebpf-capmon [-output journal|file|syslog] [-logfile PATH] [-format text|json] [-events all|fork,exec,capset,setcap]
```

| Flag | Default | Description |
|---|---|---|
| `-output` | `journal` | `file`, `syslog`, or `journal` |
| `-logfile` | `/var/log/ebpf-capmon.log` | path for `-output file` |
| `-format` | `text` | `text` key=value lines or one JSON object per line |
| `-events` | `all` | event classes: `fork`, `exec`, `capset`, `setcap` |

Needs `CAP_BPF` + `CAP_PERFMON` (or root). Example:

```
CAPCHANGE pid=4242 tid=4242 ppid=1 uid=1000 gid=1000 euid=1000 egid=1000 comm="ping" cmdline="ping -c 1 ::1" prev{eff=CAP_NET_RAW ...} cur{eff=- ...} gained{-} removed{eff=CAP_NET_RAW perm=CAP_NET_RAW}
```

### JSON example

With `-format json` each event is one line (shown wrapped here; the process
below runs with a bounding set of just `CAP_NET_RAW`, as a systemd unit with
`CapabilityBoundingSet=CAP_NET_RAW` would):

```json
{"time":"2026-10-15T09:30:12.123456789Z","event":"CAPCHANGE",
 "pid":4242,"tid":4242,"ppid":1,"uid":1000,"gid":1000,"euid":1000,"egid":1000,
 "comm":"ping","cmdline":"ping -c 1 ::1",
 "prev_caps":   {"effective":["CAP_NET_RAW"],"permitted":["CAP_NET_RAW"],"inheritable":[],"bounding":["CAP_NET_RAW"],"ambient":[]},
 "cur_caps":    {"effective":[],"permitted":[],"inheritable":[],"bounding":["CAP_NET_RAW"],"ambient":[]},
 "gained_caps": {"effective":[],"permitted":[],"inheritable":[],"bounding":[],"ambient":[]},
 "removed_caps":{"effective":["CAP_NET_RAW"],"permitted":["CAP_NET_RAW"],"inheritable":[],"bounding":[],"ambient":[]}}
```

`EXEC` events have the same shape plus `"exe"`. `FORK` events have no
`gained_caps`/`removed_caps`. `setcap` produces a `FILECAP_SET` event with
`target`, `dev`, `ino` and `file_caps` instead of the process capability sets:

```json
{"time":"2026-10-15T09:31:00Z","event":"FILECAP_SET",
 "pid":5000,"tid":5000,"ppid":4990,"uid":0,"gid":0,"euid":0,"egid":0,
 "comm":"setcap","cmdline":"setcap cap_net_raw+ep /usr/local/bin/mytool",
 "target":"/bin/mytool","dev":"259:2","ino":131075,
 "file_caps":{"permitted":["CAP_NET_RAW"],"inheritable":[],"effective_bit":true,"version":2}}
```

`target` is relative to the mount point of the filesystem holding the file.

The journal sink also sets fields `CAPMON_EVENT`, `CAPMON_PID`, `CAPMON_PPID`,
`CAPMON_UID`, `CAPMON_GID`, `CAPMON_CMDLINE`, `CAPMON_PREV_CAPS`,
`CAPMON_CUR_CAPS`: `journalctl -t ebpf-capmon CAPMON_EVENT=CAPCHANGE`.

## systemd

```
sudo useradd -r -s /usr/sbin/nologin -d / ebpf-capmon
sudo make install
sudo cp ebpf-capmon.service /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ebpf-capmon
```

For `-output file`, uncomment `ReadWritePaths=/var/log` in the unit and make
the log file writable by `ebpf-capmon`.
