package main

import (
	"fmt"
	"strings"
)

// Linux capability names indexed by bit number (include/uapi/linux/capability.h).
var capNames = [...]string{
	"CAP_CHOWN", "CAP_DAC_OVERRIDE", "CAP_DAC_READ_SEARCH", "CAP_FOWNER",
	"CAP_FSETID", "CAP_KILL", "CAP_SETGID", "CAP_SETUID", "CAP_SETPCAP",
	"CAP_LINUX_IMMUTABLE", "CAP_NET_BIND_SERVICE", "CAP_NET_BROADCAST",
	"CAP_NET_ADMIN", "CAP_NET_RAW", "CAP_IPC_LOCK", "CAP_IPC_OWNER",
	"CAP_SYS_MODULE", "CAP_SYS_RAWIO", "CAP_SYS_CHROOT", "CAP_SYS_PTRACE",
	"CAP_SYS_PACCT", "CAP_SYS_ADMIN", "CAP_SYS_BOOT", "CAP_SYS_NICE",
	"CAP_SYS_RESOURCE", "CAP_SYS_TIME", "CAP_SYS_TTY_CONFIG", "CAP_MKNOD",
	"CAP_LEASE", "CAP_AUDIT_WRITE", "CAP_AUDIT_CONTROL", "CAP_SETFCAP",
	"CAP_MAC_OVERRIDE", "CAP_MAC_ADMIN", "CAP_SYSLOG", "CAP_WAKE_ALARM",
	"CAP_BLOCK_SUSPEND", "CAP_AUDIT_READ", "CAP_PERFMON", "CAP_BPF",
	"CAP_CHECKPOINT_RESTORE",
}

// capAll is the mask with every capability known to this build set.
const capAll = (uint64(1) << uint(len(capNames))) - 1

func capName(bit int) string {
	if bit < len(capNames) {
		return capNames[bit]
	}
	return fmt.Sprintf("CAP_%d", bit)
}

// capList returns the names of the capabilities in mask, in bit order.
func capList(mask uint64) []string {
	var out []string
	for b := 0; b < 64; b++ {
		if mask&(1<<uint(b)) != 0 {
			out = append(out, capName(b))
		}
	}
	return out
}

// capString renders a mask as "-" (empty), "ALL", or a comma separated list.
func capString(mask uint64) string {
	switch {
	case mask == 0:
		return "-"
	case mask&capAll == capAll:
		if extra := mask &^ capAll; extra != 0 {
			return "ALL," + strings.Join(capList(extra), ",")
		}
		return "ALL"
	}
	return strings.Join(capList(mask), ",")
}
