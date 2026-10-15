/* Shared between the BPF program and (by mirror) the Go loader.
 * Field order/sizes must match `type event` in main.go exactly. */
#ifndef CAPMON_H
#define CAPMON_H

enum event_type {
	EV_FORK        = 1, /* new process created (fork/vfork/clone, not threads) */
	EV_EXEC        = 2, /* execve completed */
	EV_CAPCHANGE   = 3, /* credentials/capabilities of a running task changed */
	EV_FILECAP_SET = 4, /* security.capability xattr set (setcap) */
	EV_FILECAP_DEL = 5, /* security.capability xattr removed (setcap -r) */
};

#define CMDLINE_LEN 256
#define PATH_LEN    512
#define COMP_N      8
#define COMP_LEN    64

struct caps {
	__u64 eff;
	__u64 perm;
	__u64 inh;
	__u64 bnd;
	__u64 amb;
};

struct event {
	__u64 ts;
	__u32 type;
	__u32 pid;   /* tgid */
	__u32 tid;
	__u32 ppid;  /* tgid of parent */
	__u32 uid;
	__u32 gid;
	__u32 euid;
	__u32 egid;
	struct caps prev;
	struct caps cur;
	__u32 cmdline_len;
	__u32 depth;      /* EV_FILECAP_*: number of valid path components */
	__u32 file_magic; /* EV_FILECAP_SET: raw magic_etc of vfs_cap_data */
	__u32 file_rootid;
	__u64 file_perm;
	__u64 file_inh;
	__u64 file_ino;
	__u32 file_dev;
	__u32 file_valid; /* EV_FILECAP_SET: xattr value parsed */
	char comm[16];
	char cmdline[CMDLINE_LEN];
	union {
		char path[PATH_LEN];               /* EV_EXEC: bprm->filename */
		char comp[COMP_N][COMP_LEN];       /* EV_FILECAP_*: leaf first */
	};
};

#endif
