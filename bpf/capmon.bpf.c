// SPDX-License-Identifier: GPL-2.0
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "capmon.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

/* Capabilities a task had before an execve, saved by the commit_creds hook
 * and consumed by the sched_process_exec hook. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, struct caps);
} exec_prev SEC(".maps");

/* Events lost because the ring buffer was full. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

#define XATTR_CAPS "security.capability"
#define VFS_CAP_REVISION_MASK 0xFF000000

static __always_inline void count_drop(void)
{
	__u32 k = 0;
	__u64 *v = bpf_map_lookup_elem(&drops, &k);
	if (v)
		*v += 1;
}

static __always_inline void read_caps(const struct cred *c, struct caps *o)
{
	o->eff  = BPF_CORE_READ(c, cap_effective.val);
	o->perm = BPF_CORE_READ(c, cap_permitted.val);
	o->inh  = BPF_CORE_READ(c, cap_inheritable.val);
	o->bnd  = BPF_CORE_READ(c, cap_bset.val);
	o->amb  = BPF_CORE_READ(c, cap_ambient.val);
}

static __always_inline bool caps_equal(const struct caps *a, const struct caps *b)
{
	return a->eff == b->eff && a->perm == b->perm && a->inh == b->inh &&
	       a->bnd == b->bnd && a->amb == b->amb;
}

/* Reserve an event and fill every scalar field (ring buffer memory is not
 * zeroed). `t` supplies identity; `c` supplies uid/gid. */
static __always_inline struct event *new_event(__u32 type, struct task_struct *t,
					       const struct cred *c)
{
	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return NULL;
	}
	e->ts   = bpf_ktime_get_ns();
	e->type = type;
	e->pid  = BPF_CORE_READ(t, tgid);
	e->tid  = BPF_CORE_READ(t, pid);
	e->ppid = BPF_CORE_READ(t, real_parent, tgid);
	e->uid  = BPF_CORE_READ(c, uid.val);
	e->gid  = BPF_CORE_READ(c, gid.val);
	e->euid = BPF_CORE_READ(c, euid.val);
	e->egid = BPF_CORE_READ(c, egid.val);
	__builtin_memset(&e->prev, 0, sizeof(e->prev));
	__builtin_memset(&e->cur, 0, sizeof(e->cur));
	e->cmdline_len = 0;
	e->cmdline[0]  = 0;
	e->depth       = 0;
	e->file_magic  = 0;
	e->file_rootid = 0;
	e->file_perm   = 0;
	e->file_inh    = 0;
	e->file_ino    = 0;
	e->file_dev    = 0;
	e->file_valid  = 0;
	e->path[0]     = 0;
	bpf_probe_read_kernel_str(e->comm, sizeof(e->comm), &t->comm);
	return e;
}

/* Copy argv of `t` (must be the current task: user memory is read) into e. */
static __always_inline void fill_cmdline(struct event *e, struct task_struct *t)
{
	struct mm_struct *mm = BPF_CORE_READ(t, mm);
	if (!mm)
		return;
	unsigned long start = BPF_CORE_READ(mm, arg_start);
	unsigned long end   = BPF_CORE_READ(mm, arg_end);
	if (end <= start)
		return;
	unsigned long len = end - start;
	if (len > CMDLINE_LEN - 1)
		len = CMDLINE_LEN - 1;
	if (bpf_probe_read_user(e->cmdline, len, (void *)start))
		return;
	e->cmdline[len] = 0;
	e->cmdline_len  = len;
}

/* ---- process creation -------------------------------------------------- */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child)
{
	/* threads are not new processes */
	if (BPF_CORE_READ(child, pid) != BPF_CORE_READ(child, tgid))
		return 0;

	const struct cred *ccred = BPF_CORE_READ(child, cred);
	struct event *e = new_event(EV_FORK, child, ccred);
	if (!e)
		return 0;
	e->ppid = BPF_CORE_READ(parent, tgid);
	read_caps(BPF_CORE_READ(parent, cred), &e->prev);
	read_caps(ccred, &e->cur);
	/* In this hook `current` is the parent and the child still runs the
	 * same image, so the parent's argv is the child's argv. */
	fill_cmdline(e, parent);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(on_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	const struct cred *c = BPF_CORE_READ(p, cred);
	struct event *e = new_event(EV_EXEC, p, c);
	if (!e)
		return 0;
	read_caps(c, &e->cur);
	__u32 tgid = e->pid;
	struct caps *prev = bpf_map_lookup_elem(&exec_prev, &tgid);
	if (prev) {
		e->prev = *prev;
		bpf_map_delete_elem(&exec_prev, &tgid);
	} else {
		e->prev = e->cur;
	}
	fill_cmdline(e, p);
	const char *fn = BPF_CORE_READ(bprm, filename);
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), fn);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- capability / credential changes of running tasks ------------------ */

/* commit_creds() is the single choke point for every credential change:
 * capset(2), prctl(PR_CAP_AMBIENT / PR_CAPBSET_DROP / PR_SET_KEEPCAPS),
 * setuid & friends, unshare/clone(CLONE_NEWUSER), and execve. The hook runs
 * before the switch, so current->real_cred is still the old set. */
SEC("fentry/commit_creds")
int BPF_PROG(on_commit_creds, struct cred *new)
{
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct caps oldc, newc;

	read_caps(BPF_CORE_READ(t, real_cred), &oldc);
	read_caps(new, &newc);

	if (BPF_CORE_READ_BITFIELD_PROBED(t, in_execve)) {
		/* execve: remember the pre-exec caps; the exec event reports them */
		__u32 tgid = BPF_CORE_READ(t, tgid);
		bpf_map_update_elem(&exec_prev, &tgid, &oldc, BPF_ANY);
		return 0;
	}
	if (caps_equal(&oldc, &newc))
		return 0;

	struct event *e = new_event(EV_CAPCHANGE, t, new);
	if (!e)
		return 0;
	e->prev = oldc;
	e->cur  = newc;
	fill_cmdline(e, t);
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- file capabilities (setcap) ---------------------------------------- */

static __always_inline bool is_cap_xattr(const char *name)
{
	char buf[sizeof(XATTR_CAPS)];
	const char want[sizeof(XATTR_CAPS)] = XATTR_CAPS;

	if (bpf_probe_read_kernel_str(buf, sizeof(buf), name) < 0)
		return false;
#pragma unroll
	for (int i = 0; i < sizeof(want); i++)
		if (buf[i] != want[i])
			return false;
	return true;
}

/* Record the target path (leaf first), inode and device. The dentry chain
 * ends at the filesystem root, so the path is relative to its mount. */
static __always_inline void fill_target(struct event *e, struct dentry *d)
{
	struct inode *ino = BPF_CORE_READ(d, d_inode);
	e->file_ino = BPF_CORE_READ(ino, i_ino);
	e->file_dev = BPF_CORE_READ(ino, i_sb, s_dev);

	__u32 n = 0;
#pragma unroll
	for (int i = 0; i < COMP_N; i++) {
		const unsigned char *name = BPF_CORE_READ(d, d_name.name);
		bpf_probe_read_kernel_str(e->comp[i], COMP_LEN, name);
		n = i + 1;
		struct dentry *parent = BPF_CORE_READ(d, d_parent);
		if (parent == d)
			break;
		d = parent;
	}
	e->depth = n;
}

static __always_inline void fill_current(struct event *e, struct task_struct *t)
{
	read_caps(BPF_CORE_READ(t, cred), &e->cur);
	e->prev = e->cur; /* task creds are not modified by setcap itself */
	fill_cmdline(e, t);
}

SEC("fentry/security_inode_setxattr")
int BPF_PROG(on_setxattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name, const void *value, size_t size, int flags)
{
	if (!is_cap_xattr(name))
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct event *e = new_event(EV_FILECAP_SET, t, BPF_CORE_READ(t, cred));
	if (!e)
		return 0;
	fill_current(e, t);
	fill_target(e, dentry);

	/* struct vfs_ns_cap_data: magic_etc, data[2]{permitted,inheritable}, rootid */
	__u32 raw[6] = {};
	size_t n = size;
	if (n > sizeof(raw))
		n = sizeof(raw);
	if (n >= 4 && !bpf_probe_read_kernel(raw, n & 0x1f, value)) {
		__u32 magic = raw[0];
		e->file_magic = magic;
		e->file_perm  = raw[1];
		e->file_inh   = raw[2];
		if ((magic & VFS_CAP_REVISION_MASK) != 0x01000000) {
			e->file_perm |= (__u64)raw[3] << 32;
			e->file_inh  |= (__u64)raw[4] << 32;
		}
		if ((magic & VFS_CAP_REVISION_MASK) == 0x03000000)
			e->file_rootid = raw[5];
		e->file_valid = 1;
	}
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("fentry/security_inode_removexattr")
int BPF_PROG(on_removexattr, struct mnt_idmap *idmap, struct dentry *dentry,
	     const char *name)
{
	if (!is_cap_xattr(name))
		return 0;
	struct task_struct *t = (struct task_struct *)bpf_get_current_task_btf();
	struct event *e = new_event(EV_FILECAP_DEL, t, BPF_CORE_READ(t, cred));
	if (!e)
		return 0;
	fill_current(e, t);
	fill_target(e, dentry);
	bpf_ringbuf_submit(e, 0);
	return 0;
}
