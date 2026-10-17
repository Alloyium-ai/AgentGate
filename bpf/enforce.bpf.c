// SPDX-License-Identifier: GPL-2.0-only
// This experimental object supplies selected decisions, not general confinement.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define PATH_SIZE 160
#define EPERM 1
#define FMODE_WRITE 2
#define IPPROTO_TCP 6

struct dentry;
struct vfsmount;
struct path { struct vfsmount *mnt; struct dentry *dentry; } __attribute__((preserve_access_index));
struct file { struct path f_path; unsigned int f_mode; } __attribute__((preserve_access_index));

struct policy {
    __u64 generation;
    __u64 expires_ns;
    __u32 allowed_ip;
    __u32 allowed_port;
    char workspace[PATH_SIZE];
};
struct counters { __u64 decisions; __u64 lost; };
struct event {
    __u64 sequence;
    __u64 generation;
    __u64 cgroup;
    __u64 mono_ns;
    __u32 pid;
    __u32 uid;
    __u32 hook; // 1: write-open, 2: connect4
    __u32 allowed;
    __u32 ip;
    __u32 port;
    char path[PATH_SIZE];
};
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 1);
    __type(key, __u64); __type(value, struct policy); } policies SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct counters); } stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } events SEC(".maps");

static __always_inline struct policy *managed(void)
{
    // The trusted launcher creates its domain directly below the cgroup root.
    // Every descendant uses that domain's immutable policy; no map-miss allow.
    __u64 root = bpf_get_current_ancestor_cgroup_id(1);
    return bpf_map_lookup_elem(&policies, &root);
}

static __always_inline int live(struct policy *p)
{
    return p->generation && bpf_ktime_get_ns() < p->expires_ns;
}

static __always_inline int workspace_match(char *path, char *prefix)
{
    // The compiler requires a trailing slash and rejects long paths.
    for (int i = 0; i < PATH_SIZE; i++) {
        if (!prefix[i]) return i > 1;
        if (prefix[i] != path[i]) return 0;
    }
    return 0;
}

static __always_inline void report(struct policy *p, __u32 hook, int allowed,
                                    char *path, __u32 ip, __u32 port)
{
    __u32 zero = 0;
    struct counters *s = bpf_map_lookup_elem(&stats, &zero);
    if (!s) return;
    __u64 seq = __sync_fetch_and_add(&s->decisions, 1) + 1;
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) { __sync_fetch_and_add(&s->lost, 1); return; }
    __builtin_memset(e, 0, sizeof(*e));
    e->sequence = seq;
    e->generation = p->generation;
    e->cgroup = bpf_get_current_cgroup_id();
    e->mono_ns = bpf_ktime_get_ns();
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->uid = bpf_get_current_uid_gid();
    e->hook = hook;
    e->allowed = allowed;
    e->ip = ip;
    e->port = port;
    if (path) __builtin_memcpy(e->path, path, PATH_SIZE);
    bpf_ringbuf_submit(e, 0);
}

SEC("lsm/file_open")
int BPF_PROG(write_open, struct file *file, int ret)
{
    if (ret) return ret;
    struct policy *p = managed();
    if (!p || !(BPF_CORE_READ(file, f_mode) & FMODE_WRITE)) return 0;
    char path[PATH_SIZE] = {};
    long n = bpf_d_path(&file->f_path, path, sizeof(path));
    int allow = n > 0 && n < PATH_SIZE && live(p) && workspace_match(path, p->workspace);
    report(p, 1, allow, path, 0, 0);
    return allow ? 0 : -EPERM;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx)
{
    struct policy *p = managed();
    if (!p) return 0; // This attachment exists only on a prepared managed domain.
    int allow = live(p) && ctx->protocol == IPPROTO_TCP &&
        ctx->user_ip4 == p->allowed_ip && ctx->user_port == p->allowed_port;
    report(p, 2, allow, 0, ctx->user_ip4, ctx->user_port);
    return allow;
}

SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) { return 0; } // IPv6 outside the small probe.

char LICENSE[] SEC("license") = "GPL";
