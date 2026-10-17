// SPDX-License-Identifier: GPL-2.0-only
// This guard restricts socket ownership. It does not grant a socket operation.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1
struct kernfs_node { __u64 id; } __attribute__((preserve_access_index));
struct cgroup {
    int level;
    struct kernfs_node *kn;
    struct cgroup *ancestors[];
} __attribute__((preserve_access_index));
struct sock_cgroup_data { struct cgroup *cgroup; } __attribute__((preserve_access_index));
struct sock { struct sock_cgroup_data sk_cgrp_data; } __attribute__((preserve_access_index));
struct socket { struct sock *sk; } __attribute__((preserve_access_index));
struct msghdr;
struct custody_binding { __u64 generation, expires_ns; };
struct custody_stats { __u64 decisions, lost; };
struct custody_event {
    __u64 sequence, domain, socket_domain, cgroup, generation, mono_ns;
    __u32 pid, uid, hook, passed;
};
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, __u32); } cust_managed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, struct custody_binding); } cust_bindings SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct custody_stats); } cust_stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } cust_events SEC(".maps");

static __always_inline __u64 socket_domain(struct socket *socket)
{
    struct cgroup *owner = BPF_CORE_READ(socket, sk, sk_cgrp_data.cgroup);
    if (!owner || BPF_CORE_READ(owner, level) < 1) return 0;
    struct cgroup *root = 0;
    if (bpf_core_read(&root, sizeof(root), &owner->ancestors[1]) || !root) return 0;
    return BPF_CORE_READ(root, kn, id);
}

static __always_inline void record(__u64 domain, __u64 owner,
                                  struct custody_binding *binding, int passed, __u32 hook)
{
    __u32 zero = 0;
    struct custody_stats *stats = bpf_map_lookup_elem(&cust_stats, &zero);
    if (!stats) return;
    __u64 sequence = __sync_fetch_and_add(&stats->decisions, 1) + 1;
    struct custody_event *event = bpf_ringbuf_reserve(&cust_events, sizeof(*event), 0);
    if (!event) { __sync_fetch_and_add(&stats->lost, 1); return; }
    __builtin_memset(event, 0, sizeof(*event));
    event->sequence = sequence;
    event->domain = domain;
    event->socket_domain = owner;
    event->cgroup = bpf_get_current_cgroup_id();
    event->generation = binding ? binding->generation : 0;
    event->mono_ns = bpf_ktime_get_ns();
    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->uid = bpf_get_current_uid_gid();
    event->hook = hook;
    event->passed = passed;
    bpf_ringbuf_submit(event, 0);
}

static __always_inline int check_custody(struct socket *socket, int ret, __u32 hook)
{
    if (ret) return ret;
    __u64 domain = bpf_get_current_ancestor_cgroup_id(1);
    __u32 *managed = bpf_map_lookup_elem(&cust_managed, &domain);
    if (!managed) return 0; // The enrollment barrier installs this marker first.
    struct custody_binding *binding = bpf_map_lookup_elem(&cust_bindings, &domain);
    __u64 owner = socket_domain(socket);
    int passed = binding && binding->generation &&
        bpf_ktime_get_ns() < binding->expires_ns && owner == domain;
    record(domain, owner, binding, passed, hook);
    return passed ? 0 : -EPERM;
}

SEC("lsm/socket_sendmsg")
int BPF_PROG(custody_sendmsg, struct socket *socket, struct msghdr *message,
             int size, int ret) { return check_custody(socket, ret, 1); }

SEC("lsm/socket_recvmsg")
int BPF_PROG(custody_recvmsg, struct socket *socket, struct msghdr *message,
             int size, int flags, int ret) { return check_custody(socket, ret, 2); }

char LICENSE[] SEC("license") = "GPL";
