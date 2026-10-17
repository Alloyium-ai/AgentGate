// SPDX-License-Identifier: GPL-2.0-only
// Every managed socket operation starts denied. Peer and custody checks remain
// independent mandatory conditions. Non-socket file permissions stay unchanged.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "network_abi.h"
#include "network_packet.h"
#include "network_socket_abi.h"
#define EPERM 1
struct socket_eval_state {
    __u64 busy;
    __u32 invalid, count;
    __s32 best_local, best_width;
    __u32 reserved;
    __u64 domain, generation, expires_ns, peer_expires_ns;
    struct socket_operation operation;
    struct socket_decision result;
};

struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, __u32); } sock_managed SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, struct socket_policy); } sock_policies SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, struct net_policy); } net_policies SEC(".maps");
#include "network_peer_match.h"
#include "network_socket_kernel.h"
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct socket_stats); } sock_stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } sock_events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct socket_eval_state); } sock_eval SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_SK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int); __type(value, struct socket_epoch); } sock_epochs SEC(".maps");

static __always_inline int local_match(struct socket_rule *rule, struct socket_operation *operation)
{
    if (!rule->has_local) return 1;
    if (!operation->has_local || operation->port < rule->port_from || operation->port > rule->port_to) return 0;
#pragma unroll
    for (int i = 0; i < 16; i++) if (rule->address[i] != operation->address[i]) return 0;
    return 1;
}

static __always_inline int option_match(struct socket_rule *rule, struct socket_operation *operation)
{
    if (operation->operation != OP_SET_OPTION && operation->operation != OP_GET_OPTION) return 1;
    if (!rule->option_count && !rule->effect) return 1;
    for (int i = 0; i < MAX_SOCKET_OPTIONS; i++) {
        if (i >= rule->option_count) break;
        __u32 index = i;
        barrier_var(index);
        index &= MAX_SOCKET_OPTIONS - 1;
        if (rule->options[index].level == operation->level && rule->options[index].name == operation->name) return 1;
    }
    return 0;
}

static long evaluate_socket_rule(__u32 index, void *context)
{
    __u32 zero = 0;
    struct socket_eval_state *s = bpf_map_lookup_elem(&sock_eval, &zero);
    if (!s) return 1;
    if (!s->busy) { s->invalid = 1; return 1; }
    if (index >= s->count) return 1;
    struct socket_policy *policy = bpf_map_lookup_elem(&sock_policies, &s->domain);
    struct net_policy *peer = bpf_map_lookup_elem(&net_policies, &s->domain);
    if (!policy || !peer || policy->generation != s->generation || peer->generation != s->generation ||
        policy->expires_ns != s->expires_ns || peer->expires_ns != s->peer_expires_ns || peer->reserved != s->reserved || policy->count != s->count || peer->count > MAX_RULES) {
        s->invalid = 1;
        return 1;
    }
    barrier_var(index);
    index &= MAX_RULES - 1;
    struct socket_rule *rule = &policy->rules[index];
    if (rule->option_count > MAX_SOCKET_OPTIONS || rule->effect > 1 || rule->has_local > 1 ||
        rule->port_from > rule->port_to || !rule->index || !rule->operations || (rule->operations & ~OP_ALL) ||
        (rule->effect && !rule->has_local && (rule->operations & (OP_BIND | OP_LISTEN | OP_ACCEPT))) ||
        (rule->effect && rule->has_local && (rule->operations & OP_CREATE))) {
        s->invalid = 1;
        return 1;
    }
    struct socket_operation *operation = &s->operation;
    if (rule->family != operation->family || rule->protocol != operation->protocol ||
        !(rule->operations & operation->operation) || !local_match(rule, operation) || !option_match(rule, operation)) return 0;
    int local = rule->has_local;
    int width = local ? rule->port_to - rule->port_from : 65535;
    if (local < s->best_local || (local == s->best_local && width > s->best_width)) return 0;
    if (local == s->best_local && width == s->best_width && !s->result.allow) return 0;
    if (local == s->best_local && width == s->best_width && rule->effect && s->result.index < rule->index) return 0;
    s->best_local = local;
    s->best_width = width;
    s->result.allow = rule->effect == 1;
    s->result.index = rule->index;
    return 0;
}

static __always_inline struct socket_decision operation_decision(__u64 domain, struct socket_policy *policy,
                                                                struct socket_operation *operation)
{
    struct net_policy *peer = bpf_map_lookup_elem(&net_policies, &domain);
    struct socket_decision result = {.lease_revision = peer ? peer->reserved : 0};
    __u64 now = bpf_ktime_get_ns();
    if (!policy || !peer || !policy->generation || peer->generation != policy->generation ||
        now >= policy->expires_ns || now >= peer->expires_ns || policy->count > MAX_RULES || peer->count > MAX_RULES ||
        (operation->family != 2 && operation->family != 10) ||
        (operation->protocol != TCP && operation->protocol != UDP)) return result;
    __u32 zero = 0;
    struct socket_eval_state *s = bpf_map_lookup_elem(&sock_eval, &zero);
    if (!s || __sync_val_compare_and_swap(&s->busy, 0, 1)) return result;
    s->invalid = 0;
    s->count = policy->count;
    s->reserved = peer->reserved;
    s->best_local = -1;
    s->best_width = 65536;
    s->domain = domain;
    s->generation = policy->generation;
    s->expires_ns = policy->expires_ns;
    s->peer_expires_ns = peer->expires_ns;
    __builtin_memcpy(&s->operation, operation, sizeof(*operation));
    s->result = result;
    long status = bpf_loop(MAX_RULES, evaluate_socket_rule, 0, 0);
    if (status >= 0 && !s->invalid) result = s->result;
    __sync_lock_test_and_set(&s->busy, 0);
    return result;
}

static __always_inline void operation_report(__u64 domain, __u64 cgroup, __u64 owner,
                                            struct socket_policy *policy, struct socket_operation *operation,
                                            struct socket_decision decision, __u32 source)
{
    __u32 zero = 0;
    struct socket_stats *stats = bpf_map_lookup_elem(&sock_stats, &zero);
    if (!stats) return;
    __u64 sequence = __sync_fetch_and_add(&stats->decisions, 1) + 1;
    struct socket_event *event = bpf_ringbuf_reserve(&sock_events, sizeof(*event), 0);
    if (!event) { __sync_fetch_and_add(&stats->lost, 1); return; }
    __builtin_memset(event, 0, sizeof(*event));
    event->sequence = sequence;
    event->generation = policy ? policy->generation : 0;
    event->domain = domain;
    event->cgroup = cgroup;
    event->socket_domain = owner;
    event->mono_ns = bpf_ktime_get_ns();
    if (source != 3 && source != 4) { event->pid = bpf_get_current_pid_tgid() >> 32; event->uid = bpf_get_current_uid_gid(); }
    event->operation = operation->operation;
    event->allowed = decision.allow;
    event->rule_index = decision.index;
    event->family = operation->family;
    event->protocol = operation->protocol;
    event->port = operation->port;
    event->level = operation->level;
    event->name = operation->name;
    event->source = source;
    event->lease_revision = decision.lease_revision;
    __builtin_memcpy(event->address, operation->address, 16);
    bpf_ringbuf_submit(event, 0);
}

static __always_inline struct decision receive_peer(struct socket *socket, __u64 domain)
{
    struct net_policy *policy = bpf_map_lookup_elem(&net_policies, &domain);
    struct endpoint peer = {};
    struct decision denied = {.lease_revision = policy ? policy->reserved : 0};
    struct sock *sk = socket->sk;
    if (!sk) return denied;
    __u32 protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
    if (protocol == TCP) {
        if (connected_peer(socket, &peer)) return evaluate(policy, &peer, domain);
        return denied;
    }
    if (protocol != UDP) return denied;
    struct socket_epoch *epoch = bpf_sk_storage_get(&sock_epochs, sk, 0, 0);
    if (!epoch || epoch->domain != domain) return denied;
    __u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    peer.family = family == 2 ? IPV4 : family == 10 ? IPV6 : 0;
    peer.protocol = UDP;
    struct decision decision = live_udp_peers(policy, &peer, domain);
    if (epoch->lease_revision != decision.lease_revision) decision.allow = 0;
    if (decision.allow && BPF_CORE_READ(sk, __sk_common.skc_dport)) {
        if (!connected_peer(socket, &peer)) decision.allow = 0;
        else {
            struct decision connected = evaluate(policy, &peer, domain);
            if (!connected.allow || connected.lease_revision != decision.lease_revision) decision.allow = 0;
        }
    }
    return decision;
}

static __always_inline int socket_check(struct socket *socket, struct socket_operation *operation,
                                      int context_valid, __u32 source, struct endpoint *peer)
{
    __u64 domain = bpf_get_current_ancestor_cgroup_id(1);
    if (!bpf_map_lookup_elem(&sock_managed, &domain)) return 0;
    struct socket_policy *policy = bpf_map_lookup_elem(&sock_policies, &domain);
    __u64 owner = operation_socket_domain(socket);
    struct net_policy *current_peer = bpf_map_lookup_elem(&net_policies, &domain);
    struct socket_decision decision = {.lease_revision = current_peer ? current_peer->reserved : 0};
    if (context_valid && owner == domain) {
        decision = operation_decision(domain, policy, operation);
        if (decision.allow && operation->operation == OP_SEND) {
            struct net_policy *endpoints = bpf_map_lookup_elem(&net_policies, &domain);
            if (!peer) decision.allow = 0;
            else {
                struct decision endpoint = evaluate(endpoints, peer, domain);
                decision.lease_revision = endpoint.lease_revision;
                if (!endpoint.allow) decision.allow = 0;
            }
        }
        if (decision.allow && operation->operation == OP_RECEIVE) {
            struct decision endpoint = receive_peer(socket, domain);
            decision.lease_revision = endpoint.lease_revision;
            if (!endpoint.allow) decision.allow = 0;
        }
    }
    operation_report(domain, bpf_get_current_cgroup_id(), owner, policy, operation, decision, source);
    return decision.allow ? 0 : -EPERM;
}

SEC("lsm/socket_create")
int BPF_PROG(operation_create, int family, int type, int protocol, int kern, int ret)
{
    if (ret) return ret;
    __u64 domain = bpf_get_current_ancestor_cgroup_id(1);
    if (!bpf_map_lookup_elem(&sock_managed, &domain)) return 0;
    struct socket_policy *policy = bpf_map_lookup_elem(&sock_policies, &domain);
    struct socket_operation operation = {.operation = OP_CREATE, .family = family};
    type &= 15;
    if (type == 1 && (!protocol || protocol == TCP)) operation.protocol = TCP;
    else if (type == 2 && (!protocol || protocol == UDP)) operation.protocol = UDP;
    struct socket_decision decision = operation_decision(domain, policy, &operation);
    operation_report(domain, bpf_get_current_cgroup_id(), 0, policy, &operation, decision, 1);
    return decision.allow ? 0 : -EPERM;
}

SEC("lsm/socket_bind")
int BPF_PROG(operation_bind, struct socket *socket, struct sockaddr *address, int size, int ret)
{
    if (ret) return ret;
    struct socket_operation operation = {.operation = OP_BIND};
    int valid = socket_context(socket, &operation) && bind_context(address, size, &operation);
    return socket_check(socket, &operation, valid, 1, 0);
}

SEC("lsm/socket_post_create")
int BPF_PROG(operation_post_create, struct socket *socket, int family, int type,
             int protocol, int kern, int ret)
{
    if (ret) return ret;
    __u64 domain = bpf_get_current_ancestor_cgroup_id(1);
    if (!bpf_map_lookup_elem(&sock_managed, &domain)) return 0;
    struct socket_policy *policy = bpf_map_lookup_elem(&sock_policies, &domain);
    struct socket_operation operation = {.operation = OP_CREATE};
    struct net_policy *current_peer = bpf_map_lookup_elem(&net_policies, &domain);
    struct socket_decision decision = {.lease_revision = current_peer ? current_peer->reserved : 0};
    __u64 owner = operation_socket_domain(socket);
    if (socket_context(socket, &operation) && owner == domain)
        decision = operation_decision(domain, policy, &operation);
    if (decision.allow) {
        struct sock *sk = socket->sk;
        if (!sk) decision.allow = 0;
        else {
            struct socket_epoch initial = {.domain = domain, .lease_revision = decision.lease_revision};
            struct socket_epoch *epoch = bpf_sk_storage_get(&sock_epochs, sk, &initial, BPF_SK_STORAGE_GET_F_CREATE);
            if (!epoch || epoch->domain != domain || epoch->lease_revision != decision.lease_revision)
                decision.allow = 0;
        }
    }
    operation_report(domain, bpf_get_current_cgroup_id(), owner, policy, &operation, decision, 5);
    return decision.allow ? 0 : -EPERM;
}

#define SIMPLE_SOCKET_HOOK(name, section, bit, ...) \
SEC(section) int BPF_PROG(name, struct socket *socket, ##__VA_ARGS__, int ret) \
{ if (ret) return ret; struct socket_operation operation = {.operation = bit}; \
  int valid = socket_context(socket, &operation); return socket_check(socket, &operation, valid, 1, 0); }

SIMPLE_SOCKET_HOOK(operation_listen, "lsm/socket_listen", OP_LISTEN, int backlog)
SIMPLE_SOCKET_HOOK(operation_accept, "lsm/socket_accept", OP_ACCEPT, struct socket *new_socket)
SIMPLE_SOCKET_HOOK(operation_receive, "lsm/socket_recvmsg", OP_RECEIVE, struct msghdr *message, int size, int flags)
SIMPLE_SOCKET_HOOK(operation_local_name, "lsm/socket_getsockname", OP_LOCAL_NAME)
SIMPLE_SOCKET_HOOK(operation_peer_name, "lsm/socket_getpeername", OP_PEER_NAME)
SIMPLE_SOCKET_HOOK(operation_shutdown, "lsm/socket_shutdown", OP_SHUTDOWN, int how)

SEC("lsm/socket_sendmsg")
int BPF_PROG(operation_send, struct socket *socket, struct msghdr *message, int size, int ret)
{
    if (ret) return ret;
    struct socket_operation operation = {.operation = OP_SEND};
    struct endpoint peer = {};
    int valid = socket_context(socket, &operation) && message_peer(socket, message, &peer);
    return socket_check(socket, &operation, valid, 1, &peer);
}

static __always_inline int option_check(struct socket *socket, int level, int name, __u32 bit)
{
    struct socket_operation operation = {.operation = bit, .level = level, .name = name};
    int valid = level >= 0 && level <= 255 && name > 0 && name <= 65535 && socket_context(socket, &operation);
    return socket_check(socket, &operation, valid, 1, 0);
}
SEC("lsm/socket_setsockopt")
int BPF_PROG(operation_set_option, struct socket *socket, int level, int name, int ret)
{ return ret ? ret : option_check(socket, level, name, OP_SET_OPTION); }
SEC("lsm/socket_getsockopt")
int BPF_PROG(operation_get_option, struct socket *socket, int level, int name, int ret)
{ return ret ? ret : option_check(socket, level, name, OP_GET_OPTION); }

SEC("lsm/file_permission")
int BPF_PROG(operation_file_permission, struct file *file, int mask, int ret)
{
    if (ret) return ret;
    __u64 domain = bpf_get_current_ancestor_cgroup_id(1);
    if (!bpf_map_lookup_elem(&sock_managed, &domain)) return 0;
    if ((BPF_CORE_READ(file, f_inode, i_mode) & 0170000) != 0140000) return 0;
    if (!mask || (mask & ~6)) return -EPERM;
    struct socket *socket = bpf_sock_from_file(file);
    if (!socket) return -EPERM;
    if (mask & 4) {
        struct socket_operation read = {.operation = OP_RECEIVE};
        int valid = socket_context(socket, &read);
        int verdict = socket_check(socket, &read, valid, 2, 0);
        if (verdict) return verdict;
    }
    if (mask & 2) {
        struct socket_operation write = {.operation = OP_SEND};
        struct endpoint peer = {};
        int valid = socket_context(socket, &write) && connected_peer(socket, &peer);
        return socket_check(socket, &write, valid, 2, &peer);
    }
    return 0;
}

static __always_inline int operation_packet(struct __sk_buff *skb, int ingress)
{
    __u64 domain = bpf_skb_ancestor_cgroup_id(skb, 1);
    struct socket_policy *policy = bpf_map_lookup_elem(&sock_policies, &domain);
    struct socket_operation operation = {.operation = ingress ? OP_RECEIVE : OP_SEND};
    struct packet_endpoints packet = {};
    struct net_policy *peer = bpf_map_lookup_elem(&net_policies, &domain);
    struct socket_decision decision = {.lease_revision = peer ? peer->reserved : 0};
    if (read_packet(skb, ingress, &packet)) {
        operation.family = packet.family == IPV4 ? 2 : 10;
        operation.protocol = packet.protocol;
        operation.port = packet.local_port;
        operation.has_local = 1;
        __builtin_memcpy(operation.address, packet.local, 16);
        decision = operation_decision(domain, policy, &operation);
    }
    operation_report(domain, bpf_skb_cgroup_id(skb), domain, policy, &operation, decision, ingress ? 3 : 4);
    return decision.allow == 1;
}
SEC("cgroup_skb/ingress")
int operation_ingress(struct __sk_buff *skb) { return operation_packet(skb, 1); }
SEC("cgroup_skb/egress")
int operation_egress(struct __sk_buff *skb) { return operation_packet(skb, 0); }
char LICENSE[] SEC("license") = "GPL";
