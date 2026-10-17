// SPDX-License-Identifier: GPL-2.0-only
// Peer endpoint component. Socket custody and other socket operations require
// separate controls. Attach only to a prepared root-level managed job cgroup.
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "network_abi.h"
#include "network_packet.h"
struct net_counters { __u64 decisions; __u64 lost; };
struct net_event {
    __u64 sequence, generation, domain, cgroup, mono_ns;
    __u32 pid, uid, hook, allowed, rule_index, family, protocol, port;
    __u8 address[16];
    __u32 version, lease_revision;
};
_Static_assert(sizeof(struct net_event) == 96, "endpoint event v2 ABI");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 64);
    __type(key, __u64); __type(value, struct net_policy); } net_policies SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct net_counters); } net_stats SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } net_events SEC(".maps");
#include "network_peer_match.h"

static __always_inline void report(__u64 domain, __u64 cgroup, struct net_policy *p,
                                  struct endpoint *ep, struct decision d, __u32 hook)
{
    __u32 zero = 0;
    struct net_counters *stats = bpf_map_lookup_elem(&net_stats, &zero);
    if (!stats) return;
    __u64 sequence = __sync_fetch_and_add(&stats->decisions, 1) + 1;
    struct net_event *e = bpf_ringbuf_reserve(&net_events, sizeof(*e), 0);
    if (!e) { __sync_fetch_and_add(&stats->lost, 1); return; }
    __builtin_memset(e, 0, sizeof(*e));
    e->sequence = sequence;
    e->generation = p ? p->generation : 0;
    e->domain = domain;
    e->cgroup = cgroup;
    e->mono_ns = bpf_ktime_get_ns();
    // CGROUP_SKB does not expose the task identity helpers on this target.
    // A packet can also run outside the sending task's process context.
    if (hook != 5 && hook != 6) {
        e->pid = bpf_get_current_pid_tgid() >> 32;
        e->uid = bpf_get_current_uid_gid();
    }
    e->hook = hook;
    e->allowed = d.allow;
    e->rule_index = d.index;
    e->family = ep->family;
    e->protocol = ep->protocol;
    e->port = ep->port;
    e->version = 2;
    e->lease_revision = d.lease_revision;
    __builtin_memcpy(e->address, ep->address, 16);
    bpf_ringbuf_submit(e, 0);
}

static __always_inline int address_decision(struct bpf_sock_addr *ctx, __u32 family, __u32 hook)
{
    __u64 domain = bpf_get_current_ancestor_cgroup_id(1);
    struct net_policy *p = bpf_map_lookup_elem(&net_policies, &domain);
    struct endpoint ep = {.family = family, .protocol = ctx->protocol,
                          .port = bpf_ntohs((__u16)ctx->user_port)};
    if (family == IPV4) __builtin_memcpy(ep.address, &ctx->user_ip4, 4);
    else __builtin_memcpy(ep.address, ctx->user_ip6, 16);
    struct decision d = evaluate(p, &ep, domain);
    // Linux can route a mapped IPv6 UDP destination through the IPv4 hook.
    // Keep that fallback outside this component's explicit family contract.
    if (ctx->family != (family == IPV4 ? 2 : 10)) { d.allow = 0; d.index = 0; }
    report(domain, bpf_get_current_cgroup_id(), p, &ep, d, hook);
    return d.allow == 1;
}

SEC("cgroup/connect4")
int net_connect4(struct bpf_sock_addr *ctx) { return address_decision(ctx, IPV4, 1); }
SEC("cgroup/connect6")
int net_connect6(struct bpf_sock_addr *ctx) { return address_decision(ctx, IPV6, 2); }
SEC("cgroup/sendmsg4")
int net_sendmsg4(struct bpf_sock_addr *ctx) { return address_decision(ctx, IPV4, 3); }
SEC("cgroup/sendmsg6")
int net_sendmsg6(struct bpf_sock_addr *ctx) { return address_decision(ctx, IPV6, 4); }

// Egress checks the socket's domain, including sends after a connect decision.
// IPv4 options/fragments, IPv6 extension headers, and other transports deny.
// This does not control a socket created outside the managed domain.
static __always_inline int packet_decision(struct __sk_buff *skb, int ingress)
{
    __u64 domain = bpf_skb_ancestor_cgroup_id(skb, 1);
    struct net_policy *p = bpf_map_lookup_elem(&net_policies, &domain);
    struct endpoint ep = {};
    struct packet_endpoints packet = {};
    if (!read_packet(skb, ingress, &packet)) goto denied;
    ep.family = packet.family;
    ep.protocol = packet.protocol;
    ep.port = packet.peer_port;
    __builtin_memcpy(ep.address, packet.peer, 16);
    struct decision d = evaluate(p, &ep, domain);
    report(domain, bpf_skb_cgroup_id(skb), p, &ep, d, ingress ? 6 : 5);
    return d.allow == 1;
denied:
    report(domain, bpf_skb_cgroup_id(skb), p, &ep, (struct decision){.lease_revision = p ? p->reserved : 0}, ingress ? 6 : 5);
    return 0;
}

SEC("cgroup_skb/egress")
int net_egress(struct __sk_buff *skb) { return packet_decision(skb, 0); }
SEC("cgroup_skb/ingress")
int net_ingress(struct __sk_buff *skb) { return packet_decision(skb, 1); }

char LICENSE[] SEC("license") = "GPL";
