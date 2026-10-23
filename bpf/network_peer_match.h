// SPDX-License-Identifier: GPL-2.0-only
#ifndef AGENTGATE_NETWORK_PEER_MATCH_H
#define AGENTGATE_NETWORK_PEER_MATCH_H
// The consumer declares net_policies before this shared matcher.
struct endpoint { __u8 address[16]; __u32 family, protocol, port; };
struct decision { __u32 allow, index, lease_revision; };
struct peer_eval_state {
    __u64 busy;
    __u32 invalid, count;
    __s32 best_bits, best_width;
    __u32 reserved;
    __u32 mode, found;
    __u64 domain, generation, expires_ns, now;
    struct endpoint endpoint;
    struct decision result;
};

struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct peer_eval_state); } peer_eval SEC(".maps");

static __always_inline int supported(struct endpoint *ep)
{
    if (!ep->port || ep->port > 65535 || (ep->protocol != TCP && ep->protocol != UDP)) return 0;
    __u8 *a = ep->address;
    if (ep->family == IPV4) {
        if (!(a[0] | a[1] | a[2] | a[3])) return 0;
        if ((a[0] & 0xf0) == 0xe0) return 0;
        if ((a[0] & a[1] & a[2] & a[3]) == 255) return 0;
        return 1;
    }
    if (ep->family != IPV6 || a[0] == 255) return 0;
    int any = 0, mapped = 1;
#pragma unroll
    for (int i = 0; i < 16; i++) any |= a[i];
#pragma unroll
    for (int i = 0; i < 10; i++) if (a[i]) mapped = 0;
    if (mapped && a[10] == 255 && a[11] == 255) return 0;
    return any != 0;
}

// The SSH pilot guard runs before the ordinary policy rule matcher. A DNS
// lease, broad prefix, or direct numeric address cannot bypass this boundary.
static __always_inline int pilot_private(struct endpoint *ep)
{
    __u8 *a = ep->address;
    if (ep->family == IPV4) {
        if (a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224) return 1;
        if (a[0] == 100 && (a[1] & 0xc0) == 64) return 1;
        if (a[0] == 169 && a[1] == 254) return 1;
        if (a[0] == 172 && (a[1] & 0xf0) == 16) return 1;
        if (a[0] == 192 && (a[1] == 168 || a[1] == 0)) return 1;
        if (a[0] == 198 && (a[1] == 18 || a[1] == 19)) return 1;
        return 0;
    }
    if (ep->family != IPV6) return 1;
    if ((a[0] & 0xfe) == 0xfc || (a[0] == 0xfe && (a[1] & 0x80)) || a[0] == 255) return 1;
    if (a[0] == 0 && a[1] == 0x64 && a[2] == 0xff && a[3] == 0x9b) return 1;
    if (a[0] == 0x20 && (a[1] == 0x02 || (a[1] == 0x01 && a[2] == 0 && a[3] == 0))) return 1;
    int zero = 1;
#pragma unroll
    for (int i = 0; i < 12; i++) if (a[i]) zero = 0;
    return zero;
}

static __always_inline int pilot_endpoint(struct net_policy *p, struct endpoint *ep)
{
    if (!p || p->pilot_mode > 1) return 0;
    if (!p->pilot_mode || !pilot_private(ep)) return 1;
    if (ep->family != p->pilot_family || ep->protocol != TCP || ep->port != p->pilot_port) return 0;
#pragma unroll
    for (int i = 0; i < 16; i++) if (ep->address[i] != p->pilot_address[i]) return 0;
    return 1;
}

static __always_inline int prefix_match(struct endpoint *ep, struct net_rule *r)
{
#pragma unroll
    for (int i = 0; i < 16; i++) {
        int remaining = (int)r->prefix_bits - i * 8;
        if (remaining <= 0) break;
        __u8 mask = remaining >= 8 ? 255 : (__u8)(255 << (8 - remaining));
        if ((ep->address[i] & mask) != (r->address[i] & mask)) return 0;
    }
    return 1;
}

static long evaluate_peer_rule(__u32 index, void *context)
{
    __u32 zero = 0;
    struct peer_eval_state *s = bpf_map_lookup_elem(&peer_eval, &zero);
    if (!s) return 1;
    if (!s->busy) { s->invalid = 1; return 1; }
    if (index >= s->count) return 1;
    struct net_policy *p = bpf_map_lookup_elem(&net_policies, &s->domain);
    if (!p || p->generation != s->generation || p->expires_ns != s->expires_ns || p->count != s->count || p->reserved != s->reserved) {
        s->invalid = 1;
        return 1;
    }
    barrier_var(index);
    index &= MAX_RULES - 1;
    struct net_rule *r = &p->rules[index];
    if ((r->family != IPV4 && r->family != IPV6) ||
        r->prefix_bits > (r->family == IPV4 ? 32 : 128) ||
        (r->protocol != TCP && r->protocol != UDP) ||
        !r->port_from || r->port_from > r->port_to || r->effect > 1 || !r->index || !r->expires_ns) {
        s->invalid = 1;
        return 1;
    }
    struct endpoint *ep = &s->endpoint;
    if (s->mode == 1) {
        if (r->family == ep->family && r->protocol == UDP && r->effect) {
            s->found = 1;
            if (s->now >= r->expires_ns) { s->result.allow = 0; s->result.index = r->index; return 1; }
        }
        return 0;
    }
    if (s->mode) { s->invalid = 1; return 1; }
    if (r->family != ep->family || r->protocol != ep->protocol ||
        ep->port < r->port_from || ep->port > r->port_to || !prefix_match(ep, r)) return 0;
    if (r->effect && s->now >= r->expires_ns) return 0;
    int bits = r->prefix_bits, width = r->port_to - r->port_from;
    if (bits < s->best_bits || (bits == s->best_bits && width > s->best_width)) return 0;
    if (bits == s->best_bits && width == s->best_width && !s->result.allow) return 0;
    if (bits == s->best_bits && width == s->best_width && r->effect && s->result.index < r->index) return 0;
    s->best_bits = bits;
    s->best_width = width;
    s->result.allow = r->effect == 1;
    s->result.index = r->index;
    return 0;
}

static __always_inline struct decision evaluate_mode(struct net_policy *p, struct endpoint *ep, __u64 domain, __u32 mode)
{
    struct decision result = {.lease_revision = p ? p->reserved : 0};
    __u64 now = bpf_ktime_get_ns();
    if (!p || !p->generation || p->count > MAX_RULES || now >= p->expires_ns) return result;
    if (!mode && !supported(ep)) return result;
    if (!mode && !pilot_endpoint(p, ep)) return result;
    if (mode && (mode != 1 || (ep->family != IPV4 && ep->family != IPV6) || ep->protocol != UDP)) return result;
    __u32 zero = 0;
    struct peer_eval_state *s = bpf_map_lookup_elem(&peer_eval, &zero);
    // Ingress may interrupt egress on the same CPU. Nested use fails closed.
    if (!s || __sync_val_compare_and_swap(&s->busy, 0, 1)) return result;
    s->invalid = 0;
    s->count = p->count;
    s->reserved = p->reserved;
    s->mode = mode;
    s->found = 0;
    s->best_bits = -1;
    s->best_width = 65536;
    s->domain = domain;
    s->generation = p->generation;
    s->expires_ns = p->expires_ns;
    s->now = now;
    __builtin_memcpy(&s->endpoint, ep, sizeof(*ep));
    s->result = result;
    if (mode == 1) s->result.allow = 1;
    long status = bpf_loop(MAX_RULES, evaluate_peer_rule, 0, 0);
    if (status >= 0 && !s->invalid) result = s->result;
    if (mode == 1 && !s->found) result.allow = 0;
    __sync_lock_test_and_set(&s->busy, 0);
    return result;
}

static __always_inline struct decision evaluate(struct net_policy *p, struct endpoint *ep, __u64 domain)
{ return evaluate_mode(p, ep, domain, 0); }

static __always_inline struct decision live_udp_peers(struct net_policy *p, struct endpoint *family, __u64 domain)
{ return evaluate_mode(p, family, domain, 1); }

#endif
