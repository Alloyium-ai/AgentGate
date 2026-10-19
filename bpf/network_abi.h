// SPDX-License-Identifier: GPL-2.0-only
#ifndef AGENTGATE_NETWORK_ABI_H
#define AGENTGATE_NETWORK_ABI_H
#include <linux/types.h>
#define MAX_RULES 128
#define TCP 6
#define UDP 17
#define IPV4 4
#define IPV6 6
struct net_rule {
    __u8 address[16];
    __u64 expires_ns;
    __u16 prefix_bits;
    __u8 family;
    __u8 protocol;
    __u16 port_from;
    __u16 port_to;
    __u8 effect;
    __u8 reserved[3];
    __u32 index;
};
struct net_policy {
    __u64 generation;
    __u64 expires_ns;
    __u32 count;
    __u32 reserved; // Kernel DNS lease revision; literal plans use zero.
    __u8 pilot_address[16];
    __u16 pilot_port;
    __u8 pilot_family;
    __u8 pilot_mode;
    __u32 pilot_padding;
    struct net_rule rules[MAX_RULES];
};
_Static_assert(sizeof(struct net_rule) == 40, "network rule ABI");
_Static_assert(sizeof(struct net_policy) == 5168, "network policy ABI");
#endif
