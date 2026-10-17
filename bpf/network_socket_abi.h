// SPDX-License-Identifier: GPL-2.0-only
#ifndef AGENTGATE_SOCKET_ABI_H
#define AGENTGATE_SOCKET_ABI_H
#define MAX_SOCKET_OPTIONS 16
#define OP_CREATE 1
#define OP_BIND 2
#define OP_LISTEN 4
#define OP_ACCEPT 8
#define OP_SEND 16
#define OP_RECEIVE 32
#define OP_LOCAL_NAME 64
#define OP_PEER_NAME 128
#define OP_SHUTDOWN 256
#define OP_SET_OPTION 512
#define OP_GET_OPTION 1024
#define OP_ALL 2047
struct socket_option { __u16 level, name; };
struct socket_rule {
    __u8 address[16];
    struct socket_option options[MAX_SOCKET_OPTIONS];
    __u32 operations, index;
    __u16 family, protocol, port_from, port_to;
    __u8 effect, has_local;
    __u16 option_count;
};
struct socket_policy {
    __u64 generation, expires_ns;
    __u32 count, reserved;
    struct socket_rule rules[MAX_RULES];
};
struct socket_operation {
    __u8 address[16];
    __u32 operation, family, protocol, port, has_local, level, name;
};
struct socket_decision { __u32 allow, index, lease_revision; };
struct socket_epoch { __u64 domain; __u32 lease_revision, reserved; };
struct socket_stats { __u64 decisions, lost; };
struct socket_event {
    __u64 sequence, generation, domain, cgroup, mono_ns, socket_domain;
    __u32 pid, uid, operation, allowed, rule_index, family, protocol, port;
    __u32 level, name, source, lease_revision;
    __u8 address[16];
};
_Static_assert(sizeof(struct socket_rule) == 100, "socket rule ABI");
_Static_assert(sizeof(struct socket_policy) == 12824, "socket policy ABI");
_Static_assert(sizeof(struct socket_event) == 112, "socket event ABI");
#endif
