// SPDX-License-Identifier: GPL-2.0-only
#ifndef AGENTGATE_SOCKET_KERNEL_H
#define AGENTGATE_SOCKET_KERNEL_H
struct kernfs_node { __u64 id; } __attribute__((preserve_access_index));
struct cgroup { int level; struct kernfs_node *kn; struct cgroup *ancestors[]; } __attribute__((preserve_access_index));
struct sock_cgroup_data { struct cgroup *cgroup; } __attribute__((preserve_access_index));
struct in6_addr { __u8 bytes[16]; } __attribute__((preserve_access_index));
struct sock_common {
    __u16 skc_family, skc_num, skc_dport;
    __u32 skc_rcv_saddr, skc_daddr;
    struct in6_addr skc_v6_rcv_saddr, skc_v6_daddr;
} __attribute__((preserve_access_index));
struct sock {
    struct sock_common __sk_common;
    __u16 sk_protocol;
    struct sock_cgroup_data sk_cgrp_data;
} __attribute__((preserve_access_index));
struct socket { short type; struct sock *sk; } __attribute__((preserve_access_index));
struct inode { unsigned short i_mode; } __attribute__((preserve_access_index));
struct file { struct inode *f_inode; void *private_data; } __attribute__((preserve_access_index));
struct sockaddr;
struct msghdr { void *msg_name; int msg_namelen; } __attribute__((preserve_access_index));

static __always_inline __u64 operation_socket_domain(struct socket *socket)
{
    struct cgroup *owner = BPF_CORE_READ(socket, sk, sk_cgrp_data.cgroup);
    if (!owner || BPF_CORE_READ(owner, level) < 1) return 0;
    struct cgroup *root = 0;
    if (bpf_core_read(&root, sizeof(root), &owner->ancestors[1]) || !root) return 0;
    return BPF_CORE_READ(root, kn, id);
}

static __always_inline int socket_context(struct socket *socket, struct socket_operation *operation)
{
    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk) return 0;
    operation->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    operation->protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
    int type = BPF_CORE_READ(socket, type);
    if ((operation->family != 2 && operation->family != 10) ||
        !((type == 1 && operation->protocol == TCP) || (type == 2 && operation->protocol == UDP))) return 0;
    operation->port = BPF_CORE_READ(sk, __sk_common.skc_num);
    operation->has_local = 1;
    if (operation->family == 2) {
        __u32 address = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __builtin_memcpy(operation->address, &address, 4);
    } else if (bpf_core_read(operation->address, 16, &sk->__sk_common.skc_v6_rcv_saddr)) return 0;
    return 1;
}

static __always_inline int bind_context(struct sockaddr *address, int size, struct socket_operation *operation)
{
    __u8 bytes[28] = {};
    int required = operation->family == 2 ? 16 : 28;
    if (size < required || bpf_probe_read_kernel(bytes, required, address)) return 0;
    __u16 family = 0;
    __builtin_memcpy(&family, bytes, 2);
    if (family != operation->family) return 0;
    operation->port = ((__u16)bytes[2] << 8) | bytes[3];
    __builtin_memset(operation->address, 0, 16);
    if (family == 2) __builtin_memcpy(operation->address, &bytes[4], 4);
    else {
        if (bytes[24] | bytes[25] | bytes[26] | bytes[27]) return 0; // Scoped selectors need a separate contract.
        __builtin_memcpy(operation->address, &bytes[8], 16);
    }
    return 1;
}

static __always_inline int connected_peer(struct socket *socket, struct endpoint *peer)
{
    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk) return 0;
    __u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    peer->family = family == 2 ? IPV4 : family == 10 ? IPV6 : 0;
    peer->protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
    peer->port = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    if (family == 2) {
        __u32 address = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(peer->address, &address, 4);
    } else if (family == 10) {
        if (bpf_core_read(peer->address, 16, &sk->__sk_common.skc_v6_daddr)) return 0;
    } else return 0;
    return supported(peer);
}

static __always_inline int message_peer(struct socket *socket, struct msghdr *message,
                                       struct endpoint *peer)
{
    void *name = message ? BPF_CORE_READ(message, msg_name) : 0;
    int length = message ? BPF_CORE_READ(message, msg_namelen) : 0;
    if (!name && !length) return connected_peer(socket, peer);
    if (!name || length <= 0) return 0;
    struct sock *sk = BPF_CORE_READ(socket, sk);
    if (!sk || BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol) != UDP) return 0;
    __u32 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    int required = family == 2 ? 16 : family == 10 ? 28 : 0;
    if (!required || length != required) return 0;
    __u8 bytes[28] = {};
    if (bpf_probe_read_kernel(bytes, required, name)) return 0;
    __u16 supplied_family = 0;
    __builtin_memcpy(&supplied_family, bytes, 2);
    if (supplied_family != family) return 0;
    peer->family = family == 2 ? IPV4 : IPV6;
    peer->protocol = UDP;
    peer->port = ((__u16)bytes[2] << 8) | bytes[3];
    if (family == 2) __builtin_memcpy(peer->address, &bytes[4], 4);
    else {
        if (bytes[24] | bytes[25] | bytes[26] | bytes[27]) return 0;
        __builtin_memcpy(peer->address, &bytes[8], 16);
    }
    return supported(peer);
}
#endif
