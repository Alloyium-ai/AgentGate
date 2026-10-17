// SPDX-License-Identifier: GPL-2.0-only
#ifndef AGENTGATE_NETWORK_PACKET_H
#define AGENTGATE_NETWORK_PACKET_H
struct packet_endpoints {
    __u8 local[16], peer[16];
    __u32 family, protocol, local_port, peer_port;
};
// Only plain, unfragmented IPv4/IPv6 TCP/UDP packets qualify on this target.
static __always_inline int read_packet(struct __sk_buff *skb, int ingress,
                                      struct packet_endpoints *out)
{
    __u8 header[40] = {}, ports[4] = {};
    __u32 offset = 0;
    if (bpf_skb_load_bytes(skb, 0, header, 1)) return 0;
    if ((header[0] >> 4) == 4) {
        if (bpf_skb_load_bytes(skb, 0, header, 20)) return 0;
        if (header[0] != 0x45 || (header[6] & 0x3f) || header[7]) return 0;
        out->family = IPV4;
        out->protocol = header[9];
        if (ingress) {
            __builtin_memcpy(out->peer, &header[12], 4);
            __builtin_memcpy(out->local, &header[16], 4);
        } else {
            __builtin_memcpy(out->local, &header[12], 4);
            __builtin_memcpy(out->peer, &header[16], 4);
        }
        offset = 20;
    } else if ((header[0] >> 4) == 6) {
        if (bpf_skb_load_bytes(skb, 0, header, 40)) return 0;
        out->family = IPV6;
        out->protocol = header[6];
        if (ingress) {
            __builtin_memcpy(out->peer, &header[8], 16);
            __builtin_memcpy(out->local, &header[24], 16);
        } else {
            __builtin_memcpy(out->local, &header[8], 16);
            __builtin_memcpy(out->peer, &header[24], 16);
        }
        offset = 40;
    } else return 0;
    if (out->protocol != TCP && out->protocol != UDP) return 0;
    if (bpf_skb_load_bytes(skb, offset, ports, sizeof(ports))) return 0;
    __u32 source = ((__u16)ports[0] << 8) | ports[1];
    __u32 destination = ((__u16)ports[2] << 8) | ports[3];
    out->local_port = ingress ? destination : source;
    out->peer_port = ingress ? source : destination;
    return skb->sk && skb->sk->family == (out->family == IPV4 ? 2 : 10);
}
#endif
