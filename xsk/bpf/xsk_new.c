#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <linux/types.h>
#include <linux/if_arp.h>
#include <bpf/bpf_helpers.h>

#define bpf_memcpy __builtin_memcpy

struct bpf_map_def SEC(

"maps")
xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 8, // 由网卡队列数决定，如支持更多队列，需要再调整
};

// 用于存本地的ARP表，主要是给ARP请求答复用
// XDP程序内部的还需要单独维护目标IP与MAC的映射表
// 同时，仅目标IP在该表内的，数据包才会被重定向，其他的均会被丢弃
struct bpf_map_def SEC(

"maps")
local_arp_table = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u8[6]),
        .max_entries = 16,
};

// 用于在Ingress阶段进行简单过滤
// 会匹配目标端口与协议号，如不符合会直接丢包
// 仅支持TCP/UDP两种协议
struct bpf_map_def SEC(

"maps")
ingress_filter = {
        .type = BPF_MAP_TYPE_HASH,
        .key_size = sizeof(__u32),
        .value_size = sizeof(__u8),
        .max_entries = 16,
};

// 简单的校验和计算
// 仅仅支持对for的展开计算，因此需要传入的size是定长（编译时可确定的静态值），否则不被支持
static inline __u16 __checksum(void *start, int size) {
    __u32 csum = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < size >> 1; i++) {
        csum += (__u32)(*(__u8 * )(start + i * 2)) << 8;
        csum += (__u32)(*(__u8 * )(start + i * 2 + 1));
    }
    if ((size & 0x01) == 0x01)
        csum += (__u32)(*(__u8 * )(start + size)) << 8;
    return (__u16)(~((csum & 0xffff) + (csum >> 16)));
}

SEC("xdp_starOcean")

int xsk_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct iphdr *ipv4_hdr = NULL;
    struct icmphdr *icmp4_hdr = NULL;
    int index = ctx->rx_queue_index;

    // 处理L2
    if (data + sizeof(struct ethhdr) > data_end) { // 包长不对直接丢
        return XDP_DROP;
    }
    struct ethhdr *eth_hdr = data;
    switch (bpf_ntohs(eth_hdr->h_proto)) {
        case ETH_P_IP: {
            if ((void *) eth_hdr + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return XDP_DROP;
            ipv4_hdr = (void *) eth_hdr + sizeof(struct ethhdr);
            break;
        }
        case ETH_P_ARP:
            // 代答ARP
            if ((void *) eth_hdr + sizeof(struct ethhdr) + sizeof(struct arphdr) > data_end) return XDP_DROP;
            struct arphdr *arp_hdr = (void *) eth_hdr + sizeof(struct ethhdr);
            if (
                    bpf_ntohs(arp_hdr->ar_hrd) != ARPHRD_ETHER ||
                    bpf_ntohs(arp_hdr->ar_pro) != ETH_P_IP ||
                    arp_hdr->ar_hln != 6 ||
                    arp_hdr->ar_pln != 4 ||
                    bpf_ntohs(arp_hdr->ar_op) != ARPOP_REQUEST) {
                return XDP_DROP;
            }

            if ((void *) arp_hdr + sizeof(struct arphdr) + 6 + 4 + 6 + 4 > data_end) return XDP_DROP;
            __u32 arp_req_ip = *(__u32 * )((void *) arp_hdr + sizeof(struct arphdr) + 6 + 4 + 6);
            void *record = bpf_map_lookup_elem(&local_arp_table, &arp_req_ip);
            if (record == NULL) return XDP_DROP;

            bpf_memcpy(eth_hdr->h_dest, eth_hdr->h_source, ETH_ALEN);
            bpf_memcpy(eth_hdr->h_source, record, ETH_ALEN);
            arp_hdr->ar_op = bpf_htons(ARPOP_REPLY);

            bpf_memcpy((void *) arp_hdr + sizeof(struct arphdr) + 6 + 4, (void *) arp_hdr + sizeof(struct arphdr),
                       ETH_ALEN);
            bpf_memcpy((void *) arp_hdr + sizeof(struct arphdr), record, ETH_ALEN);

            __u8 tmp_ipv4[4];
            bpf_memcpy(tmp_ipv4, (void *) arp_hdr + sizeof(struct arphdr) + 6 + 4 + 6, 4);
            bpf_memcpy((void *) arp_hdr + sizeof(struct arphdr) + 6 + 4 + 6,
                       (void *) arp_hdr + sizeof(struct arphdr) + 6, 4);
            bpf_memcpy((void *) arp_hdr + sizeof(struct arphdr) + 6, tmp_ipv4, 4);

            return XDP_TX;
        default:
            return XDP_DROP;
    }

    // 处理L3
    if (ipv4_hdr != NULL) { // 处理IPv4
        // 不处理特殊长度的报文
        if ((ipv4_hdr->ihl) * 4 != sizeof(struct iphdr)) return XDP_DROP;

        if (ipv4_hdr->protocol == IPPROTO_ICMP) {
            // 代答ICMPv4
            if ((void *) ipv4_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) return XDP_DROP;
            icmp4_hdr = (void *) ipv4_hdr + sizeof(struct iphdr);
            if (icmp4_hdr->type != ICMP_ECHO) return XDP_DROP;

            // 如果能找到XDP的描述符，就重定向
            if (bpf_map_lookup_elem(&xsks_map, &index)) {
                return (int) bpf_redirect_map(&xsks_map, index, 0);
            }

            return XDP_TX;
        }

        // 仅支持TCP/UDP两种协议
        if (ipv4_hdr->protocol != IPPROTO_TCP && ipv4_hdr->protocol != IPPROTO_UDP) return XDP_DROP;
        // 检查TCP/UDP源端口、目标端口是否越界
        if ((void *) ipv4_hdr + sizeof(struct iphdr) + 4 > data_end) return XDP_DROP;
        // 简单过滤
        __u32 key = 0;
        key += ipv4_hdr->protocol;
        __u16 be_dst_port = *(__u16 * )((void *) ipv4_hdr + sizeof(struct iphdr) + 2);
        key += ((__u32) be_dst_port) << 16;
        void *permit = bpf_map_lookup_elem(&ingress_filter, &key);
        if (permit == NULL) return XDP_DROP;

        // 如果能找到XDP的描述符，就重定向
        if (bpf_map_lookup_elem(&xsks_map, &index)) {
            return (int) bpf_redirect_map(&xsks_map, index, 0);
        }
    }

    return XDP_DROP;
}

char _license[]
SEC("license") = "Dual MIT/GPL";
