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

#define bpf_memcpy __builtin_memcpy

#define _DEBUG 0

#ifdef _DEBUG

#include <bpf/bpf_helpers.h>

#endif

const __u16 dst_port = 443;

struct bpf_map_def SEC(

"maps")
xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 8, // 由网卡队列数决定，如支持更多队列，需要再调整
};

// size需要是静态值，动态值目前支持似乎还有问题
static inline __u16 __checksum(void *start, int size) {
    __u16 *next = (__u16 *) start;
    __u32 csum = 0;
#pragma clang loop unroll(full)
    for (int i = 0; i < (int) size >> 1; i++)
        csum += *(next++);
    __u16 res = ~((csum & 0xffff) + (csum >> 16));
    return res;
}

SEC("xdp_starOcean")

int xsk_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct iphdr *ipv4_hdr = NULL;
    struct ipv6hdr *ipv6_hdr = NULL;
    struct icmphdr *icmp4_hdr = NULL;
    struct icmp6hdr *icmp6_hdr = NULL;
    struct tcphdr *tcp_hdr = NULL;

#if _DEBUG
    bpf_printk("[all input] frame length: %d", data_end - data);
#endif

    // process L2
    if (data + sizeof(struct ethhdr) > data_end) {
#if _DEBUG
        bpf_printk("  ! more than l2 header, drop");
#endif
        return XDP_DROP;
    }
    struct ethhdr *eth_hdr = data;
    switch (bpf_ntohs(eth_hdr->h_proto)) {
        case ETH_P_IP: {
            if ((void *) eth_hdr + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
#if _DEBUG
                bpf_printk("  ! more than ipv4 header, drop");
#endif
                return XDP_DROP;
            }
#if _DEBUG
            bpf_printk("  - Ethernet frame protocol: IPv4");
#endif

            ipv4_hdr = (void *) eth_hdr + sizeof(struct ethhdr);
            break;
        }
// 暂时先不支持IPv6
//        case ETH_P_IPV6: {
//            if ((void *) eth_hdr + sizeof(struct ipv6hdr) + sizeof(struct ipv6hdr) + 1 > data_end) {
//#if _DEBUG
//                bpf_printk("  ! more than ipv6 header, drop");
//#endif
//                return XDP_DROP;
//            }
//#if _DEBUG
//            bpf_printk("  - Ethernet frame protocol: IPv6");
//#endif
//
//            ipv6_hdr = (void *) eth_hdr + sizeof(struct ethhdr);
//            break;
//        }
        case ETH_P_ARP: // accept all ARP packet
#if _DEBUG
            bpf_printk("  ! Ethernet frame protocol: ARP, pass");
#endif
            return XDP_PASS;
        default:
#if _DEBUG
            bpf_printk("  ! Ethernet frame protocol: other, drop");
#endif
            return XDP_DROP;
    }

    // process L3
    if (ipv4_hdr != NULL) {
        // IPv4
        switch (ipv4_hdr->protocol) {
            case IPPROTO_TCP: {
#if _DEBUG
                bpf_printk("  - IPv4 packet protocol: TCP");
#endif
                if ((void *) ipv4_hdr + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end) {
#if _DEBUG
                    bpf_printk("  ! more than tcp header, drop");
#endif
                    return XDP_DROP;
                }

                tcp_hdr = (void *) ipv4_hdr + sizeof(struct iphdr);
                break;
            }
            case IPPROTO_ICMP: { // only allow icmp echo req
#if _DEBUG
                bpf_printk("  - IPv4 packet protocol: ICMP4");
#endif
                if ((void *) ipv4_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
#if _DEBUG
                    bpf_printk("  ! more than icmp header, drop");
#endif
                    return XDP_DROP;
                }

                icmp4_hdr = (void *) ipv4_hdr + sizeof(struct iphdr);
                break;
            }
        }
    } else if (ipv6_hdr != NULL) {
        // IPv6
        switch (ipv6_hdr->nexthdr) {
            case IPPROTO_TCP: {
#if _DEBUG
                bpf_printk("  - IPv6 packet protocol: TCP");
#endif
                if ((void *) ipv6_hdr + sizeof(struct ipv6hdr) + sizeof(struct tcphdr) > data_end) {
#if _DEBUG
                    bpf_printk("  ! more than tcp header, drop");
#endif
                    return XDP_DROP;
                }

                tcp_hdr = (void *) ipv6_hdr + sizeof(struct ipv6hdr);
                break;
            }
            case IPPROTO_ICMPV6: {
#if _DEBUG
                bpf_printk("  - IPv6 packet protocol: ICMP6");
#endif
                if ((void *) ipv6_hdr + sizeof(struct ipv6hdr) + sizeof(struct icmp6hdr) > data_end) {
#if _DEBUG
                    bpf_printk("  ! more than icmp header, drop");
#endif
                    return XDP_DROP;
                }

                icmp6_hdr = (void *) ipv6_hdr + sizeof(struct ipv6hdr);
                break;
            }
        }
    } else {
        return XDP_DROP;
    }

    // process L4
    if (tcp_hdr != NULL) {
        if (tcp_hdr->dest == bpf_htons(dst_port)) {
#if _DEBUG
            bpf_printk("  - Dest port: %u", dst_port);
#endif
            int index = ctx->rx_queue_index;
            if (bpf_map_lookup_elem(&xsks_map, &index)) {
#if _DEBUG
                bpf_printk("  - redirect to map");
#endif
                return (int) bpf_redirect_map(&xsks_map, index, 0);
            }

            return XDP_DROP;
        }
#if _DEBUG
        bpf_printk("  ! TCP dest port: other, drop");
#endif
        return XDP_DROP;
    } else if (icmp4_hdr != NULL) {
        if (icmp4_hdr->type != ICMP_ECHO) {
#if _DEBUG
            bpf_printk("  ! other icmp4 type, drop");
#endif
            return XDP_DROP;
        }

        icmp4_hdr->type = ICMP_ECHOREPLY;

        __u8 tmp_mac[ETH_ALEN];
        __u32 tmp_ipv4;

        bpf_memcpy(tmp_mac, eth_hdr->h_source, ETH_ALEN);
        bpf_memcpy(eth_hdr->h_source, eth_hdr->h_dest, ETH_ALEN);
        bpf_memcpy(eth_hdr->h_dest, tmp_mac, ETH_ALEN);

        tmp_ipv4 = ipv4_hdr->saddr;
        ipv4_hdr->saddr = ipv4_hdr->daddr;
        ipv4_hdr->daddr = tmp_ipv4;

        icmp4_hdr->checksum = 0;

        ipv4_hdr->check = 0;
        ipv4_hdr->check = __checksum((void *) ipv4_hdr, sizeof(struct iphdr));

        return XDP_TX;
    } else if (icmp6_hdr != NULL) {
        if (icmp6_hdr->icmp6_type != ICMPV6_ECHO_REQUEST) {
            // accept ICMPv6 Informational Messages
            if (icmp6_hdr->icmp6_type >> 7 == 1) {
                return XDP_PASS;
            }

#if _DEBUG
            bpf_printk("  ! other icmp6 type, drop");
#endif
            return XDP_DROP;
        }

        return XDP_DROP;
    } else {
        return XDP_DROP;
    }
}

char _license[]
SEC("license") = "Dual MIT/GPL";
