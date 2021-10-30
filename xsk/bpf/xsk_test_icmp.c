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
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") xsks_map = {
        .type = BPF_MAP_TYPE_XSKMAP,
        .key_size = sizeof(int),
        .value_size = sizeof(int),
        .max_entries = 8, // 由网卡队列数决定，如支持更多队列，需要再调整
};

SEC("xdp_starOcean")
int xsk_program(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    struct iphdr *ipv4_hdr = NULL;
    struct icmphdr *icmp4_hdr = NULL;

    // process L2
    if (data + sizeof(struct ethhdr) > data_end) {
        return XDP_DROP;
    }
    struct ethhdr *eth_hdr = data;
    switch (bpf_ntohs(eth_hdr->h_proto)) {
        case ETH_P_IP: {
            if ((void *) eth_hdr + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
                return XDP_DROP;
            }

            ipv4_hdr = (void *) eth_hdr + sizeof(struct ethhdr);
            break;
        }
        case ETH_P_ARP: // accept all ARP packet
            return XDP_PASS;
        default:
            return XDP_DROP;
    }

    // process L3
    if (ipv4_hdr != NULL) {
        // IPv4
        switch (ipv4_hdr->protocol) {
            case IPPROTO_ICMP: { // only allow icmp echo req
                if ((void *) ipv4_hdr + sizeof(struct iphdr) + sizeof(struct icmphdr) > data_end) {
                    return XDP_DROP;
                }

                icmp4_hdr = (void *) ipv4_hdr + sizeof(struct iphdr);
                break;
            }
        }
    } else {
        return XDP_DROP;
    }

    if (icmp4_hdr != NULL) {
        if (icmp4_hdr->type != ICMP_ECHO) {
            return XDP_DROP;
        }

        int index = ctx->rx_queue_index;
        if (bpf_map_lookup_elem(&xsks_map, &index)) {
            return (int) bpf_redirect_map(&xsks_map, index, 0);
        }

        return XDP_DROP;
    } else {
        return XDP_DROP;
    }
}

char _license[]
SEC("license") = "Dual MIT/GPL";
