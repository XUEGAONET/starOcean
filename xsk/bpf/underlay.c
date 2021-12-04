#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>

#define bpf_memcpy __builtin_memcpy

struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 16, // 由网卡队列数决定，如支持更多队列，需要再调整
};

// 用于存放需要重定向的IPv4地址。当来的数据包在该Map中查找到记录时，才会进一步重定向
struct bpf_map_def SEC("maps") redirect_ipv4 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 16,
};

// 用于存放需要重定向的TCP/UDP协议与端口号。当来的数据包在该Map中查找到记录时，才会进一步重定向
struct bpf_map_def SEC("maps") redirect_protocol_port = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 16,
};

// 该函数主要在Underlay处理，用于加速自定义协议栈的包处理
// 仅仅只会重定向符合条件的包，其他的仍然会保持原有路径。（长度错误的除外，长度错误的直接丢弃）
SEC("xdp_starOcean_underlay")
int xsk_underlay(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;

    struct iphdr  *ipv4_hdr = NULL;
    struct tcphdr *tcp_hdr  = NULL;
    struct udphdr *udp_hdr  = NULL;
    int index = ctx->rx_queue_index;

    // 处理L2
    if (data + sizeof(struct ethhdr) > data_end) return XDP_DROP;
    struct ethhdr *eth_hdr = data;
    switch (bpf_ntohs(eth_hdr->h_proto)) {
        case ETH_P_IP: {
            if ((void *) eth_hdr + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) return XDP_DROP;
            ipv4_hdr = (void *) eth_hdr + sizeof(struct ethhdr);
            break;
        default:
            return XDP_PASS;
    }

    // 处理L3
    if (ipv4_hdr != NULL) { // 处理IPv4
        // 不处理特殊长度的报文，要求IPv4的头长必须为20
        if ((ipv4_hdr->ihl) * 4 != sizeof(struct iphdr)) return XDP_DROP;

        __u32 key = ipv4_hdr->daddr;
        void *permit = bpf_map_lookup_elem(&redirect_ipv4, &key);
        if (permit == NULL) return XDP_PASS;

        switch (ipv4_hdr->protocol) {
            case IPPROTO_TCP: {
                if ((void *)ipv4_hdr + sizeof(struct iphdr) + sizeof(tcphdr) > data_end) return XDP_DROP;
                tcp_hdr = (void *)ipv4_hdr + sizeof(struct iphdr);
                break;
            }
            case IPPROTO_UDP: {
                if ((void *)ipv4_hdr + sizeof(struct iphdr) + sizeof(udphdr) > data_end) return XDP_DROP;
                udp_hdr = (void *)ipv4_hdr + sizeof(struct iphdr);
                break;
            }
            default:
                return XDP_PASS;
        }
    }

    // 处理L4
    if (tcp_hdr != NULL) { // 处理TCP
        __u32 key = (__u32)IPPROTO_TCP + ((__u32)tcp_hdr->dest) << 16;
        void *permit = bpf_map_lookup_elem(&redirect_protocol_port, &key);
        if (permit == NULL) return XDP_PASS;
    }

    if (udp_hdr != NULL) { // 处理UDP
        __u32 key = (__u32)IPPROTO_UDP + ((__u32)udp_hdr->dest) << 16;
        void *permit = bpf_map_lookup_elem(&redirect_protocol_port, &key);
        if (permit == NULL) return XDP_PASS;
    }

    // 如果能找到XDP的描述符，就重定向
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        return (int) bpf_redirect_map(&xsks_map, index, 0);
    } else { // 未就绪，丢弃
        return XDP_DROP;
    }
}

char _license[]
SEC("license") = "Dual MIT/GPL";