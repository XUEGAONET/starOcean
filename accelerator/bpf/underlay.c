#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/types.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

struct bpf_map_def SEC("maps") xsks_map = {
    .type = BPF_MAP_TYPE_XSKMAP,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 16, // 由网卡队列数决定，如支持更多队列，需要再调整
};

// 用于存放需要重定向的IPv6地址。当来的数据包在该Map中查找到记录时，才会进一步重定向
struct bpf_map_def SEC("maps") redirect_ipv6 = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u8[16]),
    .value_size = sizeof(__u8),
    .max_entries = 16,
};

// 用于存放需要重定向的UDP协议与端口号。当来的数据包在该Map中查找到记录时，才会进一步重定向
struct bpf_map_def SEC("maps") redirect_port = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u8),
    .max_entries = 16,
};

// 该函数主要在Underlay处理，用于加速自定义协议栈的包处理
// 仅仅只会重定向符合条件的包，其他的仍然会保持原有路径。
SEC("xdp_starOcean_underlay")
int xsk_underlay(struct xdp_md *ctx) {
    void *data = (void *) (long) ctx->data;
    void *data_end = (void *) (long) ctx->data_end;
    int index = ctx->rx_queue_index;

    // 检查整体长度
    if (data + sizeof(struct ethhdr) + sizeof(struct ipv6hdr) + sizeof(struct udphdr) > data_end) return XDP_PASS;

    // 处理L2
    struct ethhdr *eth_hdr = data;
    //   不处理非IPv6的
    if (bpf_ntohs(eth_hdr->h_proto) != ETH_P_IPV6) return XDP_PASS;
    struct ipv6hdr *ipv6_hdr = (void *) eth_hdr + sizeof(struct ethhdr);

    // 处理L3
    __u8 ipv6_dest[16];
    for (int i=0; i<16; i++) {
        ipv6_dest[i] = *(__u8 *)((void *)ipv6_hdr + 24 + i);
    }
    void *permit = bpf_map_lookup_elem(&redirect_ipv6, &ipv6_dest);
    //    不处理不在map中的目标IP
    if (permit == NULL) return XDP_PASS;
    //    不处理非UDP的
    if (ipv6_hdr->nexthdr != IPPROTO_UDP) return XDP_PASS;
    struct udphdr *udp_hdr = (void *)ipv6_hdr + sizeof(struct ipv6hdr);

    // 处理L4
    __u32 udp_port = udp_hdr->dest;
    permit = bpf_map_lookup_elem(&redirect_port, &udp_port);
    //    不处理不在map中的目标端口
    if (permit == NULL) return XDP_PASS;

    // 如果能找到XDP的描述符，就重定向
    if (bpf_map_lookup_elem(&xsks_map, &index)) {
        return (int) bpf_redirect_map(&xsks_map, index, 0);
    } else { // 未就绪，丢弃
        return XDP_DROP;
    }
}

char _license[]
SEC("license") = "Dual MIT/GPL";