#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ne_crypto_flow.h"

#define ETH_P_ARP_VAL 0x0806
#define IPPROTO_TCP_VAL 6
#define IPPROTO_UDP_VAL 17

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL))
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);

        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        if (ip->protocol == IPPROTO_TCP_VAL || ip->protocol == IPPROTO_UDP_VAL) {
            int wi = ne_flow_pick_worker_ipv4(data, data_end, eth);

            if (wi >= 0)
                return bpf_redirect_map(&xsks_map, (__u32)wi, 0);
        }

        __u32 qid = ctx->rx_queue_index;
        return bpf_redirect_map(&xsks_map, qid, 0);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
