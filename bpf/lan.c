#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP_VAL 0x0806
#ifndef ETH_P_8021AD
#define ETH_P_8021AD 0x88A8
#endif

static __always_inline int skip_one_vlan(void **nh, void *data_end, __u16 *proto)
{
    if (*proto != bpf_htons(ETH_P_8021Q) && *proto != bpf_htons(ETH_P_8021AD))
        return 0;

    __u16 *vlan = *nh;
    if ((void *)(vlan + 2) > data_end)
        return -1;

    *proto = vlan[1];
    *nh = (void *)(vlan + 2);
    return 0;
}

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

    void *nh = (void *)(eth + 1);
    __u16 proto = eth->h_proto;
    if (skip_one_vlan(&nh, data_end, &proto) != 0)
        return XDP_PASS;

    if (proto == bpf_htons(ETH_P_ARP_VAL)) {
        return XDP_PASS;
    }

    if (proto == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = nh;
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        goto redirect;
    }

    return XDP_PASS;

redirect:
    ;
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
