#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, int);
    __type(value, int);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u16);
} wan_config_map SEC(".maps");

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    __u16 proto = eth->h_proto;

    if (proto == __constant_htons(ETH_P_ARP))
        return XDP_PASS;

    if (proto == __constant_htons(ETH_P_IP)) {
        struct iphdr *ip = (void *)(eth + 1);
        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;
        goto redirect;
    }

    int key0 = 0;
    __u16 *fake4 = bpf_map_lookup_elem(&wan_config_map, &key0);
    if (fake4 && *fake4 != 0 && proto == bpf_htons(*fake4))
        goto redirect;

    return XDP_PASS;

redirect:
    ;
    __u32 qid = ctx->rx_queue_index;
    return bpf_redirect_map(&wan_xsks_map, qid, XDP_DROP);
}

char _license[] SEC("license") = "GPL";
