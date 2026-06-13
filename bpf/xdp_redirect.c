#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define ETH_P_ARP_VAL 0x0806

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline int redirect_rx_queue(struct xdp_md *ctx)
{
    __u32 qid = ctx->rx_queue_index;

    if (bpf_map_lookup_elem(&xsks_map, &qid))
        return bpf_redirect_map(&xsks_map, qid, 0);
    qid = 0;
    if (bpf_map_lookup_elem(&xsks_map, &qid))
        return bpf_redirect_map(&xsks_map, qid, 0);
    return XDP_PASS;
}

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

    if (eth->h_proto == bpf_htons(ETH_P_IP))
        return redirect_rx_queue(ctx);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
