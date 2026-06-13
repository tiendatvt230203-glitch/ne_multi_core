#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ne_crypto_flow.h"

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} wan_xsks_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, int);
    __type(value, __u16);
} wan_config_map SEC(".maps");

#define IPPROTO_ICMP_VAL 1
#define IPPROTO_TCP_VAL 6
#define IPPROTO_UDP_VAL 17
#define IPPROTO_OSPF_VAL 89
#define IPPROTO_CUSTOM_VAL 99

static __always_inline int redirect_wan_fallback(struct xdp_md *ctx)
{
    int rc;
    __u32 qid = ctx->rx_queue_index;

    rc = ne_try_xsk_redirect_u32(&wan_xsks_map, qid);
    if (rc)
        return rc;
    return ne_try_xsk_redirect_u32(&wan_xsks_map, 0);
}

SEC("xdp")
int xdp_wan_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    int rc;

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

        if (ip->protocol == IPPROTO_ICMP_VAL || ip->protocol == IPPROTO_TCP_VAL ||
            ip->protocol == IPPROTO_UDP_VAL || ip->protocol == IPPROTO_OSPF_VAL ||
            ip->protocol == IPPROTO_CUSTOM_VAL) {
            rc = redirect_wan_fallback(ctx);
            if (rc)
                return rc;
            return XDP_PASS;
        }

        return XDP_PASS;
    }

    int key0 = 0;
    __u16 *fake4 = bpf_map_lookup_elem(&wan_config_map, &key0);
    if (fake4 && *fake4 != 0 && proto == bpf_htons(*fake4)) {
        int wi = ne_l2_core_id_pick_worker(data, data_end, eth);
        __u32 qid = ctx->rx_queue_index;

        /* Only redirect when core_id queue matches HW RX queue.  Cross-queue
         * bpf_redirect_map black-holes on some DRV+XSK setups; fallback to
         * rx_queue_index (usually 0) and userspace relay by core_id. */
        if (wi >= 0 && (__u32)wi == qid) {
            rc = ne_try_xsk_redirect_u32(&wan_xsks_map, (__u32)wi);
            if (rc)
                return rc;
        }
        rc = redirect_wan_fallback(ctx);
        if (rc)
            return rc;
        return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
