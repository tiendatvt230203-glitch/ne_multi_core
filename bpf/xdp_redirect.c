#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "ne_flow_hash.h"

#define ETH_P_ARP_VAL 0x0806

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    __u32 qid;

    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL))
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    {
        struct iphdr *ip = (void *)(eth + 1);
        int worker;

        if ((void *)(ip + 1) > data_end)
            return XDP_PASS;

        /* Align LAN worker with dp_crypto_flow_core_id / wire_core (not NIC RSS). */
        worker = ne_ipv4_flow_worker(ip, data_end);
        if (worker >= 0 && worker < NE_CRYPTO_WORKERS_BPF) {
            qid = (__u32)worker;
            return bpf_redirect_map(&xsks_map, qid, 0);
        }
    }

    qid = ctx->rx_queue_index;
    return bpf_redirect_map(&xsks_map, qid, 0);
}

char _license[] SEC("license") = "GPL";
