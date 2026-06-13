#ifndef NE_CRYPTO_FLOW_BPF_H
#define NE_CRYPTO_FLOW_BPF_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

/* Keep in sync with inc/core/crypto_route.c dp_crypto_flow_hash_mix(). */
#define NE_CRYPTO_WORKERS_BPF  4u
#define NE_FLOW_GOLDEN         0x9E3779B1u

#define NE_L2_CORE_ID_OFF      15u
#define NE_L2_HDR_MIN          16u
#define NE_CPU_WORKER_MIN      1u
#define NE_CPU_WORKER_MAX      4u

static __always_inline __u32 ne_flow_hash_mix(__u32 src_ip, __u32 dst_ip,
                                            __u16 src_port, __u16 dst_port,
                                            __u8 proto)
{
    __u32 key = (__u32)(src_port ^ dst_port);

    key ^= src_ip ^ dst_ip ^ (__u32)proto;
    key *= NE_FLOW_GOLDEN;
    key ^= key >> 16;
    return key;
}

static __always_inline int ne_flow_pick_worker_ipv4(void *data, void *data_end,
                                                    struct ethhdr *eth)
{
    struct iphdr *ip = (void *)(eth + 1);

    if ((void *)(ip + 1) > data_end)
        return -1;

    __u32 ihl = (__u32)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr))
        return -1;

    __u8 *l4 = (void *)ip + ihl;
    if ((void *)(l4 + 4) > data_end)
        return -1;

    __u16 src_port = bpf_ntohs(*(__be16 *)l4);
    __u16 dst_port = bpf_ntohs(*(__be16 *)(l4 + 2));
    __u32 key = ne_flow_hash_mix(bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr),
                                 src_port, dst_port, ip->protocol);

    return (int)(key % NE_CRYPTO_WORKERS_BPF);
}

static __always_inline int ne_l2_core_id_pick_worker(void *data, void *data_end,
                                                       struct ethhdr *eth)
{
    __u8 *b = (__u8 *)eth;

    if ((__u8 *)data_end < b + NE_L2_HDR_MIN)
        return -1;

    __u8 core_id = b[NE_L2_CORE_ID_OFF];

    if (core_id < NE_CPU_WORKER_MIN || core_id > NE_CPU_WORKER_MAX)
        return -1;
    return (int)(core_id - NE_CPU_WORKER_MIN);
}

#endif
