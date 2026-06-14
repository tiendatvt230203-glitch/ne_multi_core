#ifndef NE_FLOW_HASH_H
#define NE_FLOW_HASH_H

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_endian.h>

#define NE_CRYPTO_WORKERS_BPF 4

static __always_inline void ne_normalize_5tuple(__u32 *sip, __u32 *dip,
                                                __u16 *sp, __u16 *dp)
{
    __u32 a = bpf_ntohl(*sip);
    __u32 b = bpf_ntohl(*dip);

    if (a > b || (a == b && *sp > *dp)) {
        __u32 ti = *sip;
        *sip = *dip;
        *dip = ti;
        __u16 tp = *sp;
        *sp = *dp;
        *dp = tp;
    }
}

static __always_inline __u32 ne_flow_core_hash(__u32 sip, __u32 dip,
                                               __u16 sp, __u16 dp, __u8 proto)
{
    __u32 hash;

    ne_normalize_5tuple(&sip, &dip, &sp, &dp);
    hash = sip ^ dip;
    hash ^= ((__u32)sp << 16) | (__u32)dp;
    hash ^= proto;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6bU;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35U;
    hash ^= (hash >> 16);
    return hash % NE_CRYPTO_WORKERS_BPF;
}

#define NE_IPPROTO_TCP 6
#define NE_IPPROTO_UDP 17

static __always_inline int ne_ipv4_flow_worker(struct iphdr *ip, void *data_end)
{
    __u32 sip = ip->saddr;
    __u32 dip = ip->daddr;
    __u16 sp = 0;
    __u16 dp = 0;
    __u8 *l4;

    if (ip->protocol == NE_IPPROTO_TCP || ip->protocol == NE_IPPROTO_UDP) {
        l4 = (void *)(ip + 1);
        if ((void *)(l4 + 4) > data_end)
            return -1;
        sp = bpf_ntohs(*(__u16 *)l4);
        dp = bpf_ntohs(*(__u16 *)(l4 + 2));
    }

    return (int)ne_flow_core_hash(sip, dip, sp, dp, ip->protocol);
}

#endif
