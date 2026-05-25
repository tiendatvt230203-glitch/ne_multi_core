#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define IPPROTO_ICMP_VAL 1
#define IPPROTO_TCP_VAL 6
#define IPPROTO_UDP_VAL 17
#define ETH_P_ARP_VAL 0x0806

#define MAX_PROFILES_BPF 32
#define MAX_ENCRYPT_PACK_BPF 128

#define XDP_INGRESS_RATE_LIMIT 0
#define XDP_RL_WINDOW_NS       1000000ULL
#define XDP_RL_MAX_BYTES_PER_WINDOW 62500ULL

#define NE_XSK_QUEUE_ID 0

struct xdp_encrypt_rule {
    __u32 src_net;
    __u32 src_mask;
    __u32 dst_net;
    __u32 dst_mask;
    __u32 flags;
    __u8 protocol;
    __u8 pad[3];
    __s32 src_port_from;
    __s32 src_port_to;
    __s32 dst_port_from;
    __s32 dst_port_to;
};

struct bpf_profile_meta {
    __u32 enabled;
    __u32 enc_start;
    __u32 enc_num;
};

struct xdp_encrypt_ctrl {
    __u32 profile_count;
    __u32 require_filter;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} stats_map SEC(".maps");

#if XDP_INGRESS_RATE_LIMIT
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rl_last_reset_ns SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} rl_byte_count SEC(".maps");
#endif

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct xdp_encrypt_ctrl);
} encrypt_ctrl_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_PROFILES_BPF);
    __type(key, __u32);
    __type(value, struct bpf_profile_meta);
} profile_meta_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENCRYPT_PACK_BPF);
    __type(key, __u32);
    __type(value, struct xdp_encrypt_rule);
} encrypt_rules_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} ingress_profile_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline void inc_stat(__u32 idx)
{
    __u64 *val = bpf_map_lookup_elem(&stats_map, &idx);
    if (val)
        __sync_fetch_and_add(val, 1);
}

static __always_inline int read_tcp_udp_ports(void *data, void *data_end, __u8 ip_proto,
                                              __u16 *sport_out, __u16 *dport_out)
{
    *sport_out = 0;
    *dport_out = 0;
    if (ip_proto != IPPROTO_TCP_VAL && ip_proto != IPPROTO_UDP_VAL)
        return 0;

    struct ethhdr *eth = data;
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    __u32 ihl = (__u32)ip->ihl * 4U;
    if (ihl < 20)
        return -1;

    __u8 *l4 = (__u8 *)ip + ihl;
    if ((void *)(l4 + 4) > data_end)
        return -1;

    __be16 *ports = (__be16 *)l4;
    *sport_out = bpf_ntohs(ports[0]);
    *dport_out = bpf_ntohs(ports[1]);
    return 0;
}

static __always_inline int parse_ipv4(void *data, void *data_end,
                                      __u32 *src_ip, __u32 *dst_ip, __u8 *proto)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    if (proto)
        *proto = ip->protocol;
    return 0;
}

SEC("xdp")
int xdp_redirect_prog(struct xdp_md *ctx)
{
    inc_stat(0);

    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;

    if ((void *)(eth + 1) > data_end) {
        inc_stat(1);
        return XDP_PASS;
    }

    if (eth->h_proto == bpf_htons(ETH_P_ARP_VAL)) {
        inc_stat(7);
        return XDP_PASS;
    }

    __u32 src_ip, dst_ip;
    __u8 l4_proto = 0;
    if (parse_ipv4(data, data_end, &src_ip, &dst_ip, &l4_proto) < 0) {
        inc_stat(1);
        return XDP_PASS;
    }

    if (l4_proto == IPPROTO_ICMP_VAL) {
        inc_stat(4);
        return XDP_PASS;
    }

    if (l4_proto != IPPROTO_TCP_VAL && l4_proto != IPPROTO_UDP_VAL) {
        inc_stat(8);
        return XDP_PASS;
    }

    __u16 sport = 0;
    __u16 dport = 0;
    if (read_tcp_udp_ports(data, data_end, l4_proto, &sport, &dport) < 0) {
        inc_stat(10);
        return XDP_PASS;
    }
    (void)src_ip;
    (void)dst_ip;
    (void)sport;
    (void)dport;

    {
        __u32 qid = NE_XSK_QUEUE_ID;
        int *sock = bpf_map_lookup_elem(&xsks_map, &qid);
        if (!sock) {
            inc_stat(5);
            return XDP_PASS;
        }
        inc_stat(6);
        return bpf_redirect_map(&xsks_map, qid, 0);
    }
}

char _license[] SEC("license") = "GPL";
