#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/forwarder.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sched.h>
#include <string.h>

int dp_parse_flow(void *pkt_data, uint32_t pkt_len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto)
{
    if (!pkt_data || pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return -1;

    struct ether_header *eth = pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;

    struct iphdr *ip = (struct iphdr *)((uint8_t *)pkt_data + sizeof(*eth));
    uint32_t ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < sizeof(*eth) + ihl)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *proto = ip->protocol;
    *src_port = 0;
    *dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint8_t *l4 = (uint8_t *)pkt_data + sizeof(*eth) + ihl;
        if (pkt_len < (uint32_t)(l4 - (uint8_t *)pkt_data + 4))
            return -1;
        uint16_t *ports = (uint16_t *)l4;
        *src_port = ntohs(ports[0]);
        *dst_port = ntohs(ports[1]);
    }
    return 0;
}

uint32_t dp_dest_ipv4(void *pkt, uint32_t len)
{
    uint32_t src = 0, dst = 0;
    uint16_t sp = 0, dp = 0;
    uint8_t proto = 0;
    if (dp_parse_flow(pkt, len, &src, &dst, &sp, &dp, &proto) != 0)
        return 0;
    return dst;
}

int dp_write_l2_src_only(uint8_t *pkt, uint32_t len, const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_write_l2(uint8_t *pkt, uint32_t len,
                const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN],
                int allow_empty_src)
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0)
        return -1;
    if (!allow_empty_src && memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt, dst, MAC_LEN);
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_apply_wan_l2(uint8_t *pkt, uint32_t len,
                    const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0 || memcmp(src, zero, MAC_LEN) == 0)
        return 0;
    return dp_write_l2(pkt, len, dst, src, 0);
}

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt)
{
    if (pkt->len > fwd->pair.frame_size || ne_ring_try_push(ring, pkt) != 0) {
        uint32_t depth = ne_ring_count(ring);
        int cpu = sched_getcpu();

        for (int i = 0; i < fwd->wan_count; i++) {
            for (uint32_t w = 0; w < NE_CRYPTO_WORKERS; w++) {
                if (ring == &fwd->mid_to_wan[i][w]) {
                    ne_dp_warn_mid_wan(cpu, i, depth);
                    goto drop;
                }
            }
        }
        for (int i = 0; i < fwd->local_count; i++) {
            for (uint32_t w = 0; w < NE_CRYPTO_WORKERS; w++) {
                if (ring == &fwd->mid_to_local[i][w]) {
                    ne_dp_warn_mid_lan(cpu, i, depth);
                    goto drop;
                }
            }
        }
drop:
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    return 0;
}
