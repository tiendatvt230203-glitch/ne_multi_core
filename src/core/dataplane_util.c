#include "../../inc/core/dataplane_util.h"

#include "../../inc/crypto/packet_crypto.h"

#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
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

uint32_t dp_src_ipv4(void *pkt, uint32_t len)
{
    uint32_t src = 0, dst = 0;
    uint16_t sp = 0, dp = 0;
    uint8_t proto = 0;
    if (dp_parse_flow(pkt, len, &src, &dst, &sp, &dp, &proto) != 0)
        return 0;
    return src;
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

void dp_fixup_tx_csum(uint8_t *pkt, uint32_t len)
{
    struct ether_header *eth;
    uint16_t etype;
    uint8_t *ip_ptr;
    size_t l2_len;
    struct iphdr *ip;
    uint32_t ihl;
    uint8_t *l4;

    if (!pkt || len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return;

    eth = (struct ether_header *)pkt;
    etype = ntohs(eth->ether_type);
    ip_ptr = (uint8_t *)(eth + 1);
    l2_len = sizeof(*eth);

    if (etype == ETH_P_8021Q || etype == ETH_P_8021AD) {
        if (len < l2_len + 4 + sizeof(struct iphdr))
            return;
        etype = ntohs(*(uint16_t *)(ip_ptr + 2));
        ip_ptr += 4;
        l2_len += 4;
    }
    if (etype != ETHERTYPE_IP)
        return;

    ip = (struct iphdr *)ip_ptr;
    ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || len < l2_len + ihl)
        return;

    {
        uint16_t csum = crypto_calc_ip_checksum((const uint8_t *)ip, (int)ihl);
        ip->check = 0;
        ((uint8_t *)ip)[10] = (uint8_t)(csum >> 8);
        ((uint8_t *)ip)[11] = (uint8_t)(csum & 0xFF);
    }

    l4 = (uint8_t *)pkt + l2_len + ihl;
    if (ip->protocol == IPPROTO_UDP) {
        int l4_len = (int)ntohs(ip->tot_len) - (int)ihl;
        uint16_t ucsum;
        if (l4_len < 8 || len < l2_len + (uint32_t)ntohs(ip->tot_len))
            return;
        l4[6] = 0;
        l4[7] = 0;
        ucsum = crypto_calc_udp_checksum((const uint8_t *)ip, (int)ihl, l4, l4_len);
        l4[6] = (uint8_t)(ucsum >> 8);
        l4[7] = (uint8_t)(ucsum & 0xFF);
    } else if (ip->protocol == IPPROTO_TCP) {
        int l4_len = (int)ntohs(ip->tot_len) - (int)ihl;
        uint16_t tcsum;
        if (l4_len < 20 || len < l2_len + (uint32_t)ntohs(ip->tot_len))
            return;
        l4[16] = 0;
        l4[17] = 0;
        tcsum = crypto_calc_tcp_checksum((const uint8_t *)ip, (int)ihl, l4, l4_len);
        l4[16] = (uint8_t)(tcsum >> 8);
        l4[17] = (uint8_t)(tcsum & 0xFF);
    }
}

int dp_ring_push(struct forwarder *fwd, struct ne_pipeline *pl,
                 struct ne_ring *ring, struct ne_packet *pkt)
{
    (void)fwd;
    if (pkt->len > pl->pair.frame_size || ne_ring_try_push(ring, pkt) != 0) {
        ne_frame_free(&pl->pair, pkt->addr);
        return -1;
    }
    return 0;
}
