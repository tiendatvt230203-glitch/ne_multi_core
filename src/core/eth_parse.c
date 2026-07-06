#include "../../inc/core/eth_parse.h"

#include <string.h>

static uint16_t read_be16(const uint8_t *p)
{
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static void write_be16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFF);
}

int eth_parse_l2(const uint8_t *pkt, uint32_t len, struct eth_l2_info *out)
{
    if (!pkt || !out || len < NE_ETH_HDR_LEN)
        return -1;

    memset(out, 0, sizeof(*out));
    out->ethertype_off = 12;
    out->l2_hdr_len = NE_ETH_HDR_LEN;
    out->network_off = NE_ETH_HDR_LEN;

    uint16_t et = read_be16(pkt + out->ethertype_off);
    if (et == NE_ETH_P_8021Q || et == NE_ETH_P_8021AD) {
        if (len < NE_ETH_HDR_LEN + NE_VLAN_HDR_LEN)
            return -1;
        out->vlan_cnt = 1;
        out->vlan_tci = read_be16(pkt + 14);
        out->ethertype_off = 16;
        out->l2_hdr_len = NE_ETH_HDR_LEN + NE_VLAN_HDR_LEN;
        out->network_off = out->l2_hdr_len;
    }

    if (len < out->l2_hdr_len)
        return -1;
    return 0;
}

int eth_l2_require_ipv4(const uint8_t *pkt, uint32_t len,
                        struct eth_l2_info *l2_out, int *ip_hdr_len_out)
{
    struct eth_l2_info l2;
    int l3_off;
    int ihl;

    if (!pkt || !l2_out || !ip_hdr_len_out)
        return -1;
    if (eth_parse_l2(pkt, len, &l2) != 0)
        return -1;
    if (!eth_l2_is_ipv4(pkt, &l2))
        return -1;

    l3_off = (int)l2.network_off;
    if (len < (uint32_t)(l3_off + 20))
        return -1;
    ihl = (pkt[l3_off] & 0x0F) * 4;
    if (ihl < 20 || len < (uint32_t)(l3_off + ihl))
        return -1;

    *l2_out = l2;
    *ip_hdr_len_out = ihl;
    return 0;
}

int eth_l2_wire_hdr_len(const uint8_t *pkt, uint32_t len)
{
    struct eth_l2_info l2;

    if (eth_parse_l2(pkt, len, &l2) != 0)
        return (int)NE_ETH_HDR_LEN;
    return (int)l2.l2_hdr_len;
}

uint16_t eth_l2_read_ethertype(const uint8_t *pkt, const struct eth_l2_info *l2)
{
    if (!pkt || !l2)
        return 0;
    return read_be16(pkt + l2->ethertype_off);
}

int eth_l2_is_ethertype(const uint8_t *pkt, const struct eth_l2_info *l2, uint16_t ethertype)
{
    return eth_l2_read_ethertype(pkt, l2) == ethertype;
}

int eth_l2_is_ipv4(const uint8_t *pkt, const struct eth_l2_info *l2)
{
    return eth_l2_is_ethertype(pkt, l2, NE_ETH_P_IPV4);
}

void eth_l2_write_ethertype(uint8_t *pkt, const struct eth_l2_info *l2, uint16_t ethertype)
{
    if (!pkt || !l2)
        return;
    write_be16(pkt + l2->ethertype_off, ethertype);
}
