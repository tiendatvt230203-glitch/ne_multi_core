#ifndef ETH_PARSE_H
#define ETH_PARSE_H

#include <stdint.h>

#define NE_ETH_HDR_LEN      14u
#define NE_VLAN_HDR_LEN      4u
#define NE_ETH_P_IPV4   0x0800u
#define NE_ETH_P_8021Q  0x8100u
#define NE_ETH_P_8021AD 0x88A8u

struct eth_l2_info {
    uint16_t l2_hdr_len;
    uint16_t ethertype_off;
    uint16_t network_off;
    uint16_t vlan_tci;
    uint8_t vlan_cnt;
};

#define NE_L2_HDR_MAX       (NE_ETH_HDR_LEN + NE_VLAN_HDR_LEN)

int eth_parse_l2(const uint8_t *pkt, uint32_t len, struct eth_l2_info *out);
int eth_l2_require_ipv4(const uint8_t *pkt, uint32_t len,
                        struct eth_l2_info *l2_out, int *ip_hdr_len_out);
int eth_l2_wire_hdr_len(const uint8_t *pkt, uint32_t len);
uint16_t eth_l2_read_ethertype(const uint8_t *pkt, const struct eth_l2_info *l2);
int eth_l2_is_ethertype(const uint8_t *pkt, const struct eth_l2_info *l2, uint16_t ethertype);
int eth_l2_is_ipv4(const uint8_t *pkt, const struct eth_l2_info *l2);
void eth_l2_write_ethertype(uint8_t *pkt, const struct eth_l2_info *l2, uint16_t ethertype);

#endif
