#ifndef ETH_PARSE_H
#define ETH_PARSE_H

#include <stddef.h>
#include <stdint.h>

#define ETH_L2_HDR_MAX  18

int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len);
int crypto_eth_inner_et_off(const uint8_t *pkt, size_t pkt_len);
int crypto_eth_l2_prefix_len(const uint8_t *pkt, size_t pkt_len);
int crypto_pkt_is_ipv4(const uint8_t *pkt, size_t pkt_len);
void crypto_eth_set_ipv4_et(uint8_t *pkt, int inner_et_off);

#endif
