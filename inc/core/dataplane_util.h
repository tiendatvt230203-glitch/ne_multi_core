#ifndef DATAPLANE_UTIL_H
#define DATAPLANE_UTIL_H

#include "forwarder.h"

int dp_parse_flow(void *pkt, uint32_t len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto);

uint32_t dp_dest_ipv4(void *pkt, uint32_t len);

int dp_write_l2_src_only(uint8_t *pkt, uint32_t len, const uint8_t src[MAC_LEN]);

int dp_write_l2(uint8_t *pkt, uint32_t len,
                const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN],
                int allow_empty_src);

/* LAN→WAN: match legacy set_wan_l2 — skip rewrite if either MAC unset, never fail. */
int dp_apply_wan_l2(uint8_t *pkt, uint32_t len,
                    const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN]);

/* Bridge WAN (dst_ip unset): flood on tunnel link using local WAN MAC as src. */
int dp_apply_bridge_wan_eth(uint8_t *pkt, uint32_t len, const uint8_t wan_src[MAC_LEN]);

#endif
