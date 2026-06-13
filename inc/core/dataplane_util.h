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

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt);

// #region agent log
void dp_agent_log_drop(const char *hypothesis_id, const char *path,
                       const char *reason, uint32_t a, uint32_t b, uint16_t c, uint16_t d);

int dp_dest_is_nonunicast(const struct forwarder *fwd, uint32_t dest_ip);

void dp_agent_log_fwd(const char *path, uint32_t dst_host, uint16_t dst_port, uint32_t len);

void dp_agent_log_wan_route(const char *event, uint8_t core_id,
                            int recv_wi, int target_wi, uint32_t pkt_len);

void dp_agent_log_encrypt_wan(uint8_t core_id, int wi, int wan_dp,
                              uint32_t dst_host, uint16_t dst_port, uint32_t len);

void dp_agent_log_wan_tx(int wi, int wan_dp, uint32_t len, int sent);

void dp_agent_log_wan_recv(int wi, int wan_dp, uint32_t len, uint8_t core_id, uint16_t eth_type);
// #endregion

#endif
