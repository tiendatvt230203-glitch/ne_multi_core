#ifndef DATAPLANE_UTIL_H
#define DATAPLANE_UTIL_H

#include "forwarder.h"
#include "config.h"

int dp_parse_flow(void *pkt, uint32_t len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto);

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt);

/* #region agent log */
void ne_agent_debug_log(const char *hypothesis_id, const char *location,
                        const char *message, const char *data_json);

typedef enum {
    NE_STAT_SPLIT_OK = 0,
    NE_STAT_SPLIT_FAIL,
    NE_STAT_REASM_OK,
    NE_STAT_REASM_FAIL,
    NE_STAT_REASM_TIMEOUT,
    NE_STAT_RING_DROP_WAN_RX,
    NE_STAT_RING_DROP_LOCAL,
    NE_STAT_RING_PUSH_FAIL,
    NE_STAT_ENCRYPT_DROP,
    NE_STAT_WAN_DECRYPT_DROP,
    NE_STAT_FRAME_POOL_FAIL,
    NE_STAT_WIRE_FRAG_TX,
    NE_STAT_BYPASS_TX,
    NE_STAT_ENCRYPT_FULL,
    NE_STAT_NO_POLICY_DROP,
    NE_STAT_COUNT
} ne_agent_stat_id;

void ne_agent_stat_inc(ne_agent_stat_id id);
void ne_agent_drop_log(const char *hypothesis_id, const char *location,
                       const char *message, const char *data_json);
void ne_agent_stat_maybe_dump(void);

void ne_agent_policy_trace(const char *side, const char *outcome,
                           const struct crypto_policy *cp, int profile_id,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port, uint8_t proto,
                           uint32_t pkt_len, const char *detail, int always);

void ne_agent_policy_trace_plain(const char *side, const char *outcome,
                                 uint32_t pkt_len, const char *detail, int always);
/* #endregion */

#endif
