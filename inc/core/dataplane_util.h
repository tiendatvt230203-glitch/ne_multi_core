#ifndef DATAPLANE_UTIL_H
#define DATAPLANE_UTIL_H

#include "forwarder.h"

int dp_parse_flow(void *pkt, uint32_t len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto);

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt);

/* #region agent log */
void ne_agent_debug_log(const char *hypothesis_id, const char *location,
                        const char *message, const char *data_json);
/* #endregion */

#endif
