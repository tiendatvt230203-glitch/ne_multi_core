#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include "interface.h"
#include <stdint.h>

struct forwarder;

/* L2 WAN: wire core_id (0..NE_CRYPTO_WORKERS-1) selects worker via BPF; -1 = drop. */
int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

/* L2 only: wire core_id must match current worker before decrypt/reassemble. */
int dp_crypto_l2_affinity_ok(const uint8_t *pkt, uint32_t len);

uint8_t dp_crypto_worker_cpu(int worker_idx);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

/* Stable worker index for a flow (both directions share the same value). */
uint8_t dp_crypto_flow_core_id(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint8_t protocol);

#endif
