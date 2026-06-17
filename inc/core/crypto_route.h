#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include "interface.h"
#include <stdint.h>

struct forwarder;

/* CPU 0: pick encrypt worker from connection hash → local_to_mid[wi]. */
int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len);

/* CPU 11: read wire core_id on L2 crypto → wan_to_mid[wi]; -1 = drop (bad core_id). */
int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

/* Egress TX slot: hash flow → mid_to_*[iface][slot]; TX thread s chỉ pop ring[s]. */
int dp_pick_tx_slot(const uint8_t *pkt, uint32_t len);

uint8_t dp_crypto_worker_cpu(int worker_idx);
int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

#endif
