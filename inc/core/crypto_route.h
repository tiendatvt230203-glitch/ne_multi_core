#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include <stdint.h>

struct forwarder;

#define NE_CPU_CRYPTO_AUX   4u
#define NE_CRYPTO_WORKERS   2u

/* CPU 0: pick encrypt worker from connection hash → local_to_mid[wi]. */
int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len);

/* CPU 11: read wire core_id on L2 crypto → wan_to_mid[wi]. */
int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

uint8_t dp_crypto_worker_cpu(int worker_idx);
int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

#endif
