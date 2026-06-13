#ifndef CRYPTO_ROUTE_H
#define CRYPTO_ROUTE_H

#include "interface.h"
#include <stdint.h>

struct forwarder;

uint32_t dp_crypto_flow_hash_mix(uint32_t src_ip, uint32_t dst_ip,
                                 uint16_t src_port, uint16_t dst_port,
                                 uint8_t proto);

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len);
int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);

uint8_t dp_crypto_worker_cpu(int worker_idx);
int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id);

void dp_crypto_worker_bind(int worker_idx);
int dp_crypto_current_worker_idx(void);

#endif
