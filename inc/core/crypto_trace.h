#ifndef CRYPTO_TRACE_H
#define CRYPTO_TRACE_H

#include <stdint.h>

/* Mặc định bật. Tắt: export NE_CRYPTO_TRACE=0
 * Mỗi connection (5-tuple) in đúng 1 dòng ENC và 1 dòng DEC. */

void crypto_trace_encrypt(const char *layer,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto, uint8_t core_id);

void crypto_trace_decrypt(const char *layer,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto,
                          uint8_t wire_core_id, uint8_t handler_core_id);

void crypto_trace_maybe_summary(void);

#endif
