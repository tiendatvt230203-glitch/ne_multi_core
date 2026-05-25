#ifndef FRAGMENT_H
#define FRAGMENT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <time.h>
#include "config.h"
#include "packet_crypto.h"
#include "crypto_layer4.h"
#include "crypto_layer2.h"
#include "crypto_layer3.h"

#define FRAG_L4_HDR_SIZE    4
#define FRAG_MTU            1500


/* High-rate UDP split traffic needs wider table to avoid pkt_id hash overwrite before frag#2 arrives. */
#define FRAG_TABLE_SIZE     4096
#define FRAG_TIMEOUT_NS     (200ULL * 1000000ULL)

struct frag_entry {
    uint16_t pkt_id;
    uint8_t  data[1600];
    uint32_t data_len;
    uint8_t  eth_hdr[14];
    uint8_t  ip_hdr[60];
    int      ip_hdr_len;
    uint8_t  orig_proto;
    uint64_t timestamp_ns;
    int      valid;
};

struct frag_table {
    struct frag_entry entries[FRAG_TABLE_SIZE];
};

uint16_t frag_next_pkt_id(void);

void frag_table_init(struct frag_table *ft);

void frag_table_gc(struct frag_table *ft);


static inline int frag_need_split(uint32_t pkt_len) {
    return (pkt_len + crypto_layer3_frag_meta_len()) > FRAG_MTU;
}


static inline int frag_need_split_l4(uint32_t pkt_len) {
    int overhead = crypto_layer4_wire_port_len() + packet_crypto_get_tunnel_hdr_size() +
                   FRAG_L4_HDR_SIZE;
    if (packet_crypto_get_mode() == 1)
        overhead += 16;
    return (pkt_len + overhead) > FRAG_MTU;
}


static inline int frag_need_split_l2(uint32_t pkt_len) {
    int overhead = crypto_layer2_frag_meta_len();
    return (pkt_len + overhead) > FRAG_MTU;
}

int frag_split_and_encrypt(struct packet_crypto_ctx *ctx,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint8_t *frag1, uint32_t *frag1_len,
                           uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment(const struct app_config *cfg,
                     const uint8_t *pkt_data, uint32_t pkt_len,
                     uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble(struct frag_table *ft,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t pkt_id, uint8_t frag_index,
                        uint8_t *out_buf, uint32_t *out_len);

int frag_split_and_encrypt_l4(struct packet_crypto_ctx *ctx,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint8_t *frag1, uint32_t *frag1_len,
                              uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment_l4(const struct app_config *cfg,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble_l4(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len);

int frag_split_and_encrypt_l2(struct packet_crypto_ctx *ctx,
                              const uint8_t *pkt_data, uint32_t pkt_len,
                              uint8_t *frag1, uint32_t *frag1_len,
                              uint8_t *frag2, uint32_t *frag2_len);

int frag_is_fragment_l2(const struct app_config *cfg,
                        const uint8_t *pkt_data, uint32_t pkt_len,
                        uint16_t *pkt_id, uint8_t *frag_index);

int frag_try_reassemble_l2(struct frag_table *ft,
                           const uint8_t *pkt_data, uint32_t pkt_len,
                           uint16_t pkt_id, uint8_t frag_index,
                           uint8_t *out_buf, uint32_t *out_len);

#endif