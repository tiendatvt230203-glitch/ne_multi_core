#ifndef CRYPTO_LAYER2_H
#define CRYPTO_LAYER2_H

#include "packet_crypto.h"

#define CRYPTO_L2_FRAG_TAG_SIZE  4
#define CRYPTO_L2_FRAG_MAGIC     0x5B

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);
int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len);

int crypto_layer2_wire_eth_len(void);
int crypto_layer2_frag_meta_len(void);

int crypto_layer2_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len);

int crypto_layer2_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index);

#endif
