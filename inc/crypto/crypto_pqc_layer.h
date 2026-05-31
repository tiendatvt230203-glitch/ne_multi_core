#ifndef CRYPTO_PQC_LAYER_H
#define CRYPTO_PQC_LAYER_H

#include "packet_crypto.h"
#include "traffic_crypto.h"

static inline int crypto_mode_is_pqc(void) {
    return packet_crypto_get_mode() == CRYPTO_MODE_PQC;
}

static inline int crypto_mode_uses_gcm_tag(void) {
    int mode = packet_crypto_get_mode();
    return mode == CRYPTO_MODE_GCM || mode == CRYPTO_MODE_PQC;
}

typedef struct crypto_pqc_sess {
    const byte *key;
    const byte *aad;
    int aad_len;
} crypto_pqc_sess_t;

static inline int crypto_pqc_sess_load(struct packet_crypto_ctx *ctx, crypto_pqc_sess_t *sess) {
    if (!ctx || !sess)
        return -1;
    sess->key = packet_crypto_get_pqc_key_for_ctx(ctx);
    sess->aad = packet_crypto_get_pqc_test_aad();
    sess->aad_len = packet_crypto_get_pqc_test_aad_len();
    return sess->key ? 0 : -1;
}

static inline int crypto_pqc_generate_nonce(byte nonce[CRYPTO_PQC_NONCE_BYTES]) {
    return trf_pqc_generate_nonce(nonce) == TRF_PQC_OK ? 0 : -1;
}

static inline int crypto_pqc_encrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len) {
    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    if (trf_encrypt_payload_gcm(sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                sess->aad, sess->aad_len, data, len, out_len) != TRF_PQC_OK)
        return -1;
    return 0;
}

static inline int crypto_pqc_decrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len) {
    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    if (trf_decrypt_payload_gcm(sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                sess->aad, sess->aad_len, data, len, out_len) != TRF_PQC_OK)
        return -1;
    return 0;
}

#endif
