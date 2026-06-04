#ifndef CRYPTO_PQC_LAYER_H
#define CRYPTO_PQC_LAYER_H

#include "packet_crypto.h"
#include "traffic_crypto.h"
#include "scrypt.h"

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

static const byte HARDCODED_KEY[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20
}; 

static const byte HARDCODED_AAD[] = {
    0x54, 0x45, 0x53, 0x54, 0x5f, 0x41, 0x41, 0x44 
};

static inline int crypto_pqc_sess_load(struct packet_crypto_ctx *ctx, crypto_pqc_sess_t *sess) {
    if (!ctx || !sess)
        return -1;
    // sess->key = packet_crypto_get_pqc_key_for_ctx(ctx);
    sess->key = HARDCODED_KEY;
    if (!sess->key)
        return -1;

    // sess->aad = packet_crypto_get_pqc_test_aad();
    // sess->aad_len = packet_crypto_get_pqc_test_aad_len();
    sess->aad = HARDCODED_AAD;
    sess->aad_len = 12;
    return 0;
}

static inline int crypto_pqc_generate_nonce(byte nonce[CRYPTO_PQC_NONCE_BYTES]) {
    return trf_pqc_generate_nonce(nonce) == TRF_PQC_OK ? 0 : -1;
}

static inline int crypto_pqc_encrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len) {
    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx)
        return -1;
    int rc = trf_encrypt_payload_gcm(ctx, sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                     sess->aad, sess->aad_len, data, len, out_len);
    scrypt_CipherCtxFree(ctx);
    return rc == TRF_PQC_OK ? 0 : -1;
}

static inline int crypto_pqc_decrypt_payload(const crypto_pqc_sess_t *sess,
                                             const byte nonce[CRYPTO_PQC_NONCE_BYTES],
                                             byte *data, int len, int *out_len) {
    if (!sess || !sess->key || !data || len <= 0 || !out_len)
        return -1;
    SCryptCipherCtx *ctx = scrypt_CipherCtxNew();
    if (!ctx)
        return -1;
    int rc = trf_decrypt_payload_gcm(ctx, sess->key, nonce, CRYPTO_PQC_NONCE_BYTES,
                                     sess->aad, sess->aad_len, data, len, out_len);
    scrypt_CipherCtxFree(ctx);
    return rc == TRF_PQC_OK ? 0 : -1;
}

#endif
