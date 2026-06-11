#include "../../inc/crypto/packet_crypto.h"
#include "../../inc/core/config.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include <string.h>
#include <time.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <stdatomic.h>
#include "pqc_handshake.h"
static uint16_t g_fake_ethertype_ipv4 = 0;
static __thread uint8_t g_fake_protocol = 99;
static int g_encrypt_layer = 0;

static __thread int g_crypto_mode = 0;
static __thread int g_aes_bits = 128;


static __thread uint8_t g_policy_id = 0;

static atomic_uint_fast32_t g_nonce_counter = 0;
static atomic_uint_fast32_t g_gcm_epoch = 1;
static atomic_uint_fast64_t g_gcm_auth_burst_bump_ms;

static __thread EVP_CIPHER_CTX *tls_ctx = NULL;
static __thread EVP_CIPHER_CTX *tls_gcm_enc_ctx = NULL;
static __thread EVP_CIPHER_CTX *tls_gcm_dec_ctx = NULL;

static __thread uint8_t tls_cached_key[AES_MAX_KEY_SIZE];
static __thread int tls_key_cached = 0;
static __thread int tls_cached_nonce_len = 0;

static __thread uint8_t tls_dec_cached_key[AES_MAX_KEY_SIZE];
static __thread int tls_dec_key_cached = 0;
static __thread int tls_dec_cached_nonce_len = 0;
static __thread uint8_t tls_ctr_cached_key[AES_MAX_KEY_SIZE];
static __thread int tls_ctr_key_cached = 0;

static __thread uint32_t tls_gcm_enc_epoch = 0;
static __thread uint32_t tls_gcm_dec_epoch = 0;

/* Encrypt idle before new iperf session (~2s matches observed recovery time). */
#define GCM_SESSION_GAP_MS 2000u
/* Stale TCP ctrl burst → one global epoch bump (debounced), not per packet. */
#define GCM_AUTH_BURST_COUNT 3u
#define GCM_AUTH_BURST_MS  80u
#define GCM_AUTH_BURST_COOLDOWN_MS 1000u

static int key_has_nonzero(const uint8_t *key, size_t len) {
    if (!key)
        return 0;
    for (size_t i = 0; i < len; i++) {
        if (key[i] != 0)
            return 1;
    }
    return 0;
}

static EVP_CIPHER_CTX *get_ctx(void) {
    if (!tls_ctx) {
        tls_ctx = EVP_CIPHER_CTX_new();
    }
    return tls_ctx;
}

static EVP_CIPHER_CTX *get_gcm_enc_ctx(void) {
    if (!tls_gcm_enc_ctx) {
        tls_gcm_enc_ctx = EVP_CIPHER_CTX_new();
    }
    return tls_gcm_enc_ctx;
}

static EVP_CIPHER_CTX *get_gcm_dec_ctx(void) {
    if (!tls_gcm_dec_ctx) {
        tls_gcm_dec_ctx = EVP_CIPHER_CTX_new();
    }
    return tls_gcm_dec_ctx;
}

int packet_crypto_get_tunnel_hdr_size(void) {
    return PACKET_CRYPTO_NONCE_BYTES + 2;
}

void crypto_write_l3_tunnel_header(uint8_t *buf, const uint8_t *nonce,
                                    int nonce_size, uint8_t policy_id,
                                    uint8_t orig_proto) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = policy_id;
    buf[nonce_size + 1] = orig_proto;
}

void crypto_read_l3_tunnel_header(const uint8_t *buf, int nonce_size,
                                   uint8_t *nonce_out, uint8_t *proto_flag,
                                   uint8_t *policy_id, uint8_t *orig_proto) {
    memcpy(nonce_out, buf, nonce_size);
    if (proto_flag) *proto_flag = buf[0] >> 7;
    if (policy_id) *policy_id = buf[nonce_size];
    if (orig_proto) *orig_proto = buf[nonce_size + 1];
}

void packet_crypto_set_fake_ethertype(uint16_t fake_ipv4) {
    g_fake_ethertype_ipv4 = fake_ipv4;
}
uint16_t packet_crypto_get_fake_ethertype_ipv4(void) {
    return g_fake_ethertype_ipv4;
}

void packet_crypto_set_encrypt_layer(int layer) { g_encrypt_layer = layer; }

void packet_crypto_set_mode(int mode) {
    g_crypto_mode = mode;
}

int packet_crypto_get_mode(void) { return g_crypto_mode; }

void packet_crypto_set_aes_bits(int bits) { g_aes_bits = bits; }
int  packet_crypto_get_aes_bits(void) { return g_aes_bits; }

static const EVP_CIPHER *get_ctr_cipher(void) {
    return (g_aes_bits == 256) ? EVP_aes_256_ctr() : EVP_aes_128_ctr();
}

static const EVP_CIPHER *get_gcm_cipher(void) {
    return (g_aes_bits == 256) ? EVP_aes_256_gcm() : EVP_aes_128_gcm();
}

static int get_key_size(void) {
    return (g_aes_bits == 256) ? 32 : 16;
}

uint32_t packet_crypto_next_counter(void) {
    return atomic_fetch_add(&g_nonce_counter, 1) & 0x7FFFFFFF;
}

void packet_crypto_reset_counter(void) {
    atomic_store(&g_nonce_counter, 0);
}

static void derive_key(const uint8_t master[AES_MAX_KEY_SIZE],
                       uint64_t epoch,
                       uint8_t out_key[AES_MAX_KEY_SIZE]) {
    int key_size = get_key_size();
    uint8_t epoch_buf[8];
    for (int i = 0; i < 8; i++)
        epoch_buf[i] = (uint8_t)(epoch >> (i * 8));

    unsigned char hmac_out[32];
    unsigned int hmac_len = 0;

    HMAC(EVP_sha256(), master, key_size,
         epoch_buf, sizeof(epoch_buf),
         hmac_out, &hmac_len);

    memcpy(out_key, hmac_out, key_size);
}

static void check_and_update_pqc_key(struct packet_crypto_ctx *ctx) {
    uint8_t new_key[PQC_TRAFFIC_KEY_SZ];

    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC)
        return;
    if (key_has_nonzero(ctx->keys[KEY_SLOT_CURRENT], PQC_TRAFFIC_KEY_SZ))
        return;
    if (sig_pqc_diversify_key(ctx->profile_id, ctx->policy_id, new_key) != 0)
        return;
    if (memcmp(ctx->keys[KEY_SLOT_CURRENT], new_key, PQC_TRAFFIC_KEY_SZ) == 0)
        return;

    memcpy(ctx->keys[KEY_SLOT_CURRENT], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_PREV], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_NEXT], new_key, PQC_TRAFFIC_KEY_SZ);
}

void packet_crypto_update_keys(struct packet_crypto_ctx *ctx) {
    check_and_update_pqc_key(ctx);
}

void packet_crypto_refresh_pqc_keys(struct packet_crypto_ctx *ctx)
{
    uint8_t new_key[PQC_TRAFFIC_KEY_SZ];

    if (!ctx || ctx->crypto_mode != CRYPTO_MODE_PQC)
        return;
    if (sig_pqc_diversify_key(ctx->profile_id, ctx->policy_id, new_key) != 0)
        return;
    memcpy(ctx->keys[KEY_SLOT_CURRENT], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_PREV], new_key, PQC_TRAFFIC_KEY_SZ);
    memcpy(ctx->keys[KEY_SLOT_NEXT], new_key, PQC_TRAFFIC_KEY_SZ);
}

const uint8_t *packet_crypto_get_key(struct packet_crypto_ctx *ctx, int slot) {
    if (!ctx || slot < 0 || slot >= KEY_SLOT_COUNT) return NULL;
    return ctx->keys[slot];
}

int packet_crypto_init(struct packet_crypto_ctx *ctx,
                       const uint8_t master_key[AES_MAX_KEY_SIZE]) {
    if (!ctx || !master_key) return -1;

    int key_size = get_key_size();

    memset(ctx, 0, sizeof(*ctx));
    memcpy(ctx->master_key, master_key, key_size);
    ctx->initialized = true;

    derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_PREV]);
    derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_CURRENT]);
    derive_key(ctx->master_key, 0, ctx->keys[KEY_SLOT_NEXT]);

    packet_crypto_reset_counter();

    if (!get_ctx()) {
        return -1;
    }

    return 0;
}

void packet_crypto_cleanup(struct packet_crypto_ctx *ctx) {
    if (ctx) {
        memset(ctx->master_key, 0, sizeof(ctx->master_key));
        memset(ctx->keys, 0, sizeof(ctx->keys));
        ctx->initialized = false;
    }

    if (tls_ctx) {
        EVP_CIPHER_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }
    if (tls_gcm_enc_ctx) {
        EVP_CIPHER_CTX_free(tls_gcm_enc_ctx);
        tls_gcm_enc_ctx = NULL;
    }
    if (tls_gcm_dec_ctx) {
        EVP_CIPHER_CTX_free(tls_gcm_dec_ctx);
        tls_gcm_dec_ctx = NULL;
    }

    memset(tls_cached_key, 0, sizeof(tls_cached_key));
    memset(tls_dec_cached_key, 0, sizeof(tls_dec_cached_key));
    memset(tls_ctr_cached_key, 0, sizeof(tls_ctr_cached_key));
    tls_key_cached = 0;
    tls_dec_key_cached = 0;
    tls_ctr_key_cached = 0;
    tls_gcm_enc_epoch = 0;
    tls_gcm_dec_epoch = 0;
    (void)atomic_fetch_add_explicit(&g_gcm_epoch, 1u, memory_order_release);
}

int crypto_aes_ctr_with_key(const uint8_t key[AES_MAX_KEY_SIZE],
                            const uint8_t iv[AES128_IV_SIZE],
                            uint8_t *data, int len) {
    if (len <= 0) return 0;

    EVP_CIPHER_CTX *evp = get_ctx();
    if (!evp) return -1;

    int out_len;
    int key_size = get_key_size();
    int key_changed = !tls_ctr_key_cached ||
                      memcmp(tls_ctr_cached_key, key, key_size) != 0;

    if (key_changed) {
        if (EVP_EncryptInit_ex(evp, get_ctr_cipher(), NULL, key, iv) != 1)
            return -1;
        memcpy(tls_ctr_cached_key, key, key_size);
        tls_ctr_key_cached = 1;
    } else {
        if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, iv) != 1)
            return -1;
    }

    if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1)
        return -1;

    int final_len = 0;
    EVP_EncryptFinal_ex(evp, data + out_len, &final_len);

    return 0;
}

// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (__builtin_expect(len <= 0, 0)) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (__builtin_expect(!evp, 0)) return -1;

//     int out_len;
//     int key_size = get_key_size();


//     int key_changed = !tls_key_cached ||
//                       memcmp(tls_cached_key, key, key_size) != 0 ||
//                       tls_cached_nonce_len != nonce_len;

//     if (__builtin_expect(key_changed, 0)) {

//         if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1)
//             return -1;

//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
//             return -1;

//         if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1)
//             return -1;

//         memcpy(tls_cached_key, key, key_size);
//         tls_key_cached = 1;
//         tls_cached_nonce_len = nonce_len;
//     } else {

//         if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1)
//             return -1;
//     }

//     if (__builtin_expect(EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1, 0))
//         return -1;

//     if (__builtin_expect(EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1, 0))
//         return -1;

//     if (__builtin_expect(EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1, 0))
//         return -1;

//     return 0;
// }

// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (!evp || !key || !nonce || !data || !tag_out) return -1;

//     int out_len = 0;

//     if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;

//     if (EVP_EncryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;

//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;

//     if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//     if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) return -1;

//     if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) return -1;

//     return 0;
// }


// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (__builtin_expect(len <= 0, 0)) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (__builtin_expect(!evp, 0)) return -1;

//     int out_len;
//     int key_size = get_key_size();


//     int key_changed = !tls_dec_key_cached ||
//                       memcmp(tls_dec_cached_key, key, key_size) != 0 ||
//                       tls_dec_cached_nonce_len != nonce_len;

//     if (__builtin_expect(key_changed, 0)) {

//         if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1)
//             return -1;

//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
//             return -1;

//         if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1)
//             return -1;

//         memcpy(tls_dec_cached_key, key, key_size);
//         tls_dec_key_cached = 1;
//         tls_dec_cached_nonce_len = nonce_len;
//     } else {

//         if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1)
//             return -1;
//     }

//     if (__builtin_expect(EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1, 0))
//         return -1;

//     if (__builtin_expect(EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE,
//                                              (void *)tag) != 1, 0))
//         return -1;

//     if (__builtin_expect(EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1, 0))
//         return -1;

//     return 0;
// }
// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (!evp || !key || !nonce || !data || !tag) return -1;

//     int out_len = 0;

//     if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;

//     if (EVP_DecryptInit_ex(evp, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) return -1;

//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;

//     if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//     if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) return -1;

//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) return -1;

//     if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     return 0;
// }

// V1
// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (!evp || !key || !nonce || !data || !tag_out) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_key_cached ||
//                       memcmp(tls_cached_key, key, key_size) != 0 ||
//                       tls_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_cached_key, key, key_size);
//         tls_key_cached = 1;
//         tls_cached_nonce_len = nonce_len;
//     } else {
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) return -1;

//     return 0;
// }

// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (!evp || !key || !nonce || !data || !tag) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_dec_key_cached ||
//                       memcmp(tls_dec_cached_key, key, key_size) != 0 ||
//                       tls_dec_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_dec_cached_key, key, key_size);
//         tls_dec_key_cached = 1;
//         tls_dec_cached_nonce_len = nonce_len;
//     } else {
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) return -1;
//     if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     return 0;
// }

// V2
// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (!evp || !key || !nonce || !data || !tag_out) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_key_cached ||
//                       memcmp(tls_cached_key, key, key_size) != 0 ||
//                       tls_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_cached_key, key, key_size);
//         tls_key_cached = 1;
//         tls_cached_nonce_len = nonce_len;
//     } else {
//         // Làm sạch hoàn toàn trạng thái kẹt của cú Ctrl+C trước đó trong 1 nano-giây,
//         // sau đó nạp luôn Nonce mới để CPU chạy thẳng bằng phần cứng AES-NI.
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, NULL) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) return -1;

//     return 0;
// }

// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (!evp || !key || !nonce || !data || !tag) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_dec_key_cached ||
//                       memcmp(tls_dec_cached_key, key, key_size) != 0 ||
//                       tls_dec_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_dec_cached_key, key, key_size);
//         tls_dec_key_cached = 1;
//         tls_dec_cached_nonce_len = nonce_len;
//     } else {
//         // Tương tự cho phần giải mã, dọn sạch bộ đệm lỗi của phiên iperf3 cũ bị đóng đột ngột.
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, NULL) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) return -1;
//     if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     return 0;
// }

// V3
// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (!evp || !key || !nonce || !data || !tag_out) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_key_cached ||
//                       memcmp(tls_cached_key, key, key_size) != 0 ||
//                       tls_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_cached_key, key, key_size);
//         tls_key_cached = 1;
//         tls_cached_nonce_len = nonce_len;
//     } else {
//         // CƠ CHẾ TIÊU CỰC: Gọi 3 lần liên tiếp để phá vỡ cấu trúc kẹt phần cứng.
//         // Lần 1: Ép hủy trạng thái xác thực cũ.
//         EVP_EncryptInit_ex(evp, NULL, NULL, NULL, NULL); 
//         // Lần 2: Ép giải phóng độ dài IV cũ ngay lập tức.
//         EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
//         // Lần 3: Đập thẳng Nonce thật vào rãnh phần cứng sạch.
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) return -1;

//     return 0;
// }

// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (!evp || !key || !nonce || !data || !tag) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_dec_key_cached ||
//                       memcmp(tls_dec_cached_key, key, key_size) != 0 ||
//                       tls_dec_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_dec_cached_key, key, key_size);
//         tls_dec_key_cached = 1;
//         tls_dec_cached_nonce_len = nonce_len;
//     } else {
//         // Tương tự cho phần giải mã: Ép chip xả cặn lỗi dở dang của cú Ctrl+C mạng Layer 2.
//         EVP_DecryptInit_ex(evp, NULL, NULL, NULL, NULL);
//         EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) return -1;
//     if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     return 0;
// }

// V4
// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (!evp || !key || !nonce || !data || !tag_out) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_key_cached ||
//                       memcmp(tls_cached_key, key, key_size) != 0 ||
//                       tls_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_cached_key, key, key_size);
//         tls_key_cached = 1;
//         tls_cached_nonce_len = nonce_len;
//     } else {
//         // CƠ CHẾ TIÊU CỰC TỐI THƯỢNG: Phá hủy sâu trạng thái phần cứng của phiên cũ.
//         // Đập tan hoàn toàn mọi cấu trúc kẹt, giải phóng thanh ghi lệnh phần cứng nhưng GIỮ KEY TRONG CACHE.
//         EVP_CIPHER_CTX_reset(evp); 
        
//         // Ép OpenSSL nạp lại cấu trúc Cipher gốc trong 1 nano-giây.
//         EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL);
//         EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
        
//         // Nạp thẳng Key đang lưu từ RAM (tls_cached_key) và Nonce mới.
//         //CPU KHÔNG PHẢI TÌM LẠI KHÓA TỪ ĐẦU, BĂNG THÔNG GIỮ NGUYÊN 2G.
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, tls_cached_key, nonce) != 1) return -1;
//     }

//     if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) return -1;

//     return 0;
// }

// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (!evp || !key || !nonce || !data || !tag) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_dec_key_cached ||
//                       memcmp(tls_dec_cached_key, key, key_size) != 0 ||
//                       tls_dec_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_CIPHER_CTX_reset(evp) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_dec_cached_key, key, key_size);
//         tls_dec_key_cached = 1;
//         tls_dec_cached_nonce_len = nonce_len;
//     } else {
//         // Tương tự cho phần giải mã: Dọn sạch rác bằng bạo lực bộ nhớ, nạp lại Key từ bản Cache trong RAM.
//         EVP_CIPHER_CTX_reset(evp);
//         EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL);
//         EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL);
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, tls_dec_cached_key, nonce) != 1) return -1;
//     }

//     if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) return -1;
//     if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     return 0;
// }


//V5

// int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            uint8_t tag_out[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_enc_ctx();
//     if (!evp || !key || !nonce || !data || !tag_out) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_key_cached ||
//                       memcmp(tls_cached_key, key, key_size) != 0 ||
//                       tls_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_cached_key, key, key_size);
//         tls_key_cached = 1;
//         tls_cached_nonce_len = nonce_len;
//     } else {
//         // CƠ CHẾ TIÊU CỰC TỐI THƯỢNG: ĐÁNH LỪA PHẦN CỨNG (CIPHER FLIPPING)
//         // Dùng 1 byte đầu tiên của Key gốc, đảo bit nó đi để tạo ra một cái Key giả (Fake Key)
//         uint8_t fake_key[AES_MAX_KEY_SIZE];
//         memcpy(fake_key, tls_cached_key, key_size);
//         fake_key[0] ^= 0xFF; 

//         // Bước 1: Nạp Key giả kèm Nonce rỗng -> Ép chip phần cứng tự động xả sạch bộ đếm lỗi cũ trong 1 chu kỳ máy.
//         EVP_EncryptInit_ex(evp, NULL, NULL, fake_key, NULL);

//         // Bước 2: Nạp lại Nonce thật của gói tin này vào cấu trúc đã sạch.
//         // Vì Key rác vừa rồi chỉ chạy trên RAM, cấu trúc Lịch trình khóa phần cứng (AES-NI) lập tức được đồng bộ lại với Key thật.
//         if (EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_EncryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_EncryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out) != 1) return -1;

//     return 0;
// }

// int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
//                            const uint8_t *nonce, int nonce_len,
//                            uint8_t *data, int len,
//                            const uint8_t tag[AES_GCM_TAG_SIZE]) {
//     if (len <= 0) return 0;

//     EVP_CIPHER_CTX *evp = get_gcm_dec_ctx();
//     if (!evp || !key || !nonce || !data || !tag) return -1;

//     int out_len;
//     int key_size = get_key_size();

//     int key_changed = !tls_dec_key_cached ||
//                       memcmp(tls_dec_cached_key, key, key_size) != 0 ||
//                       tls_dec_cached_nonce_len != nonce_len;

//     if (key_changed) {
//         if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1) return -1;
//         if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1) return -1;
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, key, nonce) != 1) return -1;

//         memcpy(tls_dec_cached_key, key, key_size);
//         tls_dec_key_cached = 1;
//         tls_dec_cached_nonce_len = nonce_len;
//     } else {
//         // Tương tự cho phần giải mã: Dùng chiêu lừa Key giả để ép xả cặn kẹt của iperf3 cũ.
//         uint8_t fake_key[AES_MAX_KEY_SIZE];
//         memcpy(fake_key, tls_dec_cached_key, key_size);
//         fake_key[0] ^= 0xFF;

//         EVP_DecryptInit_ex(evp, NULL, NULL, fake_key, NULL);
//         if (EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce) != 1) return -1;
//     }

//     if (EVP_DecryptUpdate(evp, data, &out_len, data, len) != 1) return -1;
//     if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag) != 1) return -1;
//     if (EVP_DecryptFinal_ex(evp, data + out_len, &out_len) != 1) return -1;

//     return 0;
// }


static uint32_t ne_gcm_bump_epoch(void)
{
    return (uint32_t)atomic_fetch_add_explicit(&g_gcm_epoch, 1u, memory_order_release) + 1u;
}

static uint32_t ne_gcm_current_epoch(void)
{
    return (uint32_t)atomic_load_explicit(&g_gcm_epoch, memory_order_acquire);
}

static uint64_t ne_gcm_monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

static __thread uint64_t gcm_last_packet_ms;

static void ne_gcm_note_session_gap(int enc, int len, int nonce_len)
{
    uint64_t now = ne_gcm_monotonic_ms();
    uint64_t gap = gcm_last_packet_ms ? (now - gcm_last_packet_ms) : 0;

    (void)len;
    (void)nonce_len;

    /*
     * Bump epoch only on encrypt idle — reverse-path ctrl pkts (~1s apart)
     * must not invalidate encrypt fast path (was causing ~1.2G cap).
     */
    if (enc && gap > GCM_SESSION_GAP_MS)
        ne_gcm_bump_epoch();
    gcm_last_packet_ms = now;
}

static void gcm_enc_poison_ctx(EVP_CIPHER_CTX *evp)
{
    if (evp)
        EVP_CIPHER_CTX_reset(evp);
    tls_gcm_enc_epoch = 0;
    tls_key_cached = 0;
}

static void gcm_dec_poison_ctx(EVP_CIPHER_CTX *evp)
{
    if (evp)
        EVP_CIPHER_CTX_reset(evp);
    tls_gcm_dec_epoch = 0;
    tls_dec_key_cached = 0;
}

static void ne_gcm_maybe_bump_auth_burst(int len)
{
    static __thread uint64_t burst_first_ms;
    static __thread unsigned burst_count;
    uint64_t now = ne_gcm_monotonic_ms();
    uint64_t prev;

    if (len > 80)
        return;

    if (!burst_first_ms || (now - burst_first_ms) > GCM_AUTH_BURST_MS) {
        burst_first_ms = now;
        burst_count = 1;
        return;
    }
    burst_count++;
    if (burst_count < GCM_AUTH_BURST_COUNT)
        return;

    burst_first_ms = 0;
    burst_count = 0;

    prev = atomic_load_explicit(&g_gcm_auth_burst_bump_ms, memory_order_acquire);
    if ((now - prev) < GCM_AUTH_BURST_COOLDOWN_MS)
        return;
    if (!atomic_compare_exchange_weak_explicit(
            &g_gcm_auth_burst_bump_ms, &prev, now,
            memory_order_release, memory_order_acquire))
        return;

    ne_gcm_bump_epoch();
}

static void ne_gcm_on_fail(int enc, int step, int len)
{
    if (enc) {
        ne_gcm_bump_epoch();
        gcm_enc_poison_ctx(get_gcm_enc_ctx());
    } else if (step == 5 && len <= 80) {
        gcm_dec_poison_ctx(get_gcm_dec_ctx());
        ne_gcm_maybe_bump_auth_burst(len);
    } else if (step >= 3) {
        gcm_dec_poison_ctx(get_gcm_dec_ctx());
    }
}

static int gcm_enc_prepare_ctx(EVP_CIPHER_CTX *evp, const uint8_t *key, int nonce_len)
{
    int key_size = get_key_size();
    uint32_t epoch = ne_gcm_current_epoch();
    int key_changed = !tls_key_cached ||
                      memcmp(tls_cached_key, key, (size_t)key_size) != 0;

    if (tls_gcm_enc_epoch == epoch && !key_changed)
        return 0;

    if (EVP_CIPHER_CTX_reset(evp) != 1)
        return -1;
    if (EVP_EncryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1)
        return -1;
    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
        return -1;
    if (EVP_EncryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
        return -1;

    memcpy(tls_cached_key, key, (size_t)key_size);
    tls_key_cached = 1;
    tls_cached_nonce_len = nonce_len;
    tls_gcm_enc_epoch = epoch;
    return 0;
}

static int gcm_dec_prepare_ctx(EVP_CIPHER_CTX *evp, const uint8_t *key, int nonce_len)
{
    int key_size = get_key_size();
    uint32_t epoch = ne_gcm_current_epoch();
    int key_changed = !tls_dec_key_cached ||
                      memcmp(tls_dec_cached_key, key, (size_t)key_size) != 0;

    if (tls_gcm_dec_epoch == epoch && !key_changed)
        return 0;

    if (EVP_CIPHER_CTX_reset(evp) != 1)
        return -1;
    if (EVP_DecryptInit_ex(evp, get_gcm_cipher(), NULL, NULL, NULL) != 1)
        return -1;
    if (EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_IVLEN, nonce_len, NULL) != 1)
        return -1;
    if (EVP_DecryptInit_ex(evp, NULL, NULL, key, NULL) != 1)
        return -1;

    memcpy(tls_dec_cached_key, key, (size_t)key_size);
    tls_dec_key_cached = 1;
    tls_dec_cached_nonce_len = nonce_len;
    tls_gcm_dec_epoch = epoch;
    return 0;
}

int crypto_aes_gcm_encrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           uint8_t tag_out[AES_GCM_TAG_SIZE]) {
    int out_len;
    int rv;
    EVP_CIPHER_CTX *evp;

    if (len <= 0) return 0;

    evp = get_gcm_enc_ctx();
    if (!evp || !key || !nonce || !data || !tag_out) return -1;

    ne_gcm_note_session_gap(1, len, nonce_len);

    if (gcm_enc_prepare_ctx(evp, key, nonce_len) != 0) {
        ne_gcm_on_fail(1, 1, len);
        return -1;
    }

    rv = EVP_EncryptInit_ex(evp, NULL, NULL, NULL, nonce);
    if (rv != 1) {
        ne_gcm_on_fail(1, 2, len);
        return -1;
    }

    rv = EVP_EncryptUpdate(evp, data, &out_len, data, len);
    if (rv != 1) {
        ne_gcm_on_fail(1, 3, len);
        return -1;
    }

    rv = EVP_EncryptFinal_ex(evp, data + out_len, &out_len);
    if (rv != 1) {
        ne_gcm_on_fail(1, 4, len);
        return -1;
    }

    rv = EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_GET_TAG, AES_GCM_TAG_SIZE, tag_out);
    if (rv != 1) {
        ne_gcm_on_fail(1, 5, len);
        return -1;
    }

    return 0;
}

int crypto_aes_gcm_decrypt(const uint8_t key[AES_MAX_KEY_SIZE],
                           const uint8_t *nonce, int nonce_len,
                           uint8_t *data, int len,
                           const uint8_t tag[AES_GCM_TAG_SIZE]) {
    int out_len;
    int rv;
    EVP_CIPHER_CTX *evp;

    if (len <= 0) return 0;

    evp = get_gcm_dec_ctx();
    if (!evp || !key || !nonce || !data || !tag) return -1;

    ne_gcm_note_session_gap(0, len, nonce_len);

    if (gcm_dec_prepare_ctx(evp, key, nonce_len) != 0) {
        ne_gcm_on_fail(0, 1, len);
        gcm_dec_poison_ctx(evp);
        return -1;
    }

    rv = EVP_DecryptInit_ex(evp, NULL, NULL, NULL, nonce);
    if (rv != 1) {
        ne_gcm_on_fail(0, 2, len);
        gcm_dec_poison_ctx(evp);
        return -1;
    }

    rv = EVP_CIPHER_CTX_ctrl(evp, EVP_CTRL_GCM_SET_TAG, AES_GCM_TAG_SIZE, (void *)tag);
    if (rv != 1) {
        ne_gcm_on_fail(0, 3, len);
        gcm_dec_poison_ctx(evp);
        return -1;
    }

    rv = EVP_DecryptUpdate(evp, data, &out_len, data, len);
    if (rv != 1) {
        ne_gcm_on_fail(0, 4, len);
        gcm_dec_poison_ctx(evp);
        return -1;
    }

    rv = EVP_DecryptFinal_ex(evp, data + out_len, &out_len);
    if (rv != 1) {
        ne_gcm_on_fail(0, 5, len);
        gcm_dec_poison_ctx(evp);
        return -1;
    }

    return 0;
}

static __thread uint8_t tls_nonce_salt[16];
static __thread int tls_salt_initialized = 0;

void crypto_generate_nonce(uint32_t counter, uint8_t proto_flag,
                           uint8_t *out_nonce, int *out_nonce_len) {
    const int ns = PACKET_CRYPTO_NONCE_BYTES;

    out_nonce[0] = (proto_flag << 7) | ((counter >> 24) & 0x7F);
    out_nonce[1] = (counter >> 16) & 0xFF;
    out_nonce[2] = (counter >> 8) & 0xFF;
    out_nonce[3] = counter & 0xFF;

    if (__builtin_expect(!tls_salt_initialized, 0)) {
        RAND_bytes(tls_nonce_salt, sizeof(tls_nonce_salt));
        tls_salt_initialized = 1;
    }
    memcpy(out_nonce + 4, tls_nonce_salt, ns - 4);
    *out_nonce_len = ns;
}

void crypto_nonce_to_iv(const uint8_t *nonce, int nonce_size,
                        uint8_t iv[AES128_IV_SIZE]) {
    memcpy(iv, nonce, nonce_size);
    if (nonce_size < AES128_IV_SIZE)
        memset(iv + nonce_size, 0, AES128_IV_SIZE - nonce_size);
}

void crypto_write_counter(uint8_t *packet, const uint8_t *nonce,
                          int nonce_size, uint8_t policy_id) {
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    packet[12] = (uint8_t)(fake >> 8);
    packet[13] = (uint8_t)(fake & 0xFF);
    packet[CRYPTO_L2_POLICY_OFF] = policy_id;
    memcpy(packet + CRYPTO_L2_NONCE_OFF, nonce, (size_t)nonce_size);
}

void crypto_read_counter(const uint8_t *packet, int nonce_size,
                         uint8_t *nonce_out, uint8_t *policy_id, uint8_t *proto_flag) {
    if (policy_id)
        *policy_id = packet[CRYPTO_L2_POLICY_OFF];
    memcpy(nonce_out, packet + CRYPTO_L2_NONCE_OFF, (size_t)nonce_size);
    if (proto_flag)
        *proto_flag = nonce_out[0] >> 7;
}

uint16_t crypto_calc_ip_checksum(const uint8_t *ip_hdr, int hdr_len) {
    uint32_t sum = 0;
    for (int i = 0; i < hdr_len; i += 2) {
        uint16_t word = ((uint16_t)ip_hdr[i] << 8);
        if (i + 1 < hdr_len)
            word |= ip_hdr[i + 1];
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t crypto_calc_tcp_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                                   const uint8_t *tcp_seg, int tcp_seg_len) {
    if (ip_hdr_len < 20 || tcp_seg_len < 20) return 0;
    uint32_t sum = 0;
    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += (uint16_t)6;
    sum += (uint16_t)(tcp_seg_len & 0xFFFF);
    for (int i = 0; i < tcp_seg_len; i += 2) {
        uint16_t word;
        if (i == 16 && i + 2 <= tcp_seg_len) {
            word = 0;
        } else {
            word = ((uint16_t)tcp_seg[i] << 8);
            if (i + 1 < tcp_seg_len)
                word |= tcp_seg[i + 1];
            else
                word |= 0;
        }
        sum += word;
    }
    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

uint16_t crypto_calc_udp_checksum(const uint8_t *ip_hdr, int ip_hdr_len,
                                   const uint8_t *udp_seg, int udp_seg_len) {
    if (ip_hdr_len < 20 || udp_seg_len < 8) return 0;

    uint16_t udp_len = ((uint16_t)udp_seg[4] << 8) | udp_seg[5];
    if (udp_len < 8) udp_len = 8;
    if (udp_len > (uint16_t)udp_seg_len) udp_len = (uint16_t)udp_seg_len;

    uint32_t sum = 0;
    sum += ((uint16_t)ip_hdr[12] << 8) | ip_hdr[13];
    sum += ((uint16_t)ip_hdr[14] << 8) | ip_hdr[15];
    sum += ((uint16_t)ip_hdr[16] << 8) | ip_hdr[17];
    sum += ((uint16_t)ip_hdr[18] << 8) | ip_hdr[19];
    sum += (uint16_t)17;
    sum += (uint16_t)(udp_len & 0xFFFF);

    for (int i = 0; i < (int)udp_len; i += 2) {
        uint16_t word = ((uint16_t)udp_seg[i] << 8);
        if (i + 1 < (int)udp_len)
            word |= udp_seg[i + 1];
        sum += word;
    }

    while (sum >> 16)
        sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum);
}

int packet_decrypt(struct packet_crypto_ctx *ctx,
                   uint8_t *packet,
                   size_t pkt_len) {
    packet_crypto_update_keys(ctx);

    switch (g_encrypt_layer) {
    case 2:
        return crypto_layer2_decrypt(ctx,packet, pkt_len);
    case 3:
        return crypto_layer3_decrypt(ctx, packet, pkt_len);
    case 4:
        return crypto_layer4_decrypt(ctx, packet, pkt_len);
    default:
        return -1;
    }
}

void packet_crypto_set_fake_protocol(uint8_t proto) { g_fake_protocol = proto; }
uint8_t packet_crypto_get_fake_protocol(void) { return g_fake_protocol; }

void packet_crypto_set_policy_id(uint8_t policy_id) { g_policy_id = policy_id; }
uint8_t packet_crypto_get_policy_id(void) { return g_policy_id; }
