#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/core/config.h"
#include <string.h>

#define L2_FRAG_MAGIC      0x5B
#define MIN_ETH_PKT        (ETH_HEADER_SIZE + 8)

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

static inline int l2_enc_start_offset(int nonce_size) {
    return ETH_HEADER_SIZE + nonce_size;
}

static inline int l2_frag_enc_start_offset(int nonce_size) {
    return ETH_HEADER_SIZE + nonce_size + 1 + CRYPTO_L2_FRAG_TAG_SIZE;
}

static inline int pkt_is_ipv4_eth(const uint8_t *packet) {
    uint16_t et = ((uint16_t)packet[12] << 8) | packet[13];
    return et == 0x0800;
}

static inline int verify_ipv4_after_decrypt(const uint8_t *ip_payload, size_t len) {
    if (unlikely(len < 20))
        return 0;
    uint8_t ttl   = ip_payload[8];
    uint8_t proto = ip_payload[9];
    if (unlikely(ttl == 0))
        return 0;
    if (proto == 1 || proto == 2 || proto == 6 || proto == 17 ||
        proto == 47 || proto == 50 || proto == 51 || proto == 58 ||
        proto == 89 || proto == 132)
        return 1;
    return 0;
}

static int l2_fake_marker_byte(const uint8_t *packet, uint8_t *marker_out) {
    if (!pkt_is_ipv4_eth(packet))
        return -1;
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    if (unlikely(fake == 0))
        return -1;
    *marker_out = (uint8_t)(fake >> 8);
    return 0;
}

static int l2_has_fake_marker(const uint8_t *packet) {
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    return fake && packet[12] == (uint8_t)(fake >> 8);
}

int crypto_layer2_wire_eth_len(void) {
    return ETH_HEADER_SIZE;
}

int crypto_layer2_frag_meta_len(void) {
    int nonce_size = packet_crypto_get_nonce_size();
    int meta = nonce_size + 1 + CRYPTO_L2_FRAG_TAG_SIZE;
    if (packet_crypto_get_mode() == CRYPTO_MODE_GCM)
        meta += AES128_GCM_TAG_SIZE;
    return meta;
}

int crypto_layer2_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet || pkt_len < MIN_ETH_PKT))
        return -1;
    if (!pkt_is_ipv4_eth(packet))
        return (int)pkt_len;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_enc_start = l2_enc_start_offset(nonce_size);

    uint8_t marker_byte;
    if (l2_fake_marker_byte(packet, &marker_byte) < 0)
        return (int)pkt_len;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);

    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    const size_t payload_len = pkt_len - ETH_HEADER_SIZE;

    memmove(packet + l2_enc_start, packet + ETH_HEADER_SIZE, payload_len);
    crypto_write_counter(packet, nonce, nonce_size, marker_byte,
                         packet_crypto_get_policy_id());

    if (likely(is_gcm)) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (unlikely(crypto_aes_gcm_encrypt(key, nonce, nonce_len,
                                            packet + l2_enc_start, (int)payload_len, tag) != 0))
            return -1;
        memcpy(packet + l2_enc_start + payload_len, tag, AES128_GCM_TAG_SIZE);
        return (int)(pkt_len + nonce_size + AES128_GCM_TAG_SIZE);
    }

    uint8_t iv[AES128_IV_SIZE];
    crypto_nonce_to_iv(nonce, nonce_size, iv);
    if (unlikely(crypto_aes_ctr_with_key(key, iv, packet + l2_enc_start, (int)payload_len) != 0))
        return -1;
    return (int)(pkt_len + nonce_size);
}

int crypto_layer2_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (unlikely(!ctx || !ctx->initialized || !packet))
        return -1;

    const int nonce_size = packet_crypto_get_nonce_size();
    const int l2_enc_start = l2_enc_start_offset(nonce_size);

    if (unlikely(pkt_len < (size_t)l2_enc_start))
        return -1;
    if (!l2_has_fake_marker(packet))
        return (int)pkt_len;

    if (pkt_len >= (size_t)(ETH_HEADER_SIZE + nonce_size + 1) &&
        packet[ETH_HEADER_SIZE + nonce_size] == L2_FRAG_MAGIC)
        return (int)pkt_len;

    uint8_t policy_id;
    uint8_t proto_flag;
    uint8_t nonce[16];
    crypto_read_counter(packet, nonce_size, nonce, &policy_id, &proto_flag);
    (void)policy_id;
    (void)proto_flag;

    const int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    const int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    size_t enc_len = pkt_len - l2_enc_start;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    if (is_gcm) {
        if (unlikely(pkt_len < (size_t)(l2_enc_start + AES128_GCM_TAG_SIZE)))
            return -1;
        enc_len -= AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + l2_enc_start + enc_len, AES128_GCM_TAG_SIZE);
    }

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    uint8_t *work_ptr = packet + l2_enc_start;

    if (likely(is_gcm)) {
        if (unlikely(crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0))
            return -1;
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (unlikely(crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0))
            return -1;
        if (unlikely(!verify_ipv4_after_decrypt(work_ptr, enc_len)))
            return -1;
    }

    if (work_ptr[0] == 0x08 && work_ptr[1] == 0x00) {
        packet[12] = 0x08;
        packet[13] = 0x00;
        memmove(packet + ETH_HEADER_SIZE, work_ptr + 2, enc_len - 2);
        return (int)(ETH_HEADER_SIZE + enc_len - 2);
    }

    packet[12] = 0x08;
    packet[13] = 0x00;
    memmove(packet + ETH_HEADER_SIZE, work_ptr, enc_len);
    return (int)(ETH_HEADER_SIZE + enc_len);
}

static void l2_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void l2_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int crypto_layer2_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len) {
    if (!ctx || !ctx->initialized || !eth_hdr || !enc_plain || !out_buf || !out_len)
        return -1;
    if (enc_plain_len == 0 || !pkt_is_ipv4_eth(eth_hdr))
        return -1;

    int nonce_size = packet_crypto_get_nonce_size();
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int enc_off = l2_frag_enc_start_offset(nonce_size);
    size_t need = (size_t)enc_off + enc_plain_len + (is_gcm ? AES128_GCM_TAG_SIZE : 0);
    if (need > out_max)
        return -1;

    memcpy(out_buf, eth_hdr, ETH_HEADER_SIZE);

    uint8_t marker_byte;
    if (l2_fake_marker_byte(eth_hdr, &marker_byte) < 0)
        return -1;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    crypto_write_counter(out_buf, nonce, nonce_size, marker_byte,
                         packet_crypto_get_policy_id());
    out_buf[ETH_HEADER_SIZE + nonce_size] = L2_FRAG_MAGIC;
    l2_write_frag_tag(out_buf + ETH_HEADER_SIZE + nonce_size + 1, pkt_id, frag_index);

    memcpy(out_buf + enc_off, enc_plain, enc_plain_len);

    if (is_gcm) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, out_buf + enc_off, (int)enc_plain_len,
                                   tag) != 0)
            return -1;
        memcpy(out_buf + enc_off + enc_plain_len, tag, AES128_GCM_TAG_SIZE);
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, out_buf + enc_off, (int)enc_plain_len) != 0)
            return -1;
    }

    *out_len = (uint32_t)(enc_off + enc_plain_len + (is_gcm ? AES128_GCM_TAG_SIZE : 0));
    return 0;
}

int crypto_layer2_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;

    int nonce_size = packet_crypto_get_nonce_size();
    int enc_off = l2_frag_enc_start_offset(nonce_size);

    if (pkt_len < (size_t)enc_off || !l2_has_fake_marker(packet))
        return -1;
    if (packet[ETH_HEADER_SIZE + nonce_size] != L2_FRAG_MAGIC)
        return -1;

    l2_read_frag_tag(packet + ETH_HEADER_SIZE + nonce_size + 1, out_pkt_id, out_frag_index);

    uint8_t nonce[16];
    uint8_t policy_id;
    uint8_t proto_flag;
    crypto_read_counter(packet, nonce_size, nonce, &policy_id, &proto_flag);
    (void)policy_id;
    (void)proto_flag;

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    size_t total_after = pkt_len - (size_t)enc_off;
    size_t enc_len;
    uint8_t tag[AES128_GCM_TAG_SIZE];

    if (is_gcm) {
        if (total_after < AES128_GCM_TAG_SIZE)
            return -1;
        enc_len = total_after - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } else {
        enc_len = total_after;
    }

    uint8_t backup[2048];
    int has_backup = (enc_len <= sizeof(backup));
    if (has_backup)
        memcpy(backup, packet + enc_off, enc_len);

    int key_order[] = { KEY_SLOT_CURRENT, KEY_SLOT_PREV, KEY_SLOT_NEXT };

    for (int k = 0; k < KEY_SLOT_COUNT; k++) {
        const uint8_t *key = packet_crypto_get_key(ctx, key_order[k]);
        if (!key)
            continue;

        uint8_t *work = packet + enc_off;
        if (k > 0 && has_backup)
            memcpy(work, backup, enc_len);

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work, (int)enc_len, tag) != 0)
                continue;
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work, (int)enc_len) != 0)
                continue;
        }

        memmove(packet + ETH_HEADER_SIZE, packet + enc_off, enc_len);
        return (int)(ETH_HEADER_SIZE + enc_len);
    }
    return -1;
}
