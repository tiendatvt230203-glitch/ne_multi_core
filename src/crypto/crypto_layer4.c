#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/core/config.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/traffic_crypto.h"
#include <string.h>

#define L4_WIRE_PORT_LEN   4

static void l4_write_tunnel_header(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L4_TUNNEL_MAGIC;
}

static void l4_write_tunnel_header_frag(uint8_t *buf, const uint8_t *nonce, int nonce_size) {
    memcpy(buf, nonce, nonce_size);
    buf[nonce_size] = packet_crypto_get_policy_id();
    buf[nonce_size + 1] = CRYPTO_L4_FRAG_MAGIC;
}

static int l4_is_tunnel_header(const uint8_t *buf, int nonce_size) {
    if (buf[nonce_size + 1] != CRYPTO_L4_TUNNEL_MAGIC)
        return 0;
    if (packet_crypto_get_mode() != CRYPTO_MODE_PQC && (buf[0] & 0x80) != 0)
        return 0;
    return 1;
}

static int get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
                                  size_t remaining) {
    if (ip_proto == 6) {
        if (remaining < 20)
            return -1;
        int data_off = ((transport_hdr[12] >> 4) & 0x0F) * 4;
        if (data_off < 20 || (size_t)data_off > remaining)
            return -1;
        return data_off;
    }
    if (ip_proto == 17) {
        if (remaining < 8)
            return -1;
        return 8;
    }
    return -1;
}

int crypto_layer4_get_transport_hdr_size(const uint8_t *transport_hdr, uint8_t ip_proto,
                                         size_t remaining) {
    return get_transport_hdr_size(transport_hdr, ip_proto, remaining);
}

int crypto_layer4_wire_port_len(void) {
    return L4_WIRE_PORT_LEN;
}

int crypto_layer4_frag_meta_len(void) {
    int meta = L4_WIRE_PORT_LEN + packet_crypto_get_tunnel_hdr_size() + FRAG_L4_HDR_SIZE;
    if (packet_crypto_get_mode() == CRYPTO_MODE_GCM ||
        packet_crypto_get_mode() == CRYPTO_MODE_PQC)
        meta += AES128_GCM_TAG_SIZE;
    return meta;
}

int crypto_layer4_tunnel_off_ipv4(const uint8_t *pkt, size_t pkt_len, int *transport_off_out) {
    int l3_off = crypto_eth_ipv4_offset(pkt, pkt_len);
    if (l3_off < 0)
        return -1;
    if (pkt_len < (size_t)l3_off + 20)
        return -1;
    int ip_hdr_len = (pkt[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;
    int transport_off = l3_off + ip_hdr_len;
    if (transport_off_out)
        *transport_off_out = transport_off;
    return transport_off + L4_WIRE_PORT_LEN;
}

int crypto_eth_ipv4_offset(const uint8_t *pkt, size_t pkt_len) {
    if (!pkt || pkt_len < 14)
        return -1;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x0800)
        return 14;
    if (et == 0x8100) {
        if (pkt_len < 18)
            return -1;
        et = ((uint16_t)pkt[16] << 8) | pkt[17];
        if (et == 0x0800)
            return 18;
        if (et == 0x8100 && pkt_len >= 22) {
            et = ((uint16_t)pkt[20] << 8) | pkt[21];
            if (et == 0x0800)
                return 22;
        }
    }
    return -1;
}

static void l4_fix_ipv4_totlen_and_cksum(uint8_t *packet, int l3_off, int ip_hdr_len,
                                         size_t ip_payload_len) {
    uint16_t new_totlen = (uint16_t)(ip_hdr_len + ip_payload_len);
    packet[l3_off + 2] = (uint8_t)(new_totlen >> 8);
    packet[l3_off + 3] = (uint8_t)(new_totlen & 0xFF);
    packet[l3_off + 10] = 0;
    packet[l3_off + 11] = 0;
    uint16_t cksum = crypto_calc_ip_checksum(packet + l3_off, ip_hdr_len);
    packet[l3_off + 10] = (uint8_t)(cksum >> 8);
    packet[l3_off + 11] = (uint8_t)(cksum & 0xFF);
}

int crypto_layer4_encrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17)
        return (int)pkt_len;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    size_t remaining = pkt_len - (size_t)transport_off;
    int transport_hdr_size = get_transport_hdr_size(packet + transport_off, ip_proto, remaining);
    if (transport_hdr_size < 0)
        return (int)pkt_len;

    int plain_off = transport_off + L4_WIRE_PORT_LEN;
    size_t plain_len = pkt_len - (size_t)plain_off;
    if (plain_len == 0)
        return (int)pkt_len;

    if (packet_crypto_get_mode() == CRYPTO_MODE_PQC) {
        const int pqc_nonce_size = 12;
        int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
        byte nonce[12] = {0};
        const byte *key = (const byte *)packet_crypto_get_pqc_key_for_ctx(ctx);
        const byte *aad = (const byte *)packet_crypto_get_pqc_test_aad();
        const int aad_len = packet_crypto_get_pqc_test_aad_len();
        if (!key)
            return -1;
        if (trf_pqc_generate_nonce(nonce) != TRF_PQC_OK)
            return -1;

        int tunnel_off = plain_off;
        int enc_off = tunnel_off + tunnel_hdr_size;
        memmove(packet + enc_off, packet + plain_off, plain_len);
        int new_len = 0;
        if (trf_encrypt_payload_gcm(key, nonce, pqc_nonce_size, aad, aad_len,
                                    packet + enc_off, (int)plain_len, &new_len) != TRF_PQC_OK)
            return -1;

        l4_write_tunnel_header(packet + tunnel_off, nonce, pqc_nonce_size);

        int total_overhead = tunnel_hdr_size + AES128_GCM_TAG_SIZE;
        size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len;
        l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);
        return (int)(pkt_len + (size_t)total_overhead);
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    uint32_t counter = packet_crypto_next_counter();

    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    int tunnel_off = plain_off;
    int enc_off = tunnel_off + tunnel_hdr_size;

    if (is_gcm) {
        uint8_t tag[AES128_GCM_TAG_SIZE];
        if (crypto_aes_gcm_encrypt(key, nonce, nonce_len, packet + plain_off, (int)plain_len,
                                   tag) != 0)
            return -1;
        memmove(packet + enc_off, packet + plain_off, plain_len);
        memcpy(packet + enc_off + plain_len, tag, AES128_GCM_TAG_SIZE);
    } else {
        uint8_t iv[AES128_IV_SIZE];
        crypto_nonce_to_iv(nonce, nonce_size, iv);
        if (crypto_aes_ctr_with_key(key, iv, packet + plain_off, (int)plain_len) != 0)
            return -1;
        memmove(packet + enc_off, packet + plain_off, plain_len);
    }

    l4_write_tunnel_header(packet + tunnel_off, nonce, nonce_size);

    int total_overhead = tunnel_hdr_size + (is_gcm ? AES128_GCM_TAG_SIZE : 0);
    size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + plain_len;
    l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, ip_payload_len);

    return (int)(pkt_len + (size_t)total_overhead);
}

int crypto_layer4_decrypt(struct packet_crypto_ctx *ctx, uint8_t *packet, size_t pkt_len) {
    if (!ctx || !ctx->initialized || !packet)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return (int)pkt_len;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17)
        return (int)pkt_len;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + L4_WIRE_PORT_LEN;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size) ||
        !l4_is_tunnel_header(packet + tunnel_off, nonce_size))
        return (int)pkt_len;

    if (packet_crypto_get_mode() == CRYPTO_MODE_PQC) {
        const int pqc_nonce_size = 12;
        byte nonce[12];
        const byte *key = (const byte *)packet_crypto_get_pqc_key_for_ctx(ctx);
        const byte *aad = (const byte *)packet_crypto_get_pqc_test_aad();
        const int aad_len = packet_crypto_get_pqc_test_aad_len();
        if (!key)
            return -1;
        memcpy(nonce, packet + tunnel_off, pqc_nonce_size);

        int enc_off = tunnel_off + tunnel_hdr_size;
        int dec_len = 0;
        if (trf_decrypt_payload_gcm(key, nonce, pqc_nonce_size, aad, aad_len,
                                    packet + enc_off, (int)(pkt_len - (size_t)enc_off),
                                    &dec_len) != TRF_PQC_OK)
            return -1;

        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
        l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len,
                                     L4_WIRE_PORT_LEN + (size_t)dec_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + dec_len);
    }

    uint8_t nonce[16];
    memcpy(nonce, packet + tunnel_off, nonce_size);
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size;
    size_t enc_len;
    uint8_t tag[AES128_GCM_TAG_SIZE];
    size_t total_after_tunnel = pkt_len - (size_t)enc_off;

    if (is_gcm) {
        if (total_after_tunnel < AES128_GCM_TAG_SIZE)
            return -1;
        enc_len = total_after_tunnel - AES128_GCM_TAG_SIZE;
        memcpy(tag, packet + enc_off + enc_len, AES128_GCM_TAG_SIZE);
    } else {
        enc_len = total_after_tunnel;
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

        uint8_t *work_ptr = packet + enc_off;
        if (k > 0 && has_backup)
            memcpy(work_ptr, backup, enc_len);

        if (is_gcm) {
            if (crypto_aes_gcm_decrypt(key, nonce, nonce_len, work_ptr, (int)enc_len, tag) != 0)
                continue;
        } else {
            uint8_t iv[AES128_IV_SIZE];
            crypto_nonce_to_iv(nonce, nonce_size, iv);
            if (crypto_aes_ctr_with_key(key, iv, work_ptr, (int)enc_len) != 0)
                continue;
        }

        memmove(packet + transport_off + L4_WIRE_PORT_LEN, work_ptr, enc_len);
        l4_fix_ipv4_totlen_and_cksum(packet, l3_off, ip_hdr_len, L4_WIRE_PORT_LEN + enc_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + enc_len);
    }
    return -1;
}

static void l4_write_frag_tag(uint8_t *buf, uint16_t pkt_id, uint8_t frag_index) {
    buf[0] = (uint8_t)(pkt_id >> 8);
    buf[1] = (uint8_t)(pkt_id & 0xFF);
    buf[2] = frag_index;
    buf[3] = 0;
}

static void l4_read_frag_tag(const uint8_t *buf, uint16_t *pkt_id, uint8_t *frag_index) {
    *pkt_id = ((uint16_t)buf[0] << 8) | buf[1];
    *frag_index = buf[2];
}

int crypto_layer4_encrypt_fragment_single(struct packet_crypto_ctx *ctx,
    const uint8_t *eth_hdr, const uint8_t *ip_hdr, int ip_hdr_len,
    const uint8_t *wire_ports,
    const uint8_t *enc_plain, uint32_t enc_plain_len,
    uint16_t pkt_id, uint8_t frag_index,
    uint8_t *out_buf, size_t out_max, uint32_t *out_len) {
    if (!ctx || !ctx->initialized || !out_buf || !out_len || !wire_ports || !enc_plain)
        return -1;
    if (enc_plain_len == 0)
        return -1;

    if (packet_crypto_get_mode() == CRYPTO_MODE_PQC) {
        int nonce_size = 12;
        int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
        int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + AES128_GCM_TAG_SIZE;
        size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);
        if (need > out_max)
            return -1;

        int offset = 0;
        memcpy(out_buf, eth_hdr, 14);
        offset += 14;
        memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
        offset += ip_hdr_len;
        memcpy(out_buf + offset, wire_ports, L4_WIRE_PORT_LEN);
        offset += L4_WIRE_PORT_LEN;

        byte nonce[12] = {0};
        const byte *key = (const byte *)packet_crypto_get_pqc_key_for_ctx(ctx);
        const byte *aad = (const byte *)packet_crypto_get_pqc_test_aad();
        const int aad_len = packet_crypto_get_pqc_test_aad_len();
        if (!key)
            return -1;
        if (trf_pqc_generate_nonce(nonce) != TRF_PQC_OK)
            return -1;

        int tunnel_off = offset;
        int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
        memmove(out_buf + enc_off, enc_plain, enc_plain_len);

        l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
        l4_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

        int new_len = 0;
        if (trf_encrypt_payload_gcm(key, nonce, nonce_size, aad, aad_len,
                                    out_buf + enc_off, (int)enc_plain_len, &new_len) != TRF_PQC_OK)
            return -1;

        size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + (size_t)new_len;
        l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);
        *out_len = (uint32_t)(enc_off + new_len);
        return 0;
    }

    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int total_overhead = tunnel_hdr_size + FRAG_L4_HDR_SIZE + (is_gcm ? AES128_GCM_TAG_SIZE : 0);
    size_t need = (size_t)(14 + ip_hdr_len + L4_WIRE_PORT_LEN + total_overhead + enc_plain_len);
    if (need > out_max)
        return -1;

    int offset = 0;
    memcpy(out_buf, eth_hdr, 14);
    offset += 14;
    memcpy(out_buf + offset, ip_hdr, ip_hdr_len);
    offset += ip_hdr_len;
    memcpy(out_buf + offset, wire_ports, L4_WIRE_PORT_LEN);
    offset += L4_WIRE_PORT_LEN;

    uint32_t counter = packet_crypto_next_counter();
    uint8_t nonce[16];
    int nonce_len;
    crypto_generate_nonce(counter, PROTO_FLAG_IPV4, nonce, &nonce_len);

    packet_crypto_update_keys(ctx);
    const uint8_t *key = packet_crypto_get_key(ctx, KEY_SLOT_CURRENT);
    if (!key)
        return -1;

    int tunnel_off = offset;
    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
    memmove(out_buf + enc_off, enc_plain, enc_plain_len);

    l4_write_tunnel_header_frag(out_buf + tunnel_off, nonce, nonce_size);
    l4_write_frag_tag(out_buf + tunnel_off + tunnel_hdr_size, pkt_id, frag_index);

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

    size_t ip_payload_len = L4_WIRE_PORT_LEN + (size_t)total_overhead + enc_plain_len;
    l4_fix_ipv4_totlen_and_cksum(out_buf, 14, ip_hdr_len, ip_payload_len);

    *out_len = (uint32_t)(enc_off + enc_plain_len + (is_gcm ? AES128_GCM_TAG_SIZE : 0));
    return 0;
}

int crypto_layer4_decrypt_fragment(struct packet_crypto_ctx *ctx,
    uint8_t *packet, size_t pkt_len,
    uint16_t *out_pkt_id, uint8_t *out_frag_index) {
    if (!ctx || !ctx->initialized || !packet || !out_pkt_id || !out_frag_index)
        return -1;

    int l3_off = crypto_eth_ipv4_offset(packet, pkt_len);
    if (l3_off < 0)
        return -1;

    if (pkt_len < (size_t)l3_off + 20)
        return -1;

    uint8_t ip_proto = packet[l3_off + 9];
    if (ip_proto != 6 && ip_proto != 17)
        return -1;

    int ip_hdr_len = (packet[l3_off] & 0x0F) * 4;
    if (ip_hdr_len < 20)
        return -1;

    int transport_off = l3_off + ip_hdr_len;
    int nonce_size = packet_crypto_get_nonce_size();
    int tunnel_hdr_size = packet_crypto_get_tunnel_hdr_size();
    int tunnel_off = transport_off + L4_WIRE_PORT_LEN;

    if (pkt_len < (size_t)(tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE))
        return -1;
    if (packet[tunnel_off + nonce_size + 1] != CRYPTO_L4_FRAG_MAGIC)
        return -1;

    l4_read_frag_tag(packet + tunnel_off + tunnel_hdr_size, out_pkt_id, out_frag_index);

    if (packet_crypto_get_mode() == CRYPTO_MODE_PQC) {
        int nonce_size = 12;
        int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
        byte nonce[12];
        memcpy(nonce, packet + tunnel_off, nonce_size);
        const byte *key = (const byte *)packet_crypto_get_pqc_key_for_ctx(ctx);
        const byte *aad = (const byte *)packet_crypto_get_pqc_test_aad();
        const int aad_len = packet_crypto_get_pqc_test_aad_len();
        if (!key)
            return -1;

        int dec_len = 0;
        if (trf_decrypt_payload_gcm(key, nonce, nonce_size, aad, aad_len,
                                    packet + enc_off, (int)(pkt_len - (size_t)enc_off),
                                    &dec_len) != TRF_PQC_OK)
            return -1;
        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, (size_t)dec_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + dec_len);
    }

    uint8_t nonce[16];
    memcpy(nonce, packet + tunnel_off, nonce_size);
    int is_gcm = (packet_crypto_get_mode() == CRYPTO_MODE_GCM);
    int nonce_len = is_gcm ? nonce_size : AES128_IV_SIZE;

    int enc_off = tunnel_off + tunnel_hdr_size + FRAG_L4_HDR_SIZE;
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

        memmove(packet + transport_off + L4_WIRE_PORT_LEN, packet + enc_off, enc_len);
        return (int)(transport_off + L4_WIRE_PORT_LEN + enc_len);
    }
    return -1;
}
