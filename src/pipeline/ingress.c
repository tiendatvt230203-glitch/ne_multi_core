#include "../../inc/pipeline/pipeline.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/crypto/runtime.h"
#include "../../inc/lan_neigh/lan_neigh.h"

#include "../../inc/crypto/crypto_dispatch.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/crypto/packet_crypto.h"

#include "../../inc/crypto/fragment.h"

static int wan_has_crypto(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t pol = 0;

    if (!fwd->cfg->crypto_enabled || !pkt)
        return 0;
    if (frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx) ||
        frag_is_fragment(fwd->cfg, pkt, len, &pid, &fidx) ||
        frag_is_fragment_l4(fwd->cfg, pkt, len, &pid, &fidx))
        return 1;
    if (fwd_crypto_has_l2_marker(pkt, len))
        return 1;
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return 1;
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return 1;
    return 0;
}

static int decrypt_l2(uint8_t *pkt, uint32_t *len)
{
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    struct packet_crypto_ctx *ctx;
    int n;

    if (!fake || *len < ETH_HEADER_SIZE + CRYPTO_L2_POLICY_LEN)
        return 0;
    if ((((uint16_t)pkt[12] << 8) | pkt[13]) != fake)
        return 0;
    ctx = fwd_crypto_ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L2, pkt[CRYPTO_L2_POLICY_OFF]);
    if (!ctx)
        return -1;
    n = crypto_layer2_decrypt(ctx, pkt, *len);
    if (n < 0)
        return -1;
    *len = (uint32_t)n;
    return 0;
}

static int reassemble_l2(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, nd, rr;
    uint16_t opid;
    uint8_t ofidx;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L2, policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_policy_action_id(POLICY_ACTION_ENCRYPT_L2, policy_id));
    if (slot < 0)
        return -1;
    nd = crypto_layer2_decrypt_fragment(ctx, pkt, *len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    rr = frag_try_reassemble_l2(fwd_crypto_frag_l2(slot), pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
    if (rr == 0) {
        *pending = 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    memcpy(pkt, buf, blen);
    *len = blen;
    return 0;
}

static int reassemble_l3(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, nd, rr;
    uint16_t opid;
    uint8_t ofidx;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L3, policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_policy_action_id(POLICY_ACTION_ENCRYPT_L3, policy_id));
    if (slot < 0)
        return -1;
    nd = crypto_layer3_decrypt_fragment(ctx, pkt, *len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    rr = frag_try_reassemble(fwd_crypto_frag_l3(slot), pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
    if (rr == 0) {
        *pending = 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    memcpy(pkt, buf, blen);
    *len = blen;
    return 0;
}

static int reassemble_l4(struct forwarder *fwd, uint8_t *pkt, uint32_t *len,
                         uint8_t policy_id, int *pending)
{
    struct packet_crypto_ctx *ctx;
    int slot, nd, rr;
    uint16_t opid;
    uint8_t ofidx;
    uint8_t buf[4096];
    uint32_t blen = 0;

    ctx = fwd_crypto_ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L4, policy_id);
    if (!ctx)
        return -1;
    slot = fwd_crypto_profile_slot_for_id(
        fwd_crypto_profile_id_for_policy_action_id(POLICY_ACTION_ENCRYPT_L4, policy_id));
    if (slot < 0)
        return -1;
    nd = crypto_layer4_decrypt_fragment(ctx, pkt, *len, &opid, &ofidx);
    if (nd < 0)
        return -1;
    rr = frag_try_reassemble_l4(fwd_crypto_frag_l4(slot), pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
    if (rr == 0) {
        *pending = 1;
        return 0;
    }
    if (rr != 1)
        return -1;
    memcpy(pkt, buf, blen);
    *len = blen;
    return 0;
}

static int decrypt_wan(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t scratch[8192];
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t pol = 0;
    int pending = 0;
    struct crypto_dispatch_ctx dctx;

    if (frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx)) {
        if (reassemble_l2(fwd, pkt, &len, pkt[CRYPTO_L2_POLICY_OFF], &pending) != 0)
            return -1;
    } else if (decrypt_l2(pkt, &len) != 0) {
        return -1;
    }
    if (pending)
        return 1;

    if (!fwd->cfg->crypto_enabled) {
        job->len = len;
        return 0;
    }

    dctx = fwd_crypto_make_dispatch_ctx();
    if (frag_is_fragment(fwd->cfg, pkt, len, &pid, &fidx)) {
        if (crypto_l3_extract_policy_id(fwd->cfg, pkt, len, &pol) != 0)
            return -1;
        if (reassemble_l3(fwd, pkt, &len, pol, &pending) != 0)
            return -1;
    } else if (crypto_l3_extract_policy_id(fwd->cfg, pkt, len, &pol) == 0 &&
               crypto_decrypt_packet_auto_by_action(1, fwd->cfg, &dctx,
                                                    POLICY_ACTION_ENCRYPT_L3,
                                                    pkt, &len, scratch, sizeof(scratch)) != 0) {
        return -1;
    }
    if (pending)
        return 1;

    if (frag_is_fragment_l4(fwd->cfg, pkt, len, &pid, &fidx)) {
        if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, pkt, len, &pol) != 0)
            return -1;
        if (reassemble_l4(fwd, pkt, &len, pol, &pending) != 0)
            return -1;
    } else if (crypto_decrypt_packet_auto_by_action(1, fwd->cfg, &dctx,
                                                      POLICY_ACTION_ENCRYPT_L4,
                                                      pkt, &len, scratch,
                                                      sizeof(scratch)) != 0) {
        return -1;
    }
    if (pending)
        return 1;

    job->len = len;
    return 0;
}

static int pick_local(struct forwarder *fwd, uint8_t *pkt, uint32_t len)
{
    return config_find_local_for_ip(fwd->cfg, dp_dest_ipv4(pkt, len));
}

void pipeline_ingress(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    int li;
    int dec;

    if (wan_has_crypto(fwd, pkt, job.len)) {
        dec = decrypt_wan(fwd, &job);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec != 0)
            goto drop;
        pkt = ne_packet_data(&fwd->pair, job.addr);
    }

    li = pick_local(fwd, pkt, job.len);
    if (li < 0 || li >= fwd->local_count)
        goto drop;
    {
        uint8_t client_mac[MAC_LEN];
        uint32_t dest_ip = dp_dest_ipv4(pkt, job.len);
        if (dest_ip == 0 || lan_neigh_lookup(li, dest_ip, client_mac) != 0)
            goto drop;
        if (dp_write_l2(pkt, job.len, client_mac, fwd->locals[li].src_mac, 0) != 0)
            goto drop;
    }

    job.dir = NE_DIR_LOCAL;
    job.local_idx = (uint8_t)li;
    (void)dp_ring_push(fwd, &fwd->mid_to_local[li], &job);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}
