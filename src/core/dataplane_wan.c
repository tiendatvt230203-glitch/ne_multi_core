#include "../../inc/core/dataplane.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/config.h"

#include "../../inc/crypto/crypto_dispatch.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/crypto/packet_crypto.h"

#include "../../inc/core/fragment.h"
#include "../../inc/core/crypto_route.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <arpa/inet.h>

static const struct crypto_policy *fwd_l2_policy_by_wire_id(struct forwarder *fwd, uint8_t wire_id)
{
    if (!fwd || !fwd->cfg)
        return NULL;
    for (int i = 0; i < fwd->cfg->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
        const struct crypto_policy *cp = &fwd->cfg->policies[i];
        if (cp->action == POLICY_ACTION_ENCRYPT_L2 && (uint8_t)cp->id == wire_id)
            return cp;
    }
    return NULL;
}

static void wan_apply_l2_policy(struct forwarder *fwd, const uint8_t *pkt)
{
    const struct crypto_policy *cp = fwd_l2_policy_by_wire_id(fwd, pkt[CRYPTO_L2_POLICY_OFF]);
    if (cp)
        crypto_apply_from_policy(cp);
}

static int wan_l2_plain_ipv4(const uint8_t *pkt, uint32_t len)
{
    if (len < ETH_HEADER_SIZE)
        return 0;
    return (((uint16_t)pkt[12] << 8) | pkt[13]) == 0x0800;
}

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

    if (!fake || *len < ETH_HEADER_SIZE + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN)
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
    rr = frag_try_reassemble_l2(fwd_crypto_frag_l2(slot, dp_crypto_current_worker_idx()),
                                pkt, (uint32_t)nd, opid, ofidx, buf, &blen);
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

    {
        int frag_mark = 0;
        int ns = PACKET_CRYPTO_NONCE_BYTES;
        int mark_off = ETH_HEADER_SIZE + CRYPTO_L2_POLICY_LEN + CRYPTO_L2_CORE_ID_LEN + ns;
        uint32_t orig_len = len;

        wan_apply_l2_policy(fwd, pkt);
        if (len > (uint32_t)mark_off)
            frag_mark = (pkt[mark_off] == CRYPTO_L2_FRAG_MAGIC);

        int need_backup = frag_mark ||
            frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx);
        if (need_backup && orig_len <= sizeof(scratch))
            memcpy(scratch, pkt, orig_len);
        if (decrypt_l2(pkt, &len) != 0 || !wan_l2_plain_ipv4(pkt, len)) {
            if (need_backup)
                memcpy(pkt, scratch, orig_len);
            len = orig_len;
            if (frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx)) {
                if (reassemble_l2(fwd, pkt, &len, pkt[CRYPTO_L2_POLICY_OFF], &pending) != 0)
                    return -1;
            } else {
                return -1;
            }
        }
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
    uint32_t dest_ip = dp_dest_ipv4(pkt, len);
    if (dest_ip == 0)
        return -1;
    return config_find_local_for_ip(fwd->cfg, dest_ip);
}

void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    int li;
    int dec;

    if (wan_has_crypto(fwd, pkt, job.len)) {
        uint8_t log_core_id = 0;
        int log_wi = dp_crypto_current_worker_idx();

        if (job.len >= CRYPTO_L2_NONCE_OFF)
            (void)crypto_layer2_read_core_id(pkt, job.len, &log_core_id);
        dec = decrypt_wan(fwd, &job);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec != 0) {
            // #region agent log
            uint8_t core_id = log_core_id;
            uint32_t mark = 0;

            if (job.len >= 16)
                mark = ((uint32_t)pkt[12] << 24) | ((uint32_t)pkt[13] << 16) |
                       ((uint32_t)pkt[14] << 8) | pkt[15];
            dp_agent_log_drop("H2", "dataplane_wan.c:decrypt", "decrypt_fail",
                              (uint32_t)core_id, mark, (uint16_t)job.wan_idx, (uint16_t)job.len);
            // #endregion
            goto drop;
        }
        // #region agent log
        {
            static uint32_t ok_budget = 30;

            if (ok_budget > 0) {
                ok_budget--;
                fprintf(stderr,
                        "[DATAPLANE] decrypt_ok core_id=%u wi=%d len=%u\n",
                        (unsigned)log_core_id, log_wi, job.len);
            }
        }
        // #endregion
        pkt = ne_packet_data(&fwd->pair, job.addr);
    }

    {
        uint32_t dest = dp_dest_ipv4(pkt, job.len);

        if (dp_dest_is_nonunicast(fwd, dest))
            goto drop;
    }

    li = pick_local(fwd, pkt, job.len);
    if (li < 0 || li >= fwd->local_count) {
        // #region agent log
        dp_agent_log_drop("H4", "dataplane_wan.c:pick_local", "no_local_subnet",
                          ntohl(dp_dest_ipv4(pkt, job.len)), job.len, 0, 0);
        // #endregion
        goto drop;
    }
    if (dp_write_l2_src_only(pkt, job.len, fwd->locals[li].src_mac) != 0) {
        // #region agent log
        dp_agent_log_drop("H4", "dataplane_wan.c:lan_mac", "lan_src_mac_unset",
                          (uint32_t)li, job.len, 0, 0);
        // #endregion
        goto drop;
    }

    job.dir = NE_DIR_LOCAL;
    job.local_idx = (uint8_t)li;
    if (dp_ring_push(fwd, &fwd->worker_tx_local[li][dp_crypto_current_worker_idx()], &job) != 0) {
        // #region agent log
        dp_agent_log_drop("H5", "dataplane_wan.c:lan_tx", "lan_tx_ring_full",
                          (uint32_t)li, job.len, 0, 0);
        // #endregion
        return;
    }
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}
