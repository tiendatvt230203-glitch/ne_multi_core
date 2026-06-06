#include "../../inc/pipeline/pipeline.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/routing/wan_pick.h"
#include "../../inc/crypto/runtime.h"
#include "../../inc/br_wire/br_wire.h"
#include "../../inc/policy/policy.h"

#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/crypto/fragment.h"

#include <net/ethernet.h>
#include <stdio.h>
#include <string.h>

enum {
    EGR_DROP_OWN_MAC = 0,
    EGR_DROP_POLICY,
    EGR_DROP_NO_WAN,
    EGR_DROP_TX_ROOM,
    EGR_DROP_L2,
    EGR_DROP_CRYPTO_OFF,
    EGR_DROP_CRYPTO_NOT_READY,
    EGR_DROP_ENCRYPT,
    EGR_DROP_N
};

static const char *egr_drop_name(int reason)
{
    switch (reason) {
    case EGR_DROP_OWN_MAC:          return "own_port_src";
    case EGR_DROP_POLICY:           return "no_policy_match";
    case EGR_DROP_NO_WAN:           return "br_wire_no_wan";
    case EGR_DROP_TX_ROOM:          return "wan_tx_blocked";
    case EGR_DROP_L2:               return "l2_rewrite_fail";
    case EGR_DROP_CRYPTO_OFF:       return "crypto_disabled";
    case EGR_DROP_CRYPTO_NOT_READY: return "crypto_not_ready";
    case EGR_DROP_ENCRYPT:          return "encrypt_fail";
    default:                        return "?";
    }
}

static uint64_t g_egr_drop[EGR_DROP_N];
static uint8_t g_egr_drop_first[EGR_DROP_N];

static void egr_drop_count(int reason)
{
    if (reason < 0 || reason >= EGR_DROP_N)
        return;
    uint64_t n = __sync_add_and_fetch(&g_egr_drop[reason], 1);
    if (!g_egr_drop_first[reason]) {
        g_egr_drop_first[reason] = 1;
        fprintf(stderr, "[EGR-DROP] first: %s (lan->wan packet dropped)\n",
                egr_drop_name(reason));
        fflush(stderr);
    } else if ((n & 0x3FFFu) == 0) {
        fprintf(stderr,
                "[EGR-DROP] own_mac=%llu policy=%llu no_wan=%llu tx_room=%llu "
                "l2=%llu crypto_off=%llu not_ready=%llu encrypt=%llu\n",
                (unsigned long long)g_egr_drop[EGR_DROP_OWN_MAC],
                (unsigned long long)g_egr_drop[EGR_DROP_POLICY],
                (unsigned long long)g_egr_drop[EGR_DROP_NO_WAN],
                (unsigned long long)g_egr_drop[EGR_DROP_TX_ROOM],
                (unsigned long long)g_egr_drop[EGR_DROP_L2],
                (unsigned long long)g_egr_drop[EGR_DROP_CRYPTO_OFF],
                (unsigned long long)g_egr_drop[EGR_DROP_CRYPTO_NOT_READY],
                (unsigned long long)g_egr_drop[EGR_DROP_ENCRYPT]);
        fflush(stderr);
    }
}

static int is_own_port_src(const struct forwarder *fwd, int li,
                           const uint8_t *pkt, uint32_t pkt_len)
{
    static const uint8_t zero[MAC_LEN];

    if (!fwd || li < 0 || li >= fwd->local_count || !pkt || pkt_len < ETH_HEADER_SIZE)
        return 0;
    if (memcmp(fwd->locals[li].src_mac, zero, MAC_LEN) == 0)
        return 0;
    return memcmp(pkt + MAC_LEN, fwd->locals[li].src_mac, MAC_LEN) == 0;
}

static int push_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_dp)
{
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    return dp_ring_push(fwd, &fwd->mid_to_wan[wan_dp], job);
}

static int push_split_to_wan(struct forwarder *fwd, struct ne_packet *job,
                             uint32_t l1, const uint8_t *f2, uint32_t l2, int wan_dp)
{
    struct ne_ring *tx = &fwd->mid_to_wan[wan_dp];
    if (wan_dp < 0 || wan_dp >= fwd->wan_count || ne_ring_count(tx) + 2 > tx->cap)
        return -1;
    if (l1 == 0 || l2 == 0 || l1 > fwd->pair.frame_size || l2 > fwd->pair.frame_size)
        return -1;

    struct ne_packet tail = { .len = l2, .dir = NE_DIR_WAN, .wan_idx = (uint8_t)wan_dp };
    if (ne_frame_alloc(&fwd->pair, &tail.addr) != 0)
        return -1;
    memcpy(ne_packet_data(&fwd->pair, tail.addr), f2, l2);
    job->len = l1;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    if (ne_ring_try_push(tx, job) != 0) {
        ne_frame_free(&fwd->pair, tail.addr);
        return -1;
    }
    if (ne_ring_try_push(tx, &tail) != 0)
        ne_frame_free(&fwd->pair, tail.addr);
    return 0;
}

static int encrypt_to_wan(struct forwarder *fwd, struct ne_packet *job,
                          const struct crypto_policy *cp, int wan_dp,
                          struct packet_crypto_ctx *pctx)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t len = job->len;
    uint8_t f2[4096];
    uint32_t l1 = 0, l2 = 0;

    if (cp->action == POLICY_ACTION_ENCRYPT_L2 && frag_need_split_l2(len)) {
        if (frag_split_and_encrypt_l2(pctx, pkt, len, fwd->pair.frame_size, &l1,
                                      f2, fwd->pair.frame_size, &l2) != 0)
            return -1;
    } else if (cp->action == POLICY_ACTION_ENCRYPT_L3 && frag_need_split(len)) {
        if (frag_split_and_encrypt(pctx, pkt, len, fwd->pair.frame_size, &l1,
                                   f2, fwd->pair.frame_size, &l2) != 0)
            return -1;
    } else if (cp->action == POLICY_ACTION_ENCRYPT_L4 && frag_need_split_l4(len)) {
        if (frag_split_and_encrypt_l4(pctx, pkt, len, fwd->pair.frame_size, &l1,
                                      f2, fwd->pair.frame_size, &l2) != 0)
            return -1;
    } else {
        int n = -1;
        if (cp->action == POLICY_ACTION_ENCRYPT_L2)
            n = crypto_layer2_encrypt(pctx, pkt, len);
        else if (cp->action == POLICY_ACTION_ENCRYPT_L3)
            n = crypto_layer3_encrypt(pctx, pkt, len);
        else if (cp->action == POLICY_ACTION_ENCRYPT_L4)
            n = crypto_layer4_encrypt(pctx, pkt, len);
        if (n < 0)
            return -1;
        job->len = (uint32_t)n;
        return 0;
    }

    if (dp_apply_wan_l2(pkt, l1, fwd->wans[wan_dp].dst_mac, fwd->wans[wan_dp].src_mac) != 0 ||
        dp_apply_wan_l2(f2, l2, fwd->wans[wan_dp].dst_mac, fwd->wans[wan_dp].src_mac) != 0)
        return -1;
    return push_split_to_wan(fwd, job, l1, f2, l2, wan_dp) == 0 ? 1 : -1;
}

void pipeline_egress(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok = dp_parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0;
    int li = job.local_idx < fwd->local_count ? (int)job.local_idx : 0;
    int profile_idx;
    const struct crypto_policy *cp;
    int wan_dp;
    int pi;
    struct packet_crypto_ctx *pctx;
    int enc;

    if (is_own_port_src(fwd, li, pkt, job.len)) {
        egr_drop_count(EGR_DROP_OWN_MAC);
        goto drop;
    }
    if (policy_resolve_egress(fwd->cfg, li, flow_ok, src_ip, dst_ip,
                              src_port, dst_port, proto, &profile_idx, &cp) != 0) {
        egr_drop_count(EGR_DROP_POLICY);
        goto drop;
    }

    wan_dp = br_wire_wan_dp_for_local(fwd, li);
    if (wan_dp < 0) {
        egr_drop_count(EGR_DROP_NO_WAN);
        goto drop;
    }

    if (cp->action == POLICY_ACTION_BYPASS) {
        if (!fwd_wan_has_tx_room(fwd, wan_dp)) {
            egr_drop_count(EGR_DROP_TX_ROOM);
            goto drop;
        }
        if (dp_apply_wan_l2(pkt, job.len, fwd->wans[wan_dp].dst_mac,
                            fwd->wans[wan_dp].src_mac) != 0) {
            egr_drop_count(EGR_DROP_L2);
            goto drop;
        }
        (void)push_to_wan(fwd, &job, wan_dp);
        return;
    }

    if (!fwd_wan_has_tx_room(fwd, wan_dp)) {
        egr_drop_count(EGR_DROP_TX_ROOM);
        goto drop;
    }
    if (dp_apply_wan_l2(pkt, job.len, fwd->wans[wan_dp].dst_mac, fwd->wans[wan_dp].src_mac) != 0) {
        egr_drop_count(EGR_DROP_L2);
        goto drop;
    }
    if (!fwd->cfg->crypto_enabled) {
        egr_drop_count(EGR_DROP_CRYPTO_OFF);
        goto drop;
    }

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi)) {
        egr_drop_count(EGR_DROP_CRYPTO_NOT_READY);
        goto drop;
    }
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx) {
        egr_drop_count(EGR_DROP_CRYPTO_NOT_READY);
        goto drop;
    }
    pctx->profile_id = fwd->cfg->profiles[profile_idx].id;
    pctx->policy_id = cp->id;
    crypto_apply_from_policy(cp);
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx);
    if (enc < 0) {
        egr_drop_count(EGR_DROP_ENCRYPT);
        goto drop;
    }
    if (enc > 0)
        return;
    (void)push_to_wan(fwd, &job, wan_dp);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}
