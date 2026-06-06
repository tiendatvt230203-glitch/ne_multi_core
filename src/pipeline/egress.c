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

#include <arpa/inet.h>
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
    EGR_DROP_PUSH_FAIL,
    EGR_DROP_N
};

static uint64_t g_egr_drop[EGR_DROP_N];
static uint8_t g_egr_drop_logged[EGR_DROP_N];
static uint8_t g_egr_ok_logged;
static uint8_t g_egr_enter_logged;

static const char *egr_action_str(int action)
{
    switch (action) {
    case POLICY_ACTION_BYPASS:      return "bypass";
    case POLICY_ACTION_ENCRYPT_L2:  return "L2";
    case POLICY_ACTION_ENCRYPT_L3:  return "L3";
    case POLICY_ACTION_ENCRYPT_L4:  return "L4";
    default:                        return "?";
    }
}

static void egr_fmt_mac(const uint8_t mac[MAC_LEN], char *out, size_t outsz)
{
    snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void egr_bump_drop(int reason)
{
    if (reason >= 0 && reason < EGR_DROP_N)
        (void)__sync_add_and_fetch(&g_egr_drop[reason], 1);
}

static void egr_log_ok(struct forwarder *fwd, int li, int wan_dp,
                       const struct crypto_policy *cp, int flow_ok,
                       uint16_t dst_port)
{
    if (g_egr_ok_logged || !fwd || !cp)
        return;
    g_egr_ok_logged = 1;
    fprintf(stderr,
            "[EGR-WAN] OK li=%d lan=%s -> wan_dp=%d wan=%s "
            "policy_id=%d action=%s prio=%d flow_ok=%d dst_port=%u\n",
            li,
            (li >= 0 && li < fwd->local_count) ? fwd->locals[li].ifname : "?",
            wan_dp,
            (wan_dp >= 0 && wan_dp < fwd->wan_count) ? fwd->wans[wan_dp].ifname : "?",
            cp->id, egr_action_str(cp->action), cp->priority,
            flow_ok, (unsigned)dst_port);
    fflush(stderr);
}

static void egr_log_own_mac(struct forwarder *fwd, int li, const uint8_t *pkt)
{
    char pkt_mac[24], loc_mac[24];

    if (g_egr_drop_logged[EGR_DROP_OWN_MAC])
        return;
    g_egr_drop_logged[EGR_DROP_OWN_MAC] = 1;
    egr_fmt_mac(pkt + MAC_LEN, pkt_mac, sizeof(pkt_mac));
    egr_fmt_mac(fwd->locals[li].src_mac, loc_mac, sizeof(loc_mac));
    fprintf(stderr,
            "[EGR-WAN] DROP own_port_src: li=%d if=%s "
            "pkt_src_mac=%s == local_src_mac=%s (packet originated on NE port)\n",
            li, fwd->locals[li].ifname, pkt_mac, loc_mac);
    fflush(stderr);
}

static void egr_log_no_wan(struct forwarder *fwd, int li)
{
    if (g_egr_drop_logged[EGR_DROP_NO_WAN])
        return;
    g_egr_drop_logged[EGR_DROP_NO_WAN] = 1;
    fprintf(stderr,
            "[EGR-WAN] DROP br_wire_no_wan: li=%d if=%s br_id=%d "
            "local_to_wan_dp=%d (check ne_lan/ne_wan br_id in DB)\n",
            li, fwd->locals[li].ifname,
            (li >= 0 && li < fwd->cfg->local_count) ? fwd->cfg->locals[li].br_id : -1,
            (li >= 0 && li < MAX_INTERFACES) ? fwd->local_to_wan_dp[li] : -1);
    fflush(stderr);
}

static void egr_log_tx_room(struct forwarder *fwd, int wan_dp)
{
    if (g_egr_drop_logged[EGR_DROP_TX_ROOM])
        return;
    g_egr_drop_logged[EGR_DROP_TX_ROOM] = 1;
    fprintf(stderr,
            "[EGR-WAN] DROP wan_tx_blocked: wan_dp=%d if=%s "
            "mid_to_wan=%u stopped=%d cooldown=%u\n",
            wan_dp,
            (wan_dp >= 0 && wan_dp < fwd->wan_count) ? fwd->wans[wan_dp].ifname : "?",
            (wan_dp >= 0 && wan_dp < fwd->wan_count)
                ? ne_ring_count(&fwd->mid_to_wan[wan_dp]) : 0u,
            fwd_wan_is_stopped(wan_dp),
            (wan_dp >= 0 && wan_dp < MAX_INTERFACES) ? fwd->wan_tx_cooldown[wan_dp] : 0u);
    fflush(stderr);
}

static void egr_log_l2(struct forwarder *fwd, int wan_dp)
{
    char dst_mac[24], src_mac[24];
    static const uint8_t zero[MAC_LEN];

    if (g_egr_drop_logged[EGR_DROP_L2])
        return;
    g_egr_drop_logged[EGR_DROP_L2] = 1;
    if (wan_dp < 0 || wan_dp >= fwd->wan_count) {
        fprintf(stderr, "[EGR-WAN] DROP l2_rewrite_fail: invalid wan_dp=%d\n", wan_dp);
        fflush(stderr);
        return;
    }
    egr_fmt_mac(fwd->wans[wan_dp].dst_mac, dst_mac, sizeof(dst_mac));
    egr_fmt_mac(fwd->wans[wan_dp].src_mac, src_mac, sizeof(src_mac));
    fprintf(stderr,
            "[EGR-WAN] DROP l2_rewrite_fail: wan=%s dst_mac=%s%s src_mac=%s%s\n",
            fwd->wans[wan_dp].ifname, dst_mac,
            memcmp(fwd->wans[wan_dp].dst_mac, zero, MAC_LEN) == 0 ? " (empty)" : "",
            src_mac,
            memcmp(fwd->wans[wan_dp].src_mac, zero, MAC_LEN) == 0 ? " (empty)" : "");
    fflush(stderr);
}

static void egr_log_push_fail(struct forwarder *fwd, int wan_dp)
{
    if (g_egr_drop_logged[EGR_DROP_PUSH_FAIL])
        return;
    g_egr_drop_logged[EGR_DROP_PUSH_FAIL] = 1;
    fprintf(stderr,
            "[EGR-WAN] DROP mid_to_wan_ring_full: wan_dp=%d if=%s "
            "queue=%u/%u (policy matched but packet never queued for WAN TX)\n",
            wan_dp,
            (wan_dp >= 0 && wan_dp < fwd->wan_count) ? fwd->wans[wan_dp].ifname : "?",
            (wan_dp >= 0 && wan_dp < fwd->wan_count)
                ? ne_ring_count(&fwd->mid_to_wan[wan_dp]) : 0u,
            (wan_dp >= 0 && wan_dp < fwd->wan_count)
                ? fwd->mid_to_wan[wan_dp].cap : 0u);
    fflush(stderr);
}

static void egr_log_simple_drop(int reason, const char *detail)
{
    if (reason < 0 || reason >= EGR_DROP_N || g_egr_drop_logged[reason])
        return;
    g_egr_drop_logged[reason] = 1;
    fprintf(stderr, "[EGR-WAN] DROP %s\n", detail);
    fflush(stderr);
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

    if (!g_egr_enter_logged) {
        g_egr_enter_logged = 1;
        fprintf(stderr,
                "[TRACE] pipeline_egress entered: li=%d if=%s len=%u flow_ok=%d\n",
                li,
                (li >= 0 && li < fwd->local_count) ? fwd->locals[li].ifname : "?",
                (unsigned)job.len, flow_ok);
        fflush(stderr);
    }

    if (is_own_port_src(fwd, li, pkt, job.len)) {
        egr_bump_drop(EGR_DROP_OWN_MAC);
        egr_log_own_mac(fwd, li, pkt);
        goto drop;
    }
    if (policy_resolve_egress(fwd->cfg, li, flow_ok, src_ip, dst_ip,
                              src_port, dst_port, proto, &profile_idx, &cp) != 0) {
        egr_bump_drop(EGR_DROP_POLICY);
        policy_log_egress_miss(fwd->cfg, li, flow_ok, src_ip, dst_ip,
                               src_port, dst_port, proto);
        goto drop;
    }

    wan_dp = br_wire_wan_dp_for_local(fwd, li);
    if (wan_dp < 0) {
        egr_bump_drop(EGR_DROP_NO_WAN);
        egr_log_no_wan(fwd, li);
        goto drop;
    }

    if (cp->action == POLICY_ACTION_BYPASS) {
        if (!fwd_wan_has_tx_room(fwd, wan_dp)) {
            egr_bump_drop(EGR_DROP_TX_ROOM);
            egr_log_tx_room(fwd, wan_dp);
            goto drop;
        }
        if (dp_apply_wan_l2(pkt, job.len, fwd->wans[wan_dp].dst_mac,
                            fwd->wans[wan_dp].src_mac) != 0) {
            egr_bump_drop(EGR_DROP_L2);
            egr_log_l2(fwd, wan_dp);
            goto drop;
        }
        egr_log_ok(fwd, li, wan_dp, cp, flow_ok, dst_port);
        if (push_to_wan(fwd, &job, wan_dp) != 0) {
            egr_bump_drop(EGR_DROP_PUSH_FAIL);
            egr_log_push_fail(fwd, wan_dp);
        }
        return;
    }

    if (!fwd_wan_has_tx_room(fwd, wan_dp)) {
        egr_bump_drop(EGR_DROP_TX_ROOM);
        egr_log_tx_room(fwd, wan_dp);
        goto drop;
    }
    if (dp_apply_wan_l2(pkt, job.len, fwd->wans[wan_dp].dst_mac, fwd->wans[wan_dp].src_mac) != 0) {
        egr_bump_drop(EGR_DROP_L2);
        egr_log_l2(fwd, wan_dp);
        goto drop;
    }
    if (!fwd->cfg->crypto_enabled) {
        egr_bump_drop(EGR_DROP_CRYPTO_OFF);
        egr_log_simple_drop(EGR_DROP_CRYPTO_OFF,
                            "crypto_disabled: policy requires encrypt but crypto_enabled=0");
        goto drop;
    }

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi)) {
        egr_bump_drop(EGR_DROP_CRYPTO_NOT_READY);
        egr_log_simple_drop(EGR_DROP_CRYPTO_NOT_READY,
                            "crypto_not_ready: policy slot not initialized (keys/handshake?)");
        goto drop;
    }
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx) {
        egr_bump_drop(EGR_DROP_CRYPTO_NOT_READY);
        egr_log_simple_drop(EGR_DROP_CRYPTO_NOT_READY, "crypto_not_ready: null policy ctx");
        goto drop;
    }
    pctx->profile_id = fwd->cfg->profiles[profile_idx].id;
    pctx->policy_id = cp->id;
    crypto_apply_from_policy(cp);
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx);
    if (enc < 0) {
        egr_bump_drop(EGR_DROP_ENCRYPT);
        egr_log_simple_drop(EGR_DROP_ENCRYPT,
                            "encrypt_fail: crypto_layer encrypt returned error");
        goto drop;
    }
    if (enc > 0)
        return;
    egr_log_ok(fwd, li, wan_dp, cp, flow_ok, dst_port);
    if (push_to_wan(fwd, &job, wan_dp) != 0) {
        egr_bump_drop(EGR_DROP_PUSH_FAIL);
        egr_log_push_fail(fwd, wan_dp);
    }
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}
