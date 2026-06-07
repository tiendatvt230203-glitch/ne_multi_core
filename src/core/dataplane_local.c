#include "../../inc/core/dataplane.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_crypto_runtime.h"

#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/core/fragment.h"
#include "../../inc/core/local_hwaddr.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>

static void wan_tx_fail(struct forwarder *fwd, int wan_dp, const struct ne_packet *job,
                        const char *reason)
{
    const char *ifn = (wan_dp >= 0 && wan_dp < fwd->wan_count)
                          ? fwd->wans[wan_dp].ifname
                          : "?";
    char dst[INET_ADDRSTRLEN] = "-";
    const uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t ip = dp_dest_ipv4((void *)pkt, job->len);

    if (ip)
        inet_ntop(AF_INET, &ip, dst, sizeof(dst));
    fprintf(stderr, "[WAN-TX] %s: %s len=%u dst=%s\n", ifn, reason, job->len, dst);
    fflush(stderr);
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

static int pick_profile_policy(struct forwarder *fwd, int local_idx, int flow_ok,
                               uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port, uint8_t proto,
                               int *profile_idx, const struct crypto_policy **cp)
{
    if (!fwd || !fwd->cfg || !profile_idx || !cp)
        return -1;

    const struct crypto_policy *best = NULL;
    int best_pi = -1, best_pri = 0x7fffffff, best_id = 0x7fffffff;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *p = &fwd->cfg->profiles[pi];
        int found = 0;
        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++)
            if (p->local_indices[i] == local_idx)
                found = 1;
        if (!found)
            continue;
        const struct crypto_policy *c = config_select_crypto_policy(
            fwd->cfg, pi,
            flow_ok ? src_ip : 0,
            flow_ok ? dst_ip : 0,
            flow_ok ? src_port : 0,
            flow_ok ? dst_port : 0,
            flow_ok ? proto : 0);
        if (!c)
            continue;
        if (!best || c->priority < best_pri || (c->priority == best_pri && c->id < best_id)) {
            best = c;
            best_pi = pi;
            best_pri = c->priority;
            best_id = c->id;
        }
    }
    if (!best)
        return -1;
    *profile_idx = best_pi;
    *cp = best;
    return 0;
}

static void learn_client_mac(struct forwarder *fwd, int li, uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = dp_src_ipv4(pkt, len);

    if (src_ip && len >= sizeof(struct ether_header))
        local_neigh_learn(li, src_ip, pkt + offsetof(struct ether_header, ether_shost));
}

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok = dp_parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0;
    int li = job.local_idx < fwd->local_count ? (int)job.local_idx : 0;
    learn_client_mac(fwd, li, pkt, job.len);
    int profile_idx;
    const struct crypto_policy *cp;
    int wan_dp;
    int pi;
    struct packet_crypto_ctx *pctx;
    int enc;

    if (pick_profile_policy(fwd, li, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0) {
        if (pkt && job.len >= 14) {
            uint16_t et = (uint16_t)(((uint16_t)pkt[12] << 8) | pkt[13]);
            fprintf(stderr,
                    "[WAN-TX] ?: no matching policy len=%u flow_ok=%d ethertype=0x%04x local=%d\n",
                    job.len, flow_ok, et, li);
        } else {
            wan_tx_fail(fwd, -1, &job, "no matching policy");
        }
        fflush(stderr);
        goto drop;
    }

    wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, src_ip, dst_ip,
                                    src_port, dst_port, proto, job.len);
    if (wan_dp < 0) {
        wan_tx_fail(fwd, -1, &job, "no WAN route");
        goto drop;
    }
    if (!fwd_wan_has_tx_room(fwd, wan_dp)) {
        struct ne_ring *q = &fwd->mid_to_wan[wan_dp];
        fprintf(stderr,
                "[WAN-TX] %s: mid queue full or cooldown depth=%u cap=%u cooldown=%u len=%u\n",
                fwd->wans[wan_dp].ifname, ne_ring_count(q), q->cap,
                fwd->wan_tx_cooldown[wan_dp], job.len);
        fflush(stderr);
        goto drop;
    }
    if (dp_apply_wan_l2(pkt, job.len, fwd->wans[wan_dp].dst_mac, fwd->wans[wan_dp].src_mac) != 0) {
        wan_tx_fail(fwd, wan_dp, &job, "L2 header write failed");
        goto drop;
    }

    if (cp->action == POLICY_ACTION_BYPASS) {
        if (push_to_wan(fwd, &job, wan_dp) != 0) {
            ne_stat_bump_lan_fwd_drop();
            wan_tx_fail(fwd, wan_dp, &job, "mid_to_wan push failed");
        }
        return;
    }
    if (!fwd->cfg->crypto_enabled) {
        wan_tx_fail(fwd, wan_dp, &job, "crypto disabled");
        goto drop;
    }

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi)) {
        wan_tx_fail(fwd, wan_dp, &job, "crypto policy not ready");
        goto drop;
    }
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx) {
        wan_tx_fail(fwd, wan_dp, &job, "no crypto context");
        goto drop;
    }
    pctx->profile_id = fwd->cfg->profiles[profile_idx].id;
    pctx->policy_id = cp->id;
    crypto_apply_from_policy(cp);
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx);
    if (enc < 0) {
        wan_tx_fail(fwd, wan_dp, &job, "encrypt failed");
        goto drop;
    }
    if (enc > 0)
        return;
    if (push_to_wan(fwd, &job, wan_dp) != 0) {
        ne_stat_bump_lan_fwd_drop();
        wan_tx_fail(fwd, wan_dp, &job, "mid_to_wan push failed");
    }
    return;

drop:
    ne_stat_bump_lan_fwd_drop();
    ne_frame_free(&fwd->pair, job.addr);
}
