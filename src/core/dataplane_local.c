#include "../../inc/core/dataplane.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_crypto_runtime.h"

#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/core/fragment.h"
#include "../../inc/core/crypto_route.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdatomic.h>

#define DBG_L2_LOG "/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-250a01.log"

static _Atomic uint64_t dp_drop_policy;
static _Atomic uint64_t dp_drop_wan;
static _Atomic uint64_t dp_drop_crypto;
static _Atomic uint64_t dp_drop_tx;

static void dp_drop_log(const char *reason, _Atomic uint64_t *ctr)
{
    uint64_t n = atomic_fetch_add(ctr, 1) + 1;
    if (n <= 10 || (n & 0x3FFu) == 0)
        fprintf(stderr, "[DP-DROP] %s worker=%d total=%lu\n",
                reason, dp_crypto_current_worker_idx(), (unsigned long)n);
}

// #region agent log
static void dp_dbg_ndjson(const char *location, const char *message, const char *hypothesis_id,
                          int worker, const char *extra_json)
{
    FILE *f = fopen(DBG_L2_LOG, "a");
    if (f) {
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        long ms = (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
        fprintf(f,
                "{\"sessionId\":\"250a01\",\"location\":\"%s\",\"message\":\"%s\","
                "\"data\":{\"worker\":%d%s%s},\"timestamp\":%ld,"
                "\"hypothesisId\":\"%s\",\"runId\":\"tcp-handshake\"}\n",
                location, message, worker,
                extra_json ? "," : "", extra_json ? extra_json : "", ms, hypothesis_id);
        fclose(f);
    }
}

static void dp_lan_tcp_log(struct forwarder *fwd, uint8_t proto,
                           uint16_t dst_port, uint16_t src_port,
                           const struct crypto_policy *cp, int wan_dp,
                           int enc_rc, int flow_ok)
{
    static _Atomic uint64_t lan_tcp_log_count;
    uint64_t n = atomic_fetch_add(&lan_tcp_log_count, 1);
    if (n >= 200 && (n & 0xFFu) != 0)
        return;
    int w = dp_crypto_current_worker_idx();
    const char *mode = (cp->crypto_mode == CRYPTO_MODE_PQC) ? "pqc"
                     : (cp->action == POLICY_ACTION_BYPASS) ? "bypass"
                     : "gcm/ctr";
    const char *wan_if = (fwd && wan_dp >= 0 && wan_dp < fwd->wan_count)
                         ? fwd->wans[wan_dp].ifname : "?";
    fprintf(stderr,
            "[DP-LAN] worker=%d proto=%u sport=%u dport=%u pkt_tag=%d db_id=%d "
            "crypto=%s wan=%s enc=%d\n",
            w, (unsigned)proto, (unsigned)src_port, (unsigned)dst_port,
            cp ? (int)cp->id : -1, cp ? cp->db_id : -1, mode, wan_if, enc_rc);
    char extra[192];
    snprintf(extra, sizeof(extra),
             "\"flow_ok\":%d,\"proto\":%u,\"sport\":%u,\"dport\":%u,"
             "\"pkt_tag\":%d,\"db_id\":%d,\"wan_dp\":%d,\"enc\":%d",
             flow_ok, (unsigned)proto, (unsigned)src_port, (unsigned)dst_port,
             cp ? (int)cp->id : -1, cp ? cp->db_id : -1, wan_dp, enc_rc);
    dp_dbg_ndjson("dataplane_local.c:process_local", "lan tcp path", "A-port-policy",
                  w, extra);
    fflush(stderr);
}
// #endregion

// #region agent log
static void dbg_l2_core_log(const char *location, const char *message,
                            int worker, int wire_core, uint32_t len)
{
    FILE *f = fopen(DBG_L2_LOG, "a");
    if (!f)
        return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms = (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
    fprintf(f,
            "{\"sessionId\":\"250a01\",\"location\":\"%s\",\"message\":\"%s\","
            "\"data\":{\"worker\":%d,\"wire_core\":%d,\"len\":%u},"
            "\"timestamp\":%ld,\"hypothesisId\":\"l2-aff\",\"runId\":\"l2-core\"}\n",
            location, message, worker, wire_core, len, ms);
    fclose(f);
}
// #endregion

static void dp_wan_tx_log(struct forwarder *fwd, int worker, int wan_dp,
                          const struct ne_packet *job, int bypass)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint8_t wire_core = 0;
    const char *wan_if = (fwd && wan_dp >= 0 && wan_dp < fwd->wan_count)
                         ? fwd->wans[wan_dp].ifname : "?";

    if (!pkt)
        return;

    if (bypass) {
        static _Atomic uint64_t wan_tx_bypass;
        uint64_t n = atomic_fetch_add(&wan_tx_bypass, 1);
        if (n >= 200 && (n & 0x3Fu) != 0)
            return;
        uint32_t sip = 0, dip = 0;
        uint16_t sp = 0, dp = 0;
        uint8_t proto = 0;
        if (dp_parse_flow(pkt, job->len, &sip, &dip, &sp, &dp, &proto) == 0)
            fprintf(stderr,
                    "[DP-WAN-TX] worker=%d wan=%s bypass proto=%u "
                    "src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u len=%u\n",
                    worker, wan_if, (unsigned)proto,
                    (ntohl(sip) >> 24) & 0xff, (ntohl(sip) >> 16) & 0xff,
                    (ntohl(sip) >> 8) & 0xff, ntohl(sip) & 0xff, (unsigned)sp,
                    (ntohl(dip) >> 24) & 0xff, (ntohl(dip) >> 16) & 0xff,
                    (ntohl(dip) >> 8) & 0xff, ntohl(dip) & 0xff, (unsigned)dp,
                    job->len);
        else
            fprintf(stderr,
                    "[DP-WAN-TX] worker=%d wan=%s bypass len=%u\n",
                    worker, wan_if, job->len);
        fflush(stderr);
        return;
    }

    if (crypto_layer2_read_core_id(pkt, job->len, &wire_core) == 0) {
        static _Atomic uint64_t wan_tx_l2;
        uint64_t n = atomic_fetch_add(&wan_tx_l2, 1);
        if (n >= 200 && (n & 0xFFu) != 0)
            return;
        fprintf(stderr,
                "[DP-WAN-TX] worker=%d wan=%s wire_core=%u len=%u\n",
                worker, wan_if, (unsigned)wire_core, job->len);
        fflush(stderr);
    }
}

static int send_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_dp, int bypass)
{
    int w = dp_crypto_current_worker_idx();

    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_dp;
    // #region agent log
    dp_wan_tx_log(fwd, w, wan_dp, job, bypass);
    // #endregion
    if (ne_tx_send_wan(&fwd->pair, w, wan_dp, job) != 0) {
        dp_drop_log("wan_tx_fail", &dp_drop_tx);
        ne_frame_free(&fwd->pair, job->addr);
        return -1;
    }
    return 0;
}

static void dp_patch_l2_flow_core(uint8_t *pkt, uint32_t len,
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint8_t proto)
{
    uint8_t ignore;

    if (!pkt || crypto_layer2_read_core_id(pkt, len, &ignore) != 0)
        return;
    pkt[CRYPTO_L2_CORE_ID_OFF] = dp_crypto_flow_core_id(src_ip, dst_ip,
                                                        src_port, dst_port, proto);
}

static void dp_finish_wan_l2_packet(struct forwarder *fwd, uint8_t *pkt, uint32_t len,
                                    int wan_dp,
                                    uint32_t src_ip, uint32_t dst_ip,
                                    uint16_t src_port, uint16_t dst_port,
                                    uint8_t proto)
{
    (void)fwd;
    (void)wan_dp;
    /* Bridge: preserve end-host MAC/IP (transparent L2). Only patch wire core_id. */
    dp_patch_l2_flow_core(pkt, len, src_ip, dst_ip, src_port, dst_port, proto);
}

static int send_split_to_wan(struct forwarder *fwd, struct ne_packet *job,
                             uint32_t l1, const uint8_t *f2, uint32_t l2, int wan_dp)
{
    int w = dp_crypto_current_worker_idx();

    if (wan_dp < 0 || wan_dp >= fwd->wan_count ||
        !ne_tx_has_room_wan(&fwd->pair, w, wan_dp, 2))
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
    if (ne_tx_send_wan(&fwd->pair, w, wan_dp, job) != 0) {
        ne_frame_free(&fwd->pair, tail.addr);
        return -1;
    }
    if (ne_tx_send_wan(&fwd->pair, w, wan_dp, &tail) != 0)
        ne_frame_free(&fwd->pair, tail.addr);
    return 0;
}

static int encrypt_to_wan(struct forwarder *fwd, struct ne_packet *job,
                          const struct crypto_policy *cp, int wan_dp,
                          struct packet_crypto_ctx *pctx,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port, uint8_t proto,
                          int flow_ok)
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

    if (cp->action == POLICY_ACTION_ENCRYPT_L2) {
        dp_finish_wan_l2_packet(fwd, pkt, l1, wan_dp,
                                src_ip, dst_ip, src_port, dst_port, proto);
        dp_finish_wan_l2_packet(fwd, f2, l2, wan_dp,
                                src_ip, dst_ip, src_port, dst_port, proto);
    }
    if (send_split_to_wan(fwd, job, l1, f2, l2, wan_dp) != 0)
        return -1;
    return 1;
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
        const struct crypto_policy *c = flow_ok
            ? config_select_crypto_policy(fwd->cfg, pi, src_ip, dst_ip, src_port, dst_port, proto)
            : NULL;
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

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
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

    if (pick_profile_policy(fwd, li, flow_ok, src_ip, dst_ip, src_port, dst_port, proto,
                            &profile_idx, &cp) != 0) {
        // #region agent log
        if (proto == 6 || proto == 17) {
            static _Atomic uint64_t no_policy_tcp;
            uint64_t np = atomic_fetch_add(&no_policy_tcp, 1);
            if (np < 15)
                fprintf(stderr,
                        "[DP-DROP] no_policy worker=%d proto=%u dport=%u sport=%u flow_ok=%d\n",
                        dp_crypto_current_worker_idx(), (unsigned)proto,
                        (unsigned)dst_port, (unsigned)src_port, flow_ok);
        }
        // #endregion
        goto drop_policy;
    }

    wan_dp = fwd_wan_pick_for_local(fwd, profile_idx, flow_ok, src_ip, dst_ip,
                                    src_port, dst_port, proto, job.len);
    if (wan_dp < 0 || !fwd_wan_has_tx_room(fwd, wan_dp))
        goto drop_wan;

    if (cp->action == POLICY_ACTION_BYPASS) {
        if (proto == 6 || proto == 17)
            dp_lan_tcp_log(fwd, proto, dst_port, src_port, cp, wan_dp, 0, flow_ok);
        (void)send_to_wan(fwd, &job, wan_dp, 1);
        return;
    }
    if (!fwd->cfg->crypto_enabled)
        goto drop_crypto;

    pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !fwd_crypto_policy_ready(pi))
        goto drop_crypto;
    pctx = fwd_crypto_policy_ctx(pi);
    if (!pctx)
        goto drop_crypto;
    pctx->profile_id = fwd->cfg->profiles[profile_idx].id;
    pctx->policy_id = (cp->crypto_mode == CRYPTO_MODE_PQC) ? cp->db_id : cp->id;
    crypto_apply_from_policy(cp);
    enc = encrypt_to_wan(fwd, &job, cp, wan_dp, pctx,
                         src_ip, dst_ip, src_port, dst_port, proto, flow_ok);
    if (enc < 0)
        goto drop_crypto;
    // #region agent log
    if (proto == 6 || proto == 17)
        dp_lan_tcp_log(fwd, proto, dst_port, src_port, cp, wan_dp, enc, flow_ok);
    // #endregion
    if (cp->action == POLICY_ACTION_ENCRYPT_L2) {
        uint8_t wc = 0;
        pkt = ne_packet_data(&fwd->pair, job.addr);
        if (crypto_layer2_read_core_id(pkt, job.len, &wc) == 0)
            dbg_l2_core_log("dataplane_local.c:process_local", "l2 lan encrypt",
                            dp_crypto_current_worker_idx(), (int)wc, job.len);
    }
    if (enc > 0)
        return;
    pkt = ne_packet_data(&fwd->pair, job.addr);
    if (cp->action == POLICY_ACTION_ENCRYPT_L2)
        dp_finish_wan_l2_packet(fwd, pkt, job.len, wan_dp,
                                src_ip, dst_ip, src_port, dst_port, proto);
    (void)send_to_wan(fwd, &job, wan_dp, 0);
    return;

drop_policy:
    dp_drop_log("no_policy", &dp_drop_policy);
    goto drop;
drop_wan:
    dp_drop_log("no_wan_or_tx_room", &dp_drop_wan);
    goto drop;
drop_crypto:
    dp_drop_log("crypto", &dp_drop_crypto);
drop:
    ne_frame_free(&fwd->pair, job.addr);
}
