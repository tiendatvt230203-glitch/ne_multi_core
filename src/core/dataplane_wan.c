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
#include "../../inc/core/interface.h"

#include <string.h>
#include <stdio.h>
#include <time.h>
#include <stdatomic.h>
#include <arpa/inet.h>

#define DBG_L2_LOG "/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-250a01.log"

static int dp_core_log_ok(_Atomic uint64_t *ctr)
{
    uint64_t n = atomic_fetch_add(ctr, 1);
    return n < 100 || (n & 0xFFu) == 0;
}

_Atomic uint64_t dp_wan_drop_affinity;
_Atomic uint64_t dp_wan_drop_decrypt;
_Atomic uint64_t dp_wan_drop_local;
_Atomic uint64_t dp_wan_drop_tx;
_Atomic uint64_t dp_lan_tx_room_retry_ok;

static void dp_wan_drop_log(const char *reason, _Atomic uint64_t *ctr, uint32_t len,
                            uint8_t wire_core, int worker)
{
    uint64_t n = atomic_fetch_add(ctr, 1) + 1;
    if (n <= 10 || (n & 0x3FFu) == 0)
        fprintf(stderr, "[DP-DROP-WAN] %s worker=%d wire_core=%u len=%u total=%lu\n",
                reason, worker, (unsigned)wire_core, len, (unsigned long)n);
}

// #region agent log
static void dbg_l2_core_log(const char *location, const char *message,
                            int worker, int wire_core, int ok, uint32_t len)
{
    FILE *f = fopen(DBG_L2_LOG, "a");
    if (!f)
        return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    long ms = (long)ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
    fprintf(f,
            "{\"sessionId\":\"250a01\",\"location\":\"%s\",\"message\":\"%s\","
            "\"data\":{\"worker\":%d,\"wire_core\":%d,\"ok\":%d,\"len\":%u},"
            "\"timestamp\":%ld,\"hypothesisId\":\"l2-aff\",\"runId\":\"l2-core\"}\n",
            location, message, worker, wire_core, ok, len, ms);
    fclose(f);
}
// #endregion

static int wan_pkt_is_l2(const uint8_t *pkt, uint32_t len, uint8_t *core_id_out)
{
    if (!core_id_out)
        return 0;
    return crypto_layer2_read_core_id(pkt, len, core_id_out) == 0;
}

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

static int lan_tx_room_wait(struct forwarder *fwd, int li, uint32_t need)
{
    int w = dp_crypto_current_worker_idx();

    if (ne_tx_has_room_local(&fwd->pair, w, li, need))
        return 1;
    for (int i = 0; i < 64; i++) {
        ne_drain_cq_worker(&fwd->pair, w);
        if (ne_tx_has_room_local(&fwd->pair, w, li, need)) {
            atomic_fetch_add(&dp_lan_tx_room_retry_ok, 1);
            return 1;
        }
    }
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
    uint8_t wire_core = 0;
    uint8_t wire_tag = 0;
    int worker = dp_crypto_current_worker_idx();

    if (wan_pkt_is_l2(pkt, job.len, &wire_core)) {
        wire_tag = pkt[CRYPTO_L2_POLICY_OFF];
        const char *wan_if = (job.wan_idx < fwd->wan_count)
                             ? fwd->wans[job.wan_idx].ifname : "?";
        int bpf_ok = ((int)wire_core == worker);
        // #region agent log
        {
            static _Atomic uint64_t wan_l2_in;
            uint64_t n = atomic_fetch_add(&wan_l2_in, 1);
            if (n < 200 || (n & 0xFFu) == 0)
                fprintf(stderr, "[DP-WAN-IN] worker=%d wan=%s wire_tag=%u core=%u len=%u\n",
                        worker, wan_if, (unsigned)wire_tag, (unsigned)wire_core, job.len);
            static _Atomic uint64_t core_wan_in;
            if (dp_core_log_ok(&core_wan_in)) {
                fprintf(stderr,
                        "[DP-CORE] WAN-IN worker=%d wire_core=%u bpf_ok=%d "
                        "wan=%s tag=%u len=%u\n",
                        worker, (unsigned)wire_core, bpf_ok, wan_if,
                        (unsigned)wire_tag, job.len);
                fprintf(stderr,
                        "[DP-FLOW] NE2 tag=%u step=5-WAN-IN worker=%d wire_core=%u "
                        "bpf_ok=%d wan=%s len=%u\n",
                        (unsigned)wire_tag, worker, (unsigned)wire_core,
                        bpf_ok, wan_if, job.len);
            }
        }
        // #endregion
        int ok = dp_crypto_l2_affinity_ok(pkt, job.len);
        dbg_l2_core_log("dataplane_wan.c:process_wan", "l2 wan affinity", worker,
                        (int)wire_core, ok, job.len);
        if (!ok) {
            // #region agent log
            fprintf(stderr,
                    "[DP-CORE] WAN-IN DROP affinity worker=%d wire_core=%u wan=%s tag=%u\n",
                    worker, (unsigned)wire_core, wan_if, (unsigned)wire_tag);
            fprintf(stderr,
                    "[DP-FLOW] NE2 tag=%u step=5-WAN-IN-DROP worker=%d wire_core=%u "
                    "reason=affinity wan=%s\n",
                    (unsigned)wire_tag, worker, (unsigned)wire_core, wan_if);
            // #endregion
            dp_wan_drop_log("l2_affinity", &dp_wan_drop_affinity, job.len, wire_core, worker);
            goto drop;
        }
    } else if (wan_l2_plain_ipv4(pkt, job.len)) {
        // #region agent log
        {
            static _Atomic uint64_t wan_bypass_in;
            uint64_t n = atomic_fetch_add(&wan_bypass_in, 1);
            if (n < 200 || (n & 0x3Fu) == 0) {
                uint32_t sip = 0, dip = 0;
                uint16_t sp = 0, dp = 0;
                uint8_t proto = 0;
                if (dp_parse_flow(pkt, job.len, &sip, &dip, &sp, &dp, &proto) == 0)
                    fprintf(stderr,
                            "[DP-WAN-IN] worker=%d wan=%s bypass proto=%u "
                            "src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u len=%u\n",
                            worker,
                            (job.wan_idx < fwd->wan_count) ? fwd->wans[job.wan_idx].ifname : "?",
                            (unsigned)proto,
                            (ntohl(sip) >> 24) & 0xff, (ntohl(sip) >> 16) & 0xff,
                            (ntohl(sip) >> 8) & 0xff, ntohl(sip) & 0xff, (unsigned)sp,
                            (ntohl(dip) >> 24) & 0xff, (ntohl(dip) >> 16) & 0xff,
                            (ntohl(dip) >> 8) & 0xff, ntohl(dip) & 0xff, (unsigned)dp,
                            job.len);
                else
                    fprintf(stderr,
                            "[DP-WAN-IN] worker=%d wan=%s bypass len=%u\n",
                            worker,
                            (job.wan_idx < fwd->wan_count) ? fwd->wans[job.wan_idx].ifname : "?",
                            job.len);
                if (dp_parse_flow(pkt, job.len, &sip, &dip, &sp, &dp, &proto) == 0) {
                    static _Atomic uint64_t core_bypass_in;
                    uint8_t flow_core = dp_crypto_flow_core_id(sip, dip, sp, dp, proto);
                    if (dp_core_log_ok(&core_bypass_in))
                        fprintf(stderr,
                                "[DP-CORE] WAN-IN bypass worker=%d flow_core=%u bpf_ok=%d "
                                "proto=%u sport=%u dport=%u len=%u\n",
                                worker, (unsigned)flow_core,
                                (int)flow_core == worker, (unsigned)proto,
                                (unsigned)sp, (unsigned)dp, job.len);
                }
                fflush(stderr);
            }
        }
        // #endregion
    } else {
        // #region agent log
        {
            static _Atomic uint64_t wan_unknown;
            if (dp_core_log_ok(&wan_unknown)) {
                uint16_t eth = (uint16_t)((pkt[12] << 8) | pkt[13]);
                fprintf(stderr,
                        "[DP-CORE] WAN-IN unknown worker=%d eth=0x%04x len=%u wan=%s\n",
                        worker, (unsigned)eth, job.len,
                        (job.wan_idx < fwd->wan_count) ? fwd->wans[job.wan_idx].ifname : "?");
            }
        }
        // #endregion
    }

    if (wan_has_crypto(fwd, pkt, job.len)) {
        dec = decrypt_wan(fwd, &job);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec != 0) {
            // #region agent log
            if (wire_tag) {
                fprintf(stderr, "[DP-DROP-WAN] decrypt worker=%d wire_tag=%u len=%u\n",
                        worker, (unsigned)wire_tag, job.len);
                fprintf(stderr,
                        "[DP-FLOW] NE2 tag=%u step=6-WAN-DEC-DROP worker=%d reason=decrypt\n",
                        (unsigned)wire_tag, worker);
            }
            // #endregion
            dp_wan_drop_log("decrypt", &dp_wan_drop_decrypt, job.len, wire_core, worker);
            goto drop;
        }
        pkt = ne_packet_data(&fwd->pair, job.addr);
        // #region agent log
        {
            uint32_t sip = 0, dip = 0;
            uint16_t sp = 0, dp = 0;
            uint8_t proto = 0;
            if (dp_parse_flow(pkt, job.len, &sip, &dip, &sp, &dp, &proto) == 0) {
                static _Atomic uint64_t wan_dec_flow;
                uint64_t fn = atomic_fetch_add(&wan_dec_flow, 1);
                if (fn < 40 || (proto == 6 && fn < 80))
                    fprintf(stderr,
                            "[DP-WAN-DEC] worker=%d wire_tag=%u proto=%u "
                            "src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u len=%u\n",
                            worker, (unsigned)wire_tag, (unsigned)proto,
                            (ntohl(sip) >> 24) & 0xff, (ntohl(sip) >> 16) & 0xff,
                            (ntohl(sip) >> 8) & 0xff, ntohl(sip) & 0xff, (unsigned)sp,
                            (ntohl(dip) >> 24) & 0xff, (ntohl(dip) >> 16) & 0xff,
                            (ntohl(dip) >> 8) & 0xff, ntohl(dip) & 0xff, (unsigned)dp,
                            job.len);
                static _Atomic uint64_t flow_dec;
                if (dp_core_log_ok(&flow_dec))
                    fprintf(stderr,
                            "[DP-FLOW] NE2 dport=%u step=6-WAN-DEC worker=%d tag=%u "
                            "sport=%u proto=%u len=%u\n",
                            (unsigned)dp, worker, (unsigned)wire_tag,
                            (unsigned)sp, (unsigned)proto, job.len);
            }
        }
        // #endregion
    }

    li = pick_local(fwd, pkt, job.len);
    if (li < 0 || li >= fwd->local_count) {
        uint32_t dip = ntohl(dp_dest_ipv4(pkt, job.len));
        static _Atomic uint64_t pick_local_fail;
        uint64_t pf = atomic_fetch_add(&pick_local_fail, 1);
        if (pf < 10)
            fprintf(stderr, "[DP-DROP-WAN] pick_local worker=%d dest_ip=%u.%u.%u.%u\n",
                    worker, (dip >> 24) & 0xff, (dip >> 16) & 0xff,
                    (dip >> 8) & 0xff, dip & 0xff);
        dp_wan_drop_log("pick_local", &dp_wan_drop_local, job.len, wire_core, worker);
        goto drop;
    }
    job.dir = NE_DIR_LOCAL;
    job.local_idx = (uint8_t)li;
    if (!lan_tx_room_wait(fwd, li, 1) ||
        ne_tx_send_local(&fwd->pair, dp_crypto_current_worker_idx(), li, &job) != 0) {
        dp_wan_drop_log("lan_tx_fail", &dp_wan_drop_tx, job.len, wire_core, worker);
        goto drop;
    }
    // #region agent log
    {
        static _Atomic uint64_t wan_lan_ok;
        uint64_t wo = atomic_fetch_add(&wan_lan_ok, 1);
        if (wo < 200 || (wo & 0xFFu) == 0) {
            uint32_t sip = 0, dip = 0;
            uint16_t sp = 0, dport = 0;
            uint8_t proto = 0;
            (void)dp_parse_flow(pkt, job.len, &sip, &dip, &sp, &dport, &proto);
            dip = ntohl(dip);
            sip = ntohl(sip);
            fprintf(stderr,
                    "[DP-WAN] worker=%d -> LAN li=%d proto=%u "
                    "src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u len=%u\n",
                    worker, li, (unsigned)proto,
                    (sip >> 24) & 0xff, (sip >> 16) & 0xff,
                    (sip >> 8) & 0xff, sip & 0xff, (unsigned)sp,
                    (dip >> 24) & 0xff, (dip >> 16) & 0xff,
                    (dip >> 8) & 0xff, dip & 0xff, (unsigned)dport, job.len);
        }
        static _Atomic uint64_t core_lan_tx;
        if (dp_core_log_ok(&core_lan_tx)) {
            uint16_t dport = 0;
            uint16_t sport = 0;
            uint8_t proto = 0;
            (void)dp_parse_flow(pkt, job.len, NULL, NULL, &sport, &dport, &proto);
            fprintf(stderr,
                    "[DP-CORE] LAN-TX worker=%d local=%s li=%d wire_tag=%u len=%u\n",
                    worker,
                    (li >= 0 && li < fwd->local_count) ? fwd->locals[li].ifname : "?",
                    li, (unsigned)wire_tag, job.len);
            fprintf(stderr,
                    "[DP-FLOW] NE2 dport=%u step=7-LAN-TX worker=%d local=%s "
                    "tag=%u sport=%u len=%u\n",
                    (unsigned)dport, worker,
                    (li >= 0 && li < fwd->local_count) ? fwd->locals[li].ifname : "?",
                    (unsigned)wire_tag, (unsigned)sport, job.len);
        }
    }
    // #endregion
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}
