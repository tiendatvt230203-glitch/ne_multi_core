#include "../../inc/core/dataplane_util.h"

#include "../../inc/core/config.h"
#include "../../inc/crypto/eth_parse.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdatomic.h>

/* #region agent log */
#define NE_AGENT_DEBUG_MAX      500
#define NE_AGENT_DROP_LOG_MAX   10000
#define NE_AGENT_DEBUG_RUN_ID   "stderr-v1"

static atomic_uint_fast64_t g_agent_stats[NE_STAT_COUNT];

static const char *agent_policy_action(int action)
{
    switch (action) {
    case POLICY_ACTION_BYPASS: return "BYPASS";
    case POLICY_ACTION_ENCRYPT_L2: return "ENCRYPT_L2";
    case POLICY_ACTION_ENCRYPT_L3: return "ENCRYPT_L3";
    case POLICY_ACTION_ENCRYPT_L4: return "ENCRYPT_L4";
    default: return "UNKNOWN";
    }
}

static const char *agent_crypto_mode(int mode)
{
    switch (mode) {
    case CRYPTO_MODE_CTR: return "CTR";
    case CRYPTO_MODE_GCM: return "GCM";
    case CRYPTO_MODE_PQC: return "PQC";
    default: return "?";
    }
}

static void agent_fmt_ip4(char *buf, size_t bufsz, uint32_t ip_be)
{
    struct in_addr a = { .s_addr = ip_be };
    if (!inet_ntop(AF_INET, &a, buf, (socklen_t)bufsz))
        snprintf(buf, bufsz, "?");
}

void ne_agent_policy_trace(const char *side, const char *outcome,
                           const struct crypto_policy *cp, int profile_id,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port, uint8_t proto,
                           uint32_t pkt_len, const char *detail, int always)
{
    static atomic_uint pol_seq;
    char sip[INET_ADDRSTRLEN];
    char dip[INET_ADDRSTRLEN];
    uint32_t n;

    n = atomic_fetch_add(&pol_seq, 1);
    if (!always && n >= 50 && (n % 4096u) != 0)
        return;

    agent_fmt_ip4(sip, sizeof(sip), src_ip);
    agent_fmt_ip4(dip, sizeof(dip), dst_ip);

    if (cp) {
        fprintf(stderr,
                "[NE-POLICY] %s outcome=%s profile=%d policy_id=%d db_id=%d prio=%d "
                "action=%s mode=%s aes=%d proto=%u flow=%s:%u->%s:%u pkt_len=%u %s\n",
                side ? side : "?", outcome ? outcome : "?",
                profile_id, cp->id, cp->db_id, cp->priority,
                agent_policy_action(cp->action),
                agent_crypto_mode(cp->crypto_mode), cp->aes_bits,
                proto, sip, (unsigned)src_port, dip, (unsigned)dst_port,
                pkt_len, detail ? detail : "");
    } else {
        fprintf(stderr,
                "[NE-POLICY] %s outcome=%s profile=%d policy=(none) proto=%u "
                "flow=%s:%u->%s:%u pkt_len=%u %s\n",
                side ? side : "?", outcome ? outcome : "?",
                profile_id, proto, sip, (unsigned)src_port, dip, (unsigned)dst_port,
                pkt_len, detail ? detail : "");
    }
    fflush(stderr);
}

void ne_agent_policy_trace_plain(const char *side, const char *outcome,
                                 uint32_t pkt_len, const char *detail, int always)
{
    static atomic_uint plain_seq;
    uint32_t n;

    n = atomic_fetch_add(&plain_seq, 1);
    if (!always && n >= 50 && (n % 4096u) != 0)
        return;

    fprintf(stderr,
            "[NE-POLICY] %s outcome=%s pkt_len=%u %s\n",
            side ? side : "?", outcome ? outcome : "?",
            pkt_len, detail ? detail : "");
    fflush(stderr);
}

static void ne_agent_write_stderr(const char *hypothesis_id, const char *location,
                                  const char *message, const char *data_json)
{
    struct timespec ts;
    long long ms;

    if (!hypothesis_id || !location || !message)
        return;

    clock_gettime(CLOCK_REALTIME, &ts);
    ms = (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
    fprintf(stderr,
            "[NE-DBG %s] t=%lld hyp=%s loc=%s msg=%s data=%s\n",
            NE_AGENT_DEBUG_RUN_ID, ms, hypothesis_id, location, message,
            data_json ? data_json : "{}");
    fflush(stderr);
}

void ne_agent_stat_inc(ne_agent_stat_id id)
{
    if (id >= 0 && id < NE_STAT_COUNT)
        atomic_fetch_add(&g_agent_stats[id], 1);
}

void ne_agent_drop_log(const char *hypothesis_id, const char *location,
                       const char *message, const char *data_json)
{
    static atomic_uint drop_log_n;

    if (!hypothesis_id || !location || !message)
        return;
    if (atomic_fetch_add(&drop_log_n, 1) >= NE_AGENT_DROP_LOG_MAX)
        return;

    ne_agent_write_stderr(hypothesis_id, location, message, data_json);
}

void ne_agent_stat_maybe_dump(void)
{
    static atomic_uint dump_seq;
    static atomic_llong last_dump_ms;
    uint32_t seq;
    long long now_ms;
    long long prev_ms;
    struct timespec ts;
    uint64_t split_ok, wire_tx, bypass, enc_full, reasm_ok;
    uint64_t ring_wan, ring_push, enc_drop, dec_drop;

    seq = atomic_fetch_add(&dump_seq, 1);
    if (seq % 65536u != 0)
        return;

    clock_gettime(CLOCK_REALTIME, &ts);
    now_ms = (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL;
    prev_ms = atomic_load(&last_dump_ms);
    if (now_ms - prev_ms < 1000)
        return;
    if (!atomic_compare_exchange_strong(&last_dump_ms, &prev_ms, now_ms))
        return;

    split_ok = atomic_load(&g_agent_stats[NE_STAT_SPLIT_OK]);
    wire_tx = atomic_load(&g_agent_stats[NE_STAT_WIRE_FRAG_TX]);
    bypass = atomic_load(&g_agent_stats[NE_STAT_BYPASS_TX]);
    enc_full = atomic_load(&g_agent_stats[NE_STAT_ENCRYPT_FULL]);
    reasm_ok = atomic_load(&g_agent_stats[NE_STAT_REASM_OK]);
    ring_wan = atomic_load(&g_agent_stats[NE_STAT_RING_DROP_WAN_RX]);
    ring_push = atomic_load(&g_agent_stats[NE_STAT_RING_PUSH_FAIL]);
    enc_drop = atomic_load(&g_agent_stats[NE_STAT_ENCRYPT_DROP]);
    dec_drop = atomic_load(&g_agent_stats[NE_STAT_WAN_DECRYPT_DROP]);

    fprintf(stderr,
            "[NE-STATS] split_ok=%llu wire_frag_tx=%llu (ratio=%.2f) "
            "bypass=%llu encrypt_full=%llu reasm_ok=%llu no_policy_drop=%llu "
            "ring_drop_wan=%llu ring_push_fail=%llu encrypt_drop=%llu decrypt_drop=%llu "
            "reasm_fail=%llu frame_pool_fail=%llu reasm_timeout=%llu\n",
            (unsigned long long)split_ok,
            (unsigned long long)wire_tx,
            split_ok ? (double)wire_tx / (double)split_ok : 0.0,
            (unsigned long long)bypass,
            (unsigned long long)enc_full,
            (unsigned long long)reasm_ok,
            (unsigned long long)atomic_load(&g_agent_stats[NE_STAT_NO_POLICY_DROP]),
            (unsigned long long)ring_wan,
            (unsigned long long)ring_push,
            (unsigned long long)enc_drop,
            (unsigned long long)dec_drop,
            (unsigned long long)atomic_load(&g_agent_stats[NE_STAT_REASM_FAIL]),
            (unsigned long long)atomic_load(&g_agent_stats[NE_STAT_FRAME_POOL_FAIL]),
            (unsigned long long)atomic_load(&g_agent_stats[NE_STAT_REASM_TIMEOUT]));
    fflush(stderr);
}

void ne_agent_debug_log(const char *hypothesis_id, const char *location,
                        const char *message, const char *data_json)
{
    static atomic_uint log_n;

    if (!hypothesis_id || !location || !message)
        return;
    if (atomic_fetch_add(&log_n, 1) >= NE_AGENT_DEBUG_MAX)
        return;

    ne_agent_write_stderr(hypothesis_id, location, message, data_json);
}
/* #endregion */

int dp_parse_flow(void *pkt_data, uint32_t pkt_len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto)
{
    int l3_off;
    struct iphdr *ip;
    uint32_t ihl;

    if (!pkt_data || !src_ip || !dst_ip || !src_port || !dst_port || !proto)
        return -1;

    l3_off = crypto_eth_ipv4_offset(pkt_data, pkt_len);
    if (l3_off < 0)
        return -1;

    ip = (struct iphdr *)((uint8_t *)pkt_data + l3_off);
    ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < (uint32_t)(l3_off + ihl))
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *proto = ip->protocol;
    *src_port = 0;
    *dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint8_t *l4 = (uint8_t *)pkt_data + l3_off + ihl;
        if (pkt_len < (uint32_t)(l4 - (uint8_t *)pkt_data + 4))
            return -1;
        uint16_t *ports = (uint16_t *)l4;
        *src_port = ntohs(ports[0]);
        *dst_port = ntohs(ports[1]);
    }
    return 0;
}

uint32_t dp_dest_ipv4(void *pkt, uint32_t len)
{
    uint32_t src = 0, dst = 0;
    uint16_t sp = 0, dp = 0;
    uint8_t proto = 0;
    if (dp_parse_flow(pkt, len, &src, &dst, &sp, &dp, &proto) != 0)
        return 0;
    return dst;
}

int dp_write_l2_src_only(uint8_t *pkt, uint32_t len, const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_write_l2(uint8_t *pkt, uint32_t len,
                const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN],
                int allow_empty_src)
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0)
        return -1;
    if (!allow_empty_src && memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt, dst, MAC_LEN);
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_apply_wan_l2(uint8_t *pkt, uint32_t len,
                    const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0 || memcmp(src, zero, MAC_LEN) == 0)
        return 0;
    return dp_write_l2(pkt, len, dst, src, 0);
}

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt)
{
    if (pkt->len > fwd->pair.frame_size || ne_ring_try_push(ring, pkt) != 0) {
        ne_agent_stat_inc(NE_STAT_RING_PUSH_FAIL);
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    return 0;
}
