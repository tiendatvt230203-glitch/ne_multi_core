#include "../../inc/core/forwarder.h"

#include "../../inc/core/bridge_mac.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_dispatch.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <time.h>

static volatile int running = 1;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;

static struct packet_crypto_ctx base_crypto_ctx;
static struct packet_crypto_ctx policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int policy_crypto_ready[MAX_CRYPTO_POLICIES];
static int policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
static struct crypto_policy active_policies[MAX_CRYPTO_POLICIES];
static int active_policy_count;

static struct frag_table wan_frag_l2;
static struct frag_table wan_frag_l3;
static struct frag_table wan_frag_l4;

static int trace_hit(uint64_t *counter)
{
    uint64_t n = __sync_add_and_fetch(counter, 1);
    return n <= 256 || (n % 1024) == 0;
}

static const char *action_name(int action)
{
    switch (action) {
    case POLICY_ACTION_BYPASS:
        return "bypass";
    case POLICY_ACTION_ENCRYPT_L2:
        return "L2";
    case POLICY_ACTION_ENCRYPT_L3:
        return "L3";
    case POLICY_ACTION_ENCRYPT_L4:
        return "L4";
    default:
        return "none";
    }
}

static void ip_to_str(uint32_t ip, char *buf, size_t len)
{
    struct in_addr a = { .s_addr = ip };
    if (!inet_ntop(AF_INET, &a, buf, len))
        snprintf(buf, len, "0.0.0.0");
}

static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

void forwarder_pin_cpu(void)
{
    pin_cpu(NE_CPU_LOC);
}

static int key_nonzero(const uint8_t *key, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        if (key[i] != 0)
            return 1;
    }
    return 0;
}

static int crypto_action_valid(int action)
{
    return action == POLICY_ACTION_ENCRYPT_L2 ||
           action == POLICY_ACTION_ENCRYPT_L3 ||
           action == POLICY_ACTION_ENCRYPT_L4;
}

static void crypto_runtime_reset_indexes(void)
{
    for (int a = 0; a <= POLICY_ACTION_ENCRYPT_L4; a++) {
        for (int id = 0; id < 256; id++)
            policy_index_by_action_id[a][id] = -1;
    }
}

static int rebuild_crypto_runtime(struct app_config *cfg)
{
    memset(policy_crypto_ready, 0, sizeof(policy_crypto_ready));
    memset(active_policies, 0, sizeof(active_policies));
    active_policy_count = 0;
    crypto_runtime_reset_indexes();

    if (!cfg || !cfg->crypto_enabled)
        return 0;

    if (cfg->fake_ethertype_ipv4 == 0)
        cfg->fake_ethertype_ipv4 = 0x88b5;
    if (cfg->fake_protocol == 0)
        cfg->fake_protocol = 99;

    packet_crypto_set_fake_ethertype(cfg->fake_ethertype_ipv4);
    packet_crypto_set_fake_protocol(cfg->fake_protocol);
    crypto_apply_default_from_cfg(cfg);
    if (packet_crypto_init(&base_crypto_ctx, cfg->crypto_key) != 0)
        return -1;

    active_policy_count = cfg->policy_count;
    if (active_policy_count > MAX_CRYPTO_POLICIES)
        active_policy_count = MAX_CRYPTO_POLICIES;

    for (int i = 0; i < active_policy_count; i++) {
        const struct crypto_policy *cp = &cfg->policies[i];
        active_policies[i] = *cp;
        if (!crypto_action_valid(cp->action))
            continue;
        if (cp->id >= 0 && cp->id <= 255)
            policy_index_by_action_id[cp->action][(uint8_t)cp->id] = i;
        if (!key_nonzero(cp->key, AES_KEY_LEN))
            continue;
        crypto_apply_from_policy(cp);
        if (packet_crypto_init(&policy_crypto_ctx[i], cp->key) == 0)
            policy_crypto_ready[i] = 1;
    }

    crypto_apply_default_from_cfg(cfg);
    return 0;
}

static struct crypto_dispatch_ctx make_dispatch_ctx(void)
{
    struct crypto_dispatch_ctx dctx;
    memset(&dctx, 0, sizeof(dctx));
    dctx.base_ctx = &base_crypto_ctx;
    dctx.per_policy_ctx = policy_crypto_ctx;
    dctx.per_policy_ready = policy_crypto_ready;
    dctx.policies = active_policies;
    dctx.policy_count = active_policy_count;
    dctx.policy_index_by_action_id = policy_index_by_action_id;
    return dctx;
}

static struct packet_crypto_ctx *ctx_for_policy_action_id(int action, uint8_t id)
{
    if (action < 0 || action > POLICY_ACTION_ENCRYPT_L4)
        return NULL;
    int pi = policy_index_by_action_id[action][id];
    if (pi < 0 || pi >= active_policy_count || !policy_crypto_ready[pi])
        return NULL;
    crypto_apply_from_policy(&active_policies[pi]);
    return &policy_crypto_ctx[pi];
}

static int parse_flow(void *pkt_data, uint32_t pkt_len,
                      uint32_t *src_ip, uint32_t *dst_ip,
                      uint16_t *src_port, uint16_t *dst_port,
                      uint8_t *protocol)
{
    if (!pkt_data || pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return -1;

    uint8_t *pkt = pkt_data;
    struct ether_header *eth = (struct ether_header *)pkt;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;

    struct iphdr *ip = (struct iphdr *)(pkt + sizeof(struct ether_header));
    uint32_t ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < sizeof(struct ether_header) + ihl)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *protocol = ip->protocol;
    *src_port = 0;
    *dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint8_t *l4 = pkt + sizeof(struct ether_header) + ihl;
        if (pkt_len < (uint32_t)(l4 - pkt + 4))
            return -1;
        uint16_t *ports = (uint16_t *)l4;
        *src_port = ntohs(ports[0]);
        *dst_port = ntohs(ports[1]);
    }
    return 0;
}

static uint32_t get_dest_ip(void *pkt_data, uint32_t pkt_len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    if (parse_flow(pkt_data, pkt_len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) != 0)
        return 0;
    return dst_ip;
}

static void init_wan_flow_table(struct forwarder *fwd)
{
    uint32_t windows[MAX_INTERFACES];
    memset(windows, 0, sizeof(windows));
    for (int i = 0; i < fwd->wan_count; i++)
        windows[i] = fwd->cfg->wans[i].window_size;
    flow_table_init(&fwd->wan_flow_table, windows, fwd->wan_count);
    fwd->wan_flow_table_ready = 1;
}

static int same_topology(const struct app_config *a, const struct app_config *b)
{
    if (!a || !b)
        return 0;
    if (a->local_count != b->local_count || a->wan_count != b->wan_count)
        return 0;
    if (a->local_count <= 0 || a->wan_count <= 0)
        return 0;
    if (strcmp(a->locals[0].ifname, b->locals[0].ifname) != 0)
        return 0;
    for (int i = 0; i < a->wan_count; i++) {
        if (strcmp(a->wans[i].ifname, b->wans[i].ifname) != 0)
            return 0;
    }
    return 1;
}

static void init_iface_meta(struct xsk_interface *iface, const char *ifname,
                            const uint8_t src_mac[MAC_LEN],
                            const uint8_t dst_mac[MAC_LEN])
{
    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(ifname);
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = 1;
    iface->ring_size = NE_RING;
    iface->batch_size = NE_BATCH_SIZE;
    iface->frame_size = NE_FRAME;
    memcpy(iface->src_mac, src_mac, MAC_LEN);
    memcpy(iface->dst_mac, dst_mac, MAC_LEN);
}

static int set_wan_l2(struct forwarder *fwd, int wan_idx, uint8_t *pkt)
{
    (void)fwd;
    (void)wan_idx;
    (void)pkt;
    return 0;
}

static int set_local_l2(struct forwarder *fwd, int local_idx, uint8_t *pkt)
{
    (void)fwd;
    (void)local_idx;
    (void)pkt;
    return 0;
}

static int local_rx_is_reflected_client_frame(struct forwarder *fwd, int local_idx,
                                              const uint8_t *pkt, uint32_t pkt_len)
{
    if (!fwd || !fwd->cfg ||
        local_idx < 0 || local_idx >= fwd->local_count || !pkt || pkt_len < 14)
        return 0;
    const uint8_t *dst = fwd->locals[local_idx].dst_mac;
    static const uint8_t zero[MAC_LEN];
    if (memcmp(dst, zero, MAC_LEN) == 0)
        return 0;
    return memcmp(pkt, dst, MAC_LEN) == 0;
}

static int has_l2_crypto_marker(const uint8_t *pkt, uint32_t pkt_len)
{
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    if (!fake || !pkt || pkt_len < 14)
        return 0;
    if (pkt[12] != (uint8_t)(fake >> 8))
        return 0;
    return policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L2][pkt[13]] >= 0;
}

static int wan_packet_needs_crypto(struct forwarder *fwd, const uint8_t *pkt, uint32_t pkt_len)
{
    if (!fwd || !fwd->cfg || !fwd->cfg->crypto_enabled || !pkt)
        return 0;

    uint16_t pid = 0;
    uint8_t frag_idx = 0;
    if (frag_is_fragment_l2(fwd->cfg, pkt, pkt_len, &pid, &frag_idx))
        return 1;
    if (frag_is_fragment(fwd->cfg, pkt, pkt_len, &pid, &frag_idx))
        return 1;
    if (frag_is_fragment_l4(fwd->cfg, pkt, pkt_len, &pid, &frag_idx))
        return 1;

    if (has_l2_crypto_marker(pkt, pkt_len))
        return 1;

    uint8_t policy_id = 0;
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, pkt_len, &policy_id) == 0)
        return 1;

    int nonce_size = 0;
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, pkt_len,
                                         &policy_id, &nonce_size) == 0)
        return 1;

    return 0;
}

static int emit_owned(struct forwarder *fwd, struct ne_ring *dst, struct ne_packet *pkt)
{
    if (pkt->len > fwd->pair.frame_size || ne_ring_try_push(dst, pkt) != 0) {
        ne_frame_free(&fwd->pair, pkt->addr);
        __sync_fetch_and_add(&fwd->total_dropped, 1);
        __sync_fetch_and_add(&fwd->dropped_ring_full, 1);
        return -1;
    }
    return 0;
}

static int emit_local_to_wan(struct forwarder *fwd, struct ne_packet *job,
                             int wan_idx, int encrypted, int do_trace)
{
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_idx;
    if (emit_owned(fwd, &fwd->mid_to_wan[wan_idx], job) != 0) {
        if (do_trace) {
            fprintf(stderr,
                    "[TRACE LOCAL-DROP] reason=emit_mid_to_wan_failed wan=%d len=%u ring=%u\n",
                    wan_idx, job->len, ne_ring_count(&fwd->mid_to_wan[wan_idx]));
        }
        return -1;
    }

    if (do_trace) {
        fprintf(stderr,
                "[TRACE LOCAL-OUT] mode=%s wan=%d if=%s len=%u ring_now=%u\n",
                encrypted ? "encrypted" : "bypass", wan_idx,
                fwd->pair.wans[wan_idx].ifname, job->len,
                ne_ring_count(&fwd->mid_to_wan[wan_idx]));
    }
    __sync_fetch_and_add(&fwd->local_to_wan, 1);
    if (encrypted)
        __sync_fetch_and_add(&fwd->local_encrypted_to_wan, 1);
    else
        __sync_fetch_and_add(&fwd->local_bypass_to_wan, 1);
    return 0;
}

static int emit_split_pair_to_wan(struct forwarder *fwd, struct ne_packet *job,
                                  uint32_t frag0_len,
                                  const uint8_t *frag1, uint32_t frag1_len,
                                  int wan_idx)
{
    static uint64_t trace_counter;
    if (wan_idx < 0 || wan_idx >= fwd->wan_count)
        return -1;
    struct ne_ring *tx = &fwd->mid_to_wan[wan_idx];
    uint32_t used = ne_ring_count(tx);
    if (used + 2 > tx->cap)
        return -1;
    if (frag0_len > fwd->pair.frame_size || frag1_len > fwd->pair.frame_size)
        return -1;
    if (frag0_len == 0 || frag1_len == 0)
        return -1;

    struct ne_packet tail = { .len = frag1_len, .dir = NE_DIR_WAN, .wan_idx = (uint8_t)wan_idx };
    if (ne_frame_alloc(&fwd->pair, &tail.addr) != 0)
        return -1;

    memcpy(ne_packet_data(&fwd->pair, tail.addr), frag1, frag1_len);
    job->len = frag0_len;
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_idx;

    if (trace_hit(&trace_counter)) {
        fprintf(stderr,
                "[TRACE SPLIT-EMIT] pair_same_wan=1 wan=%d if=%s frag0=%u frag1=%u ring_before=%u\n",
                wan_idx, fwd->pair.wans[wan_idx].ifname, frag0_len, frag1_len, used);
    }

    if (ne_ring_try_push(tx, job) != 0) {
        ne_frame_free(&fwd->pair, tail.addr);
        return -1;
    }
    if (ne_ring_try_push(tx, &tail) != 0) {
        ne_frame_free(&fwd->pair, tail.addr);
        __sync_fetch_and_add(&fwd->total_dropped, 1);
        __sync_fetch_and_add(&fwd->dropped_ring_full, 1);
    }
    return 0;
}

static int encrypt_split_or_single(struct forwarder *fwd, struct ne_packet *job,
                                   const struct crypto_policy *cp, int wan_idx)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t pkt_len = job->len;
    int sent_split = 0;

    if (cp->action == POLICY_ACTION_ENCRYPT_L2 && frag_need_split_l2(pkt_len)) {
        uint8_t f2[4096];
        uint32_t l1 = 0, l2 = 0;
        if (frag_split_and_encrypt_l2(&policy_crypto_ctx[cp - fwd->cfg->policies],
                                      pkt, pkt_len, fwd->pair.frame_size, &l1,
                                      f2, fwd->pair.frame_size, &l2) != 0)
            return -1;
        if (set_wan_l2(fwd, wan_idx, pkt) != 0 || set_wan_l2(fwd, wan_idx, f2) != 0)
            return -1;
        if (emit_split_pair_to_wan(fwd, job, l1, f2, l2, wan_idx) != 0)
            return -1;
        sent_split = 1;
    } else if (cp->action == POLICY_ACTION_ENCRYPT_L3 && frag_need_split(pkt_len)) {
        uint8_t f2[4096];
        uint32_t l1 = 0, l2 = 0;
        if (frag_split_and_encrypt(&policy_crypto_ctx[cp - fwd->cfg->policies],
                                   pkt, pkt_len, fwd->pair.frame_size, &l1,
                                   f2, fwd->pair.frame_size, &l2) != 0)
            return -1;
        if (set_wan_l2(fwd, wan_idx, pkt) != 0 || set_wan_l2(fwd, wan_idx, f2) != 0)
            return -1;
        if (emit_split_pair_to_wan(fwd, job, l1, f2, l2, wan_idx) != 0)
            return -1;
        sent_split = 1;
    } else if (cp->action == POLICY_ACTION_ENCRYPT_L4 && frag_need_split_l4(pkt_len)) {
        uint8_t f2[4096];
        uint32_t l1 = 0, l2 = 0;
        if (frag_split_and_encrypt_l4(&policy_crypto_ctx[cp - fwd->cfg->policies],
                                      pkt, pkt_len, fwd->pair.frame_size, &l1,
                                      f2, fwd->pair.frame_size, &l2) != 0)
            return -1;
        if (set_wan_l2(fwd, wan_idx, pkt) != 0 || set_wan_l2(fwd, wan_idx, f2) != 0)
            return -1;
        if (emit_split_pair_to_wan(fwd, job, l1, f2, l2, wan_idx) != 0)
            return -1;
        sent_split = 1;
    }

    if (!sent_split) {
        int new_len = -1;
        if (cp->action == POLICY_ACTION_ENCRYPT_L2)
            new_len = crypto_layer2_encrypt(&policy_crypto_ctx[cp - fwd->cfg->policies], pkt, pkt_len);
        else if (cp->action == POLICY_ACTION_ENCRYPT_L3)
            new_len = crypto_layer3_encrypt(&policy_crypto_ctx[cp - fwd->cfg->policies], pkt, pkt_len);
        else if (cp->action == POLICY_ACTION_ENCRYPT_L4)
            new_len = crypto_layer4_encrypt(&policy_crypto_ctx[cp - fwd->cfg->policies], pkt, pkt_len);
        if (new_len < 0)
            return -1;
        job->len = (uint32_t)new_len;
    }
    return sent_split ? 1 : 0;
}

static int wan_has_tx_room(struct forwarder *fwd, int wan_idx)
{
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return 0;
    if (fwd->wan_tx_cooldown[wan_idx] > 0)
        return 0;
    struct ne_ring *r = &fwd->mid_to_wan[wan_idx];
    return ne_ring_count(r) + NE_BATCH_SIZE < r->cap;
}

static uint32_t flush_wan_queue(struct forwarder *fwd, int wan_idx)
{
    struct ne_packet pkt;
    uint32_t dropped = 0;
    if (!fwd || wan_idx < 0 || wan_idx >= fwd->wan_count)
        return 0;
    while (ne_ring_try_pop(&fwd->mid_to_wan[wan_idx], &pkt) == 0) {
        ne_frame_free(&fwd->pair, pkt.addr);
        dropped++;
    }
    if (dropped) {
        __sync_fetch_and_add(&fwd->total_dropped, dropped);
        __sync_fetch_and_add(&fwd->wan_tx_dropped[wan_idx], dropped);
        __sync_fetch_and_add(&fwd->wan_tx_flushes[wan_idx], 1);
    }
    return dropped;
}

static int fallback_wan_if_congested(struct forwarder *fwd, int profile_idx, int selected)
{
    if (wan_has_tx_room(fwd, selected))
        return selected;

    int best = -1;
    uint32_t best_depth = UINT32_MAX;

    if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
        struct profile_config *p = &fwd->cfg->profiles[profile_idx];
        for (int i = 0; i < p->wan_count; i++) {
            int wi = p->wan_indices[i];
            if (!wan_has_tx_room(fwd, wi))
                continue;
            uint32_t depth = ne_ring_count(&fwd->mid_to_wan[wi]);
            if (depth < best_depth) {
                best_depth = depth;
                best = wi;
            }
        }
    }

    if (best < 0) {
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (!wan_has_tx_room(fwd, wi))
                continue;
            uint32_t depth = ne_ring_count(&fwd->mid_to_wan[wi]);
            if (depth < best_depth) {
                best_depth = depth;
                best = wi;
            }
        }
    }

    if (best >= 0) {
        fprintf(stderr,
                "[TRACE LB-FAILOVER] selected_wan=%d ring=%u -> wan=%d ring=%u\n",
                selected,
                (selected >= 0 && selected < fwd->wan_count) ? ne_ring_count(&fwd->mid_to_wan[selected]) : 0,
                best, ne_ring_count(&fwd->mid_to_wan[best]));
        return best;
    }

    return selected;
}

static int select_wan_for_local(struct forwarder *fwd, int profile_idx, int flow_ok,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t proto, uint32_t pkt_len, int pin_tcp)
{
    static uint64_t trace_counter;
    if (!fwd || fwd->wan_count <= 0)
        return -1;
    if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
        struct profile_config *p = &fwd->cfg->profiles[profile_idx];
        if (p->wan_count > 0) {
            int wan_idx;
            if (pin_tcp && proto == IPPROTO_TCP) {
                wan_idx = fallback_wan_if_congested(fwd, profile_idx, p->wan_indices[0]);
                if (trace_hit(&trace_counter)) {
                    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                    ip_to_str(src_ip, src, sizeof(src));
                    ip_to_str(dst_ip, dst, sizeof(dst));
                    fprintf(stderr,
                            "[TRACE LB] profile=%d flow_ok=%d tcp_pinned %s:%u -> %s:%u len=%u selected_wan=%d if=%s ring=%u\n",
                            profile_idx, flow_ok, src, src_port, dst, dst_port, pkt_len,
                            wan_idx, fwd->pair.wans[wan_idx].ifname,
                            ne_ring_count(&fwd->mid_to_wan[wan_idx]));
                }
                return wan_idx;
            }
            if (flow_ok && fwd->wan_flow_table_ready) {
                wan_idx = flow_table_get_wan_profile(&fwd->wan_flow_table,
                                                     src_ip, dst_ip, src_port, dst_port,
                                                     proto, pkt_len,
                                                     p->wan_indices, p->wan_count,
                                                     p->wan_bandwidth_weight);
            } else {
                wan_idx = flow_table_pick_wan_per_packet(p->wan_indices,
                                                         p->wan_bandwidth_weight,
                                                         p->wan_count);
            }
            if (wan_idx >= 0 && wan_idx < fwd->wan_count) {
                wan_idx = fallback_wan_if_congested(fwd, profile_idx, wan_idx);
                if (trace_hit(&trace_counter)) {
                    char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
                    int selected_weight = 0;
                    for (int wi = 0; wi < p->wan_count; wi++) {
                        if (p->wan_indices[wi] == wan_idx) {
                            selected_weight = p->wan_bandwidth_weight[wi];
                            break;
                        }
                    }
                    ip_to_str(src_ip, src, sizeof(src));
                    ip_to_str(dst_ip, dst, sizeof(dst));
                    fprintf(stderr,
                            "[TRACE LB] profile=%d flow_ok=%d %s:%u -> %s:%u proto=%u len=%u allowed=%d selected_wan=%d if=%s weight=%d ring=%u\n",
                            profile_idx, flow_ok, src, src_port, dst, dst_port, proto, pkt_len,
                            p->wan_count, wan_idx, fwd->pair.wans[wan_idx].ifname,
                            selected_weight,
                            ne_ring_count(&fwd->mid_to_wan[wan_idx]));
                }
                return wan_idx;
            }
        }
    }
    if (trace_hit(&trace_counter)) {
        fprintf(stderr,
                "[TRACE LB] profile=%d flow_ok=%d fallback_wan=0 if=%s len=%u\n",
                profile_idx, flow_ok, fwd->pair.wans[0].ifname, pkt_len);
    }
    return fallback_wan_if_congested(fwd, profile_idx, 0);
}

static void process_local_packet(struct forwarder *fwd, struct ne_packet job)
{
    static uint64_t trace_counter;
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int encrypted = 0;
    int flow_ok = (parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0);
    int local_idx = job.local_idx < fwd->local_count ? job.local_idx : 0;
    int do_trace = trace_hit(&trace_counter);
    if (local_rx_is_reflected_client_frame(fwd, local_idx, pkt, job.len)) {
        if (do_trace) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            ip_to_str(src_ip, src, sizeof(src));
            ip_to_str(dst_ip, dst, sizeof(dst));
            fprintf(stderr,
                    "[TRACE LOCAL-SKIP] reason=reflected_client_frame local=%d len=%u %s:%u -> %s:%u proto=%u dmac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    local_idx, job.len, src, src_port, dst, dst_port, proto,
                    pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
        }
        __sync_fetch_and_add(&fwd->local_reflected_drop, 1);
        ne_frame_free(&fwd->pair, job.addr);
        return;
    }
    int profile_idx = config_select_profile_for_local(fwd->cfg, local_idx);
    const struct crypto_policy *cp = NULL;
    if (fwd->cfg->crypto_enabled && flow_ok)
        cp = config_select_crypto_policy(fwd->cfg, profile_idx, src_ip, dst_ip,
                                         src_port, dst_port, proto);
    int pin_tcp = (!fwd->cfg->crypto_enabled || !cp || cp->action == POLICY_ACTION_BYPASS);
    int wan_idx = select_wan_for_local(fwd, profile_idx, flow_ok,
                                       src_ip, dst_ip, src_port, dst_port,
                                       proto, job.len, pin_tcp);
    if (do_trace) {
        char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
        ip_to_str(src_ip, src, sizeof(src));
        ip_to_str(dst_ip, dst, sizeof(dst));
        fprintf(stderr,
                "[TRACE LOCAL-IN] len=%u flow_ok=%d profile=%d wan=%d %s:%u -> %s:%u proto=%u eth=%02x%02x\n",
                job.len, flow_ok, profile_idx, wan_idx, src, src_port, dst, dst_port, proto,
                pkt[12], pkt[13]);
    }
    if (wan_idx < 0) {
        if (do_trace)
            fprintf(stderr, "[TRACE LOCAL-DROP] reason=no_wan len=%u profile=%d\n", job.len, profile_idx);
        __sync_fetch_and_add(&fwd->dropped_no_wan, 1);
        goto drop;
    }
    if (!wan_has_tx_room(fwd, wan_idx)) {
        if (do_trace)
            fprintf(stderr,
                    "[TRACE LOCAL-DROP] reason=wan_congested wan=%d cooldown=%u ring=%u len=%u\n",
                    wan_idx, fwd->wan_tx_cooldown[wan_idx],
                    ne_ring_count(&fwd->mid_to_wan[wan_idx]), job.len);
        __sync_fetch_and_add(&fwd->dropped_wan_congested, 1);
        goto drop;
    }

    if (set_wan_l2(fwd, wan_idx, pkt) != 0) {
        if (do_trace)
            fprintf(stderr, "[TRACE LOCAL-DROP] reason=wan_l2 wan=%d len=%u\n", wan_idx, job.len);
        __sync_fetch_and_add(&fwd->dropped_wan_l2, 1);
        goto drop;
    }

    if (fwd->cfg->crypto_enabled && do_trace) {
        if (cp) {
            fprintf(stderr,
                    "[TRACE POLICY] db_id=%d wire_id=%d action=%s ready=%d\n",
                    cp->db_id, cp->id, action_name(cp->action),
                    (cp->action >= 0 && cp->action <= POLICY_ACTION_ENCRYPT_L4) ?
                        policy_crypto_ready[cp - fwd->cfg->policies] : 0);
        } else {
            fprintf(stderr, "[TRACE POLICY] no_match -> bypass_fast\n");
        }
    }

    if (!fwd->cfg->crypto_enabled || !cp || cp->action == POLICY_ACTION_BYPASS) {
        (void)emit_local_to_wan(fwd, &job, wan_idx, 0, do_trace);
        return;
    }

    int pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !policy_crypto_ready[pi]) {
        if (do_trace)
            fprintf(stderr, "[TRACE LOCAL-DROP] reason=policy_not_ready pi=%d\n", pi);
        __sync_fetch_and_add(&fwd->dropped_policy_not_ready, 1);
        goto drop;
    }
    crypto_apply_from_policy(cp);
    int enc_rc = encrypt_split_or_single(fwd, &job, cp, wan_idx);
    if (enc_rc < 0) {
        if (do_trace)
            fprintf(stderr, "[TRACE LOCAL-DROP] reason=encrypt_fail action=%s len=%u\n",
                    action_name(cp->action), job.len);
        __sync_fetch_and_add(&fwd->dropped_encrypt_fail, 1);
        goto drop;
    }
    if (enc_rc > 0) {
        if (do_trace)
            fprintf(stderr, "[TRACE LOCAL-OUT] split action=%s wan=%d ring_now=%u\n",
                    action_name(cp->action), wan_idx, ne_ring_count(&fwd->mid_to_wan[wan_idx]));
        __sync_fetch_and_add(&fwd->local_to_wan, 1);
        __sync_fetch_and_add(&fwd->local_split_to_wan, 1);
        return;
    }
    encrypted = 1;
    (void)emit_local_to_wan(fwd, &job, wan_idx, encrypted, do_trace);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
    __sync_fetch_and_add(&fwd->total_dropped, 1);
}

static int decrypt_l2_if_needed(struct forwarder *fwd, uint8_t *pkt, uint32_t *pkt_len)
{
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    if (!fake || *pkt_len < 14 || pkt[12] != (uint8_t)(fake >> 8))
        return 0;

    uint8_t policy_id = pkt[13];
    struct packet_crypto_ctx *ctx = ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L2, policy_id);
    if (!ctx)
        return -1;
    int new_len = crypto_layer2_decrypt(ctx, pkt, *pkt_len);
    if (new_len < 0)
        return -1;
    *pkt_len = (uint32_t)new_len;
    (void)fwd;
    return 0;
}

static int decrypt_wan_packet(struct forwarder *fwd, struct ne_packet *job)
{
    uint8_t scratch[8192];
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t pkt_len = job->len;

    uint16_t pid = 0;
    uint8_t frag_idx = 0;
    if (frag_is_fragment_l2(fwd->cfg, pkt, pkt_len, &pid, &frag_idx)) {
        uint8_t policy_id = pkt[13];
        struct packet_crypto_ctx *ctx = ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L2, policy_id);
        if (!ctx)
            return -1;
        uint16_t opid = 0;
        uint8_t ofidx = 0;
        int nd = crypto_layer2_decrypt_fragment(ctx, pkt, pkt_len, &opid, &ofidx);
        if (nd < 0)
            return -1;
        uint8_t reass[4096];
        uint32_t reass_len = 0;
        int rr = frag_try_reassemble_l2(&wan_frag_l2, pkt, (uint32_t)nd, opid, ofidx,
                                        reass, &reass_len);
        if (rr == 0)
            return 1;
        if (rr != 1)
            return -1;
        memcpy(pkt, reass, reass_len);
        pkt_len = reass_len;
    } else if (decrypt_l2_if_needed(fwd, pkt, &pkt_len) != 0) {
        return -1;
    }

    if (fwd->cfg->crypto_enabled) {
        struct crypto_dispatch_ctx dctx = make_dispatch_ctx();
        if (frag_is_fragment(fwd->cfg, pkt, pkt_len, &pid, &frag_idx)) {
            uint8_t policy_id = 0;
            if (crypto_l3_extract_policy_id(fwd->cfg, pkt, pkt_len, &policy_id) != 0)
                return -1;
            struct packet_crypto_ctx *ctx = ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L3, policy_id);
            if (!ctx)
                return -1;
            uint16_t opid = 0;
            uint8_t ofidx = 0;
            int nd = crypto_layer3_decrypt_fragment(ctx, pkt, pkt_len, &opid, &ofidx);
            if (nd < 0)
                return -1;
            uint8_t reass[4096];
            uint32_t reass_len = 0;
            int rr = frag_try_reassemble(&wan_frag_l3, pkt, (uint32_t)nd, opid, ofidx,
                                         reass, &reass_len);
            if (rr == 0)
                return 1;
            if (rr != 1)
                return -1;
            memcpy(pkt, reass, reass_len);
            pkt_len = reass_len;
        } else if (crypto_decrypt_packet_auto_by_action(1, fwd->cfg, &dctx,
                                                        POLICY_ACTION_ENCRYPT_L3,
                                                        pkt, &pkt_len,
                                                        scratch, sizeof(scratch)) != 0) {
            return -1;
        }

        if (frag_is_fragment_l4(fwd->cfg, pkt, pkt_len, &pid, &frag_idx)) {
            uint8_t policy_id = 0;
            int nonce_size = 0;
            if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, pkt, pkt_len, &policy_id, &nonce_size) != 0)
                return -1;
            struct packet_crypto_ctx *ctx = ctx_for_policy_action_id(POLICY_ACTION_ENCRYPT_L4, policy_id);
            if (!ctx)
                return -1;
            uint16_t opid = 0;
            uint8_t ofidx = 0;
            int nd = crypto_layer4_decrypt_fragment(ctx, pkt, pkt_len, &opid, &ofidx);
            if (nd < 0)
                return -1;
            uint8_t reass[4096];
            uint32_t reass_len = 0;
            int rr = frag_try_reassemble_l4(&wan_frag_l4, pkt, (uint32_t)nd, opid, ofidx,
                                            reass, &reass_len);
            if (rr == 0)
                return 1;
            if (rr != 1)
                return -1;
            memcpy(pkt, reass, reass_len);
            pkt_len = reass_len;
        } else if (crypto_decrypt_packet_auto_by_action(1, fwd->cfg, &dctx,
                                                        POLICY_ACTION_ENCRYPT_L4,
                                                        pkt, &pkt_len,
                                                        scratch, sizeof(scratch)) != 0) {
            return -1;
        }
    }

    job->len = pkt_len;
    return 0;
}

static int pick_local_for_packet(struct forwarder *fwd, uint8_t *pkt, uint32_t pkt_len)
{
    int local_idx = bridge_mac_local_for_dmac(fwd, pkt, pkt_len);
    if (local_idx >= 0)
        return local_idx;

    uint32_t dst_ip = get_dest_ip(pkt, pkt_len);
    if (!dst_ip)
        return -1;
    return config_find_local_for_ip(fwd->cfg, dst_ip);
}

static void process_wan_packet(struct forwarder *fwd, struct ne_packet job)
{
    static uint64_t trace_counter;
    int do_trace = trace_hit(&trace_counter);
    if (do_trace) {
        uint8_t *raw = ne_packet_data(&fwd->pair, job.addr);
        fprintf(stderr,
                "[TRACE WAN-IN] wan=%u len=%u eth=%02x%02x\n",
                job.wan_idx, job.len, raw[12], raw[13]);
    }
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    if (wan_packet_needs_crypto(fwd, pkt, job.len)) {
        int dec = decrypt_wan_packet(fwd, &job);
        if (dec == 1) {
            if (do_trace)
                fprintf(stderr, "[TRACE WAN-WAIT] fragment buffered wan=%u\n", job.wan_idx);
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec != 0) {
            if (do_trace)
                fprintf(stderr, "[TRACE WAN-DROP] reason=decrypt_fail wan=%u len=%u\n", job.wan_idx, job.len);
            goto drop;
        }
        pkt = ne_packet_data(&fwd->pair, job.addr);
    } else if (do_trace) {
        fprintf(stderr, "[TRACE WAN-FAST] mode=bypass wan=%u len=%u\n",
                job.wan_idx, job.len);
    }

    int local_idx = pick_local_for_packet(fwd, pkt, job.len);
    if (do_trace) {
        uint32_t src_ip = 0, dst_ip = 0;
        uint16_t src_port = 0, dst_port = 0;
        uint8_t proto = 0;
        if (parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0) {
            char src[INET_ADDRSTRLEN], dst[INET_ADDRSTRLEN];
            ip_to_str(src_ip, src, sizeof(src));
            ip_to_str(dst_ip, dst, sizeof(dst));
            fprintf(stderr,
                    "[TRACE WAN-FLOW] wan=%u local=%d %s:%u -> %s:%u proto=%u len=%u dmac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    job.wan_idx, local_idx, src, src_port, dst, dst_port, proto, job.len,
                    pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
        }
    }
    if (local_idx < 0 || local_idx >= fwd->local_count) {
        if (do_trace)
            fprintf(stderr,
                    "[TRACE WAN-DROP] reason=no_local_match wan=%u len=%u dmac=%02x:%02x:%02x:%02x:%02x:%02x\n",
                    job.wan_idx, job.len, pkt[0], pkt[1], pkt[2], pkt[3], pkt[4], pkt[5]);
        __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
        goto drop;
    }
    if (set_local_l2(fwd, local_idx, pkt) != 0) {
        if (do_trace)
            fprintf(stderr, "[TRACE WAN-DROP] reason=local_l2_fail local=%d len=%u\n",
                    local_idx, job.len);
        __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
        goto drop;
    }

    job.dir = NE_DIR_LOCAL;
    job.local_idx = (uint8_t)local_idx;
    if (emit_owned(fwd, &fwd->mid_to_local[local_idx], &job) == 0) {
        if (do_trace)
            fprintf(stderr,
                    "[TRACE WAN-OUT] local=%d if=%s len=%u mid_to_local=%u\n",
                    local_idx, fwd->pair.locals[local_idx].ifname, job.len,
                    ne_ring_count(&fwd->mid_to_local[local_idx]));
        __sync_fetch_and_add(&fwd->wan_to_local, 1);
    } else if (do_trace) {
        fprintf(stderr, "[TRACE WAN-DROP] reason=emit_mid_to_local_failed local=%d len=%u ring=%u\n",
                local_idx, job.len, ne_ring_count(&fwd->mid_to_local[local_idx]));
    }
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
    __sync_fetch_and_add(&fwd->total_dropped, 1);
}

static void *local_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
    uint64_t trace_counter = 0;
    pin_cpu(NE_CPU_LOC);

    while (running) {
        ne_drain_cq_local(&fwd->pair);
        ne_refill_fq_local(&fwd->pair);
        for (int li = 0; li < fwd->local_count; li++)
            (void)ne_tx_drain_local(&fwd->pair, &fwd->mid_to_local[li], li);

        int rcvd = ne_recv_local(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        if (trace_hit(&trace_counter)) {
            fprintf(stderr,
                    "[TRACE LOCAL-RX] batch=%d local_to_mid_before=%u mid_to_local0=%u\n",
                    rcvd, ne_ring_count(&fwd->local_to_mid),
                    fwd->local_count > 0 ? ne_ring_count(&fwd->mid_to_local[0]) : 0);
        }
        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->local_to_mid, &batch[i]) != 0) {
                fprintf(stderr,
                        "[TRACE LOCAL-RX-DROP] reason=local_to_mid_full len=%u ring=%u\n",
                        batch[i].len, ne_ring_count(&fwd->local_to_mid));
                ne_frame_free(&fwd->pair, batch[i].addr);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_ring_full, 1);
            } else {
                __sync_fetch_and_add(&fwd->local_rx_to_mid, 1);
            }
        }
        ne_recv_release_local(&fwd->pair, (uint32_t)rcvd);
    }
    return NULL;
}

static void *wan_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
    uint64_t tx_trace_counter = 0;
    uint64_t rx_trace_counter = 0;
    pin_cpu(NE_CPU_WAN);

    while (running) {
        ne_drain_cq_wan(&fwd->pair);
        ne_refill_fq_wan(&fwd->pair);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (fwd->wan_tx_cooldown[wi] > 0)
                fwd->wan_tx_cooldown[wi]--;
            uint32_t before = ne_ring_count(&fwd->mid_to_wan[wi]);
            uint64_t no_free_before = fwd->pair.wans[wi].tx_no_free;
            int sent = ne_tx_drain_wan(&fwd->pair, &fwd->mid_to_wan[wi], wi);
            if (sent > 0) {
                fwd->wan_tx_stuck[wi] = 0;
            } else if (before > 0 && fwd->pair.wans[wi].tx_no_free != no_free_before) {
                uint64_t stuck = __sync_add_and_fetch(&fwd->wan_tx_stuck[wi], 1);
                if (before >= fwd->mid_to_wan[wi].cap && stuck >= 1024) {
                    uint32_t dropped = flush_wan_queue(fwd, wi);
                    fwd->wan_tx_cooldown[wi] = 65535;
                    fwd->wan_tx_stuck[wi] = 0;
                    fprintf(stderr,
                            "[TRACE WAN-TX-FAULT] wan=%d if=%s tx_no_free_stuck dropped_queue=%u cooldown=%u tx_packets=%llu\n",
                            wi, fwd->pair.wans[wi].ifname, dropped,
                            fwd->wan_tx_cooldown[wi],
                            (unsigned long long)fwd->pair.wans[wi].tx_packets);
                }
            }
            if ((sent > 0 || before > 0) && trace_hit(&tx_trace_counter)) {
                fprintf(stderr,
                        "[TRACE WAN-TX-DRAIN] wan=%d if=%s ring_before=%u sent=%d ring_after=%u tx_packets=%llu no_free=%llu reserve_fail=%llu cooldown=%u\n",
                        wi, fwd->pair.wans[wi].ifname, before, sent,
                        ne_ring_count(&fwd->mid_to_wan[wi]),
                        (unsigned long long)fwd->pair.wans[wi].tx_packets,
                        (unsigned long long)fwd->pair.wans[wi].tx_no_free,
                        (unsigned long long)fwd->pair.wans[wi].tx_reserve_fail,
                        fwd->wan_tx_cooldown[wi]);
            }
        }

        int rcvd = ne_recv_wan(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        if (trace_hit(&rx_trace_counter)) {
            fprintf(stderr,
                    "[TRACE WAN-RX] batch=%d wan_to_mid_before=%u\n",
                    rcvd, ne_ring_count(&fwd->wan_to_mid));
        }
        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->wan_to_mid, &batch[i]) != 0) {
                fprintf(stderr,
                        "[TRACE WAN-RX-DROP] reason=wan_to_mid_full wan=%u len=%u ring=%u\n",
                        batch[i].wan_idx, batch[i].len, ne_ring_count(&fwd->wan_to_mid));
                ne_frame_free(&fwd->pair, batch[i].addr);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_ring_full, 1);
            } else {
                __sync_fetch_and_add(&fwd->wan_rx_to_mid, 1);
            }
        }
        ne_recv_release_wan(&fwd->pair, (uint32_t)rcvd);
    }
    return NULL;
}

static void *middle_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    uint64_t trace_counter = 0;
    pin_cpu(NE_CPU_MID);

    while (running) {
        int did_work = 0;

        pthread_mutex_lock(&runtime_lock);
        if (ne_ring_try_pop(&fwd->wan_to_mid, &job) == 0) {
            if (trace_hit(&trace_counter)) {
                fprintf(stderr,
                        "[TRACE MID] pop wan_to_mid len=%u wan=%u remaining=%u\n",
                        job.len, job.wan_idx, ne_ring_count(&fwd->wan_to_mid));
            }
            process_wan_packet(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid, &job) == 0) {
            if (trace_hit(&trace_counter)) {
                fprintf(stderr,
                        "[TRACE MID] pop local_to_mid len=%u remaining=%u\n",
                        job.len, ne_ring_count(&fwd->local_to_mid));
            }
            process_local_packet(fwd, job);
            did_work = 1;
        }
        if (++gc_tick >= 8192) {
            frag_table_gc(&wan_frag_l2);
            frag_table_gc(&wan_frag_l3);
            frag_table_gc(&wan_frag_l4);
            gc_tick = 0;
        }
        pthread_mutex_unlock(&runtime_lock);

        if (!did_work)
            sched_yield();
    }
    return NULL;
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0 || cfg->wan_count <= 0)
        return -1;

    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = cfg->wan_count;
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;

    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname,
                        cfg->locals[i].src_mac, cfg->locals[i].dst_mac);
    for (int i = 0; i < fwd->wan_count; i++)
        init_iface_meta(&fwd->wans[i], cfg->wans[i].ifname,
                        cfg->wans[i].src_mac, cfg->wans[i].dst_mac);

    interface_xdp_detach_all_from_config(cfg);
    interface_reset_redirect_maps();

    if (bridge_mac_prepare(cfg) != 0)
        return -1;

    if (rebuild_crypto_runtime(cfg) != 0)
        return -1;
    frag_table_init(&wan_frag_l2);
    frag_table_init(&wan_frag_l3);
    frag_table_init(&wan_frag_l4);

    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;

    if (ne_ring_init(&fwd->local_to_mid, NE_RING) != 0 ||
        ne_ring_init(&fwd->wan_to_mid, NE_RING) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }
    for (int i = 0; i < fwd->local_count; i++) {
        if (ne_ring_init(&fwd->mid_to_local[i], NE_RING) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        if (ne_ring_init(&fwd->mid_to_wan[i], NE_RING) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }

    init_wan_flow_table(fwd);

    (void)bridge_mac_install(fwd);

    running = 1;
    return 0;
}

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg)
        return -1;
    if (!same_topology(fwd->cfg, cfg)) {
        fprintf(stderr, "[RELOAD] topology changed; restart required\n");
        return -1;
    }

    pthread_mutex_lock(&runtime_lock);
    (void)bridge_mac_prepare(cfg);
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = cfg->wan_count;
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;
    (void)bridge_mac_install(fwd);
    if (fwd->wan_flow_table_ready)
        flow_table_cleanup(&fwd->wan_flow_table);
    init_wan_flow_table(fwd);
    int rc = rebuild_crypto_runtime(cfg);
    pthread_mutex_unlock(&runtime_lock);
    return rc;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (!fwd)
        return;
    ne_ring_destroy(&fwd->local_to_mid);
    ne_ring_destroy(&fwd->wan_to_mid);
    for (int i = 0; i < MAX_INTERFACES; i++)
        ne_ring_destroy(&fwd->mid_to_wan[i]);
    for (int i = 0; i < MAX_INTERFACES; i++)
        ne_ring_destroy(&fwd->mid_to_local[i]);
    if (fwd->wan_flow_table_ready) {
        flow_table_cleanup(&fwd->wan_flow_table);
        fwd->wan_flow_table_ready = 0;
    }
    ne_pair_close(&fwd->pair);
}

void forwarder_run(struct forwarder *fwd)
{
    if (!fwd || forwarder_should_stop())
        return;

    if (pthread_create(&fwd->local_thread, NULL, local_core_thread, fwd) != 0)
        return;
    if (pthread_create(&fwd->mid_thread, NULL, middle_core_thread, fwd) != 0) {
        running = 0;
        pthread_join(fwd->local_thread, NULL);
        return;
    }
    if (pthread_create(&fwd->wan_thread, NULL, wan_core_thread, fwd) != 0) {
        running = 0;
        pthread_join(fwd->local_thread, NULL);
        pthread_join(fwd->mid_thread, NULL);
        return;
    }

    fwd->threads_started = 1;
    pthread_join(fwd->local_thread, NULL);
    pthread_join(fwd->mid_thread, NULL);
    pthread_join(fwd->wan_thread, NULL);
    fwd->threads_started = 0;
}

void forwarder_stop(void)
{
    running = 0;
}

int forwarder_should_stop(void)
{
    return !running;
}

void forwarder_print_stats(struct forwarder *fwd)
{
    if (!fwd)
        return;
    uint64_t local_rx = 0;
    uint64_t local_tx = 0;
    for (int i = 0; i < fwd->local_count; i++) {
        local_rx += fwd->pair.locals[i].rx_packets;
        local_tx += fwd->pair.locals[i].tx_packets;
    }
    fprintf(stderr,
            "[STATS] local_rx=%llu local_tx=%llu local_to_wan=%llu wan_to_local=%llu dropped=%llu ring_full=%llu "
            "no_local=%llu local_tx_fail=%llu local_rx_to_mid=%llu wan_rx_to_mid=%llu\n",
            (unsigned long long)local_rx,
            (unsigned long long)local_tx,
            (unsigned long long)fwd->local_to_wan,
            (unsigned long long)fwd->wan_to_local,
            (unsigned long long)fwd->total_dropped,
            (unsigned long long)fwd->dropped_ring_full,
            (unsigned long long)fwd->dropped_no_local_match,
            (unsigned long long)fwd->dropped_local_tx_fail,
            (unsigned long long)fwd->local_rx_to_mid,
            (unsigned long long)fwd->wan_rx_to_mid);
    fprintf(stderr,
            "[STATS] local_path bypass=%llu encrypted=%llu split=%llu reflected_skip=%llu no_wan=%llu wan_l2=%llu policy_not_ready=%llu encrypt_fail=%llu wan_congested=%llu\n",
            (unsigned long long)fwd->local_bypass_to_wan,
            (unsigned long long)fwd->local_encrypted_to_wan,
            (unsigned long long)fwd->local_split_to_wan,
            (unsigned long long)fwd->local_reflected_drop,
            (unsigned long long)fwd->dropped_no_wan,
            (unsigned long long)fwd->dropped_wan_l2,
            (unsigned long long)fwd->dropped_policy_not_ready,
            (unsigned long long)fwd->dropped_encrypt_fail,
            (unsigned long long)fwd->dropped_wan_congested);
    interface_print_xdp_stats(&fwd->pair);
    for (int i = 0; i < fwd->local_count; i++) {
        fprintf(stderr,
                "[STATS] local[%d]=%s mid_to_local=%u tx_packets=%llu rx_packets=%llu tx_no_free=%llu tx_reserve_fail=%llu tx_submit=%llu tx_popped=%llu cq=%llu fq_no_slots=%llu fq_pool_empty=%llu fq_reserve_fail=%llu fq_refill=%llu\n",
                i, fwd->pair.locals[i].ifname,
                ne_ring_count(&fwd->mid_to_local[i]),
                (unsigned long long)fwd->pair.locals[i].tx_packets,
                (unsigned long long)fwd->pair.locals[i].rx_packets,
                (unsigned long long)fwd->pair.locals[i].tx_no_free,
                (unsigned long long)fwd->pair.locals[i].tx_reserve_fail,
                (unsigned long long)fwd->pair.locals[i].tx_submit_calls,
                (unsigned long long)fwd->pair.locals[i].tx_popped,
                (unsigned long long)fwd->pair.locals[i].cq_packets,
                (unsigned long long)fwd->pair.locals[i].fq_no_slots,
                (unsigned long long)fwd->pair.locals[i].fq_pool_empty,
                (unsigned long long)fwd->pair.locals[i].fq_reserve_fail,
                (unsigned long long)fwd->pair.locals[i].fq_refill_packets);
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        fprintf(stderr,
                "[STATS] wan[%d]=%s mid_to_wan=%u tx_packets=%llu rx_packets=%llu tx_no_free=%llu tx_reserve_fail=%llu tx_submit=%llu tx_popped=%llu cq=%llu fq_no_slots=%llu fq_pool_empty=%llu fq_reserve_fail=%llu fq_refill=%llu stuck=%llu cooldown=%u flushes=%llu queue_dropped=%llu\n",
                i, fwd->pair.wans[i].ifname,
                ne_ring_count(&fwd->mid_to_wan[i]),
                (unsigned long long)fwd->pair.wans[i].tx_packets,
                (unsigned long long)fwd->pair.wans[i].rx_packets,
                (unsigned long long)fwd->pair.wans[i].tx_no_free,
                (unsigned long long)fwd->pair.wans[i].tx_reserve_fail,
                (unsigned long long)fwd->pair.wans[i].tx_submit_calls,
                (unsigned long long)fwd->pair.wans[i].tx_popped,
                (unsigned long long)fwd->pair.wans[i].cq_packets,
                (unsigned long long)fwd->pair.wans[i].fq_no_slots,
                (unsigned long long)fwd->pair.wans[i].fq_pool_empty,
                (unsigned long long)fwd->pair.wans[i].fq_reserve_fail,
                (unsigned long long)fwd->pair.wans[i].fq_refill_packets,
                (unsigned long long)fwd->wan_tx_stuck[i],
                fwd->wan_tx_cooldown[i],
                (unsigned long long)fwd->wan_tx_flushes[i],
                (unsigned long long)fwd->wan_tx_dropped[i]);
    }
}
