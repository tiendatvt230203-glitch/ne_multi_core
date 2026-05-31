#include "../../inc/core/forwarder.h"

#include "../../inc/core/bridge_mac.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_dispatch.h"
#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"
#include "../../inc/crypto/pqc_l2_handshake.h"
#include "../../inc/crypto/pqc_handshake.h"

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
static int policy_profile_id_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
static struct crypto_policy active_policies[MAX_CRYPTO_POLICIES];
static int active_policy_count;
static struct packet_crypto_ctx prev_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
static int prev_policy_crypto_ready[MAX_CRYPTO_POLICIES];
static int prev_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
static int prev_policy_profile_id_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
static struct crypto_policy prev_active_policies[MAX_CRYPTO_POLICIES];
static int prev_active_policy_count;
static int prev_grace_active;
static uint64_t prev_grace_until_ms;

#define PROFILE_RELOAD_GRACE_MS 3000u

static struct frag_table profile_frag_l2[MAX_PROFILES];
static struct frag_table profile_frag_l3[MAX_PROFILES];
static struct frag_table profile_frag_l4[MAX_PROFILES];
static struct flow_table profile_flow_tables[MAX_PROFILES];
static int profile_flow_table_ready[MAX_PROFILES];
static int profile_flow_profile_id[MAX_PROFILES];

static int profile_slot_for_id(int profile_id)
{
    for (int i = 0; i < MAX_PROFILES; i++) {
        if (profile_flow_table_ready[i] && profile_flow_profile_id[i] == profile_id)
            return i;
    }
    return -1;
}

static int profile_slot_alloc(int profile_id)
{
    int slot = profile_slot_for_id(profile_id);
    if (slot >= 0)
        return slot;
    for (int i = 0; i < MAX_PROFILES; i++) {
        if (!profile_flow_table_ready[i]) {
            profile_flow_profile_id[i] = profile_id;
            return i;
        }
    }
    return -1;
}

static int ensure_profile_runtime_slots(struct app_config *cfg)
{
    if (!cfg)
        return -1;
    for (int pi = 0; pi < cfg->profile_count && pi < MAX_PROFILES; pi++) {
        int profile_id = cfg->profiles[pi].id;
        int slot = profile_slot_alloc(profile_id);
        if (slot < 0)
            return -1;
        if (!profile_flow_table_ready[slot]) {
            uint32_t windows[MAX_INTERFACES];
            memset(windows, 0, sizeof(windows));
            for (int wi = 0; wi < cfg->wan_count && wi < MAX_INTERFACES; wi++)
                windows[wi] = cfg->wans[wi].window_size;
            flow_table_init(&profile_flow_tables[slot], windows, cfg->wan_count);
            profile_flow_table_ready[slot] = 1;
            frag_table_init(&profile_frag_l2[slot]);
            frag_table_init(&profile_frag_l3[slot]);
            frag_table_init(&profile_frag_l4[slot]);
        }
    }
    return 0;
}

static void cleanup_stale_profile_slots(const struct app_config *cfg)
{
    if (!cfg || prev_grace_active)
        return;
    for (int s = 0; s < MAX_PROFILES; s++) {
        if (!profile_flow_table_ready[s])
            continue;
        int pid = profile_flow_profile_id[s];
        int still_active = 0;
        for (int pi = 0; pi < cfg->profile_count && pi < MAX_PROFILES; pi++) {
            if (cfg->profiles[pi].id == pid) {
                still_active = 1;
                break;
            }
        }
        if (still_active)
            continue;
        flow_table_cleanup(&profile_flow_tables[s]);
        profile_flow_table_ready[s] = 0;
        profile_flow_profile_id[s] = 0;
        memset(&profile_frag_l2[s], 0, sizeof(profile_frag_l2[s]));
        memset(&profile_frag_l3[s], 0, sizeof(profile_frag_l3[s]));
        memset(&profile_frag_l4[s], 0, sizeof(profile_frag_l4[s]));
    }
}

static uint64_t monotonic_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ULL) + ((uint64_t)ts.tv_nsec / 1000000ULL);
}

static void maybe_expire_prev_grace(void)
{
    if (!prev_grace_active)
        return;
    if (monotonic_ms() >= prev_grace_until_ms)
        prev_grace_active = 0;
}

static void snapshot_active_to_prev(void)
{
    memcpy(prev_policy_crypto_ctx, policy_crypto_ctx, sizeof(prev_policy_crypto_ctx));
    memcpy(prev_policy_crypto_ready, policy_crypto_ready, sizeof(prev_policy_crypto_ready));
    memcpy(prev_policy_index_by_action_id, policy_index_by_action_id, sizeof(prev_policy_index_by_action_id));
    memcpy(prev_policy_profile_id_by_action_id, policy_profile_id_by_action_id,
           sizeof(prev_policy_profile_id_by_action_id));
    memcpy(prev_active_policies, active_policies, sizeof(prev_active_policies));
    prev_active_policy_count = active_policy_count;
    prev_grace_active = (prev_active_policy_count > 0) ? 1 : 0;
    prev_grace_until_ms = monotonic_ms() + PROFILE_RELOAD_GRACE_MS;
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

void forwarder_pre_diversify_pqc_keys(int profile_id)
{
    for (int i = 0; i < active_policy_count; i++) {
        if (!policy_crypto_ready[i])
            continue;
        if (policy_crypto_ctx[i].crypto_mode != CRYPTO_MODE_PQC)
            continue;
        if (policy_crypto_ctx[i].profile_id != profile_id)
            continue;
        packet_crypto_update_keys(&policy_crypto_ctx[i]);
    }
}

static int rebuild_crypto_runtime(struct app_config *cfg)
{
    struct packet_crypto_ctx old_policy_crypto_ctx[MAX_CRYPTO_POLICIES];
    int old_policy_crypto_ready[MAX_CRYPTO_POLICIES];
    int old_policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L4 + 1][256];
    struct crypto_policy old_active_policies[MAX_CRYPTO_POLICIES];
    int old_active_policy_count = active_policy_count;
    memcpy(old_policy_crypto_ctx, policy_crypto_ctx, sizeof(old_policy_crypto_ctx));
    memcpy(old_policy_crypto_ready, policy_crypto_ready, sizeof(old_policy_crypto_ready));
    memcpy(old_policy_index_by_action_id, policy_index_by_action_id, sizeof(old_policy_index_by_action_id));
    memcpy(old_active_policies, active_policies, sizeof(old_active_policies));

    memset(policy_crypto_ready, 0, sizeof(policy_crypto_ready));
    memset(active_policies, 0, sizeof(active_policies));
    active_policy_count = 0;
    crypto_runtime_reset_indexes();
    memset(policy_profile_id_by_action_id, -1, sizeof(policy_profile_id_by_action_id));

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

        int reused = 0;
        if (cp->id >= 0 && cp->id <= 255) {
            int old_i = old_policy_index_by_action_id[cp->action][(uint8_t)cp->id];
            if (old_i >= 0 && old_i < old_active_policy_count && old_policy_crypto_ready[old_i]) {
                const struct crypto_policy *old_cp = &old_active_policies[old_i];
                if (old_cp->crypto_mode == cp->crypto_mode &&
                    old_cp->aes_bits == cp->aes_bits &&
                    old_cp->nonce_size == cp->nonce_size &&
                    memcmp(old_cp->key, cp->key, AES_KEY_LEN) == 0) {
                    policy_crypto_ctx[i] = old_policy_crypto_ctx[old_i];
                    policy_crypto_ready[i] = 1;
                    reused = 1;
                }
            }
        }
        if (reused)
            continue;

        if (cp->crypto_mode == CRYPTO_MODE_PQC) {
            memset(&policy_crypto_ctx[i], 0, sizeof(policy_crypto_ctx[i]));
            policy_crypto_ctx[i].initialized = true;
            policy_crypto_ctx[i].crypto_mode = CRYPTO_MODE_PQC;
            policy_crypto_ctx[i].policy_id = cp->id;
            policy_crypto_ready[i] = 1;
            continue;
        }
        if (!key_nonzero(cp->key, AES_KEY_LEN))
            continue;
        crypto_apply_from_policy(cp);
        if (packet_crypto_init(&policy_crypto_ctx[i], cp->key) == 0)
            policy_crypto_ready[i] = 1;
    }

    for (int pidx = 0; pidx < cfg->profile_count && pidx < MAX_PROFILES; pidx++) {
        const struct profile_config *p = &cfg->profiles[pidx];
        for (int j = 0; j < p->policy_count && j < MAX_CRYPTO_POLICIES; j++) {
            int pi = p->policy_indices[j];
            if (pi < 0 || pi >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pi];
            if (!crypto_action_valid(cp->action))
                continue;
            if (cp->id >= 0 && cp->id <= 255) {
                int old_pid = policy_profile_id_by_action_id[cp->action][(uint8_t)cp->id];
                if (old_pid > 0 && old_pid != p->id) {
                    fprintf(stderr,
                            "[RELOAD] policy id collision action=%d id=%d profile=%d conflicts with profile=%d\n",
                            cp->action, cp->id, p->id, old_pid);
                    return -1;
                }
                policy_profile_id_by_action_id[cp->action][(uint8_t)cp->id] = p->id;
            }
            if (cp->crypto_mode == CRYPTO_MODE_PQC && policy_crypto_ready[pi]) {
                policy_crypto_ctx[pi].profile_id = p->id;
                policy_crypto_ctx[pi].policy_id = cp->id;
                if (sig_pqc_profile_binding_key_ready(p->id))
                    packet_crypto_update_keys(&policy_crypto_ctx[pi]);
            }
        }
    }

    crypto_apply_default_from_cfg(cfg);
    return 0;
}

static struct crypto_dispatch_ctx make_dispatch_ctx(void)
{
    struct crypto_dispatch_ctx dctx;
    memset(&dctx, 0, sizeof(dctx));
    maybe_expire_prev_grace();
    dctx.base_ctx = &base_crypto_ctx;
    dctx.per_policy_ctx = policy_crypto_ctx;
    dctx.per_policy_ready = policy_crypto_ready;
    dctx.policies = active_policies;
    dctx.policy_count = active_policy_count;
    dctx.policy_index_by_action_id = policy_index_by_action_id;
    dctx.prev_per_policy_ctx = prev_policy_crypto_ctx;
    dctx.prev_per_policy_ready = prev_policy_crypto_ready;
    dctx.prev_policies = prev_active_policies;
    dctx.prev_policy_count = prev_active_policy_count;
    dctx.prev_policy_index_by_action_id = prev_policy_index_by_action_id;
    dctx.prev_grace_active = prev_grace_active;
    return dctx;
}

static struct packet_crypto_ctx *ctx_for_policy_action_id(int action, uint8_t id)
{
    maybe_expire_prev_grace();
    if (action < 0 || action > POLICY_ACTION_ENCRYPT_L4)
        return NULL;
    int pi = policy_index_by_action_id[action][id];
    if (pi >= 0 && pi < active_policy_count && policy_crypto_ready[pi]) {
        crypto_apply_from_policy(&active_policies[pi]);
        return &policy_crypto_ctx[pi];
    }
    if (prev_grace_active) {
        int ppi = prev_policy_index_by_action_id[action][id];
        if (ppi >= 0 && ppi < prev_active_policy_count && prev_policy_crypto_ready[ppi]) {
            crypto_apply_from_policy(&prev_active_policies[ppi]);
            return &prev_policy_crypto_ctx[ppi];
        }
    }
    return NULL;
}

static int profile_id_for_policy_action_id(int action, uint8_t id)
{
    maybe_expire_prev_grace();
    if (action < 0 || action > POLICY_ACTION_ENCRYPT_L4)
        return -1;
    int pid = policy_profile_id_by_action_id[action][id];
    if (pid > 0)
        return pid;
    if (prev_grace_active) {
        int old_pid = prev_policy_profile_id_by_action_id[action][id];
        if (old_pid > 0)
            return old_pid;
    }
    return -1;
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

static int same_topology(const struct app_config *a, const struct app_config *b)
{
    if (!a || !b)
        return 0;
    if (a->local_count != b->local_count || a->wan_count != b->wan_count)
        return 0;
    if (a->local_count <= 0 || a->wan_count <= 0)
        return 0;

    for (int i = 0; i < a->local_count; i++) {
        int found = 0;
        for (int j = 0; j < b->local_count; j++) {
            if (strcmp(a->locals[i].ifname, b->locals[j].ifname) == 0) {
                found = 1;
                break;
            }
        }
        if (!found)
            return 0;
    }
    for (int i = 0; i < a->wan_count; i++) {
        int found = 0;
        for (int j = 0; j < b->wan_count; j++) {
            if (strcmp(a->wans[i].ifname, b->wans[j].ifname) == 0) {
                found = 1;
                break;
            }
        }
        if (!found)
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
    iface->queue_count = 0;
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
    if (!fake || !pkt || pkt_len < ETH_HEADER_SIZE + CRYPTO_L2_POLICY_LEN)
        return 0;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et != fake)
        return 0;
    return policy_index_by_action_id[POLICY_ACTION_ENCRYPT_L2][pkt[CRYPTO_L2_POLICY_OFF]] >= 0;
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
        return -1;
    }
    return 0;
}

static int emit_local_to_wan(struct forwarder *fwd, struct ne_packet *job, int wan_idx)
{
    job->dir = NE_DIR_WAN;
    job->wan_idx = (uint8_t)wan_idx;
    return emit_owned(fwd, &fwd->mid_to_wan[wan_idx], job);
}

static int emit_split_pair_to_wan(struct forwarder *fwd, struct ne_packet *job,
                                  uint32_t frag0_len,
                                  const uint8_t *frag1, uint32_t frag1_len,
                                  int wan_idx)
{
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

    if (ne_ring_try_push(tx, job) != 0) {
        ne_frame_free(&fwd->pair, tail.addr);
        return -1;
    }
    if (ne_ring_try_push(tx, &tail) != 0) {
        ne_frame_free(&fwd->pair, tail.addr);
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
    return dropped;
}

static int fallback_wan_if_congested(struct forwarder *fwd, int profile_idx, int selected)
{
    if (wan_has_tx_room(fwd, selected))
        return selected;

    int best = -1;
    uint32_t best_depth = UINT32_MAX;
    int has_profile_pool = 0;

    if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
        struct profile_config *p = &fwd->cfg->profiles[profile_idx];
        int sumw = 0;
        for (int i = 0; i < p->wan_count; i++) {
            if (p->wan_bandwidth_weight[i] > 0)
                sumw += p->wan_bandwidth_weight[i];
        }
        has_profile_pool = p->wan_count > 0;
        for (int i = 0; i < p->wan_count; i++) {
            if (sumw > 0 && p->wan_bandwidth_weight[i] <= 0)
                continue;
            int dp = config_wan_cfg_to_dp(fwd->cfg, p->wan_indices[i]);
            if (dp < 0 || !wan_has_tx_room(fwd, dp))
                continue;
            uint32_t depth = ne_ring_count(&fwd->mid_to_wan[dp]);
            if (depth < best_depth) {
                best_depth = depth;
                best = dp;
            }
        }
    }

    if (best < 0 && !has_profile_pool) {
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

    if (best >= 0)
        return best;

    return selected;
}

static int select_wan_for_local(struct forwarder *fwd, int profile_idx, int flow_ok,
                                uint32_t src_ip, uint32_t dst_ip,
                                uint16_t src_port, uint16_t dst_port,
                                uint8_t proto, uint32_t pkt_len)
{
    if (!fwd || fwd->wan_count <= 0)
        return -1;
    if (profile_idx >= 0 && profile_idx < fwd->cfg->profile_count) {
        struct profile_config *p = &fwd->cfg->profiles[profile_idx];
        if (p->wan_count > 0) {
            int slot = profile_slot_for_id(p->id);
            int wan_idx;
            if (flow_ok && slot >= 0 && profile_flow_table_ready[slot]) {
                wan_idx = flow_table_get_wan_profile(&profile_flow_tables[slot],
                                                     src_ip, dst_ip, src_port, dst_port,
                                                     proto, pkt_len,
                                                     p->wan_indices, p->wan_count,
                                                     p->wan_bandwidth_weight);
            } else {
                wan_idx = flow_table_pick_wan_per_packet(p->wan_indices,
                                                         p->wan_bandwidth_weight,
                                                         p->wan_count);
            }
            if (wan_idx >= 0) {
                int dp = config_wan_cfg_to_dp(fwd->cfg, wan_idx);
                if (dp >= 0 && dp < fwd->wan_count) {
                    dp = fallback_wan_if_congested(fwd, profile_idx, dp);
                    return dp;
                }
            }
        }
    }
    return fallback_wan_if_congested(fwd, profile_idx, 0);
}

static int profile_contains_local(const struct profile_config *p, int local_idx)
{
    if (!p || local_idx < 0)
        return 0;
    for (int i = 0; i < p->local_count; i++) {
        if (p->local_indices[i] == local_idx)
            return 1;
    }
    return 0;
}

static int select_profile_and_policy_for_local(struct forwarder *fwd, int local_idx,
                                               int flow_ok,
                                               uint32_t src_ip, uint32_t dst_ip,
                                               uint16_t src_port, uint16_t dst_port,
                                               uint8_t proto,
                                               int *out_profile_idx,
                                               const struct crypto_policy **out_cp)
{
    if (!fwd || !fwd->cfg || !out_profile_idx || !out_cp)
        return -1;

    const struct crypto_policy *best_cp = NULL;
    int best_profile = -1;
    int best_priority = 0x7fffffff;
    int best_id = 0x7fffffff;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *p = &fwd->cfg->profiles[pi];
        if (!p->enabled)
            continue;
        if (!profile_contains_local(p, local_idx))
            continue;

        const struct crypto_policy *cp = NULL;
        if (flow_ok)
            cp = config_select_crypto_policy(fwd->cfg, pi, src_ip, dst_ip, src_port, dst_port, proto);
        if (!cp)
            continue;

        if (!best_cp ||
            cp->priority < best_priority ||
            (cp->priority == best_priority && cp->id < best_id)) {
            best_cp = cp;
            best_profile = pi;
            best_priority = cp->priority;
            best_id = cp->id;
        }
    }

    if (!best_cp || best_profile < 0)
        return -1;

    *out_profile_idx = best_profile;
    *out_cp = best_cp;
    return 0;
}

static void process_local_packet(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok = (parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0);
    int local_idx = job.local_idx < fwd->local_count ? job.local_idx : 0;
    if (local_rx_is_reflected_client_frame(fwd, local_idx, pkt, job.len)) {
        ne_frame_free(&fwd->pair, job.addr);
        return;
    }
    int profile_idx = -1;
    const struct crypto_policy *cp = NULL;
    if (select_profile_and_policy_for_local(fwd, local_idx, flow_ok,
                                            src_ip, dst_ip, src_port, dst_port, proto,
                                            &profile_idx, &cp) != 0)
        goto drop;

    int wan_idx = select_wan_for_local(fwd, profile_idx, flow_ok,
                                       src_ip, dst_ip, src_port, dst_port,
                                       proto, job.len);
    if (wan_idx < 0)
        goto drop;
    if (!wan_has_tx_room(fwd, wan_idx))
        goto drop;

    if (set_wan_l2(fwd, wan_idx, pkt) != 0)
        goto drop;

    if (cp->action == POLICY_ACTION_BYPASS) {
        (void)emit_local_to_wan(fwd, &job, wan_idx);
        return;
    }

    if (!fwd->cfg->crypto_enabled)
        goto drop;

    int pi = (int)(cp - fwd->cfg->policies);
    if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !policy_crypto_ready[pi])
        goto drop;
    crypto_apply_from_policy(cp);
    int enc_rc = encrypt_split_or_single(fwd, &job, cp, wan_idx);
    if (enc_rc < 0)
        goto drop;
    if (enc_rc > 0)
        return;
    (void)emit_local_to_wan(fwd, &job, wan_idx);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}

static int decrypt_l2_if_needed(struct forwarder *fwd, uint8_t *pkt, uint32_t *pkt_len)
{
    uint16_t fake = packet_crypto_get_fake_ethertype_ipv4();
    if (!fake || *pkt_len < ETH_HEADER_SIZE + CRYPTO_L2_POLICY_LEN)
        return 0;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et != fake)
        return 0;

    uint8_t policy_id = pkt[CRYPTO_L2_POLICY_OFF];
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
        uint8_t policy_id = pkt[CRYPTO_L2_POLICY_OFF];
        int profile_id = profile_id_for_policy_action_id(POLICY_ACTION_ENCRYPT_L2, policy_id);
        int slot = (profile_id > 0) ? profile_slot_for_id(profile_id) : -1;
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
        if (slot < 0)
            return -1;
        int rr = frag_try_reassemble_l2(&profile_frag_l2[slot], pkt, (uint32_t)nd, opid, ofidx,
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
            int profile_id = profile_id_for_policy_action_id(POLICY_ACTION_ENCRYPT_L3, policy_id);
            int slot = (profile_id > 0) ? profile_slot_for_id(profile_id) : -1;
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
            if (slot < 0)
                return -1;
            int rr = frag_try_reassemble(&profile_frag_l3[slot], pkt, (uint32_t)nd, opid, ofidx,
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
            int profile_id = profile_id_for_policy_action_id(POLICY_ACTION_ENCRYPT_L4, policy_id);
            int slot = (profile_id > 0) ? profile_slot_for_id(profile_id) : -1;
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
            if (slot < 0)
                return -1;
            int rr = frag_try_reassemble_l4(&profile_frag_l4[slot], pkt, (uint32_t)nd, opid, ofidx,
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
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    if (wan_packet_needs_crypto(fwd, pkt, job.len)) {
        int dec = decrypt_wan_packet(fwd, &job);
        if (dec == 1) {
            ne_frame_free(&fwd->pair, job.addr);
            return;
        }
        if (dec != 0)
            goto drop;
        pkt = ne_packet_data(&fwd->pair, job.addr);
    }

    int local_idx = pick_local_for_packet(fwd, pkt, job.len);
    if (local_idx < 0 || local_idx >= fwd->local_count)
        goto drop;
    if (set_local_l2(fwd, local_idx, pkt) != 0)
        goto drop;

    job.dir = NE_DIR_LOCAL;
    job.local_idx = (uint8_t)local_idx;
    (void)emit_owned(fwd, &fwd->mid_to_local[local_idx], &job);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
}

static void *local_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
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

        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->local_to_mid, &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_local(&fwd->pair);
    }
    return NULL;
}

static void *wan_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
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
                    (void)flush_wan_queue(fwd, wi);
                    fwd->wan_tx_cooldown[wi] = 65535;
                    fwd->wan_tx_stuck[wi] = 0;
                }
            }
        }

        int rcvd = ne_recv_wan(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->wan_to_mid, &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_wan(&fwd->pair);
    }
    return NULL;
}

static void *middle_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    pin_cpu(NE_CPU_MID);

    while (running) {
        int did_work = 0;

        pthread_mutex_lock(&runtime_lock);
        maybe_expire_prev_grace();
        cleanup_stale_profile_slots(fwd->cfg);
        if (ne_ring_try_pop(&fwd->wan_to_mid, &job) == 0) {
            process_wan_packet(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid, &job) == 0) {
            process_local_packet(fwd, job);
            did_work = 1;
        }
        if (++gc_tick >= 8192) {
            for (int s = 0; s < MAX_PROFILES; s++) {
                if (!profile_flow_table_ready[s])
                    continue;
                frag_table_gc(&profile_frag_l2[s]);
                frag_table_gc(&profile_frag_l3[s]);
                frag_table_gc(&profile_frag_l4[s]);
            }
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
    if (!fwd || !cfg || cfg->local_count <= 0 || config_count_dataplane_wans(cfg) <= 0)
        return -1;

    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = config_count_dataplane_wans(cfg);
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;
    
    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname,
                        cfg->locals[i].src_mac, cfg->locals[i].dst_mac);
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        fwd->wan_cfg_idx[di] = ci;
        init_iface_meta(&fwd->wans[di], cfg->wans[ci].ifname,
                        cfg->wans[ci].src_mac, cfg->wans[ci].dst_mac);
    }

    interface_xdp_detach_all_from_config(cfg);
    interface_reset_redirect_maps();

    if (bridge_mac_prepare(cfg) != 0)
        return -1;

    if (rebuild_crypto_runtime(cfg) != 0)
        return -1;

    /* Peer + policy ctx must be ready before HS thread derives into policy_crypto_ctx. */
    pqc_runtime_setup_profiles(cfg);
    pqc_handshake_start_all_profiles(cfg);

    memset(profile_flow_table_ready, 0, sizeof(profile_flow_table_ready));
    memset(profile_flow_profile_id, 0, sizeof(profile_flow_profile_id));
    if (ensure_profile_runtime_slots(cfg) != 0)
        return -1;
    prev_active_policy_count = 0;
    prev_grace_active = 0;
    prev_grace_until_ms = 0;
    memset(prev_policy_crypto_ready, 0, sizeof(prev_policy_crypto_ready));
    memset(prev_policy_index_by_action_id, -1, sizeof(prev_policy_index_by_action_id));
    memset(prev_active_policies, 0, sizeof(prev_active_policies));
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
    fwd->wan_count = config_count_dataplane_wans(cfg);
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0) {
            pthread_mutex_unlock(&runtime_lock);
            return -1;
        }
        fwd->wan_cfg_idx[di] = ci;
        init_iface_meta(&fwd->wans[di], cfg->wans[ci].ifname,
                        cfg->wans[ci].src_mac, cfg->wans[ci].dst_mac);
    }
    (void)bridge_mac_install(fwd);
    if (ensure_profile_runtime_slots(cfg) != 0) {
        pthread_mutex_unlock(&runtime_lock);
        return -1;
    }
    snapshot_active_to_prev();
    int rc = rebuild_crypto_runtime(cfg);
    if (rc == 0) {
        pqc_runtime_setup_profiles(cfg);
        pqc_handshake_start_all_profiles(cfg);
    }
    if (rc != 0)
        prev_grace_active = 0;
    cleanup_stale_profile_slots(cfg);
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
    for (int i = 0; i < MAX_PROFILES; i++) {
        if (profile_flow_table_ready[i]) {
            flow_table_cleanup(&profile_flow_tables[i]);
            profile_flow_table_ready[i] = 0;
            profile_flow_profile_id[i] = 0;
        }
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
    (void)fwd;
}