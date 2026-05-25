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

static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

void forwarder_pin_cpu(void)
{
    pin_cpu(NE_PIPE_CPU_LOCAL);
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

static int same_topology(const struct app_config *a, const struct app_config *b)
{
    if (!a || !b)
        return 0;
    if (a->local_count != b->local_count || a->wan_count != b->wan_count)
        return 0;
    if (a->local_count <= 0 || a->wan_count <= 0)
        return 0;
    return strcmp(a->locals[0].ifname, b->locals[0].ifname) == 0 &&
           strcmp(a->wans[0].ifname, b->wans[0].ifname) == 0;
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
    iface->ring_size = NE_PIPE_RING;
    iface->batch_size = NE_PIPE_BATCH;
    iface->frame_size = DEFAULT_FRAME_SIZE;
    memcpy(iface->src_mac, src_mac, MAC_LEN);
    memcpy(iface->dst_mac, dst_mac, MAC_LEN);
}

static int set_wan_l2(struct forwarder *fwd, uint8_t *pkt)
{
    if (config_wan_bridge_mode(fwd->cfg))
        return 0;
    const struct wan_config *wan = &fwd->cfg->wans[0];
    if (memcmp(wan->dst_mac, "\0\0\0\0\0\0", MAC_LEN) == 0)
        return -1;
    memcpy(pkt, wan->dst_mac, MAC_LEN);
    memcpy(pkt + MAC_LEN, wan->src_mac, MAC_LEN);
    return 0;
}

static int set_local_l2(struct forwarder *fwd, int local_idx, uint8_t *pkt)
{
    const struct xsk_interface *local = &fwd->locals[local_idx];
    if (memcmp(local->dst_mac, "\0\0\0\0\0\0", MAC_LEN) == 0)
        return -1;
    memcpy(pkt, local->dst_mac, MAC_LEN);
    memcpy(pkt + MAC_LEN, local->src_mac, MAC_LEN);
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

static int emit_copy(struct forwarder *fwd, struct ne_ring *dst,
                     const uint8_t *data, uint32_t len, uint8_t dir)
{
    if (len > fwd->pair.frame_size)
        return -1;
    struct ne_packet out = { .len = len, .dir = dir };
    if (ne_frame_alloc(&fwd->pair, &out.addr) != 0)
        return -1;
    memcpy(ne_packet_data(&fwd->pair, out.addr), data, len);
    return emit_owned(fwd, dst, &out);
}

static int encrypt_split_or_single(struct forwarder *fwd, struct ne_packet *job,
                                   const struct crypto_policy *cp)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job->addr);
    uint32_t pkt_len = job->len;
    int sent_split = 0;

    if (cp->action == POLICY_ACTION_ENCRYPT_L2 && frag_need_split_l2(pkt_len)) {
        uint8_t f1[4096], f2[4096];
        uint32_t l1 = 0, l2 = 0;
        if (frag_split_and_encrypt_l2(&policy_crypto_ctx[cp - fwd->cfg->policies],
                                      pkt, pkt_len, f1, &l1, f2, &l2) != 0)
            return -1;
        if (set_wan_l2(fwd, f1) != 0 || set_wan_l2(fwd, f2) != 0)
            return -1;
        if (emit_copy(fwd, &fwd->mid_to_wan, f2, l2, NE_DIR_WAN) != 0)
            return -1;
        memcpy(pkt, f1, l1);
        job->len = l1;
        sent_split = 1;
    } else if (cp->action == POLICY_ACTION_ENCRYPT_L3 && frag_need_split(pkt_len)) {
        uint8_t f1[4096], f2[4096];
        uint32_t l1 = 0, l2 = 0;
        if (frag_split_and_encrypt(&policy_crypto_ctx[cp - fwd->cfg->policies],
                                   pkt, pkt_len, f1, &l1, f2, &l2) != 0)
            return -1;
        if (set_wan_l2(fwd, f1) != 0 || set_wan_l2(fwd, f2) != 0)
            return -1;
        if (emit_copy(fwd, &fwd->mid_to_wan, f2, l2, NE_DIR_WAN) != 0)
            return -1;
        memcpy(pkt, f1, l1);
        job->len = l1;
        sent_split = 1;
    } else if (cp->action == POLICY_ACTION_ENCRYPT_L4 && frag_need_split_l4(pkt_len)) {
        uint8_t f1[4096], f2[4096];
        uint32_t l1 = 0, l2 = 0;
        if (frag_split_and_encrypt_l4(&policy_crypto_ctx[cp - fwd->cfg->policies],
                                      pkt, pkt_len, f1, &l1, f2, &l2) != 0)
            return -1;
        if (set_wan_l2(fwd, f1) != 0 || set_wan_l2(fwd, f2) != 0)
            return -1;
        if (emit_copy(fwd, &fwd->mid_to_wan, f2, l2, NE_DIR_WAN) != 0)
            return -1;
        memcpy(pkt, f1, l1);
        job->len = l1;
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
    return 0;
}

static void process_local_packet(struct forwarder *fwd, struct ne_packet job)
{
    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int flow_ok = (parse_flow(pkt, job.len, &src_ip, &dst_ip, &src_port, &dst_port, &proto) == 0);
    int profile_idx = config_select_profile_for_local(fwd->cfg, 0);

    if (config_wan_bridge_mode(fwd->cfg))
        bridge_mac_learn_rx(fwd, 0, pkt, job.len);

    if (set_wan_l2(fwd, pkt) != 0)
        goto drop;

    if (fwd->cfg->crypto_enabled) {
        const struct crypto_policy *cp = NULL;
        if (flow_ok)
            cp = config_select_crypto_policy(fwd->cfg, profile_idx, src_ip, dst_ip,
                                             src_port, dst_port, proto);
        if (!cp) {
            if (fwd->cfg->policy_count > 0)
                goto drop;
        } else if (cp->action != POLICY_ACTION_BYPASS) {
            int pi = (int)(cp - fwd->cfg->policies);
            if (pi < 0 || pi >= MAX_CRYPTO_POLICIES || !policy_crypto_ready[pi])
                goto drop;
            crypto_apply_from_policy(cp);
            if (encrypt_split_or_single(fwd, &job, cp) != 0)
                goto drop;
        }
    }

    job.dir = NE_DIR_WAN;
    if (emit_owned(fwd, &fwd->mid_to_wan, &job) == 0)
        __sync_fetch_and_add(&fwd->local_to_wan, 1);
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
    if (config_wan_bridge_mode(fwd->cfg)) {
        bridge_wan_rx_normalize_eth_ipv4(pkt, pkt_len);
        if (fwd->local_count == 1)
            return 0;
        return bridge_mac_local_for_dmac(fwd, pkt, pkt_len);
    }

    uint32_t dst_ip = get_dest_ip(pkt, pkt_len);
    if (!dst_ip)
        return -1;
    return config_find_local_for_ip(fwd->cfg, dst_ip);
}

static void process_wan_packet(struct forwarder *fwd, struct ne_packet job)
{
    int dec = decrypt_wan_packet(fwd, &job);
    if (dec == 1) {
        ne_frame_free(&fwd->pair, job.addr);
        return;
    }
    if (dec != 0)
        goto drop;

    uint8_t *pkt = ne_packet_data(&fwd->pair, job.addr);
    int local_idx = pick_local_for_packet(fwd, pkt, job.len);
    if (local_idx < 0 || local_idx >= fwd->local_count) {
        __sync_fetch_and_add(&fwd->dropped_no_local_match, 1);
        goto drop;
    }
    if (set_local_l2(fwd, local_idx, pkt) != 0) {
        __sync_fetch_and_add(&fwd->dropped_local_tx_fail, 1);
        goto drop;
    }

    job.dir = NE_DIR_LOCAL;
    if (emit_owned(fwd, &fwd->mid_to_local, &job) == 0)
        __sync_fetch_and_add(&fwd->wan_to_local, 1);
    return;

drop:
    ne_frame_free(&fwd->pair, job.addr);
    __sync_fetch_and_add(&fwd->total_dropped, 1);
}

static void *local_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_PIPE_BATCH];
    pin_cpu(NE_PIPE_CPU_LOCAL);

    while (running) {
        ne_drain_cq_local(&fwd->pair);
        ne_refill_fq_local(&fwd->pair);
        (void)ne_tx_drain_local(&fwd->pair, &fwd->mid_to_local);

        int rcvd = ne_recv_local(&fwd->pair, batch, NE_PIPE_BATCH);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->local_to_mid, &batch[i]) != 0) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_ring_full, 1);
            }
        }
        ne_recv_release_local(&fwd->pair, (uint32_t)rcvd);
    }
    return NULL;
}

static void *wan_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_PIPE_BATCH];
    pin_cpu(NE_PIPE_CPU_WAN);

    while (running) {
        ne_drain_cq_wan(&fwd->pair);
        ne_refill_fq_wan(&fwd->pair);
        (void)ne_tx_drain_wan(&fwd->pair, &fwd->mid_to_wan);

        int rcvd = ne_recv_wan(&fwd->pair, batch, NE_PIPE_BATCH);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->wan_to_mid, &batch[i]) != 0) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                __sync_fetch_and_add(&fwd->total_dropped, 1);
                __sync_fetch_and_add(&fwd->dropped_ring_full, 1);
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
    pin_cpu(NE_PIPE_CPU_MID);

    while (running) {
        int did_work = 0;

        pthread_mutex_lock(&runtime_lock);
        if (ne_ring_try_pop(&fwd->wan_to_mid, &job) == 0) {
            process_wan_packet(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid, &job) == 0) {
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

    if (config_wan_bridge_mode(cfg) && bridge_mac_prepare(cfg) != 0)
        return -1;

    if (rebuild_crypto_runtime(cfg) != 0)
        return -1;
    frag_table_init(&wan_frag_l2);
    frag_table_init(&wan_frag_l3);
    frag_table_init(&wan_frag_l4);

    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;

    if (ne_ring_init(&fwd->local_to_mid, NE_PIPE_RING) != 0 ||
        ne_ring_init(&fwd->wan_to_mid, NE_PIPE_RING) != 0 ||
        ne_ring_init(&fwd->mid_to_wan, NE_PIPE_RING) != 0 ||
        ne_ring_init(&fwd->mid_to_local, NE_PIPE_RING) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }

    if (config_wan_bridge_mode(cfg))
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
    if (config_wan_bridge_mode(cfg))
        (void)bridge_mac_prepare(cfg);
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = cfg->wan_count;
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;
    if (config_wan_bridge_mode(cfg))
        (void)bridge_mac_install(fwd);
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
    ne_ring_destroy(&fwd->mid_to_wan);
    ne_ring_destroy(&fwd->mid_to_local);
    ne_pair_close(&fwd->pair);
    bridge_mac_shutdown();
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
    fprintf(stderr,
            "[STATS] local_to_wan=%llu wan_to_local=%llu dropped=%llu ring_full=%llu "
            "no_local=%llu local_tx_fail=%llu\n",
            (unsigned long long)fwd->local_to_wan,
            (unsigned long long)fwd->wan_to_local,
            (unsigned long long)fwd->total_dropped,
            (unsigned long long)fwd->dropped_ring_full,
            (unsigned long long)fwd->dropped_no_local_match,
            (unsigned long long)fwd->dropped_local_tx_fail);
}
