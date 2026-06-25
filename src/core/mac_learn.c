#include "../../inc/core/mac_learn.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/crypto_route.h"
#include "../../inc/core/config.h"

#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* --- config --- */

#define MAC_LEARN_TEST_SEED 0

#define MAC_LEARN_ENTRY_TTL_MS  (300000u)

#if MAC_LEARN_TEST_SEED
struct mac_learn_test_seed {
    const char *local_ifname;
    uint8_t learned_mac[MAC_LEN];
};

static const struct mac_learn_test_seed mac_learn_test_seeds[] = {
    { "enp5s0", { 0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4e } },
    { "enp6s0", { 0x20, 0x7c, 0x14, 0xf8, 0x0d, 0x4f } },
};
#endif

/* --- internal: time --- */

static uint64_t monotonic_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ((uint64_t)ts.tv_sec * 1000ull) + ((uint64_t)ts.tv_nsec / 1000000ull);
}

/* --- internal: MAC table --- */

static uint8_t mac_hash_key(const uint8_t mac[MAC_LEN])
{
    return mac[5];
}

static void hash_rebuild_locked(struct mac_learn_table *t)
{
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    for (int i = 0; i < t->count; i++) {
        uint8_t b = mac_hash_key(t->list[i].mac);
        t->hash_next[i] = t->hash_head[b];
        t->hash_head[b] = i;
    }
}

static int find_idx_by_mac_locked(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN])
{
    uint8_t b = mac_hash_key(mac);

    for (int i = t->hash_head[b]; i >= 0; i = t->hash_next[i]) {
        if (memcmp(t->list[i].mac, mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

static void upsert_locked(struct mac_learn_table *t, const char *ifname,
                          const uint8_t mac[MAC_LEN], uint64_t now_ms)
{
    int i = find_idx_by_mac_locked(t, mac);

    if (i >= 0) {
        strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
        t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
        t->list[i].last_seen_ms = now_ms;
        return;
    }
    if (t->count >= MAC_LEARN_MAX_ENTRIES)
        return;

    i = t->count++;
    memcpy(t->list[i].mac, mac, MAC_LEN);
    strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
    t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
    t->list[i].last_seen_ms = now_ms;

    {
        uint8_t b = mac_hash_key(mac);
        t->hash_next[i] = t->hash_head[b];
        t->hash_head[b] = i;
    }
}

static void table_init(struct mac_learn_table *t)
{
    memset(t, 0, sizeof(*t));
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    pthread_spin_init(&t->lock, PTHREAD_PROCESS_PRIVATE);
}

static void table_learn(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    uint64_t now_ms;

    if (!t || !ifname || !mac || ifname[0] == '\0')
        return;
    now_ms = monotonic_ms();
    pthread_spin_lock(&t->lock);
    upsert_locked(t, ifname, mac, now_ms);
    pthread_spin_unlock(&t->lock);
}

static int table_lookup(struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
                        char ifname[IF_NAMESIZE])
{
    int i;

    if (!t || !mac || !ifname)
        return -1;
    pthread_spin_lock(&t->lock);
    i = find_idx_by_mac_locked(t, mac);
    if (i < 0) {
        pthread_spin_unlock(&t->lock);
        return -1;
    }
    strncpy(ifname, t->list[i].ifname, IF_NAMESIZE - 1);
    ifname[IF_NAMESIZE - 1] = '\0';
    pthread_spin_unlock(&t->lock);
    return 0;
}

static int ifname_in_profile_locals(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname || !ifname[0])
        return 0;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *prof = &cfg->profiles[pi];

        if (!prof->enabled)
            continue;
        for (int i = 0; i < prof->local_count; i++) {
            int li = prof->local_indices[i];
            if (li < 0 || li >= cfg->local_count)
                continue;
            if (strcmp(cfg->locals[li].ifname, ifname) == 0)
                return 1;
        }
    }
    return 0;
}

static void table_purge_orphan_locked(struct mac_learn_table *t, const struct app_config *cfg)
{
    int w = 0;

    if (!t || !cfg)
        return;

    for (int i = 0; i < t->count; i++) {
        if (ifname_in_profile_locals(cfg, t->list[i].ifname)) {
            if (w != i)
                t->list[w] = t->list[i];
            w++;
        }
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

static void table_expire_stale_locked(struct mac_learn_table *t, uint64_t now_ms, uint64_t ttl_ms)
{
    int w = 0;

    if (!t)
        return;

    for (int i = 0; i < t->count; i++) {
        if (now_ms - t->list[i].last_seen_ms <= ttl_ms) {
            if (w != i)
                t->list[w] = t->list[i];
            w++;
        }
    }
    if (w != t->count) {
        t->count = w;
        hash_rebuild_locked(t);
    }
}

static void table_maintain(struct mac_learn_table *t, const struct app_config *cfg)
{
    uint64_t now_ms;

    if (!t)
        return;
    now_ms = monotonic_ms();
    pthread_spin_lock(&t->lock);
    table_purge_orphan_locked(t, cfg);
    table_expire_stale_locked(t, now_ms, MAC_LEARN_ENTRY_TTL_MS);
    pthread_spin_unlock(&t->lock);
}

#if MAC_LEARN_TEST_SEED
static void table_apply_test_seed(struct mac_learn_table *t)
{
    if (!t)
        return;
    for (size_t i = 0; i < sizeof(mac_learn_test_seeds) / sizeof(mac_learn_test_seeds[0]); i++) {
        const struct mac_learn_test_seed *s = &mac_learn_test_seeds[i];
        table_learn(t, s->local_ifname, s->learned_mac);
        fprintf(stderr, "[MAC-TEST] learned %02x:%02x:%02x:%02x:%02x:%02x -> %s\n",
                s->learned_mac[0], s->learned_mac[1], s->learned_mac[2],
                s->learned_mac[3], s->learned_mac[4], s->learned_mac[5],
                s->local_ifname);
    }
}
#endif

/* --- internal: WAN forward --- */

static int local_idx_by_ifname(struct forwarder *fwd, const char *ifname)
{
    for (int i = 0; i < fwd->local_count; i++) {
        if (strcmp(fwd->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int eth_dmac_is_unicast(const uint8_t *pkt)
{
    return (pkt[0] & 0x01u) == 0;
}

static int profile_owns_local(const struct app_config *cfg, int profile_pi, int local_idx)
{
    const struct profile_config *prof;

    if (!cfg || profile_pi < 0 || profile_pi >= cfg->profile_count)
        return 0;
    prof = &cfg->profiles[profile_pi];
    if (!prof->enabled)
        return 0;
    for (int i = 0; i < prof->local_count; i++) {
        if (prof->local_indices[i] == local_idx)
            return 1;
    }
    return 0;
}

static int profile_pi_for_wire_policy(struct forwarder *fwd, uint8_t wire_id)
{
    int profile_id;

    if (!fwd || !fwd->cfg)
        return -1;
    profile_id = fwd_crypto_profile_id_for_wire_id(wire_id);
    if (profile_id < 0)
        return -1;
    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        if (fwd->cfg->profiles[pi].id == profile_id)
            return pi;
    }
    return -1;
}

static int pick_local_idx(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    char ifname[IF_NAMESIZE];

    if (!fwd || !pkt || len < 14u)
        return -1;
    if (table_lookup(&fwd->mac_table, pkt, ifname) != 0)
        return -1;
    return local_idx_by_ifname(fwd, ifname);
}

static int flood_to_profile_locals(struct forwarder *fwd, struct ne_packet *job,
                                   const uint8_t *pkt, int profile_pi)
{
    const struct profile_config *prof;
    int wi;
    int sent = 0;
    uint16_t sent_mask = 0;

    if (!fwd || !job || !pkt || !fwd->cfg || profile_pi < 0 ||
        profile_pi >= fwd->cfg->profile_count)
        return -1;

    prof = &fwd->cfg->profiles[profile_pi];
    if (!prof->enabled || prof->local_count <= 0)
        return -1;

    wi = dp_crypto_current_worker_idx();

    for (int i = 0; i < prof->local_count; i++) {
        int li = prof->local_indices[i];
        struct ne_ring *ring;

        if (li < 0 || li >= fwd->local_count)
            continue;
        if (li < (int)(sizeof(sent_mask) * 8) && (sent_mask & (1u << li)) != 0)
            continue;

        ring = &fwd->mid_to_local[li][wi];

        if (sent == 0) {
            job->dir = NE_DIR_LOCAL;
            job->local_idx = (uint8_t)li;
            if (ne_ring_try_push(ring, job) != 0)
                return -1;
            sent = 1;
        } else {
            struct ne_packet clone = {
                .len = job->len,
                .dir = NE_DIR_LOCAL,
                .local_idx = (uint8_t)li,
            };
            if (ne_frame_alloc(&fwd->pair, &clone.addr) != 0)
                return -1;
            memcpy(ne_packet_data(&fwd->pair, clone.addr), pkt, job->len);
            if (ne_ring_try_push(ring, &clone) != 0) {
                ne_frame_free(&fwd->pair, clone.addr);
                return -1;
            }
        }
        if (li < (int)(sizeof(sent_mask) * 8))
            sent_mask |= (1u << li);
    }
    return sent > 0 ? 0 : -1;
}

static int wan_profile_pi_bypass(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    int best_pi = -1;
    int best_pri = 0x7fffffff;
    int best_id = 0x7fffffff;

    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0)
        return -1;

    for (int pi = 0; pi < fwd->cfg->profile_count; pi++) {
        const struct profile_config *prof = &fwd->cfg->profiles[pi];
        const struct crypto_policy *cp;

        if (!prof->enabled)
            continue;
        cp = config_select_crypto_policy(fwd->cfg, pi, src_ip, dst_ip,
                                         src_port, dst_port, proto);
        if (!cp || cp->action != POLICY_ACTION_BYPASS)
            continue;
        if (best_pi < 0 || cp->priority < best_pri ||
            (cp->priority == best_pri && cp->id < best_id)) {
            best_pi = pi;
            best_pri = cp->priority;
            best_id = cp->id;
        }
    }
    return best_pi;
}

static int wan_profile_pi(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint8_t pol = 0;

    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (fwd_crypto_has_l2_marker(pkt, len))
        return profile_pi_for_wire_policy(fwd, pkt[CRYPTO_L2_POLICY_OFF]);
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return profile_pi_for_wire_policy(fwd, pol);
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return profile_pi_for_wire_policy(fwd, pol);
    return wan_profile_pi_bypass(fwd, pkt, len);
}

static int wan_forward(struct forwarder *fwd, struct ne_packet *job, int profile_pi)
{
    uint8_t *pkt;
    int li;

    if (!fwd || !job)
        return -1;
    pkt = ne_packet_data(&fwd->pair, job->addr);
    if (!pkt || job->len < 14u)
        return -1;
    if (!eth_dmac_is_unicast(pkt))
        return -1;
    if (profile_pi < 0)
        return -1;

    li = pick_local_idx(fwd, pkt, job->len);
    if (li >= 0 && profile_owns_local(fwd->cfg, profile_pi, li)) {
        job->dir = NE_DIR_LOCAL;
        job->local_idx = (uint8_t)li;
        return dp_ring_push(fwd, &fwd->mid_to_local[li][dp_crypto_current_worker_idx()], job);
    }

    return flood_to_profile_locals(fwd, job, pkt, profile_pi);
}

/* --- public API --- */

void mac_learn_bootstrap(struct mac_learn_table *t)
{
    if (!t)
        return;
    table_init(t);
#if MAC_LEARN_TEST_SEED
    table_apply_test_seed(t);
#endif
}

void mac_learn_shutdown(struct mac_learn_table *t)
{
    if (!t)
        return;
    pthread_spin_destroy(&t->lock);
}

void mac_learn_tick(struct forwarder *fwd)
{
    if (!fwd)
        return;
    table_maintain(&fwd->mac_table, fwd->cfg);
}

void mac_learn_local(struct forwarder *fwd, int local_idx, const uint8_t *pkt)
{
    if (!fwd || !pkt || local_idx < 0 || local_idx >= fwd->local_count)
        return;
    table_learn(&fwd->mac_table, fwd->locals[local_idx].ifname, pkt + 6);
}

int mac_learn_wan(struct forwarder *fwd, struct ne_packet *job,
                  const uint8_t *wire_pkt, uint32_t wire_len)
{
    int profile_pi;

    if (!fwd || !job || !wire_pkt || wire_len < 14u)
        return -1;
    profile_pi = wan_profile_pi(fwd, wire_pkt, wire_len);
    return wan_forward(fwd, job, profile_pi);
}