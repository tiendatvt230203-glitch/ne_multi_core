#include "../../inc/core/mac_learn.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/crypto_route.h"
#include "../../inc/db/db_env.h"

#include "../../inc/crypto/crypto_layer2.h"
#include "../../inc/crypto/crypto_layer3.h"
#include "../../inc/crypto/crypto_layer4.h"
#include "../../inc/crypto/crypto_policy_utils.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define MAC_LEARN_STATE_MAGIC 0x4e454d41u
#define MAC_LEARN_STATE_VER   1u

#define MAC_LEARN_TEST_SEED 0

#if MAC_LEARN_TEST_SEED
struct mac_learn_test_seed {
    const char *local_ifname;
    uint8_t learned_mac[MAC_LEN];
};

static const struct mac_learn_test_seed mac_learn_test_seeds[] = {
    { "eno5s0", { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 } },
    { "enp6s0", { 0x02, 0x00, 0x00, 0x00, 0x00, 0x02 } },
};
#endif

struct mac_learn_file_hdr {
    uint32_t magic;
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
};

static uint8_t mac_hash_key(const uint8_t mac[MAC_LEN])
{
    return mac[5];
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

static void upsert_locked(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    int i = find_idx_by_mac_locked(t, mac);

    if (i >= 0) {
        if (strncmp(t->list[i].ifname, ifname, IF_NAMESIZE) == 0)
            return;
        strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
        t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
        t->dirty = 1;
        return;
    }
    if (t->count >= MAC_LEARN_MAX_ENTRIES)
        return;

    i = t->count++;
    memcpy(t->list[i].mac, mac, MAC_LEN);
    strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
    t->list[i].ifname[IF_NAMESIZE - 1] = '\0';

    {
        uint8_t b = mac_hash_key(mac);
        t->hash_next[i] = t->hash_head[b];
        t->hash_head[b] = i;
    }
    t->dirty = 1;
}

static const struct crypto_policy *arp_match_policy(struct app_config *cfg, int local_idx,
                                                    uint32_t sender_ip, uint32_t target_ip)
{
    const struct crypto_policy *best = NULL;
    int best_pri = 0x7fffffff;
    int best_id = 0x7fffffff;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *prof = &cfg->profiles[pi];
        const struct crypto_policy *cp;
        int on_local = 0;

        if (!prof->enabled)
            continue;
        for (int i = 0; i < prof->local_count; i++) {
            if (prof->local_indices[i] == local_idx)
                on_local = 1;
        }
        if (!on_local)
            continue;

        cp = config_select_crypto_policy(cfg, pi, sender_ip, target_ip, 0, 0, 0);
        if (!cp)
            continue;
        if (!best || cp->priority < best_pri ||
            (cp->priority == best_pri && cp->id < best_id)) {
            best = cp;
            best_pri = cp->priority;
            best_id = cp->id;
        }
    }
    return best;
}

static int mac_learn_state_path(char *out, size_t outsz)
{
    if (!out || outsz == 0)
        return -1;
    snprintf(out, outsz, "%s/mac_learn.bin", NE_STATE_DIR);
    return 0;
}

void mac_learn_init(struct mac_learn_table *t)
{
    memset(t, 0, sizeof(*t));
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    pthread_spin_init(&t->lock, PTHREAD_PROCESS_PRIVATE);
}

void mac_learn(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    if (!t || !ifname || !mac)
        return;
    pthread_spin_lock(&t->lock);
    upsert_locked(t, ifname, mac);
    pthread_spin_unlock(&t->lock);
}

#if MAC_LEARN_TEST_SEED
static void mac_learn_apply_test_seed(struct mac_learn_table *t)
{
    if (!t)
        return;
    for (size_t i = 0; i < sizeof(mac_learn_test_seeds) / sizeof(mac_learn_test_seeds[0]); i++) {
        const struct mac_learn_test_seed *s = &mac_learn_test_seeds[i];
        mac_learn(t, s->local_ifname, s->learned_mac);
        fprintf(stderr, "[MAC-TEST] learned %02x:%02x:%02x:%02x:%02x:%02x -> %s\n",
                s->learned_mac[0], s->learned_mac[1], s->learned_mac[2],
                s->learned_mac[3], s->learned_mac[4], s->learned_mac[5],
                s->local_ifname);
    }
}
#endif

void mac_learn_arp(struct mac_learn_table *t, struct app_config *cfg, int local_idx,
                   const char *ifname, const uint8_t *pkt, uint32_t len)
{
    const uint8_t *arp;
    uint16_t ethertype;
    uint8_t sender_mac[MAC_LEN];
    uint32_t sender_ip;
    uint32_t target_ip;

    if (!t || !cfg || !ifname || !pkt)
        return;
    if (len < 14u + 28u)
        return;

    ethertype = (uint16_t)((pkt[12] << 8) | pkt[13]);
    if (ethertype != 0x0806u)
        return;

    arp = pkt + 14;
    if (arp[0] != 0x00 || arp[1] != 0x01 || arp[2] != 0x08 || arp[3] != 0x00)
        return;
    if (arp[4] != 6 || arp[5] != 4)
        return;

    memcpy(sender_mac, arp + 8, MAC_LEN);
    memcpy(&sender_ip, arp + 14, sizeof(sender_ip));
    memcpy(&target_ip, arp + 24, sizeof(target_ip));

    if (!arp_match_policy(cfg, local_idx, sender_ip, target_ip))
        return;

    pthread_spin_lock(&t->lock);
    upsert_locked(t, ifname, sender_mac);
    pthread_spin_unlock(&t->lock);
}

int mac_learn_lookup(struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
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

int mac_learn_load(struct mac_learn_table *t)
{
    char path[256];
    FILE *fp;
    struct mac_learn_file_hdr hdr;
    struct mac_learn_entry batch[MAC_LEARN_MAX_ENTRIES];
    size_t n;

    if (!t)
        return -1;
    if (mac_learn_state_path(path, sizeof(path)) != 0)
        return -1;

    fp = fopen(path, "rb");
    if (!fp) {
        if (errno == ENOENT) {
#if MAC_LEARN_TEST_SEED
            mac_learn_apply_test_seed(t);
#endif
            return 0;
        }
        return -1;
    }

    if (fread(&hdr, sizeof(hdr), 1, fp) != 1) {
        fclose(fp);
        return -1;
    }
    if (hdr.magic != MAC_LEARN_STATE_MAGIC || hdr.version != MAC_LEARN_STATE_VER ||
        hdr.count > MAC_LEARN_MAX_ENTRIES) {
        fclose(fp);
        return -1;
    }

    if (hdr.count > 0) {
        n = fread(batch, sizeof(batch[0]), hdr.count, fp);
        if (n != hdr.count) {
            fclose(fp);
            return -1;
        }
    }
    fclose(fp);

    pthread_spin_lock(&t->lock);
    t->count = 0;
    memset(t->hash_head, -1, sizeof(t->hash_head));
    memset(t->hash_next, -1, sizeof(t->hash_next));
    t->dirty = 0;
    for (uint32_t i = 0; i < hdr.count; i++) {
        if (batch[i].ifname[0] == '\0')
            continue;
        upsert_locked(t, batch[i].ifname, batch[i].mac);
    }
    t->dirty = 0;
    pthread_spin_unlock(&t->lock);

    fprintf(stderr, "[MAC] loaded %u entries from %s\n", hdr.count, path);
#if MAC_LEARN_TEST_SEED
    mac_learn_apply_test_seed(t);
#endif
    return 0;
}

int mac_learn_save(struct mac_learn_table *t)
{
    char path[256];
    char tmp[280];
    FILE *fp;
    struct mac_learn_file_hdr hdr;
    struct mac_learn_entry snap[MAC_LEARN_MAX_ENTRIES];
    int count;

    if (!t)
        return -1;
    if (mac_learn_state_path(path, sizeof(path)) != 0)
        return -1;

    (void)mkdir(NE_STATE_DIR, 0755);

    pthread_spin_lock(&t->lock);
    count = t->count;
    if (count > MAC_LEARN_MAX_ENTRIES)
        count = MAC_LEARN_MAX_ENTRIES;
    memcpy(snap, t->list, (size_t)count * sizeof(snap[0]));
    t->dirty = 0;
    pthread_spin_unlock(&t->lock);

    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    fp = fopen(tmp, "wb");
    if (!fp)
        return -1;

    hdr.magic = MAC_LEARN_STATE_MAGIC;
    hdr.version = MAC_LEARN_STATE_VER;
    hdr.count = (uint32_t)count;
    hdr.reserved = 0;
    if (fwrite(&hdr, sizeof(hdr), 1, fp) != 1 ||
        (count > 0 && fwrite(snap, sizeof(snap[0]), (size_t)count, fp) != (size_t)count)) {
        fclose(fp);
        remove(tmp);
        return -1;
    }
    fflush(fp);
    fclose(fp);
    if (rename(tmp, path) != 0) {
        remove(tmp);
        return -1;
    }
    return 0;
}

void mac_learn_flush_if_dirty(struct mac_learn_table *t)
{
    int dirty;

    if (!t)
        return;
    pthread_spin_lock(&t->lock);
    dirty = t->dirty;
    t->dirty = 0;
    pthread_spin_unlock(&t->lock);
    if (!dirty)
        return;
    if (mac_learn_save(t) != 0)
        t->dirty = 1;
}

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

static int profile_pi_for_wire_policy(struct forwarder *fwd, int action, uint8_t wire_id)
{
    int profile_id;

    if (!fwd || !fwd->cfg)
        return -1;
    profile_id = fwd_crypto_profile_id_for_policy_action_id(action, wire_id);
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
    if (mac_learn_lookup(&fwd->mac_table, pkt, ifname) != 0)
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

void mac_learn_local_ingress(struct forwarder *fwd, int local_idx, const uint8_t *pkt)
{
    if (!fwd || !pkt || local_idx < 0 || local_idx >= fwd->local_count)
        return;
    mac_learn(&fwd->mac_table, fwd->locals[local_idx].ifname, pkt + 6);
}

int mac_learn_wan_profile_pi(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint8_t pol = 0;

    if (!fwd || !pkt || !fwd->cfg)
        return -1;
    if (fwd_crypto_has_l2_marker(pkt, len))
        return profile_pi_for_wire_policy(fwd, POLICY_ACTION_ENCRYPT_L2, pkt[CRYPTO_L2_POLICY_OFF]);
    if (crypto_l3_extract_policy_id(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return profile_pi_for_wire_policy(fwd, POLICY_ACTION_ENCRYPT_L3, pol);
    if (crypto_l4_extract_policy_id_ipv4(fwd->cfg, (uint8_t *)pkt, len, &pol) == 0)
        return profile_pi_for_wire_policy(fwd, POLICY_ACTION_ENCRYPT_L4, pol);
    return -1;
}

int mac_learn_wan_forward(struct forwarder *fwd, struct ne_packet *job, int profile_pi)
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
