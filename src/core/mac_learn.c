#include "../../inc/core/mac_learn.h"

#include <string.h>

#define MAC_LEARN_ETH_P_ARP 0x0806u

static int find_idx_by_mac(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN])
{
    for (int i = 0; i < t->count; i++) {
        if (memcmp(t->list[i].mac, mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

static void upsert(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    int i = find_idx_by_mac(t, mac);

    if (i >= 0) {
        strncpy(t->list[i].ifname, ifname, IF_NAMESIZE - 1);
        t->list[i].ifname[IF_NAMESIZE - 1] = '\0';
        return;
    }
    if (t->count >= MAC_LEARN_MAX_ENTRIES)
        return;

    memcpy(t->list[t->count].mac, mac, MAC_LEN);
    strncpy(t->list[t->count].ifname, ifname, IF_NAMESIZE - 1);
    t->list[t->count].ifname[IF_NAMESIZE - 1] = '\0';
    t->count++;
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

void mac_learn_init(struct mac_learn_table *t)
{
    memset(t, 0, sizeof(*t));
}
// Học mac chiều LAN -> WAN cho những traffic nào match với policy-encryp
void mac_learn(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN])
{
    upsert(t, ifname, mac);
}

void mac_learn_arp(struct mac_learn_table *t, struct app_config *cfg, int local_idx,
                   const char *ifname, const uint8_t *pkt, uint32_t len)
{
    const uint8_t *arp;
    uint16_t ethertype;
    uint8_t sender_mac[MAC_LEN];
    uint32_t sender_ip;
    uint32_t target_ip;

    if (len < 14u + 28u)
        return;

    ethertype = (uint16_t)((pkt[12] << 8) | pkt[13]);
    if (ethertype != MAC_LEARN_ETH_P_ARP)
        return;

    arp = pkt + 14;
    if (arp[0] != 0x00 || arp[1] != 0x01 || arp[2] != 0x08 || arp[3] != 0x00)
        return;
    if (arp[4] != 6 || arp[5] != 4)
        return;

    memcpy(sender_mac, arp + 8, MAC_LEN);
    memcpy(&sender_ip, arp + 14, sizeof(sender_ip));
    memcpy(&target_ip, arp + 24, sizeof(target_ip));

    // chỉ upsert địa chỉ mac nào thuộc policy không học mac khác
    if (!arp_match_policy(cfg, local_idx, sender_ip, target_ip))
        return;

    upsert(t, ifname, sender_mac);
}

int mac_learn_lookup(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
                     char ifname[IF_NAMESIZE])
{
    int i = find_idx_by_mac(t, mac);
    if (i < 0)
        return -1;
    strncpy(ifname, t->list[i].ifname, IF_NAMESIZE - 1);
    ifname[IF_NAMESIZE - 1] = '\0';
    return 0;
}