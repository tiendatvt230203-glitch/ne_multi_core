#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "config.h"
#include <stdint.h>

#define MAC_LEARN_MAX_ENTRIES 256

struct mac_learn_entry {
    uint8_t mac[MAC_LEN];
    char ifname[IF_NAMESIZE];
};

struct mac_learn_table {
    struct mac_learn_entry list[MAC_LEARN_MAX_ENTRIES];
    int count;
};

void mac_learn_init(struct mac_learn_table *t);

void mac_learn(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN]);

void mac_learn_arp(struct mac_learn_table *t, struct app_config *cfg, int local_idx,
                   const char *ifname, const uint8_t *pkt, uint32_t len);

int mac_learn_lookup(const struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
                     char ifname[IF_NAMESIZE]);

#endif