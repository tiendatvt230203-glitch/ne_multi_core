#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "config.h"
#include <stdint.h>

struct mac_learn_entry {
    char ifname[IF_NAMESIZE];
    uint8_t mac[MAC_LEN];
};

struct mac_learn_table {
    struct mac_learn_entry list[MAX_INTERFACES];
    int count;
};

void mac_learn_init(struct mac_learn_table *t);
void mac_learn_add(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN]);
void mac_learn_edit(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN]);
void mac_learn_delete(struct mac_learn_table *t, const char *ifname);

#endif