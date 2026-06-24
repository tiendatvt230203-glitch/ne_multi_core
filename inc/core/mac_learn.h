#ifndef MAC_LEARN_H
#define MAC_LEARN_H

#include "config.h"
#include <pthread.h>
#include <stdint.h>

struct forwarder;
struct ne_packet;

#define MAC_LEARN_MAX_ENTRIES 256
#define MAC_LEARN_HASH_BUCKETS 256

struct mac_learn_entry {
    uint8_t mac[MAC_LEN];
    char ifname[IF_NAMESIZE];
};

struct mac_learn_table {
    struct mac_learn_entry list[MAC_LEARN_MAX_ENTRIES];
    int count;
    int hash_head[MAC_LEARN_HASH_BUCKETS];
    int hash_next[MAC_LEARN_MAX_ENTRIES];
    pthread_spinlock_t lock;
    int dirty;
};

void mac_learn_init(struct mac_learn_table *t);

void mac_learn(struct mac_learn_table *t, const char *ifname, const uint8_t mac[MAC_LEN]);

void mac_learn_arp(struct mac_learn_table *t, struct app_config *cfg, int local_idx,
                   const char *ifname, const uint8_t *pkt, uint32_t len);

int mac_learn_lookup(struct mac_learn_table *t, const uint8_t mac[MAC_LEN],
                     char ifname[IF_NAMESIZE]);

int mac_learn_load(struct mac_learn_table *t);
int mac_learn_save(struct mac_learn_table *t);
void mac_learn_flush_if_dirty(struct mac_learn_table *t);

void mac_learn_local_ingress(struct forwarder *fwd, int local_idx, const uint8_t *pkt);
int mac_learn_wan_profile_pi(struct forwarder *fwd, const uint8_t *pkt, uint32_t len);
int mac_learn_wan_forward(struct forwarder *fwd, struct ne_packet *job, int profile_pi);

#endif
