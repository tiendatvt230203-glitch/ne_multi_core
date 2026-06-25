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
    uint64_t last_seen_ms;
};

struct mac_learn_table {
    struct mac_learn_entry list[MAC_LEARN_MAX_ENTRIES];
    int count;
    int hash_head[MAC_LEARN_HASH_BUCKETS];
    int hash_next[MAC_LEARN_MAX_ENTRIES];
    pthread_spinlock_t lock;
};

// API lean mac
void mac_learn_bootstrap(struct mac_learn_table *t);
void mac_learn_shutdown(struct mac_learn_table *t);
void mac_learn_tick(struct forwarder *fwd);

void mac_learn_local(struct forwarder *fwd, int local_idx, const uint8_t *pkt);
int mac_learn_wan(struct forwarder *fwd, struct ne_packet *job,
                  const uint8_t *wire_pkt, uint32_t wire_len);

#endif