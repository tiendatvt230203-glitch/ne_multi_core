#ifndef LAN_NEIGH_H
#define LAN_NEIGH_H

#include "../core/config.h"

struct forwarder;

#define LAN_NEIGH_TIMEOUT_SEC 300

void lan_neigh_reset(void);

int lan_neigh_prepare(struct app_config *cfg);
int lan_neigh_install(struct forwarder *fwd);

void lan_neigh_learn(int local_idx, uint32_t ip, const uint8_t mac[MAC_LEN],
                     const struct app_config *cfg);

int lan_neigh_lookup(int local_idx, uint32_t ip, uint8_t mac_out[MAC_LEN]);

int lan_neigh_lookup_by_ip(uint32_t ip, int *local_idx_out, uint8_t mac_out[MAC_LEN]);

/* WAN->LAN: find (local port, MAC); ARP probe on miss. Logs via main_diag. */
int lan_neigh_resolve(struct forwarder *fwd, uint32_t ip,
                      int *local_idx_out, uint8_t mac_out[MAC_LEN]);

int lan_neigh_is_own_src(const struct forwarder *fwd, int local_idx,
                         const uint8_t *pkt, uint32_t pkt_len);

void lan_neigh_gc_tick(void);

#endif
