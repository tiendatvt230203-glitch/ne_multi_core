#ifndef LOCAL_HWADDR_H
#define LOCAL_HWADDR_H

#include "config.h"

struct forwarder;

int local_hwaddr_prepare(struct app_config *cfg);
int local_hwaddr_install(struct forwarder *fwd);

void local_neigh_reset(void);
void local_neigh_learn(int local_idx, uint32_t ip, const uint8_t mac[MAC_LEN]);
int local_neigh_resolve(int local_idx, const char *ifname, uint32_t ip,
                        uint8_t mac_out[MAC_LEN]);

#endif
