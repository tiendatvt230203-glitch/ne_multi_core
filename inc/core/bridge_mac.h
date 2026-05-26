#ifndef BRIDGE_MAC_H
#define BRIDGE_MAC_H

#include "config.h"

struct forwarder;
struct app_config;

int bridge_mac_prepare(struct app_config *cfg);
int bridge_mac_install(struct forwarder *fwd);

int bridge_mac_local_for_dmac(struct forwarder *fwd,
                              const uint8_t *pkt, uint32_t pkt_len);

#endif
