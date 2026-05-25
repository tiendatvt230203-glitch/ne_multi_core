#ifndef BRIDGE_MAC_H
#define BRIDGE_MAC_H

#include "config.h"

struct forwarder;
struct app_config;

/* True when profile WAN rows have no dst_ip (transparent inter-SEP links). */
int config_wan_bridge_mode(const struct app_config *cfg);

int bridge_mac_prepare(struct app_config *cfg);
int bridge_mac_install(struct forwarder *fwd);
void bridge_mac_shutdown(void);

void bridge_mac_learn_rx(struct forwarder *fwd, int local_idx,
                         const uint8_t *pkt, uint32_t pkt_len);
int bridge_mac_local_for_dmac(struct forwarder *fwd,
                              const uint8_t *pkt, uint32_t pkt_len);
void bridge_mac_sync_cfg_to_iface(struct forwarder *fwd);

void bridge_wan_rx_normalize_eth_ipv4(uint8_t *pkt, uint32_t pkt_len);

#endif
