#ifndef CPU_MAP_H
#define CPU_MAP_H

#include <stdint.h>
#include "config.h"

#define NE_CLUSTER_RX_LAN    1u
#define NE_CLUSTER_RX_WAN    1u
#define NE_CLUSTER_TX        4u
#define NE_CLUSTER_CRYPTO    6u

#define NE_RX_LAN_SLOTS      NE_CLUSTER_RX_LAN
#define NE_RX_WAN_SLOTS      NE_CLUSTER_RX_WAN
#define NE_TX_SLOTS          NE_CLUSTER_TX
#define NE_CRYPTO_WORKERS    NE_CLUSTER_CRYPTO

#if NE_CLUSTER_RX_LAN > 1 && NE_CLUSTER_RX_LAN > NE_LOCAL_QUEUE_TARGET
#error "NE_CLUSTER_RX_LAN > NE_LOCAL_QUEUE_TARGET"
#endif
#if NE_CLUSTER_RX_WAN > 1 && NE_CLUSTER_RX_WAN > NE_WAN_QUEUE_TARGET
#error "NE_CLUSTER_RX_WAN > NE_WAN_QUEUE_TARGET"
#endif

#define NE_CPU_RX_LAN0       0u
#define NE_CPU_RX_WAN0       11u
#define NE_CPU_TX0           1u
#define NE_CPU_TX1           2u
#define NE_CPU_TX2           9u
#define NE_CPU_TX3           10u
#define NE_CPU_CRYPTO0       3u
#define NE_CPU_CRYPTO1       4u
#define NE_CPU_CRYPTO2       5u
#define NE_CPU_CRYPTO3       6u
#define NE_CPU_CRYPTO4       7u
#define NE_CPU_CRYPTO5       8u

#define NE_CPU_LOC           NE_CPU_RX_LAN0
#define NE_CPU_WAN           NE_CPU_RX_WAN0
#define NE_CPU_MID1          NE_CPU_CRYPTO0
#define NE_CPU_MID2          NE_CPU_CRYPTO1
#define NE_CPU_MID3          NE_CPU_CRYPTO2
#define NE_CPU_MID4          NE_CPU_CRYPTO3
#define NE_CPU_MID5          NE_CPU_CRYPTO4
#define NE_CPU_MID6          NE_CPU_CRYPTO5

extern const uint8_t ne_cpu_rx_lan[NE_CLUSTER_RX_LAN];
extern const uint8_t ne_cpu_rx_wan[NE_CLUSTER_RX_WAN];
extern const uint8_t ne_cpu_tx[NE_CLUSTER_TX];
extern const uint8_t ne_cpu_crypto[NE_CLUSTER_CRYPTO];

int ne_cpu_map_validate(void);
void ne_cpu_map_log(void);

#endif
