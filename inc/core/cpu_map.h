#ifndef CPU_MAP_H
#define CPU_MAP_H

/*
 * Bản đồ CPU dataplane (12 core 0–11). CHỈ SỬA FILE NÀY khi đổi core.
 *
 * Kiến trúc ổn định (~3G GCM): FQ refill trên RX, CQ drain trên TX.
 *
 * ┌─────────┬──────────────────────────────────────────────────────────┐
 * │ Core    │ Vai trò                                                  │
 * ├─────────┼──────────────────────────────────────────────────────────┤
 * │ ne_rx_lan │ RX LAN + FQ refill LAN                                 │
 * │ ne_rx_wan │ RX WAN + FQ refill WAN                                 │
 * │ ne_tx_lan │ TX LAN + CQ drain (slot q % NE_TX_SLOTS)               │
 * │ ne_tx_wan │ TX WAN + CQ drain                                      │
 * │ ne_crypto │ Mã hóa / giải mã / rã ráp                              │
 * └─────────┴──────────────────────────────────────────────────────────┘
 *
 * Scale: sửa NE_*_SLOTS / NE_CRYPTO_WORKERS và mảng cpu tương ứng (cùng độ dài).
 */

#define NE_RX_LAN_SLOTS     1u
#define NE_RX_WAN_SLOTS     1u
#define NE_TX_SLOTS         2u
#define NE_CRYPTO_WORKERS   6u

static const uint8_t ne_rx_lan_cpus[NE_RX_LAN_SLOTS] = { 0u };
static const uint8_t ne_rx_wan_cpus[NE_RX_WAN_SLOTS] = { 11u };

static const uint8_t ne_tx_lan_cpus[NE_TX_SLOTS] = { 1u, 2u };
static const uint8_t ne_tx_wan_cpus[NE_TX_SLOTS] = { 9u, 10u };

static const uint8_t ne_crypto_cpus[NE_CRYPTO_WORKERS] = {
    3u, 4u, 5u, 6u, 7u, 8u,
};

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(ne_rx_lan_cpus) / sizeof(ne_rx_lan_cpus[0]) == NE_RX_LAN_SLOTS,
               "ne_rx_lan_cpus[] length must match NE_RX_LAN_SLOTS");
_Static_assert(sizeof(ne_rx_wan_cpus) / sizeof(ne_rx_wan_cpus[0]) == NE_RX_WAN_SLOTS,
               "ne_rx_wan_cpus[] length must match NE_RX_WAN_SLOTS");
_Static_assert(sizeof(ne_tx_lan_cpus) / sizeof(ne_tx_lan_cpus[0]) == NE_TX_SLOTS,
               "ne_tx_lan_cpus[] length must match NE_TX_SLOTS");
_Static_assert(sizeof(ne_tx_wan_cpus) / sizeof(ne_tx_wan_cpus[0]) == NE_TX_SLOTS,
               "ne_tx_wan_cpus[] length must match NE_TX_SLOTS");
_Static_assert(sizeof(ne_crypto_cpus) / sizeof(ne_crypto_cpus[0]) == NE_CRYPTO_WORKERS,
               "ne_crypto_cpus[] length must match NE_CRYPTO_WORKERS");
#endif

#define NE_CPU_IO           ne_rx_lan_cpus[0]
#define NE_CPU_LOC_RX       ne_rx_lan_cpus[0]
#define NE_CPU_WAN_RX       ne_rx_wan_cpus[0]
#define NE_CPU_LOC_TX0      ne_tx_lan_cpus[0]
#define NE_CPU_LOC_TX1      ne_tx_lan_cpus[1]
#define NE_CPU_WAN_TX0      ne_tx_wan_cpus[0]
#define NE_CPU_WAN_TX1      ne_tx_wan_cpus[1]
#define NE_CPU_MID1         ne_crypto_cpus[0]
#define NE_CPU_MID2         ne_crypto_cpus[1]
#define NE_CPU_MID3         ne_crypto_cpus[2]
#define NE_CPU_MID4         ne_crypto_cpus[3]
#define NE_CPU_MID5         ne_crypto_cpus[4]
#define NE_CPU_MID6         ne_crypto_cpus[5]

#define NE_CPU_LOC          NE_CPU_LOC_RX
#define NE_CPU_LOC_TX       NE_CPU_LOC_TX0
#define NE_CPU_WAN          NE_CPU_WAN_RX
#define NE_CPU_WAN_TX       NE_CPU_WAN_TX0

#endif
