#ifndef CPU_MAP_H
#define CPU_MAP_H

/*
 * Bản đồ CPU dataplane (12 core 0–11). CHỈ SỬA FILE NÀY khi đổi core.
 *
 * ┌─────────┬──────────────────────────────────────────────────────────┐
 * │ Core    │ Vai trò (mặc định)                                       │
 * ├─────────┼──────────────────────────────────────────────────────────┤
 * │ 0       │ IO — FQ + CQ (cố định, không scale thêm thread)          │
 * │ ne_rx_* │ RX LAN / RX WAN                                          │
 * │ ne_tx_* │ TX LAN / TX WAN (queue q → slot q % NE_TX_SLOTS)         │
 * │ ne_crypto_* │ Mã hóa / giải mã / rã ráp                          │
 * └─────────┴──────────────────────────────────────────────────────────┘
 *
 * Cách scale:
 *   Crypto — đổi NE_CRYPTO_WORKERS, thêm/bớt phần tử ne_crypto_cpus[].
 *   TX     — đổi NE_TX_SLOTS, sửa ne_tx_lan_cpus[] và ne_tx_wan_cpus[] (cùng số slot).
 *   RX     — đổi NE_RX_LAN_SLOTS / NE_RX_WAN_SLOTS, sửa ne_rx_*_cpus[].
 *            (NE_RX_* > 1 cần thêm rx thread theo slot trong forwarder.c)
 *
 * Lưu ý: mỗi core 1–11 chỉ nên gán một vai trò nặng; tránh trùng core trừ khi cố ý.
 */

#define NE_CPU_IO           0u

#define NE_RX_LAN_SLOTS     1u
#define NE_RX_WAN_SLOTS     1u

#define NE_TX_SLOTS         2u

#define NE_CRYPTO_WORKERS   6u

static const uint8_t ne_rx_lan_cpus[NE_RX_LAN_SLOTS] = { 1u };
static const uint8_t ne_rx_wan_cpus[NE_RX_WAN_SLOTS] = { 11u };

static const uint8_t ne_tx_lan_cpus[NE_TX_SLOTS] = { 2u, 5u };
static const uint8_t ne_tx_wan_cpus[NE_TX_SLOTS] = { 8u, 11u };

static const uint8_t ne_crypto_cpus[NE_CRYPTO_WORKERS] = {
    3u, 4u, 6u, 7u, 9u, 10u,
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

/* Alias tương thích code cũ */
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
