# forwarder.h — điều phối luồng & ring giữa các core

Nguồn: [`inc/core/forwarder.h`](../inc/core/forwarder.h) · [`src/core/forwarder.c`](../src/core/forwarder.c)  
Liên quan: [`interface.md`](interface.md)

## Chỉ số thường gặp

| Ký hiệu | Nghĩa | Trong code |
|---------|-------|------------|
| `crypto_w` | Luồng crypto thứ mấy (0…5) | RX: biến `wi`; crypto thread: `worker_idx` |
| `tx_slot` | Luồng TX thứ mấy (0…3) | `dp_pick_tx_slot()` trả `ts` |
| `wan_dp` / `wan_idx` | Card WAN dataplane | `mid_to_wan[wan_dp][tx_slot]` |
| `local_idx` | Card LAN dataplane | `mid_to_local[local_idx][tx_slot]` |
| `rx_slot` | Luồng RX thứ mấy | `local_rx_threads[]`, `wan_rx_threads[]` |

---

## 1. struct forwarder

```c
struct forwarder {
    struct app_config *cfg;

    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;
    int wan_cfg_idx[MAX_INTERFACES];

    struct ne_pair pair;
    struct ne_ring local_to_mid[NE_CRYPTO_WORKERS];
    struct ne_ring wan_to_mid[NE_CRYPTO_WORKERS];
    struct ne_ring mid_to_wan[MAX_INTERFACES][NE_TX_SLOTS];
    struct ne_ring mid_to_local[MAX_INTERFACES][NE_TX_SLOTS];

    pthread_t local_rx_threads[NE_RX_LAN_SLOTS];
    pthread_t tx_threads[NE_TX_SLOTS];
    pthread_t crypto_threads[NE_CRYPTO_WORKERS];
    pthread_t wan_rx_threads[NE_RX_WAN_SLOTS];
    int threads_started;

    uint64_t wan_tx_stuck[MAX_INTERFACES];
    uint32_t wan_tx_cooldown[MAX_INTERFACES];
};
```

---

## 2. Tổng quan luồng gói tin

```
RX → local_to_mid[crypto_w] / wan_to_mid[crypto_w]
  → crypto_threads[crypto_w] → dataplane_process_*
  → mid_to_wan[wan][tx_slot] / mid_to_local[local][tx_slot]
  → tx_threads[tx_slot] → NIC
```

---

## 3. Bảng ring

| Mảng | Index | Push | Pop |
|------|-------|------|-----|
| `local_to_mid` | `crypto_w` | `local_rx_thread` | `crypto_threads[crypto_w]` |
| `wan_to_mid` | `crypto_w` | `wan_rx_thread` | `crypto_threads[crypto_w]` |
| `mid_to_wan` | WAN + `tx_slot` | crypto (`dp_pick_tx_slot`) | `tx_threads[tx_slot]` |
| `mid_to_local` | local + `tx_slot` | crypto | `tx_threads[tx_slot]` |

`mid_to_wan` / `mid_to_local` index theo **tx_slot**, không theo crypto worker.

---

## 4. Cụm CPU & thread (baseline)

| Cụm | Macro | Hàm | CPU |
|-----|-------|-----|-----|
| RX LAN | `NE_CLUSTER_RX_LAN` | `local_rx_thread` | `ne_cpu_rx_lan` |
| RX WAN | `NE_CLUSTER_RX_WAN` | `wan_rx_thread` | `ne_cpu_rx_wan` |
| TX | `NE_CLUSTER_TX` | `tx_thread` | `ne_cpu_tx` |
| Crypto | `NE_CLUSTER_CRYPTO` | `crypto_worker_thread` | `ne_cpu_crypto` |

---

## 5. Gói tin đi thế nào

### LAN → WAN

| Bước | Ai | Việc |
|:--:|-----|------|
| 1 | NIC LAN | Gói vào card |
| 2 | `local_rx_thread` | `ne_recv_local_slot` |
| 3 | `local_rx_thread` | `crypto_w = dp_crypto_pick_local_worker` |
| 4 | `local_rx_thread` | push `local_to_mid[crypto_w]` |
| 5 | `crypto_threads[crypto_w]` | `dataplane_process_local` |
| 6 | crypto | `tx_slot = dp_pick_tx_slot` |
| 7 | crypto | push `mid_to_wan[wan_idx][tx_slot]` |
| 8 | `tx_threads[tx_slot]` | `ne_tx_drain_wan_all` |
| 9 | NIC WAN | Gói ra mạng |

### WAN → LAN

| Bước | Ai | Việc |
|:--:|-----|------|
| 1 | NIC WAN | Gói vào card |
| 2 | `wan_rx_thread` | `ne_recv_wan_slot` |
| 3 | `wan_rx_thread` | `crypto_w = dp_crypto_pick_wan_worker` |
| 4 | `wan_rx_thread` | push `wan_to_mid[crypto_w]` |
| 5 | `crypto_threads[crypto_w]` | `dataplane_process_wan` |
| 6 | crypto | `tx_slot = dp_pick_tx_slot` |
| 7 | crypto | push `mid_to_local[local_idx][tx_slot]` |
| 8 | `tx_threads[tx_slot]` | `ne_tx_drain_local_all` |
| 9 | NIC LAN | Gói ra LAN |

### So sánh nhanh

| | LAN → WAN | WAN → LAN |
|--|-----------|-----------|
| RX thread | `local_rx_thread` | `wan_rx_thread` |
| Ring → crypto | `local_to_mid` | `wan_to_mid` |
| Hàm crypto | `dataplane_process_local` | `dataplane_process_wan` |
| Ring → TX | `mid_to_wan` | `mid_to_local` |
| TX thread | `tx_threads[tx_slot]` (chung) | `tx_threads[tx_slot]` (chung) |

---

## 6. Vòng đời chương trình

```
main()
  → forwarder_init()      // chuẩn bị, chưa có thread
  → forwarder_run()       // tạo thread, block đến khi stop
  → forwarder_cleanup()   // hủy ring, đóng AF_XDP
```

**forwarder_init:** CPU map → config → crypto → `ne_pair_open` → `ne_ring_init`

**forwarder_run:** tạo thread theo thứ tự RX LAN → TX (4) → crypto (6) → RX WAN → `pthread_join` khi `forwarder_stop()`

**forwarder_cleanup:** `ne_ring_destroy` → `ne_pair_close`

---

## 7. tx_thread

Mỗi `tx_slot` mỗi vòng lặp:

1. `ne_drain_cq_all(pair, tx_slot)`
2. `ne_tx_drain_wan_all` — drain `mid_to_wan[wan][tx_slot]` mọi WAN
3. `ne_tx_drain_local_all` — drain `mid_to_local[local][tx_slot]` mọi LAN

Một TX thread lo cả WAN lẫn LAN.

---

## 8. ne_ring_count và fwd_mid_to_wan_depth

`ne_ring_count(ring)` = số gói đang chờ trong ring (`head - tail`).

`fwd_mid_to_wan_depth(fwd, wan_dp)` = tổng gói chờ gửi WAN trên cả 4 TX slot:

```c
uint32_t d = 0;
for (int w = 0; w < NE_TX_SLOTS; w++)
    d += ne_ring_count(&fwd->mid_to_wan[wan_dp][w]);
```

- `d` lớn → WAN egress chậm
- `d == 0` → hết gói kẹt; TX slot 0 reset `wan_tx_stuck`
- `fwd_wan_pick_for_local` chọn WAN có `d` nhỏ nhất

---

## 9. Ma trận ring (baseline)

```
                 crypto_w:  0   1   2   3   4   5
local_to_mid        [R] [R] [R] [R] [R] [R]
wan_to_mid          [R] [R] [R] [R] [R] [R]

mid_to_wan[wan0]  tx_slot: [0] [1] [2] [3]
mid_to_local[loc0] tx_slot: [0] [1] [2] [3]
```

[R] = một `ne_ring`, dung lượng `NE_RING` (16384).

---

## 10. Debug nhanh

| Triệu chứng | Kiểm tra |
|-------------|----------|
| Không ra WAN | crypto push `mid_to_wan[wan][tx_slot]` — TX drain cùng `tx_slot`? |
| Scale TX lỗi | `NE_CLUSTER_TX` tăng, `tx_threads[t]` drain đúng `t`? |
| RX không nhận | `NE_CLUSTER_RX_*` > số hardware queue? |
