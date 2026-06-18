# forwarder — kiến trúc dataplane

> **Mục đích:** file này **không** thay `forwarder.h`. Header liệt kê field; doc này trả lời **ai nối với ai**, **gói đi đường nào**, **index ring thế nào**.  
> Chi tiết field: [`inc/core/forwarder.h`](../inc/core/forwarder.h) · AF_XDP: [`interface.md`](interface.md)

<style>
.t{color:#4ec9b0}.p{color:#c586c0}.v{color:#e0e0e0}.m{color:#4fc1ff}.fn{color:#dcdcaa}
</style>

---

## 1. Sơ đồ quan hệ struct (toàn bộ)

```mermaid
classDiagram
    direction TB

    class forwarder {
        app_config cfg
        xsk_interface locals
        xsk_interface wans
        ne_pair pair
        ne_ring local_to_mid
        ne_ring wan_to_mid
        ne_ring mid_to_wan
        ne_ring mid_to_local
        pthread_t local_rx_threads
        pthread_t tx_threads
        pthread_t crypto_threads
        pthread_t wan_rx_threads
    }

    class ne_pair {
        void bufs
        xsk_umem umem
        ne_iface locals
        ne_iface wans
        ne_pool pool
    }

    class ne_iface {
        int ifindex
        char ifname
        ne_xsk_queue queues
    }

    class ne_xsk_queue {
        xsk_socket xsk
        rx tx fq cq
    }

    class ne_pool {
        frame stack UMEM
    }

    class ne_ring {
        ne_packet buf array
        head tail
    }

    class ne_packet {
        uint64_t addr
        uint32_t len
        uint8_t dir
    }

    class xsk_interface {
        ifname MAC config
    }

    forwarder *-- ne_pair : pair
    forwarder *-- ne_ring : 4 mang ring
    forwarder o-- xsk_interface : metadata config
    ne_pair *-- ne_iface : locals wans
    ne_pair *-- ne_pool
    ne_iface *-- ne_xsk_queue
    ne_ring *-- ne_packet : cap phan tu
    ne_packet ..> ne_pair : addr trỏ UMEM bufs
    ne_pool ..> ne_pair : cung vung UMEM
```

**Đọc sơ đồ:**

| Mũi tên | Nghĩa |
|---------|--------|
| `*--` | struct **chứa** struct/array bên trong (sở hữu) |
| `o--` | tham chiếu metadata, **không** dùng I/O |
| `..>` | con trỏ / offset trỏ sang vùng khác |

- <span class="t">forwarder</span>.<span class="v">pair</span> → toàn bộ AF_XDP (UMEM, NIC)  
- <span class="t">forwarder</span>.<span class="v">local_to_mid</span>… → ring mềm giữa thread (phần tử là <span class="t">ne_packet</span>)  
- <span class="t">forwarder</span>.<span class="v">locals</span>/<span class="v">wans</span> (<span class="t">xsk_interface</span>) → tên/MAC config, I/O đi qua <span class="v">pair</span>

Chi tiết <span class="t">ne_pair</span> → <span class="t">ne_iface</span> → <span class="t">ne_xsk_queue</span>: [`interface.md` §1](interface.md#1-phân-cấp-struct-interfaceh)

---

## 2. Bức tranh luồng thread (runtime)

```mermaid
flowchart TB
    subgraph RX["Nhận gói"]
        LRX["local_rx_threads"]
        WRX["wan_rx_threads"]
    end

    subgraph R1["Ring RX → crypto"]
        LTM["local_to_mid[crypto_w]"]
        WTM["wan_to_mid[crypto_w]"]
    end

    subgraph CR["Mã hóa / routing"]
        CW["crypto_threads[crypto_w]"]
    end

    subgraph R2["Ring crypto → TX"]
        MTW["mid_to_wan[wan][tx_slot]"]
        MTL["mid_to_local[local][tx_slot]"]
    end

    subgraph TX["Gửi gói"]
        TTX["tx_threads[tx_slot]"]
    end

    PAIR["ne_pair — AF_XDP"] 

    LRX --> LTM --> CW
    WRX --> WTM --> CW
    CW --> MTW --> TTX
    CW --> MTL --> TTX
    TTX --> PAIR
    LRX --> PAIR
    WRX --> PAIR
```

**12 thread baseline:** 1 RX LAN + 1 RX WAN + 4 TX + 6 crypto. CPU map: [`cpu_map.h`](../inc/core/cpu_map.h).

---

## 3. `struct forwarder` — field dataplane trong sơ đồ trên

Không liệt kê lại header — xem [`forwarder.h`](../inc/core/forwarder.h).  
Trong sơ đồ §1, các field ring/thread là **mảng** (kích thước `NE_CRYPTO_WORKERS`, `NE_TX_SLOTS`, …).

Ví dụ tách <span class="t">kiểu</span> / <span class="v">tên</span>:

<div style="font-family:monospace;font-size:0.95em;line-height:1.8">

<span class="t">ne_ring</span> <span class="v">mid_to_wan</span><span style="color:#888">[MAX_INTERFACES][NE_TX_SLOTS]</span><br>
<span class="t">ne_ring</span> <span class="v">local_to_mid</span><span style="color:#888">[NE_CRYPTO_WORKERS]</span><br>
<span class="t">pthread_t</span> <span class="v">tx_threads</span><span style="color:#888">[NE_TX_SLOTS]</span>

</div>

---

## 4. Ring — ai push, ai pop

```mermaid
flowchart LR
    subgraph lan2wan["LAN → WAN"]
        direction TB
        A1["local_rx"] -->|push| B1["local_to_mid[w]"]
        B1 -->|pop| C1["crypto[w]"]
        C1 -->|push| D1["mid_to_wan[wan][t]"]
        D1 -->|pop| E1["tx[t]"]
    end

    subgraph wan2lan["WAN → LAN"]
        direction TB
        A2["wan_rx"] -->|push| B2["wan_to_mid[w]"]
        B2 -->|pop| C2["crypto[w]"]
        C2 -->|push| D2["mid_to_local[loc][t]"]
        D2 -->|pop| E2["tx[t]"]
    end
```

| Ký hiệu | Nghĩa |
|---------|--------|
| `w` / `crypto_w` | crypto worker 0…5 (code RX: `wi`, crypto: `worker_idx`) |
| `t` / `tx_slot` | TX thread 0…3 (`dp_pick_tx_slot`) |
| `wan`, `loc` | chỉ số card dataplane |

**Quan trọng:** `mid_to_wan` index theo **`tx_slot`**, không theo crypto worker.

---

## 5. LAN → WAN — 9 bước

```mermaid
flowchart TD
    N1["① NIC LAN"] --> N2["② local_rx_thread"]
    N2 --> N3["③ chọn crypto_w"]
    N3 --> N4["④ push local_to_mid"]
    N4 --> N5["⑤ crypto: dataplane_process_local"]
    N5 --> N6["⑥ chọn tx_slot"]
    N6 --> N7["⑦ push mid_to_wan"]
    N7 --> N8["⑧ tx_thread drain"]
    N8 --> N9["⑨ NIC WAN"]
```

| Bước | Hàm chính |
|:--:|-----------|
| ② | `ne_recv_local_slot` |
| ③ | `dp_crypto_pick_local_worker` |
| ⑤ | `dataplane_process_local` |
| ⑥ | `dp_pick_tx_slot` |
| ⑧ | `ne_tx_drain_wan_all` |

---

## 6. WAN → LAN — 9 bước

```mermaid
flowchart TD
    N1["① NIC WAN"] --> N2["② wan_rx_thread"]
    N2 --> N3["③ chọn crypto_w"]
    N3 --> N4["④ push wan_to_mid"]
    N4 --> N5["⑤ crypto: dataplane_process_wan"]
    N5 --> N6["⑥ chọn tx_slot"]
    N6 --> N7["⑦ push mid_to_local"]
    N7 --> N8["⑧ tx_thread drain"]
    N8 --> N9["⑨ NIC LAN"]
```

Khác LAN→WAN ở ring: `wan_to_mid` + `mid_to_local` + `ne_tx_drain_local_all`.

---

## 7. Vòng đời chương trình

**Không** phải đường gói tin — là thứ tự khi chạy binary:

```mermaid
flowchart TD
    M["main"] --> I["forwarder_init"]
    I --> R["forwarder_run — block tại đây"]
    R --> S["forwarder_stop — running=0"]
    S --> J["pthread_join tất cả thread"]
    J --> C["forwarder_cleanup"]
```

| Giai đoạn | Làm gì |
|-----------|--------|
| `init` | Mở `ne_pair`, `ne_ring_init`, **chưa** có thread RX/TX |
| `run` | Tạo thread: RX LAN → TX×4 → crypto×6 → RX WAN |
| `cleanup` | `ne_ring_destroy`, `ne_pair_close` |

---

## 8. tx_thread — mỗi vòng lặp

```mermaid
flowchart LR
    CQ["ne_drain_cq_all"] --> WAN["drain mid_to_wan[*][tx_slot]"]
    WAN --> LAN["drain mid_to_local[*][tx_slot]"]
```

Một `tx_threads[t]` lo **cả** WAN và LAN; chỉ drain ring có cùng `t`.

---

## 9. fwd_mid_to_wan_depth — đếm gói kẹt WAN

```mermaid
flowchart LR
    R0["mid_to_wan[wan][0]"] --> SUM["d = tổng ne_ring_count"]
    R1["mid_to_wan[wan][1]"] --> SUM
    R2["mid_to_wan[wan][2]"] --> SUM
    R3["mid_to_wan[wan][3]"] --> SUM
    SUM --> USE["chọn WAN ít tắc / wan_tx_stuck"]
```

- <span class="fn">ne_ring_count</span>(ring) = số gói đang chờ trong **một** ring  
- <span class="fn">fwd_mid_to_wan_depth</span> = cộng 4 ring `mid_to_wan[wan_dp][0..3]`

---

## 10. Ma trận ring (baseline)

```
              crypto_w:   0    1    2    3    4    5
local_to_mid           [R]  [R]  [R]  [R]  [R]  [R]
wan_to_mid             [R]  [R]  [R]  [R]  [R]  [R]

mid_to_wan[wan0]  tx:  [0]  [1]  [2]  [3]
mid_to_local[loc0] tx: [0]  [1]  [2]  [3]
```

---

## 11. Khi debug

| Triệu chứng | Hỏi |
|-------------|-----|
| Không ra WAN | Crypto push `mid_to_wan[wan][t]` — TX drain cùng `t`? |
| Scale TX hỏng | `tx_threads[i]` có drain `mid_to_wan[*][i]`? |
| RX chết | Số RX slot > số hardware queue? |

Màu trong doc: <span class="t">kiểu</span> · <span class="v">biến/field</span> · <span class="fn">hàm</span>
