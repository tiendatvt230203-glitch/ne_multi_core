# interface.h — lớp AF_XDP & bộ nhớ gói tin

Nguồn: [`inc/core/interface.h`](../inc/core/interface.h) · [`src/core/interface.c`](../src/core/interface.c)  
Liên quan: [`forwarder.md`](forwarder.md)

---

## 1. struct ne_pair

```c
struct ne_pair {
    void *bufs;
    size_t bufsize;
    uint32_t frame_size;
    uint32_t n_frames;
    struct xsk_umem *umem;
    struct ne_iface locals[MAX_INTERFACES];
    int local_count;
    struct ne_iface wans[MAX_INTERFACES];
    int wan_count;
    struct ne_pool pool;
    /* bpf_locals, bpf_wans, local_live, wan_live, ... */
};
```

---

## 2. struct ne_iface · ne_xsk_queue

```c
struct ne_iface {
    int ifindex;
    char ifname[IF_NAMESIZE];
    int queue_count;
    struct ne_xsk_queue queues[MAX_QUEUES];
};

struct ne_xsk_queue {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    uint32_t rx_pending;
};
```

Phân cấp: `ne_pair` → `locals` / `wans` → `queues[]`

---

## 3. struct ne_packet

```c
struct ne_packet {
    uint64_t addr;   /* offset UMEM trong ne_pair.bufs */
    uint32_t len;
    uint8_t dir;     /* NE_DIR_LOCAL / NE_DIR_WAN */
    uint8_t wan_idx;
    uint8_t local_idx;
};
```

`ne_packet_data(p, addr)` trỏ payload — không copy byte.

---

## 4. struct ne_ring

Khai báo trong `interface.h`, sở hữu bởi `struct forwarder`.

```c
struct ne_ring {
    struct ne_packet *buf;
    uint32_t cap, mask;
    volatile uint32_t head, tail;
    /* push_lock, pop_lock, mpsc_pop */
};
```

---

## 5. Hardware queue ↔ CPU slot

Công thức: `q % slot_count` — hàm `xsk_queue_for_slot` trong `interface.c`

| Cluster | Macro | CPU |
|---------|-------|-----|
| RX LAN | `NE_RX_LAN_SLOTS` | `ne_cpu_rx_lan` |
| RX WAN | `NE_RX_WAN_SLOTS` | `ne_cpu_rx_wan` |
| TX | `NE_TX_SLOTS` | `ne_cpu_tx` |

---

## 6. API theo thread

| Thread | Hàm |
|--------|-----|
| RX LAN slot `s` | `ne_refill_fq_local_slot`, `ne_recv_local_slot`, `ne_recv_release_local_slot` |
| RX WAN slot `s` | `ne_refill_fq_wan_slot`, `ne_recv_wan_slot`, `ne_recv_release_wan_slot` |
| TX slot `t` | `ne_drain_cq_all`, `ne_tx_drain_local_all`, `ne_tx_drain_wan_all` |

---

## 7. ne_pair vs xsk_interface

| | `ne_pair` | `xsk_interface` |
|--|-----------|-----------------|
| Vai trò | Runtime AF_XDP | Metadata trong `forwarder` |
| I/O | `pair` — recv/tx thật | `wans[]` — tên, MAC config |

---

## 8. Macro

| Macro | Giá trị |
|-------|---------|
| `NE_FRAME` | 2048 |
| `NE_N_FRAMES` | 131072 |
| `NE_BATCH_SIZE` | 64 |
| `NE_RING` | 16384 |
