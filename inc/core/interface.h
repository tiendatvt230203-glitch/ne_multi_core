#ifndef INTERFACE_H
#define INTERFACE_H

#include "common.h"
#include "config.h"
#include <pthread.h>
#include <signal.h>

#define NE_RING        8192u
#define NE_FRAME       2048u
#define NE_N_FRAMES    131072u
#define NE_BATCH_SIZE  64u

/*
 * Dataplane CPU map — 10 pinned threads:
 *
 *   NE_CPU_LOC        (0)   local RX worker[0]: queues q%2==0 + FQ refill
 *   NE_CPU_LOC_RX1    (7)   local RX worker[1]: queues q%2==1 + FQ refill
 *   NE_CPU_LOC_TX     (1)   local TX worker[0]: mid_to_local[*][0] + CQ q%2==0
 *   NE_CPU_LOC_TX1    (2)   local TX worker[1]: mid_to_local[*][1] + CQ q%2==1
 *   NE_CPU_MID1       (3)   crypto worker[0]: encrypt / decrypt / frag
 *   NE_CPU_MID2       (4)   crypto worker[1]: same as mid 1 (parallel)
 *   NE_CPU_WAN_RX1    (8)   wan RX worker[1]:   queues q%2==1 + FQ refill
 *   NE_CPU_WAN_TX1    (9)   wan TX worker[1]: mid_to_wan[*][1] + CQ q%2==1
 *   NE_CPU_WAN_TX     (10)  wan TX worker[0]: mid_to_wan[*][0] + CQ q%2==0
 *   NE_CPU_WAN        (11)  wan RX worker[0]:   queues q%2==0 + FQ refill
 *
 * IO worker index matches crypto ring index and XSK queue (q % NE_CRYPTO_WORKERS).
 * Wire core_id carries CPU 3 or 4 for decrypt routing (crypto_route.c).
 */

#define NE_CPU_LOC        0u
#define NE_CPU_LOC_RX1    7u
#define NE_CPU_LOC_TX     1u
#define NE_CPU_LOC_TX1    2u
#define NE_CPU_MID1       3u
#define NE_CPU_MID2       4u
#define NE_CPU_WAN_RX1    8u
#define NE_CPU_WAN_TX1    9u
#define NE_CPU_WAN_TX     10u
#define NE_CPU_WAN        11u
#define NE_CRYPTO_WORKERS 2u

struct bpf_object;

struct xsk_queue {
    struct xsk_socket *xsk;
    struct xsk_umem *umem;
    void *bufs;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    uint64_t tx_slot;
    int pending_tx_count;
    pthread_mutex_t tx_lock;
    uint64_t tx_wait_loops;
};

struct xsk_interface {
    struct xsk_umem *umem;
    void *bufs;
    size_t umem_size;
    uint32_t ring_size;
    uint32_t frame_size;
    uint32_t batch_size;
    struct xsk_queue queues[MAX_QUEUES];
    int queue_count;
    int current_queue;
    struct xsk_socket *xsk;
    struct xsk_ring_prod fill;
    struct xsk_ring_cons comp;
    struct xsk_ring_prod tx;
    struct xsk_ring_cons rx;
    int ifindex;
    char ifname[IF_NAMESIZE];
    uint8_t src_mac[MAC_LEN];
    uint8_t dst_mac[MAC_LEN];
    uint64_t tx_slot;
    pthread_mutex_t tx_lock;
    int pending_tx_count;
    uint64_t rx_packets;
    uint64_t tx_packets;
    uint64_t rx_bytes;
    uint64_t tx_bytes;
};

enum ne_packet_dir {
    NE_DIR_LOCAL = 0,
    NE_DIR_WAN = 1,
};

struct ne_packet {
    uint64_t addr;
    uint32_t len;
    uint8_t dir;
    uint8_t wan_idx;
    uint8_t local_idx;
};

struct ne_ring {
    struct ne_packet *buf;
    uint32_t cap;
    uint32_t mask;
    __attribute__((aligned(64))) volatile uint32_t head;
    __attribute__((aligned(64))) volatile uint32_t tail;
    pthread_spinlock_t push_lock; /* mid_to_wan/mid_to_local: 2 crypto workers push */
};

struct ne_pool {
    uint64_t *buf;
    uint32_t cap;
    uint32_t mask;
    uint32_t head;
    uint32_t tail;
    pthread_spinlock_t lock;
};

struct ne_xsk_queue {
    struct xsk_socket *xsk;
    struct xsk_ring_cons rx;
    struct xsk_ring_prod tx;
    struct xsk_ring_prod fq;
    struct xsk_ring_cons cq;
    uint32_t rx_pending;
};

struct ne_iface {
    int ifindex;
    char ifname[IF_NAMESIZE];
    int queue_count;
    struct ne_xsk_queue queues[MAX_QUEUES];
    uint64_t tx_no_free;
    uint32_t tx_queue_rr;
};

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
    int local_queue_total;
    int wan_queue_total;
    struct ne_pool pool;
    struct bpf_object *bpf_locals[MAX_INTERFACES];
    struct bpf_object *bpf_wans[MAX_INTERFACES];
    uint8_t xdp_local_on[MAX_INTERFACES];
    uint8_t xdp_wan_on[MAX_INTERFACES];
    uint32_t xdp_flags;
};

int ne_ring_init(struct ne_ring *r, uint32_t cap);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt);
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt);
uint32_t ne_ring_count(const struct ne_ring *r);

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg);
void ne_pair_close(struct ne_pair *p);

int ne_recv_local_worker(struct ne_pair *p, struct ne_packet *out, uint32_t max, int rx_worker);
int ne_recv_wan_worker(struct ne_pair *p, struct ne_packet *out, uint32_t max, int rx_worker);
void ne_recv_release_local_worker(struct ne_pair *p, int rx_worker);
void ne_recv_release_wan_worker(struct ne_pair *p, int rx_worker);
void ne_kick_rx_wakeup_local_worker(struct ne_pair *p, int rx_worker);
void ne_kick_rx_wakeup_wan_worker(struct ne_pair *p, int rx_worker);
void ne_drain_cq_local_worker(struct ne_pair *p, int io_worker);
void ne_drain_cq_wan_worker(struct ne_pair *p, int io_worker);

void ne_drain_cq_local(struct ne_pair *p, int tx_worker);
void ne_drain_cq_wan(struct ne_pair *p, int tx_worker);
void ne_refill_fq_local_worker(struct ne_pair *p, int rx_worker);
void ne_refill_fq_wan_worker(struct ne_pair *p, int rx_worker);
int ne_tx_drain_local(struct ne_pair *p, struct ne_ring *src, int local_idx, int tx_worker);
int ne_tx_drain_wan(struct ne_pair *p, struct ne_ring *src, int wan_idx, int tx_worker);

void *ne_packet_data(struct ne_pair *p, uint64_t addr);
int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out);
void ne_frame_free(struct ne_pair *p, uint64_t addr);
uint32_t ne_pool_free_count(struct ne_pair *p);

void interface_reset_redirect_maps(void);
int interface_push_encrypt_filters(const struct app_config *cfg);
void interface_ip_xdp_off(const char *ifname);
void interface_ip_xdp_off_config(const struct app_config *cfg);
void interface_promisc_off_config(const struct app_config *cfg);
int interface_set_queue_count(const char *ifname, int desired_count);
int interface_get_queue_count(const char *ifname);

#endif
