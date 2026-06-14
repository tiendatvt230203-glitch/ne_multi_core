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
 * Dataplane CPU map — 9 pinned threads:
 *
 *   NE_CPU_LOC        (0)   local RX:  AF_XDP recv + FQ refill → local_to_mid
 *   NE_CPU_LOC_TX     (1)   local TX[0]: all mid_to_local[*][*] + XSK queue q%2==0
 *   NE_CPU_LOC_TX1    (2)   local TX[1]: all mid_to_local[*][*] + XSK queue q%2==1
 *   NE_CPU_MID1       (3)   crypto worker[0]
 *   NE_CPU_MID2       (4)   crypto worker[1]
 *   NE_CPU_MID3       (5)   crypto worker[2]
 *   NE_CPU_WAN_TX1    (9)   wan TX[1]:   all mid_to_wan[*][*]   + XSK queue q%2==1
 *   NE_CPU_WAN_TX     (10)  wan TX[0]:   all mid_to_wan[*][*]   + XSK queue q%2==0
 *   NE_CPU_WAN        (11)  wan RX:      AF_XDP recv + FQ refill → wan_to_mid
 *
 * TX slots (NE_TX_SLOTS) partition XSK hardware queues only (q % NE_TX_SLOTS).
 * Both TX threads per direction pop every crypto output ring (MPSC via pop_lock).
 */

#define NE_CPU_LOC        0u
#define NE_CPU_LOC_TX     1u
#define NE_CPU_LOC_TX1    2u
#define NE_CPU_MID1       3u
#define NE_CPU_MID2       4u
#define NE_CPU_MID3       5u
#define NE_CPU_WAN_TX1    9u
#define NE_CPU_WAN_TX     10u
#define NE_CPU_WAN        11u
#define NE_CRYPTO_WORKERS 3u
#define NE_TX_SLOTS       2u

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
    pthread_spinlock_t push_lock;
    pthread_spinlock_t pop_lock;
    uint8_t mpsc_pop;
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
    uint8_t local_live[MAX_INTERFACES];
    uint8_t wan_live[MAX_INTERFACES];
    uint32_t xdp_flags;
};

int ne_pair_local_live(const struct ne_pair *p, int pair_local_idx);
int ne_pair_wan_live(const struct ne_pair *p, int dp_slot);
int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg, int cfg_local_idx,
                         int pair_li);
int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg, int cfg_wan_idx,
                         int dp_slot);
void ne_pair_unplumb_local(struct ne_pair *p, int pair_li);
void ne_pair_unplumb_wan_dp(struct ne_pair *p, int dp_slot);

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop);
void ne_ring_destroy(struct ne_ring *r);
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt);
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt);
uint32_t ne_ring_count(const struct ne_ring *r);

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg);
void ne_pair_close(struct ne_pair *p);

int ne_recv_local(struct ne_pair *p, struct ne_packet *out, uint32_t max);
int ne_recv_wan(struct ne_pair *p, struct ne_packet *out, uint32_t max);
void ne_recv_release_local(struct ne_pair *p);
void ne_recv_release_wan(struct ne_pair *p);

void ne_drain_cq_local(struct ne_pair *p, int tx_slot);
void ne_drain_cq_wan(struct ne_pair *p, int tx_slot);
void ne_refill_fq_local(struct ne_pair *p);
void ne_refill_fq_wan(struct ne_pair *p);
int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                          int local_idx, int tx_slot);
int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                        int wan_idx, int tx_slot);

void *ne_packet_data(struct ne_pair *p, uint64_t addr);
int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out);
void ne_frame_free(struct ne_pair *p, uint64_t addr);

void interface_reset_redirect_maps(void);
void interface_ip_xdp_off(const char *ifname);
void interface_ip_xdp_off_config(const struct app_config *cfg);
void interface_promisc_off_config(const struct app_config *cfg);
int interface_set_queue_count(const char *ifname, int desired_count);
int interface_get_queue_count(const char *ifname);
int interface_link_is_up(const char *ifname);

#endif
