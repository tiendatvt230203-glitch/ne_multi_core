#include "../../inc/core/interface.h"
#include "../../inc/io/interface_internal.h"

#include <linux/if_xdp.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>

int ne_ring_init(struct ne_ring *r, uint32_t cap)
{
    if (!r || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(r, 0, sizeof(*r));
    r->buf = calloc(cap, sizeof(*r->buf));
    if (!r->buf)
        return -1;
    r->cap = cap;
    r->mask = cap - 1;
    return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
    if (!r)
        return;
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt)
{
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if ((uint32_t)(head - tail) >= r->cap)
        return -1;
    r->buf[head & r->mask] = *pkt;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    return 0;
}

int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt)
{
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    if (tail == head)
        return -1;
    *pkt = r->buf[tail & r->mask];
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
    return 0;
}

uint32_t ne_ring_count(const struct ne_ring *r)
{
    uint32_t head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    uint32_t tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    return head - tail;
}

int ne_pool_init(struct ne_pool *p, uint32_t cap)
{
    if (!p || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(p, 0, sizeof(*p));
    p->buf = calloc(cap, sizeof(*p->buf));
    if (!p->buf)
        return -1;
    p->cap = cap;
    p->mask = cap - 1;
    if (pthread_spin_init(&p->lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(p->buf);
        memset(p, 0, sizeof(*p));
        return -1;
    }
    return 0;
}

void ne_pool_destroy(struct ne_pool *p)
{
    if (!p || !p->buf)
        return;
    pthread_spin_destroy(&p->lock);
    free(p->buf);
    memset(p, 0, sizeof(*p));
}

uint32_t ne_pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n)
{
    pthread_spin_lock(&p->lock);
    uint32_t free_slots = p->cap - (p->head - p->tail);
    uint32_t put = n < free_slots ? n : free_slots;
    uint32_t head = p->head;
    for (uint32_t i = 0; i < put; i++)
        p->buf[(head + i) & p->mask] = addrs[i];
    p->head += put;
    pthread_spin_unlock(&p->lock);
    return put;
}

uint32_t ne_pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n)
{
    pthread_spin_lock(&p->lock);
    uint32_t avail = p->head - p->tail;
    uint32_t got = n < avail ? n : avail;
    uint32_t tail = p->tail;
    for (uint32_t i = 0; i < got; i++)
        addrs[i] = p->buf[(tail + i) & p->mask];
    p->tail += got;
    pthread_spin_unlock(&p->lock);
    return got;
}

int ne_frame_alloc(struct ne_pair *p, uint64_t *addr_out)
{
    return (p && addr_out && ne_pool_pop(&p->pool, addr_out, 1) == 1) ? 0 : -1;
}

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    if (p)
        (void)ne_pool_push(&p->pool, &addr, 1);
}

void *ne_packet_data(struct ne_pair *p, uint64_t addr)
{
    return xsk_umem__get_data(p->bufs, addr);
}

static int recv_queue(struct ne_xsk_queue *slot, struct ne_packet *out, uint32_t max,
                      uint8_t dir, uint8_t wan_idx, uint8_t local_idx)
{
    uint32_t idx = 0;

    if (slot->rx.flags && (*slot->rx.flags & XDP_RING_NEED_WAKEUP))
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);

    uint32_t n = xsk_ring_cons__peek(&slot->rx, max, &idx);
    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&slot->rx, idx + i);
        out[i].addr = d->addr;
        out[i].len = d->len;
        out[i].dir = dir;
        out[i].wan_idx = wan_idx;
        out[i].local_idx = local_idx;
    }
    slot->rx_pending = n;
    return (int)n;
}

int ne_recv_local(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out; 

    for (int i = 0; i < p->local_count && total < max; i++) {
        struct ne_iface *iface = &p->locals[i];
        int q_count = iface->queue_count;
        
        for (int q = 0; q < q_count && total < max; q++) {
            iface->queues[q].rx_pending = 0; 
            
            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_LOCAL, 0, (uint8_t)i);
            
            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

int ne_recv_wan(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out; 

    for (int i = 0; i < p->wan_count && total < max; i++) {
        struct ne_iface *iface = &p->wans[i];
        int q_count = iface->queue_count;
        
        for (int q = 0; q < q_count && total < max; q++) {
            iface->queues[q].rx_pending = 0; 
            
            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_WAN, (uint8_t)i, 0);
            
            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}


void ne_recv_release_local(struct ne_pair *p)
{
    for (int i = 0; i < p->local_count; i++) {
        struct ne_iface *iface = &p->locals[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

void ne_recv_release_wan(struct ne_pair *p)
{
    for (int i = 0; i < p->wan_count; i++) {
        struct ne_iface *iface = &p->wans[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

static void drain_cq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t n;

    while ((n = xsk_ring_cons__peek(&slot->cq, NE_BATCH_SIZE, &idx)) > 0) {
        for (uint32_t i = 0; i < n; i++)
            addrs[i] = *xsk_ring_cons__comp_addr(&slot->cq, idx + i);
        xsk_ring_cons__release(&slot->cq, n);
        (void)ne_pool_push(pool, addrs, n);
        if (n < NE_BATCH_SIZE) {
            break;
        }
    }
}

static void drain_cq_iface(struct ne_iface *iface, struct ne_pool *pool)
{
    for (int q = 0; q < iface->queue_count; q++)
        drain_cq_queue(&iface->queues[q], pool);
}

static void drain_cq_umem(struct ne_pair *p)
{
    if (p->local_count > 0)
        drain_cq_queue(&p->locals[0].queues[0], &p->pool);
}

void ne_drain_cq_local(struct ne_pair *p)
{
    /* Single UMEM completion ring shared by all AF_XDP sockets. */
    drain_cq_umem(p);
}

void ne_drain_cq_wan(struct ne_pair *p)
{
    drain_cq_umem(p);
}

static void refill_fq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&slot->fq, NE_BATCH_SIZE);
    if (free_slots < NE_BATCH_SIZE)
        return;

    uint32_t got = ne_pool_pop(pool, addrs, NE_BATCH_SIZE);
    if (!got)
        return;
    if (xsk_ring_prod__reserve(&slot->fq, got, &idx) != got) {
        (void)ne_pool_push(pool, addrs, got);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&slot->fq, got);
}

static void refill_fq_iface(struct ne_iface *iface, struct ne_pool *pool)
{
    for (int q = 0; q < iface->queue_count; q++)
        refill_fq_queue(&iface->queues[q], pool);
}

void ne_refill_fq_local(struct ne_pair *p)
{
    if (p->local_count > 0)
        refill_fq_queue(&p->locals[0].queues[0], &p->pool);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
    if (p->local_count > 0)
        refill_fq_queue(&p->locals[0].queues[0], &p->pool);
}

static int tx_drain_queue(struct ne_xsk_queue *slot, struct ne_ring *src, uint32_t max_frame,
                          uint64_t *tx_no_free)
{
    struct ne_packet jobs[NE_BATCH_SIZE];
    uint32_t free_slots = xsk_prod_nb_free(&slot->tx, NE_BATCH_SIZE);
    if (!free_slots) {
        if (tx_no_free)
            (*tx_no_free)++;
        
        if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
            (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        }
        return 0;
    }

    uint32_t popped = 0;
    uint32_t want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    while (popped < want && ne_ring_try_pop(src, &jobs[popped]) == 0)
        popped++;
    if (!popped)
        return 0;

    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&slot->tx, popped, &idx) != popped) {
        for (uint32_t i = 0; i < popped; i++)
            (void)ne_ring_try_push(src, &jobs[i]);
        return 0;
    }

    for (uint32_t i = 0; i < popped; i++) {
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&slot->tx, idx + i);
        d->addr = jobs[i].addr;
        d->len = jobs[i].len > max_frame ? max_frame : jobs[i].len;
    }
    
    xsk_ring_prod__submit(&slot->tx, popped);
    if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
    
    return (int)popped;
}


static int tx_drain_iface(struct ne_iface *iface, struct ne_ring *src, uint32_t max_frame)
{
    int sent = 0;
    int q = iface->tx_queue_rr % iface->queue_count;
    sent += tx_drain_queue(&iface->queues[q], src, max_frame, &iface->tx_no_free);
    iface->tx_queue_rr = (q + 1) % iface->queue_count;
    return sent;
}

int ne_tx_drain_local(struct ne_pair *p, struct ne_ring *src, int local_idx)
{
    if (!p || local_idx < 0 || local_idx >= p->local_count)
        return 0;
    return tx_drain_iface(&p->locals[local_idx], src, p->frame_size);
}

int ne_tx_drain_wan(struct ne_pair *p, struct ne_ring *src, int wan_idx)
{
    if (!p || wan_idx < 0 || wan_idx >= p->wan_count)
        return 0;
    return tx_drain_iface(&p->wans[wan_idx], src, p->frame_size);
}

