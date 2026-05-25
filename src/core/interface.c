#include "../../inc/core/interface.h"

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>

static void xdp_try_detach(int ifindex, const char *ifname)
{
    static const int modes[] = {
        XDP_FLAGS_SKB_MODE,
        XDP_FLAGS_DRV_MODE,
        XDP_FLAGS_HW_MODE,
    };

    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
        int ret = bpf_xdp_detach(ifindex, modes[i], NULL);
        if (ret < 0) {
            int err = -ret;
            if (err != EINVAL && err != EOPNOTSUPP && err != ENODEV && err != ENOENT && ifname)
                fprintf(stderr, "[XDP] %s: detach flags=0x%x ret=%d (%s)\n",
                        ifname, (unsigned)modes[i], ret, strerror(err));
        }
    }
}

void interface_xdp_detach_all_from_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++) {
        unsigned ix = if_nametoindex(cfg->locals[i].ifname);
        if (ix)
            xdp_try_detach((int)ix, cfg->locals[i].ifname);
    }
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++) {
        unsigned ix = if_nametoindex(cfg->wans[i].ifname);
        if (ix)
            xdp_try_detach((int)ix, cfg->wans[i].ifname);
    }
}

void interface_reset_redirect_maps(void) {}

int interface_push_encrypt_filters(const struct app_config *cfg)
{
    (void)cfg;
    return 0;
}

int interface_set_queue_count(const char *ifname, int desired_count)
{
    (void)ifname;
    (void)desired_count;
    return 0;
}

int interface_get_queue_count(const char *ifname)
{
    (void)ifname;
    return 1;
}

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

static int pool_init(struct ne_pool *p, uint32_t cap)
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

static void pool_destroy(struct ne_pool *p)
{
    if (!p || !p->buf)
        return;
    pthread_spin_destroy(&p->lock);
    free(p->buf);
    memset(p, 0, sizeof(*p));
}

static uint32_t pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n)
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

static uint32_t pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n)
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
    return (p && addr_out && pool_pop(&p->pool, addr_out, 1) == 1) ? 0 : -1;
}

void ne_frame_free(struct ne_pair *p, uint64_t addr)
{
    if (p)
        (void)pool_push(&p->pool, &addr, 1);
}

void *ne_packet_data(struct ne_pair *p, uint64_t addr)
{
    return xsk_umem__get_data(p->bufs, addr);
}

static int update_xsk_map(struct xsk_socket *xsk, int map_fd)
{
    int key = 0;
    int fd = xsk_socket__fd(xsk);
    if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
        return 0;
    return bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY);
}

static int open_bpf_object(const char *path, struct bpf_object **obj_out,
                           const char *prog_name, struct bpf_program **prog_out,
                           const char *map_name, struct bpf_map **map_out)
{
    struct bpf_object *obj = bpf_object__open_file(path, NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "[XDP] open failed: %s\n", path);
        return -1;
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[XDP] load failed: %s\n", path);
        bpf_object__close(obj);
        return -1;
    }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[XDP] object %s missing program/map\n", path);
        bpf_object__close(obj);
        return -1;
    }

    *obj_out = obj;
    *prog_out = prog;
    *map_out = map;
    return 0;
}

static int open_port(struct ne_pair *p, struct ne_port *port, const char *ifname)
{
    struct xsk_socket_config cfg = {
        .rx_size = 4096,
        .tx_size = 4096,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = p->xdp_flags,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    port->ifindex = if_nametoindex(ifname);
    if (!port->ifindex) {
        fprintf(stderr, "[XSK] interface not found: %s\n", ifname);
        return -1;
    }
    strncpy(port->ifname, ifname, sizeof(port->ifname) - 1);
    port->ifname[sizeof(port->ifname) - 1] = '\0';

    int ret = xsk_socket__create_shared(&port->xsk, ifname, 0, p->umem,
                                        &port->rx, &port->tx,
                                        &port->fq, &port->cq, &cfg);
    if (ret) {
        fprintf(stderr, "[XSK] create %s failed: %d\n", ifname, ret);
        return -1;
    }
    return 0;
}

static void prefill_port(struct ne_pair *p, struct ne_port *port, uint32_t want)
{
    uint64_t addrs[NE_BATCH_SIZE];

    while (want > 0) {
        uint32_t n = want > NE_BATCH_SIZE ? NE_BATCH_SIZE : want;
        uint32_t got = pool_pop(&p->pool, addrs, n);
        if (got == 0)
            return;

        uint32_t idx = 0;
        uint32_t reserved = xsk_ring_prod__reserve(&port->fq, got, &idx);
        if (reserved != got) {
            (void)pool_push(&p->pool, addrs, got);
            return;
        }
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&port->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&port->fq, got);
        want -= got;
    }
}

static void update_wan_fake_ethertype(struct bpf_object *obj, uint16_t fake_ethertype_ipv4)
{
    if (!obj || fake_ethertype_ipv4 == 0)
        return;
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "wan_config_map");
    if (!map)
        return;
    int key = 0;
    (void)bpf_map_update_elem(bpf_map__fd(map), &key, &fake_ethertype_ipv4, BPF_ANY);
}

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
#define NE_TRY(expr) do { if (expr) goto fail; } while (0)
    if (!p || !cfg || cfg->local_count <= 0 || cfg->wan_count <= 0)
        return -1;

    memset(p, 0, sizeof(*p));
    p->wan_count = cfg->wan_count;
    if (p->wan_count > MAX_INTERFACES)
        p->wan_count = MAX_INTERFACES;
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    p->frame_size = NE_FRAME;
    p->n_frames = NE_N_FRAMES;
    p->bufsize = (size_t)p->n_frames * (size_t)p->frame_size;
    p->xdp_flags = XDP_FLAGS_DRV_MODE;

    p->bufs = mmap(NULL, p->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p->bufs == MAP_FAILED)
        return -1;

    NE_TRY(pool_init(&p->pool, p->n_frames));
    for (uint32_t i = 0; i < p->n_frames; i++) {
        uint64_t addr = (uint64_t)i * p->frame_size;
        (void)pool_push(&p->pool, &addr, 1);
    }

    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                            &p->local.fq, &p->local.cq, &ucfg));

    NE_TRY(open_port(p, &p->local, cfg->locals[0].ifname));
    for (int i = 0; i < p->wan_count; i++)
        NE_TRY(open_port(p, &p->wans[i], cfg->wans[i].ifname));

    struct bpf_program *local_prog = NULL;
    struct bpf_map *local_map = NULL;
    NE_TRY(open_bpf_object(cfg->bpf_file, &p->bpf_local,
                           "xdp_redirect_prog", &local_prog, "xsks_map", &local_map));

    NE_TRY(bpf_xdp_attach(p->local.ifindex, bpf_program__fd(local_prog), p->xdp_flags, NULL));
    p->xdp_local_on = 1;

    NE_TRY(update_xsk_map(p->local.xsk, bpf_map__fd(local_map)));

    for (int i = 0; i < p->wan_count; i++) {
        struct bpf_program *wan_prog = NULL;
        struct bpf_map *wan_map = NULL;
        NE_TRY(open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[i],
                               "xdp_wan_redirect_prog", &wan_prog, "wan_xsks_map", &wan_map));
        update_wan_fake_ethertype(p->bpf_wans[i], cfg->fake_ethertype_ipv4);
        NE_TRY(bpf_xdp_attach(p->wans[i].ifindex, bpf_program__fd(wan_prog), p->xdp_flags, NULL));
        p->xdp_wan_on[i] = 1;
        NE_TRY(update_xsk_map(p->wans[i].xsk, bpf_map__fd(wan_map)));
    }

    uint32_t prefill = NE_N_FRAMES / (uint32_t)(p->wan_count + 2);
    if (prefill == 0)
        prefill = 1;
    prefill_port(p, &p->local, prefill);
    for (int i = 0; i < p->wan_count; i++)
        prefill_port(p, &p->wans[i], prefill);
    return 0;

fail:
    ne_pair_close(p);
    return -1;
#undef NE_TRY
}

void ne_pair_close(struct ne_pair *p)
{
    if (!p)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (p->xdp_wan_on[i])
            bpf_xdp_detach(p->wans[i].ifindex, p->xdp_flags, NULL);
    }
    if (p->xdp_local_on)
        bpf_xdp_detach(p->local.ifindex, p->xdp_flags, NULL);
    for (int i = 0; i < p->wan_count; i++) {
        if (p->bpf_wans[i])
            bpf_object__close(p->bpf_wans[i]);
    }
    if (p->bpf_local)
        bpf_object__close(p->bpf_local);
    for (int i = 0; i < p->wan_count; i++) {
        if (p->wans[i].xsk)
            xsk_socket__delete(p->wans[i].xsk);
    }
    if (p->local.xsk)
        xsk_socket__delete(p->local.xsk);
    if (p->umem)
        xsk_umem__delete(p->umem);
    pool_destroy(&p->pool);
    if (p->bufs && p->bufs != MAP_FAILED)
        munmap(p->bufs, p->bufsize);
    memset(p, 0, sizeof(*p));
}

static int recv_port(struct ne_port *port, struct ne_packet *out, uint32_t max, uint8_t dir, uint8_t wan_idx)
{
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&port->rx, max, &idx);
    for (uint32_t i = 0; i < n; i++) {
        const struct xdp_desc *d = xsk_ring_cons__rx_desc(&port->rx, idx + i);
        out[i].addr = d->addr;
        out[i].len = d->len;
        out[i].dir = dir;
        out[i].wan_idx = wan_idx;
    }
    port->rx_packets += n;
    return (int)n;
}

int ne_recv_local(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    return recv_port(&p->local, out, max, NE_DIR_LOCAL, 0);
}

int ne_recv_wan(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    memset(p->wan_rx_pending, 0, sizeof(p->wan_rx_pending));
    for (int i = 0; i < p->wan_count && total < max; i++) {
        int n = recv_port(&p->wans[i], out + total, max - total, NE_DIR_WAN, (uint8_t)i);
        if (n > 0) {
            p->wan_rx_pending[i] = (uint32_t)n;
            total += (uint32_t)n;
        }
    }
    return (int)total;
}

void ne_recv_release_local(struct ne_pair *p, uint32_t n)
{
    if (n)
        xsk_ring_cons__release(&p->local.rx, n);
}

void ne_recv_release_wan(struct ne_pair *p, uint32_t n)
{
    (void)n;
    for (int i = 0; i < p->wan_count; i++) {
        if (p->wan_rx_pending[i])
            xsk_ring_cons__release(&p->wans[i].rx, p->wan_rx_pending[i]);
        p->wan_rx_pending[i] = 0;
    }
}

static void drain_cq(struct ne_port *port, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t n = xsk_ring_cons__peek(&port->cq, NE_BATCH_SIZE, &idx);
    if (!n)
        return;
    for (uint32_t i = 0; i < n; i++)
        addrs[i] = *xsk_ring_cons__comp_addr(&port->cq, idx + i);
    xsk_ring_cons__release(&port->cq, n);
    (void)pool_push(pool, addrs, n);
}

void ne_drain_cq_local(struct ne_pair *p)
{
    drain_cq(&p->local, &p->pool);
}

void ne_drain_cq_wan(struct ne_pair *p)
{
    for (int i = 0; i < p->wan_count; i++)
        drain_cq(&p->wans[i], &p->pool);
}

static void refill_fq(struct ne_port *port, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&port->fq, NE_BATCH_SIZE);
    if (free_slots < NE_BATCH_SIZE)
        return;

    uint32_t got = pool_pop(pool, addrs, NE_BATCH_SIZE);
    if (!got)
        return;
    if (xsk_ring_prod__reserve(&port->fq, got, &idx) != got) {
        (void)pool_push(pool, addrs, got);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&port->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&port->fq, got);
}

void ne_refill_fq_local(struct ne_pair *p)
{
    refill_fq(&p->local, &p->pool);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
    for (int i = 0; i < p->wan_count; i++)
        refill_fq(&p->wans[i], &p->pool);
}

static int tx_drain_port(struct ne_port *port, struct ne_ring *src, uint32_t max_frame)
{
    struct ne_packet jobs[NE_BATCH_SIZE];
    uint32_t free_slots = xsk_prod_nb_free(&port->tx, NE_BATCH_SIZE);
    if (!free_slots)
        return 0;

    uint32_t popped = 0;
    uint32_t want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    while (popped < want && ne_ring_try_pop(src, &jobs[popped]) == 0)
        popped++;
    if (!popped)
        return 0;

    uint32_t idx = 0;
    if (xsk_ring_prod__reserve(&port->tx, popped, &idx) != popped) {
        for (uint32_t i = 0; i < popped; i++)
            (void)ne_ring_try_push(src, &jobs[i]);
        return 0;
    }

    for (uint32_t i = 0; i < popped; i++) {
        struct xdp_desc *d = xsk_ring_prod__tx_desc(&port->tx, idx + i);
        d->addr = jobs[i].addr;
        d->len = jobs[i].len > max_frame ? max_frame : jobs[i].len;
    }
    xsk_ring_prod__submit(&port->tx, popped);
    (void)sendto(xsk_socket__fd(port->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    port->tx_packets += popped;
    return (int)popped;
}

int ne_tx_drain_local(struct ne_pair *p, struct ne_ring *src)
{
    return tx_drain_port(&p->local, src, p->frame_size);
}

int ne_tx_drain_wan(struct ne_pair *p, struct ne_ring *src, int wan_idx)
{
    if (!p || wan_idx < 0 || wan_idx >= p->wan_count)
        return 0;
    return tx_drain_port(&p->wans[wan_idx], src, p->frame_size);
}
