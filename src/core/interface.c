#include "../../inc/core/interface.h"

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <ctype.h>
#include <dirent.h>

static uint32_t next_pow2_u32(uint32_t v)
{
    if (v <= 1)
        return 1;
    v--;
    v |= v >> 1;
    v |= v >> 2;
    v |= v >> 4;
    v |= v >> 8;
    v |= v >> 16;
    return v + 1;
}

static int ifname_is_safe(const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

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
        if (!cfg->wans[i].dataplane)
            continue;
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
    if (!ifname_is_safe(ifname) || desired_count <= 0)
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ethtool -L %s combined %d >/dev/null 2>&1",
             ifname, desired_count);
    if (system(cmd) == 0) {
        fprintf(stderr, "[QUEUE] %s combined=%d\n", ifname, desired_count);
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "ethtool -L %s rx %d tx %d >/dev/null 2>&1",
             ifname, desired_count, desired_count);
    if (system(cmd) == 0) {
        fprintf(stderr, "[QUEUE] %s rx=%d tx=%d\n",
                ifname, desired_count, desired_count);
        return 0;
    }

    fprintf(stderr, "[QUEUE] %s unable to force queue_count=%d\n",
            ifname, desired_count);
    return -1;
}

static int interface_set_promisc(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on >/dev/null 2>&1", ifname);
    if (system(cmd) == 0) {
        fprintf(stderr, "[PROMISC] %s on\n", ifname);
        return 0;
    }

    fprintf(stderr, "[PROMISC] %s unable to enable promisc\n", ifname);
    return -1;
}

int interface_get_queue_count(const char *ifname)
{
    char path[256];
    int count = 0;

    if (!ifname_is_safe(ifname))
        return 1;

    snprintf(path, sizeof(path), "/sys/class/net/%s/queues", ifname);
    DIR *dir = opendir(path);
    if (!dir)
        return 1;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (strncmp(ent->d_name, "rx-", 3) == 0)
            count++;
    }
    closedir(dir);
    return count > 0 ? count : 1;
}

static int resolve_iface_queue_count(const char *ifname, int cfg_count, int target_default)
{
    int want = cfg_count > 0 ? cfg_count : target_default;
    int hw = interface_get_queue_count(ifname);

    if (hw > 0 && want > hw)
        want = hw;
    if (want > MAX_QUEUES)
        want = MAX_QUEUES;
    if (want < 1)
        want = 1;
    return want;
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

static int update_xsk_map_queue(struct xsk_socket *xsk, int map_fd, int queue_id)
{
    int key = queue_id;
    int fd = xsk_socket__fd(xsk);
    if (xsk_socket__update_xskmap(xsk, map_fd) == 0)
        return 0;
    return bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY);
}

static int update_xsk_map_iface(struct ne_iface *iface, int map_fd)
{
    for (int q = 0; q < iface->queue_count; q++) {
        if (!iface->queues[q].xsk)
            return -1;
        if (update_xsk_map_queue(iface->queues[q].xsk, map_fd, q) != 0)
            return -1;
    }
    return 0;
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

static int open_iface_queues(struct ne_pair *p, struct ne_iface *iface,
                             const char *ifname, int queue_count)
{
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = p->xdp_flags,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex) {
        fprintf(stderr, "[XSK] interface not found: %s\n", ifname);
        return -1;
    }
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = queue_count;

    for (int q = 0; q < queue_count; q++) {
        struct ne_xsk_queue *slot = &iface->queues[q];
        int ret = xsk_socket__create_shared(&slot->xsk, ifname, (uint32_t)q, p->umem,
                                            &slot->rx, &slot->tx,
                                            &slot->fq, &slot->cq, &cfg);
        if (ret) {
            fprintf(stderr, "[XSK] create %s queue=%d failed: %d\n", ifname, q, ret);
            return -1;
        }
        fprintf(stderr, "[TRACE XSK] opened if=%s q=%d ifindex=%d rx=%u tx=%u mode=copy\n",
                iface->ifname, q, iface->ifindex, NE_RING, NE_RING);
    }
    return 0;
}

static void prefill_queue(struct ne_pair *p, struct ne_xsk_queue *slot, uint32_t want)
{
    uint64_t addrs[NE_BATCH_SIZE];

    while (want > 0) {
        uint32_t n = want > NE_BATCH_SIZE ? NE_BATCH_SIZE : want;
        uint32_t got = pool_pop(&p->pool, addrs, n);
        if (got == 0)
            return;

        uint32_t idx = 0;
        uint32_t reserved = xsk_ring_prod__reserve(&slot->fq, got, &idx);
        if (reserved != got) {
            (void)pool_push(&p->pool, addrs, got);
            return;
        }
        for (uint32_t i = 0; i < got; i++)
            *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
        xsk_ring_prod__submit(&slot->fq, got);
        want -= got;
    }
}

static void prefill_iface(struct ne_pair *p, struct ne_iface *iface, uint32_t want_per_queue)
{
    for (int q = 0; q < iface->queue_count; q++)
        prefill_queue(p, &iface->queues[q], want_per_queue);
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
    if (!p || !cfg || cfg->local_count <= 0 || config_count_dataplane_wans(cfg) <= 0)
        return -1;

    memset(p, 0, sizeof(*p));
    p->local_count = cfg->local_count;
    if (p->local_count > MAX_INTERFACES)
        p->local_count = MAX_INTERFACES;
    p->wan_count = config_count_dataplane_wans(cfg);
    if (p->wan_count > MAX_INTERFACES)
        p->wan_count = MAX_INTERFACES;
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    p->frame_size = NE_FRAME;
    p->n_frames = next_pow2_u32(NE_N_FRAMES * (uint32_t)(p->local_count + p->wan_count + 1));
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

    p->local_queue_total = 0;
    p->wan_queue_total = 0;

    for (int i = 0; i < p->local_count; i++) {
        int nq = resolve_iface_queue_count(cfg->locals[i].ifname,
                                           cfg->locals[i].queue_count,
                                           NE_LOCAL_QUEUE_TARGET);
        NE_TRY(interface_set_queue_count(cfg->locals[i].ifname, nq));
        p->locals[i].queue_count = nq;
        p->local_queue_total += nq;
    }
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        int nq = resolve_iface_queue_count(cfg->wans[ci].ifname,
                                           cfg->wans[ci].queue_count,
                                           NE_WAN_QUEUE_TARGET);
        NE_TRY(interface_set_queue_count(cfg->wans[ci].ifname, nq));
        p->wans[di].queue_count = nq;
        p->wan_queue_total += nq;
    }

    for (int i = 0; i < p->local_count; i++)
        NE_TRY(interface_set_promisc(cfg->locals[i].ifname));
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        NE_TRY(interface_set_promisc(cfg->wans[ci].ifname));
    }

    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                            &p->locals[0].queues[0].fq,
                            &p->locals[0].queues[0].cq, &ucfg));

    for (int i = 0; i < p->local_count; i++)
        NE_TRY(open_iface_queues(p, &p->locals[i], cfg->locals[i].ifname,
                                 p->locals[i].queue_count));
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        NE_TRY(open_iface_queues(p, &p->wans[di], cfg->wans[ci].ifname,
                                 p->wans[di].queue_count));
    }

    for (int i = 0; i < p->local_count; i++) {
        struct bpf_program *local_prog = NULL;
        struct bpf_map *local_map = NULL;
        NE_TRY(open_bpf_object(cfg->bpf_file, &p->bpf_locals[i],
                               "xdp_redirect_prog", &local_prog, "xsks_map", &local_map));
        NE_TRY(bpf_xdp_attach(p->locals[i].ifindex, bpf_program__fd(local_prog), p->xdp_flags, NULL));
        p->xdp_local_on[i] = 1;
        NE_TRY(update_xsk_map_iface(&p->locals[i], bpf_map__fd(local_map)));
        fprintf(stderr, "[TRACE XDP] local[%d] if=%s attached xskmap queues=%d (core %u polls all)\n",
                i, p->locals[i].ifname, p->locals[i].queue_count, (unsigned)NE_CPU_LOC);
    }

    for (int di = 0; di < p->wan_count; di++) {
        struct bpf_program *wan_prog = NULL;
        struct bpf_map *wan_map = NULL;
        NE_TRY(open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[di],
                               "xdp_wan_redirect_prog", &wan_prog, "wan_xsks_map", &wan_map));
        update_wan_fake_ethertype(p->bpf_wans[di], cfg->fake_ethertype_ipv4);
        NE_TRY(bpf_xdp_attach(p->wans[di].ifindex, bpf_program__fd(wan_prog), p->xdp_flags, NULL));
        p->xdp_wan_on[di] = 1;
        NE_TRY(update_xsk_map_iface(&p->wans[di], bpf_map__fd(wan_map)));
        fprintf(stderr, "[TRACE XDP] wan[%d] if=%s attached xskmap queues=%d (core %u polls all)\n",
                di, p->wans[di].ifname, p->wans[di].queue_count, (unsigned)NE_CPU_WAN);
    }

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    for (int i = 0; i < p->local_count; i++)
        prefill_iface(p, &p->locals[i], prefill);
    for (int i = 0; i < p->wan_count; i++)
        prefill_iface(p, &p->wans[i], prefill);

    int total_queues = p->local_queue_total + p->wan_queue_total;
    fprintf(stderr,
            "[TRACE UMEM] frames=%u frame_size=%u mb=%zu prefill_per_queue=%u "
            "local_if=%d local_queues=%d wan_if=%d wan_queues=%d total_xsk_queues=%d\n",
            p->n_frames, p->frame_size, p->bufsize / (1024 * 1024), prefill,
            p->local_count, p->local_queue_total, p->wan_count, p->wan_queue_total,
            total_queues);
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
    for (int i = 0; i < p->local_count; i++) {
        if (p->xdp_local_on[i])
            bpf_xdp_detach(p->locals[i].ifindex, p->xdp_flags, NULL);
    }
    for (int i = 0; i < p->local_count; i++) {
        if (p->bpf_locals[i])
            bpf_object__close(p->bpf_locals[i]);
    }
    for (int i = 0; i < p->wan_count; i++) {
        if (p->bpf_wans[i])
            bpf_object__close(p->bpf_wans[i]);
    }
    for (int i = 0; i < p->wan_count; i++) {
        for (int q = 0; q < p->wans[i].queue_count; q++) {
            if (p->wans[i].queues[q].xsk)
                xsk_socket__delete(p->wans[i].queues[q].xsk);
        }
    }
    for (int i = 0; i < p->local_count; i++) {
        for (int q = 0; q < p->locals[i].queue_count; q++) {
            if (p->locals[i].queues[q].xsk)
                xsk_socket__delete(p->locals[i].queues[q].xsk);
        }
    }
    if (p->umem)
        xsk_umem__delete(p->umem);
    pool_destroy(&p->pool);
    if (p->bufs && p->bufs != MAP_FAILED)
        munmap(p->bufs, p->bufsize);
    memset(p, 0, sizeof(*p));
}

static int recv_queue(struct ne_xsk_queue *slot, struct ne_packet *out, uint32_t max,
                      uint8_t dir, uint8_t wan_idx, uint8_t local_idx)
{
    uint32_t idx = 0;
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

    for (int i = 0; i < p->local_count && total < max; i++) {
        struct ne_iface *iface = &p->locals[i];
        for (int q = 0; q < iface->queue_count && total < max; q++) {
            iface->queues[q].rx_pending = 0;
            int n = recv_queue(&iface->queues[q], out + total, max - total,
                               NE_DIR_LOCAL, 0, (uint8_t)i);
            total += (uint32_t)n;
        }
    }
    return (int)total;
}

int ne_recv_wan(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;

    for (int i = 0; i < p->wan_count && total < max; i++) {
        struct ne_iface *iface = &p->wans[i];
        for (int q = 0; q < iface->queue_count && total < max; q++) {
            iface->queues[q].rx_pending = 0;
            int n = recv_queue(&iface->queues[q], out + total, max - total,
                               NE_DIR_WAN, (uint8_t)i, 0);
            total += (uint32_t)n;
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
        (void)pool_push(pool, addrs, n);
    }
}

static void drain_cq_iface(struct ne_iface *iface, struct ne_pool *pool)
{
    for (int q = 0; q < iface->queue_count; q++)
        drain_cq_queue(&iface->queues[q], pool);
}

void ne_drain_cq_local(struct ne_pair *p)
{
    for (int i = 0; i < p->local_count; i++)
        drain_cq_iface(&p->locals[i], &p->pool);
}

void ne_drain_cq_wan(struct ne_pair *p)
{
    for (int i = 0; i < p->wan_count; i++)
        drain_cq_iface(&p->wans[i], &p->pool);
}

static void refill_fq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&slot->fq, NE_BATCH_SIZE);
    if (free_slots < NE_BATCH_SIZE)
        return;

    uint32_t got = pool_pop(pool, addrs, NE_BATCH_SIZE);
    if (!got)
        return;
    if (xsk_ring_prod__reserve(&slot->fq, got, &idx) != got) {
        (void)pool_push(pool, addrs, got);
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
    for (int i = 0; i < p->local_count; i++)
        refill_fq_iface(&p->locals[i], &p->pool);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
    for (int i = 0; i < p->wan_count; i++)
        refill_fq_iface(&p->wans[i], &p->pool);
}

static int tx_drain_queue(struct ne_xsk_queue *slot, struct ne_ring *src, uint32_t max_frame,
                          uint64_t *tx_no_free)
{
    struct ne_packet jobs[NE_BATCH_SIZE];
    uint32_t free_slots = xsk_prod_nb_free(&slot->tx, NE_BATCH_SIZE);
    if (!free_slots) {
        if (tx_no_free)
            (*tx_no_free)++;
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
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
    (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
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

