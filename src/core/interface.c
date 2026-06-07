#include "../../inc/core/interface.h"

#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
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

void interface_ip_xdp_off(const char *ifname)
{
    if (!ifname || !ifname[0] || !ifname_is_safe(ifname))
        return;
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "/sbin/ip link set dev %s xdp off", ifname);
    int st = system(cmd);
    int ok = (st == 0) || (WIFEXITED(st) && WEXITSTATUS(st) == 0);
    fprintf(stderr, "[XDP] ip link set dev %s xdp off: %s\n", ifname, ok ? "ok" : "FAILED");
    fflush(stderr);
}

void interface_ip_xdp_off_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        interface_ip_xdp_off(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        interface_ip_xdp_off(cfg->wans[i].ifname);
}

static int interface_set_promisc_off(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc off >/dev/null 2>&1", ifname);
    return system(cmd) == 0 ? 0 : -1;
}

void interface_promisc_off_config(const struct app_config *cfg)
{
    if (!cfg)
        return;
    for (int i = 0; i < cfg->local_count && i < MAX_INTERFACES; i++)
        interface_set_promisc_off(cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count && i < MAX_INTERFACES; i++)
        interface_set_promisc_off(cfg->wans[i].ifname);
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
        return 0;
    }

    snprintf(cmd, sizeof(cmd), "ethtool -L %s rx %d tx %d >/dev/null 2>&1",
             ifname, desired_count, desired_count);
    if (system(cmd) == 0)
        return 0;

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

static int update_xsk_map_iface(struct ne_iface *iface, int map_fd, uint8_t shard_id)
{
    int mapped = 0;

    for (int q = 0; q < iface->queue_count; q++) {
        if ((q & 1) != shard_id || !iface->queues[q].xsk)
            continue;
        if (update_xsk_map_queue(iface->queues[q].xsk, map_fd, q) != 0)
            return -1;
        mapped++;
    }
    return mapped > 0 ? 0 : -1;
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

static struct ne_xsk_queue *pair_first_owned_queue(struct ne_pair *p, uint8_t shard_id)
{
    for (int i = 0; i < p->local_count; i++) {
        for (int q = 0; q < p->locals[i].queue_count; q++) {
            if ((q & 1) == shard_id)
                return &p->locals[i].queues[q];
        }
    }
    for (int i = 0; i < p->wan_count; i++) {
        for (int q = 0; q < p->wans[i].queue_count; q++) {
            if ((q & 1) == shard_id)
                return &p->wans[i].queues[q];
        }
    }
    return NULL;
}

static int open_iface_queues(struct ne_pair *p, struct ne_iface *iface,
                             const char *ifname, int queue_count, uint8_t shard_id)
{
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = p->xdp_flags,
        .bind_flags = XDP_COPY | XDP_USE_NEED_WAKEUP,
    };
    int opened = 0;

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
        if ((q & 1) != shard_id) {
            memset(slot, 0, sizeof(*slot));
            continue;
        }
        int ret = xsk_socket__create_shared(&slot->xsk, ifname, (uint32_t)q, p->umem,
                                            &slot->rx, &slot->tx,
                                            &slot->fq, &slot->cq, &cfg);
        if (ret) {
            fprintf(stderr, "[XSK] shard%u create %s queue=%d failed: %d\n",
                    shard_id, ifname, q, ret);
            return -1;
        }
        opened++;
    }
    return opened > 0 ? 0 : -1;
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
    for (int q = 0; q < iface->queue_count; q++) {
        if (!iface->queues[q].xsk)
            continue;
        prefill_queue(p, &iface->queues[q], want_per_queue);
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

static int ne_pair_open_shard(struct ne_pair *p, const struct app_config *cfg,
                              uint8_t shard_id, int owns_xdp,
                              int local_count, int wan_count)
{
#define NE_TRY(expr) do { if (expr) goto fail; } while (0)
    struct ne_xsk_queue *umem_q;
    struct xsk_umem_config ucfg;

    memset(p, 0, sizeof(*p));
    p->shard_id = shard_id;
    p->owns_xdp = (uint8_t)(owns_xdp ? 1 : 0);
    p->local_count = local_count;
    p->wan_count = wan_count;
    p->frame_size = NE_FRAME;
    p->n_frames = next_pow2_u32((NE_N_FRAMES / NE_PIPELINE_COUNT) *
                                (uint32_t)(local_count + wan_count + 1));
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

    for (int i = 0; i < p->local_count; i++) {
        int nq = resolve_iface_queue_count(cfg->locals[i].ifname,
                                           cfg->locals[i].queue_count,
                                           NE_LOCAL_QUEUE_TARGET);
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
        p->wans[di].queue_count = nq;
        p->wan_queue_total += nq;
    }

    /* Set ifindex/ifname on iface stubs before UMEM (needs queue struct fq/cq). */
    for (int i = 0; i < p->local_count; i++) {
        p->locals[i].ifindex = (int)if_nametoindex(cfg->locals[i].ifname);
        if (!p->locals[i].ifindex)
            goto fail;
        strncpy(p->locals[i].ifname, cfg->locals[i].ifname,
                sizeof(p->locals[i].ifname) - 1);
        p->locals[i].ifname[sizeof(p->locals[i].ifname) - 1] = '\0';
    }
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        p->wans[di].ifindex = (int)if_nametoindex(cfg->wans[ci].ifname);
        if (!p->wans[di].ifindex)
            goto fail;
        strncpy(p->wans[di].ifname, cfg->wans[ci].ifname,
                sizeof(p->wans[di].ifname) - 1);
        p->wans[di].ifname[sizeof(p->wans[di].ifname) - 1] = '\0';
    }

    umem_q = pair_first_owned_queue(p, shard_id);
    if (!umem_q)
        goto fail;

    ucfg = (struct xsk_umem_config){
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = p->frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };
    NE_TRY(xsk_umem__create(&p->umem, p->bufs, p->bufsize,
                            &umem_q->fq, &umem_q->cq, &ucfg));

    for (int i = 0; i < p->local_count; i++)
        NE_TRY(open_iface_queues(p, &p->locals[i], cfg->locals[i].ifname,
                                 p->locals[i].queue_count, shard_id));
    for (int di = 0; di < p->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            goto fail;
        NE_TRY(open_iface_queues(p, &p->wans[di], cfg->wans[ci].ifname,
                                 p->wans[di].queue_count, shard_id));
    }

    if (owns_xdp) {
        for (int i = 0; i < p->local_count; i++) {
            struct bpf_program *local_prog = NULL;
            struct bpf_map *local_map = NULL;
            NE_TRY(open_bpf_object(cfg->bpf_file, &p->bpf_locals[i],
                                   "xdp_redirect_prog", &local_prog, "xsks_map", &local_map));
            NE_TRY(bpf_xdp_attach(p->locals[i].ifindex, bpf_program__fd(local_prog),
                                  p->xdp_flags, NULL));
            p->xdp_local_on[i] = 1;
            NE_TRY(update_xsk_map_iface(&p->locals[i], bpf_map__fd(local_map), shard_id));
        }
        for (int di = 0; di < p->wan_count; di++) {
            struct bpf_program *wan_prog = NULL;
            struct bpf_map *wan_map = NULL;
            NE_TRY(open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[di],
                                   "xdp_wan_redirect_prog", &wan_prog, "wan_xsks_map", &wan_map));
            update_wan_fake_ethertype(p->bpf_wans[di], cfg->fake_ethertype_ipv4);
            NE_TRY(bpf_xdp_attach(p->wans[di].ifindex, bpf_program__fd(wan_prog),
                                  p->xdp_flags, NULL));
            p->xdp_wan_on[di] = 1;
            NE_TRY(update_xsk_map_iface(&p->wans[di], bpf_map__fd(wan_map), shard_id));
        }
    }

    {
        uint32_t prefill = NE_RING - 1;
        if (prefill == 0)
            prefill = 1;
        for (int i = 0; i < p->local_count; i++)
            prefill_iface(p, &p->locals[i], prefill);
        for (int i = 0; i < p->wan_count; i++)
            prefill_iface(p, &p->wans[i], prefill);
    }

    return 0;

fail:
    ne_pair_close(p);
    return -1;
#undef NE_TRY
}

int ne_pairs_open(struct ne_pair pairs[NE_PIPELINE_COUNT], const struct app_config *cfg)
{
    int local_count, wan_count;
    struct rlimit rl = { RLIM_INFINITY, RLIM_INFINITY };

    if (!pairs || !cfg || cfg->local_count <= 0 || config_count_dataplane_wans(cfg) <= 0)
        return -1;

    memset(pairs, 0, sizeof(pairs[0]) * NE_PIPELINE_COUNT);
    (void)setrlimit(RLIMIT_MEMLOCK, &rl);

    local_count = cfg->local_count;
    if (local_count > MAX_INTERFACES)
        local_count = MAX_INTERFACES;
    wan_count = config_count_dataplane_wans(cfg);
    if (wan_count > MAX_INTERFACES)
        wan_count = MAX_INTERFACES;

    for (int i = 0; i < local_count; i++) {
        int nq = resolve_iface_queue_count(cfg->locals[i].ifname,
                                           cfg->locals[i].queue_count,
                                           NE_LOCAL_QUEUE_TARGET);
        if (interface_set_queue_count(cfg->locals[i].ifname, nq) != 0)
            return -1;
        if (interface_set_promisc(cfg->locals[i].ifname) != 0)
            return -1;
    }
    for (int di = 0; di < wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        int nq = resolve_iface_queue_count(cfg->wans[ci].ifname,
                                           cfg->wans[ci].queue_count,
                                           NE_WAN_QUEUE_TARGET);
        if (interface_set_queue_count(cfg->wans[ci].ifname, nq) != 0)
            return -1;
        if (interface_set_promisc(cfg->wans[ci].ifname) != 0)
            return -1;
    }

    if (ne_pair_open_shard(&pairs[0], cfg, 0, 1, local_count, wan_count) != 0) {
        ne_pairs_close(pairs);
        return -1;
    }

    if (ne_pair_open_shard(&pairs[1], cfg, 1, 0, local_count, wan_count) != 0) {
        ne_pairs_close(pairs);
        return -1;
    }

    /* Shard B updates xsks_map using BPF objects owned by shard A. */
    for (int i = 0; i < pairs[1].local_count; i++) {
        struct bpf_map *local_map = bpf_object__find_map_by_name(pairs[0].bpf_locals[i], "xsks_map");
        if (!local_map ||
            update_xsk_map_iface(&pairs[1].locals[i], bpf_map__fd(local_map), 1) != 0) {
            ne_pairs_close(pairs);
            return -1;
        }
    }
    for (int di = 0; di < pairs[1].wan_count; di++) {
        struct bpf_map *wan_map = bpf_object__find_map_by_name(pairs[0].bpf_wans[di], "wan_xsks_map");
        if (!wan_map ||
            update_xsk_map_iface(&pairs[1].wans[di], bpf_map__fd(wan_map), 1) != 0) {
            ne_pairs_close(pairs);
            return -1;
        }
    }

    fprintf(stderr,
            "[PIPE] dual pipeline: A(cpu %u/%u/%u, even queues) "
            "B(cpu %u/%u/%u, odd queues) umem_frames_each=%u\n",
            NE_CPU_LOC_A, NE_CPU_MID_A, NE_CPU_WAN_A,
            NE_CPU_LOC_B, NE_CPU_MID_B, NE_CPU_WAN_B,
            pairs[0].n_frames);
    fflush(stderr);
    return 0;
}

void ne_pairs_close(struct ne_pair pairs[NE_PIPELINE_COUNT])
{
    for (uint32_t s = 0; s < NE_PIPELINE_COUNT; s++)
        ne_pair_close(&pairs[s]);
}

int ne_pair_open(struct ne_pair *p, const struct app_config *cfg)
{
    struct ne_pair pairs[NE_PIPELINE_COUNT];

    if (!p || ne_pairs_open(pairs, cfg) != 0)
        return -1;
    memcpy(p, &pairs[0], sizeof(*p));
    pairs[1].owns_xdp = 0;
    ne_pair_close(&pairs[1]);
    return 0;
}

void ne_pair_close(struct ne_pair *p)
{
    if (!p)
        return;
    if (p->owns_xdp) {
        for (int i = 0; i < p->local_count; i++) {
            if (p->bpf_locals[i])
                bpf_object__close(p->bpf_locals[i]);
        }
        for (int i = 0; i < p->wan_count; i++) {
            if (p->bpf_wans[i])
                bpf_object__close(p->bpf_wans[i]);
        }
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
    struct ne_packet *out_ptr = out; 

    for (int i = 0; i < p->local_count && total < max; i++) {
        struct ne_iface *iface = &p->locals[i];
        int q_count = iface->queue_count;
        
        for (int q = 0; q < q_count && total < max; q++) {
            if (!iface->queues[q].xsk)
                continue;
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
            if (!iface->queues[q].xsk)
                continue;
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
            if (!iface->queues[q].xsk || !iface->queues[q].rx_pending)
                continue;
            xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
            iface->queues[q].rx_pending = 0;
        }
    }
}

void ne_recv_release_wan(struct ne_pair *p)
{
    for (int i = 0; i < p->wan_count; i++) {
        struct ne_iface *iface = &p->wans[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!iface->queues[q].xsk || !iface->queues[q].rx_pending)
                continue;
            xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
            iface->queues[q].rx_pending = 0;
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
        if (n < NE_BATCH_SIZE) {
            break;
        }
    }
}

static void drain_cq_iface(struct ne_iface *iface, struct ne_pool *pool)
{
    for (int q = 0; q < iface->queue_count; q++) {
        if (!iface->queues[q].xsk)
            continue;
        drain_cq_queue(&iface->queues[q], pool);
    }
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
    for (int q = 0; q < iface->queue_count; q++) {
        if (!iface->queues[q].xsk)
            continue;
        refill_fq_queue(&iface->queues[q], pool);
    }
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
    int qc = iface->queue_count;
    if (qc <= 0)
        return 0;
    for (int attempt = 0; attempt < qc; attempt++) {
        int q = iface->tx_queue_rr % qc;
        iface->tx_queue_rr = (q + 1) % qc;
        if (!iface->queues[q].xsk)
            continue;
        return tx_drain_queue(&iface->queues[q], src, max_frame, &iface->tx_no_free);
    }
    return 0;
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

