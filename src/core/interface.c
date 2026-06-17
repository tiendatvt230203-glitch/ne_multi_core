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
#include <netinet/ip.h>  
#include <netinet/udp.h>  
#include <arpa/inet.h>
#include <stdarg.h>

static void dp_warn_once(int *done, const char *fmt, ...)
{
    int cpu;
    va_list ap;

    if (!done || *done)
        return;
    *done = 1;
    cpu = sched_getcpu();
    va_start(ap, fmt);
    fprintf(stderr, "[DP-WARN] core=%d ", cpu >= 0 ? cpu : -1);
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    fflush(stderr);
    va_end(ap);
}

static int warned_tx_ring_full;
static int warned_fq_pool_empty;
static int warned_cq_backlog;
static int warned_rx_batch_full;

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
    (void)system(cmd);
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

    return -1;
}

static int interface_set_promisc(const char *ifname)
{
    if (!ifname_is_safe(ifname))
        return -1;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "ip link set dev %s promisc on >/dev/null 2>&1", ifname);
    if (system(cmd) == 0)
        return 0;

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

int ne_ring_init(struct ne_ring *r, uint32_t cap, int mpsc_pop)
{
    if (!r || cap == 0 || (cap & (cap - 1)) != 0)
        return -1;
    memset(r, 0, sizeof(*r));
    r->buf = calloc(cap, sizeof(*r->buf));
    if (!r->buf)
        return -1;
    r->cap = cap;
    r->mask = cap - 1;
    r->mpsc_pop = mpsc_pop ? 1 : 0;
    if (pthread_spin_init(&r->push_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    if (r->mpsc_pop && pthread_spin_init(&r->pop_lock, PTHREAD_PROCESS_PRIVATE) != 0) {
        pthread_spin_destroy(&r->push_lock);
        free(r->buf);
        memset(r, 0, sizeof(*r));
        return -1;
    }
    return 0;
}

void ne_ring_destroy(struct ne_ring *r)
{
    if (!r)
        return;
    if (r->mpsc_pop)
        pthread_spin_destroy(&r->pop_lock);
    pthread_spin_destroy(&r->push_lock);
    free(r->buf);
    memset(r, 0, sizeof(*r));
}

// Push gói tin đi vào ring (muilti core push)
int ne_ring_try_push(struct ne_ring *r, const struct ne_packet *pkt)
{
    uint32_t head, tail;

    if (!r || !pkt)
        return -1;

    pthread_spin_lock(&r->push_lock);
    head = __atomic_load_n(&r->head, __ATOMIC_RELAXED);
    tail = __atomic_load_n(&r->tail, __ATOMIC_ACQUIRE);
    if ((uint32_t)(head - tail) >= r->cap) {
        pthread_spin_unlock(&r->push_lock);
        return -1;
    }
    r->buf[head & r->mask] = *pkt;
    __atomic_store_n(&r->head, head + 1, __ATOMIC_RELEASE);
    pthread_spin_unlock(&r->push_lock);
    return 0;
}

// Pop gói tin đi ra khỏi ring
int ne_ring_try_pop(struct ne_ring *r, struct ne_packet *pkt)
{
    uint32_t tail, head;

    if (!r || !pkt)
        return -1;

    if (r->mpsc_pop)
        pthread_spin_lock(&r->pop_lock);
    tail = __atomic_load_n(&r->tail, __ATOMIC_RELAXED);
    head = __atomic_load_n(&r->head, __ATOMIC_ACQUIRE);
    if (tail == head) { // ring trống
        if (r->mpsc_pop)
            pthread_spin_unlock(&r->pop_lock);
        return -1;
    }
    *pkt = r->buf[tail & r->mask];
    __atomic_store_n(&r->tail, tail + 1, __ATOMIC_RELEASE);
    if (r->mpsc_pop)
        pthread_spin_unlock(&r->pop_lock);
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

int ne_frame_alloc(struct ne_pair *p, int umem_slot, uint64_t *addr_out)
{
    if (!p || umem_slot < 0 || umem_slot >= (int)NE_TX_SLOTS || !addr_out)
        return -1;
    return pool_pop(&p->shards[umem_slot].pool, addr_out, 1) == 1 ? 0 : -1;
}

void ne_frame_free(struct ne_pair *p, int umem_slot, uint64_t addr)
{
    if (!p || umem_slot < 0 || umem_slot >= (int)NE_TX_SLOTS)
        return;
    (void)pool_push(&p->shards[umem_slot].pool, &addr, 1);
}

void *ne_packet_data(struct ne_pair *p, int umem_slot, uint64_t addr)
{
    if (!p || umem_slot < 0 || umem_slot >= (int)NE_TX_SLOTS)
        return NULL;
    return xsk_umem__get_data(p->shards[umem_slot].bufs, addr);
}

static int umem_shard_open(struct ne_umem_shard *s, uint32_t n_frames, uint32_t frame_size)
{
    struct xsk_umem_config ucfg = {
        .fill_size = NE_RING,
        .comp_size = NE_RING,
        .frame_size = frame_size,
        .frame_headroom = XSK_UMEM__DEFAULT_FRAME_HEADROOM,
        .flags = 0,
    };

    memset(s, 0, sizeof(*s));
    s->n_frames = n_frames;
    s->frame_size = frame_size;
    s->bufsize = (size_t)n_frames * (size_t)frame_size;
    s->bufs = mmap(NULL, s->bufsize, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (s->bufs == MAP_FAILED)
        return -1;
    if (pool_init(&s->pool, n_frames) != 0)
        goto fail_map;
    for (uint32_t i = 0; i < n_frames; i++) {
        uint64_t addr = (uint64_t)i * frame_size;
        (void)pool_push(&s->pool, &addr, 1);
    }
    if (xsk_umem__create(&s->umem, s->bufs, s->bufsize, &s->fq, &s->cq, &ucfg) != 0)
        goto fail_pool;
    s->live = 1;
    return 0;

fail_pool:
    pool_destroy(&s->pool);
fail_map:
    if (s->bufs && s->bufs != MAP_FAILED)
        munmap(s->bufs, s->bufsize);
    memset(s, 0, sizeof(*s));
    return -1;
}

static void umem_shard_close(struct ne_umem_shard *s)
{
    if (!s || !s->live)
        return;
    if (s->umem)
        xsk_umem__delete(s->umem);
    pool_destroy(&s->pool);
    if (s->bufs && s->bufs != MAP_FAILED)
        munmap(s->bufs, s->bufsize);
    memset(s, 0, sizeof(*s));
}

static int open_iface_queues(struct ne_pair *p, struct ne_iface *iface,
                             const char *ifname, int queue_count)
{
    struct xsk_socket_config cfg = {
        .rx_size = NE_RING,
        .tx_size = NE_RING,
        .libbpf_flags = XSK_LIBBPF_FLAGS__INHIBIT_PROG_LOAD,
        .xdp_flags = p->xdp_flags,
        .bind_flags = NE_XSK_BIND_FLAGS,
    };

    iface->ifindex = (int)if_nametoindex(ifname);
    if (!iface->ifindex)
        return -1;
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = queue_count;

    for (int q = 0; q < queue_count; q++) {
        int us = q % (int)NE_TX_SLOTS;
        struct ne_umem_shard *shard = &p->shards[us];
        struct ne_xsk_queue *slot = &iface->queues[q];

        if (!shard->live || !shard->umem)
            return -1;
        slot->umem_slot = (uint8_t)us;
        int ret = xsk_socket__create_shared(&slot->xsk, ifname, (uint32_t)q, shard->umem,
                                            &slot->rx, &slot->tx,
                                            &slot->fq, &slot->cq, &cfg);
        if (ret)
            return -1;
    }
    return 0;
}

static void prefill_queue(struct ne_umem_shard *shard, struct ne_xsk_queue *slot, uint32_t want)
{
    uint64_t addrs[NE_BATCH_SIZE];

    while (want > 0) {
        uint32_t n = want > NE_BATCH_SIZE ? NE_BATCH_SIZE : want;
        uint32_t got = pool_pop(&shard->pool, addrs, n);
        if (got == 0)
            return;

        uint32_t idx = 0;
        uint32_t reserved = xsk_ring_prod__reserve(&slot->fq, got, &idx);
        if (reserved != got) {
            (void)pool_push(&shard->pool, addrs, got);
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
        int us = q % (int)NE_TX_SLOTS;
        prefill_queue(&p->shards[us], &iface->queues[q], want_per_queue);
    }
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
    {
        uint32_t total = next_pow2_u32(NE_N_FRAMES * (uint32_t)(p->local_count + p->wan_count + 1));
        p->n_frames_per_shard = next_pow2_u32(total / NE_TX_SLOTS);
        if (p->n_frames_per_shard < 8192u)
            p->n_frames_per_shard = 8192u;
    }
    p->xdp_flags = XDP_FLAGS_DRV_MODE;

    for (int s = 0; s < (int)NE_TX_SLOTS; s++)
        NE_TRY(umem_shard_open(&p->shards[s], p->n_frames_per_shard, p->frame_size));

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

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    for (int i = 0; i < p->local_count; i++)
        prefill_iface(p, &p->locals[i], prefill);
    for (int i = 0; i < p->wan_count; i++)
        prefill_iface(p, &p->wans[i], prefill);

    for (int i = 0; i < p->local_count; i++)
        p->local_live[i] = 1;
    for (int i = 0; i < p->wan_count; i++)
        p->wan_live[i] = 1;

    return 0;

fail:
    for (int i = 0; i < p->local_count && i < MAX_INTERFACES; i++)
        interface_ip_xdp_off(p->locals[i].ifname);
    for (int i = 0; i < p->wan_count && i < MAX_INTERFACES; i++)
        interface_ip_xdp_off(p->wans[i].ifname);
    ne_pair_close(p);
    return -1;
#undef NE_TRY
}

void ne_pair_close(struct ne_pair *p)
{
    if (!p)
        return;
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
    for (int s = 0; s < (int)NE_TX_SLOTS; s++)
        umem_shard_close(&p->shards[s]);
    memset(p, 0, sizeof(*p));
}

int ne_pair_local_live(const struct ne_pair *p, int pair_local_idx)
{
    if (!p || pair_local_idx < 0 || pair_local_idx >= p->local_count)
        return 0;
    return p->local_live[pair_local_idx] != 0;
}

int ne_pair_wan_live(const struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= p->wan_count)
        return 0;
    return p->wan_live[dp_slot] != 0;
}

int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg, int cfg_local_idx,
                        int pair_li)
{
    if (!p || !cfg || !p->shards[0].live || cfg_local_idx < 0 || cfg_local_idx >= cfg->local_count)
        return -1;
    if (pair_li < 0 || pair_li >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->locals[cfg_local_idx].ifname;
    int nq = resolve_iface_queue_count(ifname, cfg->locals[cfg_local_idx].queue_count,
                                       NE_LOCAL_QUEUE_TARGET);
    if (interface_set_queue_count(ifname, nq) != 0)
        return -1;
    p->locals[pair_li].queue_count = nq;
    if (interface_set_promisc(ifname) != 0)
        return -1;
    if (open_iface_queues(p, &p->locals[pair_li], ifname, nq) != 0)
        return -1;

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    prefill_iface(p, &p->locals[pair_li], prefill);
    p->local_live[pair_li] = 1;
    if (pair_li >= p->local_count)
        p->local_count = pair_li + 1;
    p->local_queue_total += nq;
    return 0;
}

int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg, int cfg_wan_idx,
                         int dp_slot)
{
    if (!p || !cfg || !p->shards[0].live || cfg_wan_idx < 0 || cfg_wan_idx >= cfg->wan_count)
        return -1;
    if (!cfg->wans[cfg_wan_idx].dataplane || dp_slot < 0 || dp_slot >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->wans[cfg_wan_idx].ifname;
    int nq = resolve_iface_queue_count(ifname, cfg->wans[cfg_wan_idx].queue_count,
                                       NE_WAN_QUEUE_TARGET);
    if (interface_set_queue_count(ifname, nq) != 0)
        return -1;
    p->wans[dp_slot].queue_count = nq;
    if (interface_set_promisc(ifname) != 0)
        return -1;
    if (open_iface_queues(p, &p->wans[dp_slot], ifname, nq) != 0)
        return -1;

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    prefill_iface(p, &p->wans[dp_slot], prefill);
    p->wan_live[dp_slot] = 1;
    if (dp_slot >= p->wan_count)
        p->wan_count = dp_slot + 1;
    p->wan_queue_total += nq;
    return 0;
}

void ne_pair_unplumb_local(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= p->local_count || !p->local_live[pair_li])
        return;

    interface_ip_xdp_off(p->locals[pair_li].ifname);
    p->xdp_local_on[pair_li] = 0;
    p->local_live[pair_li] = 0;
    p->locals[pair_li].queue_count = 0;
    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
    }
    for (int q = 0; q < p->locals[pair_li].queue_count; q++) {
        if (p->locals[pair_li].queues[q].xsk) {
            xsk_socket__delete(p->locals[pair_li].queues[q].xsk);
            p->locals[pair_li].queues[q].xsk = NULL;
        }
    }
}

void ne_pair_unplumb_wan_dp(struct ne_pair *p, int dp_slot)
{
    if (!p || dp_slot < 0 || dp_slot >= p->wan_count || !p->wan_live[dp_slot])
        return;

    interface_ip_xdp_off(p->wans[dp_slot].ifname);
    p->xdp_wan_on[dp_slot] = 0;
    p->wan_live[dp_slot] = 0;
    p->wans[dp_slot].queue_count = 0;
    if (p->bpf_wans[dp_slot]) {
        bpf_object__close(p->bpf_wans[dp_slot]);
        p->bpf_wans[dp_slot] = NULL;
    }
    for (int q = 0; q < p->wans[dp_slot].queue_count; q++) {
        if (p->wans[dp_slot].queues[q].xsk) {
            xsk_socket__delete(p->wans[dp_slot].queues[q].xsk);
            p->wans[dp_slot].queues[q].xsk = NULL;
        }
    }
}
// RX
static int recv_queue(struct ne_xsk_queue *slot, struct ne_packet *out, uint32_t max,
                      uint8_t dir, uint8_t wan_idx, uint8_t local_idx,
                      const char *ifname, int qid)
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
        out[i].umem_slot = slot->umem_slot;
    }
    slot->rx_pending = n;
    if (n > 0 && n == max)
        dp_warn_once(&warned_rx_batch_full,
                     "RX batch full if=%s q=%d (RX thread or downstream slow)",
                     ifname ? ifname : "?", qid);
    return (int)n;
}

static int xsk_queue_for_slot(int q, int slot, int nq, int max_slots)
{
    int slots = nq < max_slots ? (nq > 0 ? nq : 1) : max_slots;

    if (slot < 0 || slot >= slots)
        return 0;
    return (q % slots) == slot;
}

int ne_recv_local_slot(struct ne_pair *p, struct ne_packet *out, uint32_t max, int rx_slot)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_SLOTS)
        return 0;

    for (int i = 0; i < p->local_count && total < max; i++) {
        if (!p->local_live[i])
            continue;
        struct ne_iface *iface = &p->locals[i];
        int q_count = iface->queue_count;

        for (int q = 0; q < q_count && total < max; q++) {
            if (!xsk_queue_for_slot(q, rx_slot, q_count, (int)NE_RX_SLOTS))
                continue;
            iface->queues[q].rx_pending = 0;
            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_LOCAL, 0, (uint8_t)i,
                               iface->ifname, q);
            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

int ne_recv_wan_slot(struct ne_pair *p, struct ne_packet *out, uint32_t max, int rx_slot)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_SLOTS)
        return 0;

    for (int i = 0; i < p->wan_count && total < max; i++) {
        if (!p->wan_live[i])
            continue;
        struct ne_iface *iface = &p->wans[i];
        int q_count = iface->queue_count;

        for (int q = 0; q < q_count && total < max; q++) {
            if (!xsk_queue_for_slot(q, rx_slot, q_count, (int)NE_RX_SLOTS))
                continue;
            iface->queues[q].rx_pending = 0;
            int n = recv_queue(&iface->queues[q], out_ptr, max - total,
                               NE_DIR_WAN, (uint8_t)i, 0,
                               iface->ifname, q);
            total += (uint32_t)n;
            out_ptr += n;
        }
    }
    return (int)total;
}

int ne_recv_local(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    return ne_recv_local_slot(p, out, max, 0);
}

int ne_recv_wan(struct ne_pair *p, struct ne_packet *out, uint32_t max)
{
    return ne_recv_wan_slot(p, out, max, 0);
}


void ne_recv_release_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        struct ne_iface *iface = &p->locals[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!xsk_queue_for_slot(q, rx_slot, iface->queue_count, (int)NE_RX_SLOTS))
                continue;
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

void ne_recv_release_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        struct ne_iface *iface = &p->wans[i];
        for (int q = 0; q < iface->queue_count; q++) {
            if (!xsk_queue_for_slot(q, rx_slot, iface->queue_count, (int)NE_RX_SLOTS))
                continue;
            if (iface->queues[q].rx_pending) {
                xsk_ring_cons__release(&iface->queues[q].rx, iface->queues[q].rx_pending);
                iface->queues[q].rx_pending = 0;
            }
        }
    }
}

void ne_recv_release_local(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_SLOTS; s++)
        ne_recv_release_local_slot(p, s);
}

void ne_recv_release_wan(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_SLOTS; s++)
        ne_recv_release_wan_slot(p, s);
}


// CQ

static void drain_cq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool,
                           const char *ifname, int qid)
{
    uint32_t idx = 0;
    uint32_t n;

    while ((n = xsk_ring_cons__peek(&slot->cq, NE_BATCH_SIZE, &idx)) > 0) {
        uint32_t released = 0;

        for (uint32_t i = 0; i < n; i++) {
            uint64_t addr = *xsk_ring_cons__comp_addr(&slot->cq, idx + i);
            if (pool_push(pool, &addr, 1) != 1)
                break;
            released++;
        }
        if (!released)
            break;
        xsk_ring_cons__release(&slot->cq, released);
        if (released < n)
            break;
    }
    if (xsk_ring_cons__peek(&slot->cq, 1, &idx) > 0)
        dp_warn_once(&warned_cq_backlog,
                     "CQ backlog if=%s q=%d (TX completion drain slow → pool starved)",
                     ifname ? ifname : "?", qid);
}

static int xsk_queue_for_tx_slot(int q, int tx_slot, int nq)
{
    return xsk_queue_for_slot(q, tx_slot, nq, (int)NE_TX_SLOTS);
}

static void drain_cq_iface_slot(struct ne_iface *iface, struct ne_pool *pool, int tx_slot)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        drain_cq_queue(&iface->queues[q], pool, iface->ifname, q);
    }
}

void ne_drain_cq_local(struct ne_pair *p, int tx_slot)
{
    if (!p || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    struct ne_pool *pool = &p->shards[tx_slot].pool;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        drain_cq_iface_slot(&p->locals[i], pool, tx_slot);
    }
}

void ne_drain_cq_wan(struct ne_pair *p, int tx_slot)
{
    if (!p || tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;
    struct ne_pool *pool = &p->shards[tx_slot].pool;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        drain_cq_iface_slot(&p->wans[i], pool, tx_slot);
    }
}

void ne_drain_cq_all(struct ne_pair *p, int tx_slot)
{
    ne_drain_cq_local(p, tx_slot);
    ne_drain_cq_wan(p, tx_slot);
}


// FILL
static void refill_fq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool,
                            const char *ifname, int qid)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&slot->fq, NE_BATCH_SIZE);

    if (!free_slots)
        return;
    uint32_t want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    uint32_t got = pool_pop(pool, addrs, want);
    if (!got) {
        dp_warn_once(&warned_fq_pool_empty,
                     "UMEM pool empty if=%s q=%d (FQ refill — need more CQ drain / TX)",
                     ifname ? ifname : "?", qid);
        return;
    }
    if (xsk_ring_prod__reserve(&slot->fq, got, &idx) != got) {
        (void)pool_push(pool, addrs, got);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&slot->fq, got);
}

static void refill_fq_iface_slot(struct ne_pair *p, struct ne_iface *iface, int rx_slot)
{
    for (int q = 0; q < iface->queue_count; q++) {
        if (!xsk_queue_for_slot(q, rx_slot, iface->queue_count, (int)NE_RX_SLOTS))
            continue;
        int us = q % (int)NE_TX_SLOTS;
        refill_fq_queue(&iface->queues[q], &p->shards[us].pool, iface->ifname, q);
    }
}

void ne_refill_fq_local_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_SLOTS)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        refill_fq_iface_slot(p, &p->locals[i], rx_slot);
    }
}

void ne_refill_fq_wan_slot(struct ne_pair *p, int rx_slot)
{
    if (!p || rx_slot < 0 || rx_slot >= (int)NE_RX_SLOTS)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        refill_fq_iface_slot(p, &p->wans[i], rx_slot);
    }
}

void ne_refill_fq_local(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_SLOTS; s++)
        ne_refill_fq_local_slot(p, s);
}

void ne_refill_fq_wan(struct ne_pair *p)
{
    for (int s = 0; s < (int)NE_RX_SLOTS; s++)
        ne_refill_fq_wan_slot(p, s);
}

// TX
static int tx_drain_queue(struct ne_xsk_queue *slot, struct ne_ring *src, uint32_t max_frame,
                          uint64_t *tx_no_free, const char *ifname, int qid)
{
    struct ne_packet jobs[NE_BATCH_SIZE];
    uint32_t free_slots = xsk_prod_nb_free(&slot->tx, NE_BATCH_SIZE);

    if (!free_slots) {
        if (tx_no_free)
            (*tx_no_free)++;
        dp_warn_once(&warned_tx_ring_full,
                     "TX ring full if=%s q=%d (TX core saturated)",
                     ifname ? ifname : "?", qid);
        if (xsk_ring_prod__needs_wakeup(&slot->tx))
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
    if (xsk_ring_prod__needs_wakeup(&slot->tx)) {
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    }
    return (int)popped;
}


static int tx_drain_iface_ring(struct ne_iface *iface, struct ne_ring *src, uint32_t max_frame,
                               int tx_slot)
{
    int nq = iface->queue_count;

    for (int q = 0; q < nq; q++) {
        if (!xsk_queue_for_tx_slot(q, tx_slot, nq))
            continue;
        int sent = tx_drain_queue(&iface->queues[q], src, max_frame, &iface->tx_no_free,
                                  iface->ifname, q);
        if (sent > 0)
            return sent;
    }
    return 0;
}

static int tx_drain_iface_all_rings(struct ne_iface *iface, struct ne_ring *srcs[],
                                    int src_count, uint32_t max_frame, int tx_slot)
{
    int sent = 0;
    for (int s = 0; s < src_count; s++) {
        if (!srcs[s])
            continue;
        sent += tx_drain_iface_ring(iface, srcs[s], max_frame, tx_slot);
    }
    return sent;
}

int ne_tx_drain_local_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                          int local_idx, int tx_slot)
{
    if (!p || local_idx < 0 || local_idx >= p->local_count)
        return 0;
    if (!p->local_live[local_idx])
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    return tx_drain_iface_all_rings(&p->locals[local_idx], srcs, src_count, p->frame_size,
                                    tx_slot);
}

int ne_tx_drain_wan_all(struct ne_pair *p, struct ne_ring *srcs[], int src_count,
                        int wan_idx, int tx_slot)
{
    if (!p || wan_idx < 0 || wan_idx >= p->wan_count)
        return 0;
    if (!p->wan_live[wan_idx])
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;
    return tx_drain_iface_all_rings(&p->wans[wan_idx], srcs, src_count, p->frame_size, tx_slot);
}
