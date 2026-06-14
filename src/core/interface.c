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
#include <sys/stat.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>

static void kick_xsk_rx(struct ne_xsk_queue *slot)
{
    if (!slot || !slot->xsk)
        return;
    if (xsk_ring_prod__needs_wakeup(&slot->fq))
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
}

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

static struct ne_xsk_queue *worker_queue(struct ne_iface *iface, int worker_id)
{
    if (!iface || worker_id < 0 || worker_id >= iface->queue_count)
        return NULL;
    return &iface->queues[worker_id];
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

static void refill_fq_queue(struct ne_xsk_queue *slot, struct ne_pool *pool)
{
    uint64_t addrs[NE_BATCH_SIZE];
    uint32_t idx = 0;
    uint32_t free_slots = xsk_prod_nb_free(&slot->fq, NE_BATCH_SIZE);
    uint32_t want;

    if (!free_slots)
        return;

    want = free_slots > NE_BATCH_SIZE ? NE_BATCH_SIZE : free_slots;
    uint32_t got = pool_pop(pool, addrs, want);
    if (!got)
        return;
    if (xsk_ring_prod__reserve(&slot->fq, got, &idx) != got) {
        (void)pool_push(pool, addrs, got);
        return;
    }
    for (uint32_t i = 0; i < got; i++)
        *xsk_ring_prod__fill_addr(&slot->fq, idx + i) = addrs[i];
    xsk_ring_prod__submit(&slot->fq, got);
    kick_xsk_rx(slot);
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

    {
        struct stat st;
        if (stat(path, &st) == 0)
            fprintf(stderr, "[XDP] loaded %s size=%ld mtime=%ld\n",
                    path, (long)st.st_size, (long)st.st_mtime);
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

int ne_pair_local_live(const struct ne_pair *p, int pair_li)
{
    return p && pair_li >= 0 && pair_li < MAX_INTERFACES && p->local_live[pair_li];
}

int ne_pair_wan_live(const struct ne_pair *p, int pair_wi)
{
    return p && pair_wi >= 0 && pair_wi < MAX_INTERFACES && p->wan_live[pair_wi];
}

int ne_pair_plumb_local(struct ne_pair *p, const struct app_config *cfg, int cfg_li, int pair_li)
{
    if (!p || !cfg || !p->umem || cfg_li < 0 || cfg_li >= cfg->local_count ||
        pair_li < 0 || pair_li >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->locals[cfg_li].ifname;
    int nq = resolve_iface_queue_count(ifname, cfg->locals[cfg_li].queue_count,
                                       NE_LOCAL_QUEUE_TARGET);

    if (interface_set_queue_count(ifname, nq) != 0)
        return -1;
    if (interface_set_promisc(ifname) != 0)
        return -1;
    if (open_iface_queues(p, &p->locals[pair_li], ifname, nq) != 0)
        return -1;

    p->local_live[pair_li] = 1;
    if (pair_li + 1 > p->local_count)
        p->local_count = pair_li + 1;

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    prefill_iface(p, &p->locals[pair_li], prefill);
    return 0;
}

void ne_pair_unplumb_local(struct ne_pair *p, int pair_li)
{
    if (!p || pair_li < 0 || pair_li >= MAX_INTERFACES || !p->local_live[pair_li])
        return;

    struct ne_iface *iface = &p->locals[pair_li];

    for (int q = 0; q < iface->queue_count; q++) {
        if (iface->queues[q].xsk)
            xsk_socket__delete(iface->queues[q].xsk);
    }

    if (p->xdp_local_on[pair_li]) {
        interface_ip_xdp_off(iface->ifname);
        p->xdp_local_on[pair_li] = 0;
    }
    if (p->bpf_locals[pair_li]) {
        bpf_object__close(p->bpf_locals[pair_li]);
        p->bpf_locals[pair_li] = NULL;
    }

    memset(iface, 0, sizeof(*iface));
    p->local_live[pair_li] = 0;
}

int ne_pair_plumb_wan_dp(struct ne_pair *p, const struct app_config *cfg, int cfg_wi, int pair_wi)
{
    if (!p || !cfg || !p->umem || cfg_wi < 0 || cfg_wi >= cfg->wan_count ||
        !cfg->wans[cfg_wi].dataplane || pair_wi < 0 || pair_wi >= MAX_INTERFACES)
        return -1;

    const char *ifname = cfg->wans[cfg_wi].ifname;
    int nq = resolve_iface_queue_count(ifname, cfg->wans[cfg_wi].queue_count,
                                       NE_WAN_QUEUE_TARGET);

    if (interface_set_queue_count(ifname, nq) != 0)
        return -1;
    if (interface_set_promisc(ifname) != 0)
        return -1;
    if (open_iface_queues(p, &p->wans[pair_wi], ifname, nq) != 0)
        return -1;

    p->wan_live[pair_wi] = 1;
    if (pair_wi + 1 > p->wan_count)
        p->wan_count = pair_wi + 1;

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    prefill_iface(p, &p->wans[pair_wi], prefill);
    return 0;
}

void ne_pair_unplumb_wan_dp(struct ne_pair *p, int pair_wi)
{
    if (!p || pair_wi < 0 || pair_wi >= MAX_INTERFACES || !p->wan_live[pair_wi])
        return;

    struct ne_iface *iface = &p->wans[pair_wi];

    for (int q = 0; q < iface->queue_count; q++) {
        if (iface->queues[q].xsk)
            xsk_socket__delete(iface->queues[q].xsk);
    }

    if (p->xdp_wan_on[pair_wi]) {
        interface_ip_xdp_off(iface->ifname);
        p->xdp_wan_on[pair_wi] = 0;
    }
    if (p->bpf_wans[pair_wi]) {
        bpf_object__close(p->bpf_wans[pair_wi]);
        p->bpf_wans[pair_wi] = NULL;
    }

    memset(iface, 0, sizeof(*iface));
    p->wan_live[pair_wi] = 0;
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
        p->local_live[i] = 1;
        NE_TRY(update_xsk_map_iface(&p->locals[i], bpf_map__fd(local_map)));
    }

    for (int di = 0; di < p->wan_count; di++) {
        struct bpf_program *wan_prog = NULL;
        struct bpf_map *wan_map = NULL;
        NE_TRY(open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[di],
                               "xdp_wan_redirect_prog", &wan_prog, "wan_xsks_map", &wan_map));
        update_wan_fake_ethertype(p->bpf_wans[di], cfg->fake_ethertype_ipv4);
        NE_TRY(bpf_xdp_attach(p->wans[di].ifindex, bpf_program__fd(wan_prog), p->xdp_flags, NULL));
        p->xdp_wan_on[di] = 1;
        p->wan_live[di] = 1;
        NE_TRY(update_xsk_map_iface(&p->wans[di], bpf_map__fd(wan_map)));
    }

    for (int i = 0; i < p->local_count; i++)
        fprintf(stderr, "[XSK] LAN %s queues=%d xdp=on\n",
                p->locals[i].ifname, p->locals[i].queue_count);
    for (int i = 0; i < p->wan_count; i++)
        fprintf(stderr, "[XSK] WAN %s queues=%d xdp=on\n",
                p->wans[i].ifname, p->wans[i].queue_count);
    if ((int)NE_CRYPTO_WORKERS > p->locals[0].queue_count ||
        (p->wan_count > 0 && (int)NE_CRYPTO_WORKERS > p->wans[0].queue_count))
        fprintf(stderr,
                "[XSK][WARN] NE_CRYPTO_WORKERS=%u but iface queues lower — workers above "
                "min(queue_count)-1 will idle\n",
                (unsigned)NE_CRYPTO_WORKERS);
    fflush(stderr);

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    for (int i = 0; i < p->local_count; i++)
        prefill_iface(p, &p->locals[i], prefill);
    for (int i = 0; i < p->wan_count; i++)
        prefill_iface(p, &p->wans[i], prefill);

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
    uint32_t n;

    kick_xsk_rx(slot);
    n = xsk_ring_cons__peek(&slot->rx, max, &idx);
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

int ne_recv_local_worker(struct ne_pair *p, int worker_id, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || worker_id < 0 || !out || max == 0)
        return 0;

    for (int i = 0; i < p->local_count && total < max; i++) {
        if (!p->local_live[i])
            continue;
        struct ne_iface *iface = &p->locals[i];
        struct ne_xsk_queue *slot = worker_queue(iface, worker_id);
        if (!slot)
            continue;

        slot->rx_pending = 0;
        int n = recv_queue(slot, out_ptr, max - total, NE_DIR_LOCAL, 0, (uint8_t)i);
        total += (uint32_t)n;
        out_ptr += n;
    }
    return (int)total;
}

int ne_recv_wan_worker(struct ne_pair *p, int worker_id, struct ne_packet *out, uint32_t max)
{
    uint32_t total = 0;
    struct ne_packet *out_ptr = out;

    if (!p || worker_id < 0 || !out || max == 0)
        return 0;

    for (int i = 0; i < p->wan_count && total < max; i++) {
        if (!p->wan_live[i])
            continue;
        struct ne_iface *iface = &p->wans[i];
        struct ne_xsk_queue *slot = worker_queue(iface, worker_id);
        if (!slot)
            continue;

        slot->rx_pending = 0;
        int n = recv_queue(slot, out_ptr, max - total, NE_DIR_WAN, (uint8_t)i, 0);
        total += (uint32_t)n;
        out_ptr += n;
    }
    return (int)total;
}

void ne_recv_release_local_worker(struct ne_pair *p, int worker_id)
{
    if (!p || worker_id < 0)
        return;
    for (int i = 0; i < p->local_count; i++) {
        struct ne_iface *iface = &p->locals[i];
        struct ne_xsk_queue *slot = worker_queue(iface, worker_id);
        if (!slot)
            continue;
        if (slot->rx_pending) {
            xsk_ring_cons__release(&slot->rx, slot->rx_pending);
            slot->rx_pending = 0;
        }
    }
}

void ne_recv_release_wan_worker(struct ne_pair *p, int worker_id)
{
    if (!p || worker_id < 0)
        return;
    for (int i = 0; i < p->wan_count; i++) {
        struct ne_iface *iface = &p->wans[i];
        struct ne_xsk_queue *slot = worker_queue(iface, worker_id);
        if (!slot)
            continue;
        if (slot->rx_pending) {
            xsk_ring_cons__release(&slot->rx, slot->rx_pending);
            slot->rx_pending = 0;
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

static void refill_fq_worker_queue(struct ne_pair *p, struct ne_xsk_queue *slot)
{
    if (slot)
        refill_fq_queue(slot, &p->pool);
}

void ne_refill_fq_worker(struct ne_pair *p, int worker_id)
{
    if (!p || worker_id < 0)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        struct ne_xsk_queue *slot = worker_queue(&p->locals[i], worker_id);
        refill_fq_worker_queue(p, slot);
        kick_xsk_rx(slot);
    }
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        struct ne_xsk_queue *slot = worker_queue(&p->wans[i], worker_id);
        refill_fq_worker_queue(p, slot);
        kick_xsk_rx(slot);
    }
}

void ne_drain_cq_worker(struct ne_pair *p, int worker_id)
{
    if (!p || worker_id < 0)
        return;
    for (int i = 0; i < p->local_count; i++) {
        if (!p->local_live[i])
            continue;
        struct ne_xsk_queue *slot = worker_queue(&p->locals[i], worker_id);
        if (slot)
            drain_cq_queue(slot, &p->pool);
    }
    for (int i = 0; i < p->wan_count; i++) {
        if (!p->wan_live[i])
            continue;
        struct ne_xsk_queue *slot = worker_queue(&p->wans[i], worker_id);
        if (slot)
            drain_cq_queue(slot, &p->pool);
    }
}

static int tx_send_one(struct ne_xsk_queue *slot, struct ne_iface *iface,
                       const struct ne_packet *job, uint32_t max_frame)
{
    uint32_t idx = 0;

    if (!slot || !job)
        return -1;
    if (xsk_prod_nb_free(&slot->tx, 1) == 0) {
        if (iface)
            iface->tx_no_free++;
        if (xsk_ring_prod__needs_wakeup(&slot->tx))
            (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
        return -1;
    }
    if (xsk_ring_prod__reserve(&slot->tx, 1, &idx) != 1)
        return -1;
    struct xdp_desc *d = xsk_ring_prod__tx_desc(&slot->tx, idx);
    d->addr = job->addr;
    d->len = job->len > max_frame ? max_frame : job->len;
    xsk_ring_prod__submit(&slot->tx, 1);
    if (xsk_ring_prod__needs_wakeup(&slot->tx))
        (void)sendto(xsk_socket__fd(slot->xsk), NULL, 0, MSG_DONTWAIT, NULL, 0);
    return 0;
}

int ne_tx_has_room_wan(struct ne_pair *p, int worker_id, int wan_idx, uint32_t need)
{
    struct ne_xsk_queue *slot;

    if (!p || wan_idx < 0 || wan_idx >= p->wan_count || need == 0)
        return 0;
    slot = worker_queue(&p->wans[wan_idx], worker_id);
    return slot && xsk_prod_nb_free(&slot->tx, need) >= need;
}

int ne_tx_has_room_local(struct ne_pair *p, int worker_id, int local_idx, uint32_t need)
{
    struct ne_xsk_queue *slot;

    if (!p || local_idx < 0 || local_idx >= p->local_count || need == 0)
        return 0;
    slot = worker_queue(&p->locals[local_idx], worker_id);
    return slot && xsk_prod_nb_free(&slot->tx, need) >= need;
}

int ne_tx_send_wan(struct ne_pair *p, int worker_id, int wan_idx, const struct ne_packet *job)
{
    struct ne_iface *iface;
    struct ne_xsk_queue *slot;

    if (!p || !job || wan_idx < 0 || wan_idx >= p->wan_count)
        return -1;
    iface = &p->wans[wan_idx];
    slot = worker_queue(iface, worker_id);
    if (!slot)
        return -1;
    return tx_send_one(slot, iface, job, p->frame_size);
}

int ne_tx_send_local(struct ne_pair *p, int worker_id, int local_idx, const struct ne_packet *job)
{
    struct ne_iface *iface;
    struct ne_xsk_queue *slot;

    if (!p || !job || local_idx < 0 || local_idx >= p->local_count)
        return -1;
    iface = &p->locals[local_idx];
    slot = worker_queue(iface, worker_id);
    if (!slot)
        return -1;
    return tx_send_one(slot, iface, job, p->frame_size);
}

