#include "../../inc/core/interface.h"
#include "../../inc/io/interface_internal.h"

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>
#include <linux/if_xdp.h>
#include <net/if.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <ctype.h>
#include <dirent.h>

/* BPF objects embedded at link time (see Makefile bpf/embed/). */
extern char _binary_xdp_redirect_o_start[];
extern char _binary_xdp_redirect_o_end[];
extern char _binary_xdp_wan_redirect_o_start[];
extern char _binary_xdp_wan_redirect_o_end[];

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
    struct bpf_object *obj = NULL;

    if (path && strcmp(path, "bpf/xdp_redirect.o") == 0) {
        size_t size = (size_t)(_binary_xdp_redirect_o_end - _binary_xdp_redirect_o_start);
        obj = bpf_object__open_mem(_binary_xdp_redirect_o_start, size, NULL);
    } else if (path && strcmp(path, "bpf/xdp_wan_redirect.o") == 0) {
        size_t size = (size_t)(_binary_xdp_wan_redirect_o_end - _binary_xdp_wan_redirect_o_start);
        obj = bpf_object__open_mem(_binary_xdp_wan_redirect_o_start, size, NULL);
    } else if (path && path[0]) {
        obj = bpf_object__open_file(path, NULL);
    }

    if (!obj || libbpf_get_error(obj)) {
        fprintf(stderr, "[XDP] open failed: %s\n", path ? path : "(null)");
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

    /*
     * Shared UMEM: every socket must use the same FILL/COMPLETION rings that
     * xsk_umem__create() registered. Per-socket fq/cq breaks buffer recycle
     * and kills LAN TX under high WAN RX (mid_to_local starved).
     */
    struct xsk_ring_prod *umem_fq = &p->locals[0].queues[0].fq;
    struct xsk_ring_cons *umem_cq = &p->locals[0].queues[0].cq;

    for (int q = 0; q < queue_count; q++) {
        struct ne_xsk_queue *slot = &iface->queues[q];
        int ret = xsk_socket__create_shared(&slot->xsk, ifname, (uint32_t)q, p->umem,
                                            &slot->rx, &slot->tx,
                                            umem_fq, umem_cq, &cfg);
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
        uint32_t got = ne_pool_pop(&p->pool, addrs, n);
        if (got == 0)
            return;

        uint32_t idx = 0;
        uint32_t reserved = xsk_ring_prod__reserve(&slot->fq, got, &idx);
        if (reserved != got) {
            (void)ne_pool_push(&p->pool, addrs, got);
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

    NE_TRY(ne_pool_init(&p->pool, p->n_frames));
    for (uint32_t i = 0; i < p->n_frames; i++) {
        uint64_t addr = (uint64_t)i * p->frame_size;
        (void)ne_pool_push(&p->pool, &addr, 1);
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
    }

    uint32_t prefill = NE_RING - 1;
    if (prefill == 0)
        prefill = 1;
    if (p->local_count > 0)
        prefill_queue(p, &p->locals[0].queues[0], prefill);

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
    ne_pool_destroy(&p->pool);
    if (p->bufs && p->bufs != MAP_FAILED)
        munmap(p->bufs, p->bufsize);
    memset(p, 0, sizeof(*p));
}

