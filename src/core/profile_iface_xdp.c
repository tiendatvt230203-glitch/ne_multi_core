#include "../../inc/core/profile_iface_xdp.h"

#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/local_hwaddr.h"

#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <unistd.h>
#include <time.h>

// #region agent log
#define AGENT_LOG_PATH_LOCAL "/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-dfdcf7.log"
#define AGENT_LOG_PATH_CWD   ".cursor/debug-dfdcf7.log"

static void agent_log_xdp(const char *hypothesis_id, const char *location,
                          const char *message, const char *path, int err_no,
                          int file_missing)
{
    FILE *f = fopen(AGENT_LOG_PATH_CWD, "a");

    if (!f)
        f = fopen(AGENT_LOG_PATH_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"%s\",\"location\":\"%s\","
            "\"message\":\"%s\",\"data\":{\"path\":\"%s\",\"errno\":%d,"
            "\"file_missing\":%d},\"timestamp\":%ld}\n",
            hypothesis_id, location, message,
            path ? path : "", err_no, file_missing, (long)(time(NULL) * 1000));
    fclose(f);
}
// #endregion

int forwarder_queue_profile_iface_xdp(struct forwarder *fwd, struct app_config *cfg,
                                      enum profile_iface_xdp_reload_mode mode);

static int cfg_has_local_ifname(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}

static int cfg_has_wan_ifname(const struct app_config *cfg, const char *ifname)
{
    if (!cfg || !ifname)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return 1;
    }
    return 0;
}


static int lan_still_in_merged_cfg(const struct app_config *cfg, const char *ifname)
{
    return cfg_has_local_ifname(cfg, ifname);
}

static int lan_is_new_to_merged(const struct app_config *old, const struct app_config *new,
                                const char *ifname)
{
    return !cfg_has_local_ifname(old, ifname) && cfg_has_local_ifname(new, ifname);
}

static int wan_dataplane_dropped_from_merged(const struct app_config *old,
                                             const struct app_config *new,
                                             const char *ifname)
{
    return fwd_wan_ifname_dataplane_in_cfg(old, ifname) &&
           !fwd_wan_ifname_dataplane_in_cfg(new, ifname);
}


static int cfg_locals_subset(const struct app_config *sub, const struct app_config *sup)
{
    for (int i = 0; i < sub->local_count; i++) {
        if (!cfg_has_local_ifname(sup, sub->locals[i].ifname))
            return 0;
    }
    return 1;
}

static int cfg_wans_subset(const struct app_config *sub, const struct app_config *sup)
{
    for (int i = 0; i < sub->wan_count; i++) {
        if (!cfg_has_wan_ifname(sup, sub->wans[i].ifname))
            return 0;
    }
    return 1;
}

static int cfg_has_lan_row_addition(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < new->local_count; i++) {
        if (!cfg_has_local_ifname(old, new->locals[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_wan_row_addition(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < new->wan_count; i++) {
        if (!cfg_has_wan_ifname(old, new->wans[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_lan_row_removal(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->local_count; i++) {
        if (!cfg_has_local_ifname(new, old->locals[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_wan_row_removal(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->wan_count; i++) {
        if (!cfg_has_wan_ifname(new, old->wans[i].ifname))
            return 1;
    }
    return 0;
}

static int cfg_has_iface_addition(const struct app_config *old, const struct app_config *new)
{
    return cfg_has_lan_row_addition(old, new) || cfg_has_wan_row_addition(old, new);
}

static int cfg_has_iface_removal(const struct app_config *old, const struct app_config *new)
{
    return cfg_has_lan_row_removal(old, new) || cfg_has_wan_row_removal(old, new);
}

static int wan_is_new_dataplane_to_merged(const struct app_config *old, const struct app_config *new,
                                          const char *ifname)
{
    return !fwd_wan_ifname_dataplane_in_cfg(old, ifname) &&
           fwd_wan_ifname_dataplane_in_cfg(new, ifname);
}

static const struct local_config *local_by_ifname(const struct app_config *cfg,
                                                  const char *ifname)
{
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return &cfg->locals[i];
    }
    return NULL;
}

static const struct wan_config *wan_by_ifname(const struct app_config *cfg, const char *ifname)
{
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return &cfg->wans[i];
    }
    return NULL;
}

static int local_db_equal(const struct local_config *a, const struct local_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0 &&
           a->ip == b->ip &&
           a->netmask == b->netmask &&
           a->network == b->network &&
           a->umem_mb == b->umem_mb &&
           a->ring_size == b->ring_size &&
           a->batch_size == b->batch_size &&
           a->frame_size == b->frame_size &&
           a->queue_count == b->queue_count;
}

static int wan_db_equal(const struct wan_config *a, const struct wan_config *b)
{
    return strcmp(a->ifname, b->ifname) == 0 &&
           a->dst_ip == b->dst_ip &&
           a->window_size == b->window_size &&
           a->umem_mb == b->umem_mb &&
           a->ring_size == b->ring_size &&
           a->batch_size == b->batch_size &&
           a->frame_size == b->frame_size &&
           a->queue_count == b->queue_count &&
           a->dataplane == b->dataplane;
}

static int cfg_shared_ifaces_unchanged(const struct app_config *old, const struct app_config *new)
{
    for (int i = 0; i < old->local_count; i++) {
        const char *ifn = old->locals[i].ifname;
        const struct local_config *nl = local_by_ifname(new, ifn);
        if (nl && !local_db_equal(&old->locals[i], nl))
            return 0;
    }
    for (int i = 0; i < old->wan_count; i++) {
        const char *ifn = old->wans[i].ifname;
        const struct wan_config *nw = wan_by_ifname(new, ifn);
        if (nw && !wan_db_equal(&old->wans[i], nw))
            return 0;
    }
    return 1;
}

void profile_iface_xdp_prepare_init(const struct app_config *cfg)
{
    if (!cfg)
        return;
    interface_ip_xdp_off_config(cfg);
    interface_reset_redirect_maps();
}

int profile_iface_xdp_can_add(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || !old->profile_count)
        return 0;
    if (!cfg_locals_subset(old, new) || !cfg_wans_subset(old, new))
        return 0;
    return cfg_has_iface_addition(old, new);
}

int profile_iface_xdp_can_remove(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new)
        return 0;
    if (!cfg_locals_subset(new, old) || !cfg_wans_subset(new, old))
        return 0;
    return cfg_has_iface_removal(old, new);
}

int profile_iface_xdp_can_delta(const struct app_config *old, const struct app_config *new)
{
    if (!old || !new || !old->profile_count)
        return 0;
    if (!cfg_has_iface_addition(old, new) && !cfg_has_iface_removal(old, new))
        return 0;
    if (!cfg_shared_ifaces_unchanged(old, new))
        return 0;
    return 1;
}


static int read_xdp_prog_id(const char *ifname, uint32_t *out_id)
{
    char path[128];
    FILE *f;

    if (!ifname || !out_id)
        return -1;
    snprintf(path, sizeof(path), "/sys/class/net/%s/xdp/prog_id", ifname);
    f = fopen(path, "r");
    if (!f)
        return -1;
    if (fscanf(f, "%u", out_id) != 1) {
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

static int lan_iface_has_kernel_xdp(const char *ifname, uint32_t *prog_id_out)
{
    uint32_t prog_id = 0;

    if (!ifname)
        return 0;
    if (read_xdp_prog_id(ifname, &prog_id) != 0 || prog_id == 0)
        return 0;
    if (prog_id_out)
        *prog_id_out = prog_id;
    return 1;
}

typedef int (*ne_bpf_xdp_attach_fn)(int ifindex, int prog_fd, __u32 flags, const void *opts);
typedef int (*ne_bpf_xdp_detach_fn)(int ifindex, __u32 flags, const void *opts);
typedef int (*ne_bpf_set_link_xdp_fd_fn)(int ifindex, int fd, __u32 flags);
typedef int (*ne_bpf_get_link_xdp_id_fn)(int ifindex, __u32 *prog_id, __u32 flags);
typedef int (*ne_bpf_xdp_query_id_fn)(int ifindex, int flags, __u32 *prog_id);

static ne_bpf_xdp_attach_fn ne_bpf_xdp_attach;
static ne_bpf_xdp_detach_fn ne_bpf_xdp_detach;
static ne_bpf_set_link_xdp_fd_fn ne_bpf_set_link_xdp_fd;
static ne_bpf_get_link_xdp_id_fn ne_bpf_get_link_xdp_id;
static ne_bpf_xdp_query_id_fn ne_bpf_xdp_query_id;
static int ne_xdp_api_inited;

static void ne_xdp_api_init_once(void)
{
    if (ne_xdp_api_inited)
        return;
    ne_xdp_api_inited = 1;
    ne_bpf_xdp_attach = (ne_bpf_xdp_attach_fn)dlsym(RTLD_DEFAULT, "bpf_xdp_attach");
    ne_bpf_xdp_detach = (ne_bpf_xdp_detach_fn)dlsym(RTLD_DEFAULT, "bpf_xdp_detach");
    ne_bpf_set_link_xdp_fd =
        (ne_bpf_set_link_xdp_fd_fn)dlsym(RTLD_DEFAULT, "bpf_set_link_xdp_fd");
    ne_bpf_get_link_xdp_id =
        (ne_bpf_get_link_xdp_id_fn)dlsym(RTLD_DEFAULT, "bpf_get_link_xdp_id");
    ne_bpf_xdp_query_id =
        (ne_bpf_xdp_query_id_fn)dlsym(RTLD_DEFAULT, "bpf_xdp_query_id");
}

static int ne_xdp_do_attach(int ifindex, int prog_fd, uint32_t flags)
{
    ne_xdp_api_init_once();
    if (ne_bpf_xdp_attach)
        return ne_bpf_xdp_attach(ifindex, prog_fd, flags, NULL);
    if (ne_bpf_set_link_xdp_fd)
        return ne_bpf_set_link_xdp_fd(ifindex, prog_fd, flags);
    return -ENOSYS;
}

static int ne_xdp_do_detach(int ifindex, uint32_t flags)
{
    ne_xdp_api_init_once();
    if (ne_bpf_xdp_detach)
        return ne_bpf_xdp_detach(ifindex, flags, NULL);
    if (ne_bpf_set_link_xdp_fd)
        return ne_bpf_set_link_xdp_fd(ifindex, -1, flags);
    return -ENOSYS;
}

static int ne_xdp_query_prog_id(int ifindex, const char *ifname, uint32_t attach_flags,
                                uint32_t *prog_id_out)
{
    __u32 prog_id = 0;
    int qflags[3];
    int nq = 0;

    if (!prog_id_out)
        return -1;
    *prog_id_out = 0;
    ne_xdp_api_init_once();

    qflags[nq++] = (int)attach_flags;
    qflags[nq++] = (int)XDP_FLAGS_DRV_MODE;
    qflags[nq++] = (int)XDP_FLAGS_SKB_MODE;

    if (ne_bpf_get_link_xdp_id) {
        for (int i = 0; i < nq; i++) {
            prog_id = 0;
            if (ne_bpf_get_link_xdp_id(ifindex, &prog_id, (__u32)qflags[i]) == 0 &&
                prog_id != 0) {
                *prog_id_out = prog_id;
                return 0;
            }
        }
    }
    if (ne_bpf_xdp_query_id) {
        for (int i = 0; i < nq; i++) {
            prog_id = 0;
            if (ne_bpf_xdp_query_id(ifindex, qflags[i], &prog_id) == 0 && prog_id != 0) {
                *prog_id_out = prog_id;
                return 0;
            }
        }
    }
    if (ifname && read_xdp_prog_id(ifname, prog_id_out) == 0 && *prog_id_out != 0)
        return 0;
    return -1;
}

static int validate_xdp_attached(int ifindex, const char *ifname, const char *role,
                                 uint32_t attach_flags)
{
    uint32_t prog_id = 0;

    for (int retry = 0; retry < 20; retry++) {
        if (ne_xdp_query_prog_id(ifindex, ifname, attach_flags, &prog_id) == 0 &&
            prog_id != 0) {
            fprintf(stderr,
                    "[PROFILE-XDP] validate OK %s %s prog_id=%u (xdp/id:%u ifindex=%d)\n",
                    role, ifname, prog_id, prog_id, ifindex);
            fflush(stderr);
            return 0;
        }
        if (retry < 19)
            usleep(5000);
    }
    fprintf(stderr,
            "[PROFILE-XDP] validate FAIL %s %s: no prog_id (ifindex=%d flags=0x%x)\n",
            role, ifname, ifindex, attach_flags);
    fflush(stderr);
    return -1;
}

static void xdp_try_detach(int ifindex, uint32_t flags)
{
    int rc = ne_xdp_do_detach(ifindex, flags);

    if (rc < 0 && rc != -EINVAL && rc != -ENOENT)
        fprintf(stderr, "[PROFILE-XDP] detach ifindex=%d flags=0x%x: %s\n",
                ifindex, flags, strerror(-rc));
}

static int xdp_attach_prog(int ifindex, int prog_fd, uint32_t flags,
                           const char *ifname, const char *role)
{
    uint32_t try_flags[2];
    int n_try = 0;

    if (prog_fd < 0) {
        fprintf(stderr, "[PROFILE-XDP] attach failed %s %s: invalid prog_fd\n",
                role, ifname);
        fflush(stderr);
        return -1;
    }

    ne_xdp_api_init_once();
    if (!ne_bpf_xdp_attach && !ne_bpf_set_link_xdp_fd) {
        fprintf(stderr,
                "[PROFILE-XDP] attach failed %s %s: libbpf has no XDP attach API\n",
                role, ifname);
        fflush(stderr);
        return -1;
    }

    try_flags[n_try++] = flags;
    if (flags != (XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST))
        try_flags[n_try++] = XDP_FLAGS_SKB_MODE | XDP_FLAGS_UPDATE_IF_NOEXIST;

    fprintf(stderr,
            "[PROFILE-XDP] attach %s %s ifindex=%d prog_fd=%d primary_flags=0x%x api=%s\n",
            role, ifname, ifindex, prog_fd, flags,
            ne_bpf_xdp_attach ? "bpf_xdp_attach" : "bpf_set_link_xdp_fd");
    fflush(stderr);

    for (int i = 0; i < n_try; i++) {
        uint32_t f = try_flags[i];
        int rc;

        if (i > 0)
            xdp_try_detach(ifindex, try_flags[i - 1]);

        rc = ne_xdp_do_attach(ifindex, prog_fd, f);
        if (rc < 0) {
            fprintf(stderr, "[PROFILE-XDP] attach attempt %s %s flags=0x%x: %s\n",
                    role, ifname, f, strerror(-rc));
            fflush(stderr);
            continue;
        }
        if (validate_xdp_attached(ifindex, ifname, role, f) == 0)
            return 0;
        /*
         * bpf_xdp_attach (libbpf ≥0.7) may succeed without sysfs prog_id when
         * query APIs are absent (older NE nodes). Trust attach in that case.
         */
        if (ne_bpf_xdp_attach && !ne_bpf_get_link_xdp_id && !ne_bpf_xdp_query_id) {
            fprintf(stderr,
                    "[PROFILE-XDP] validate skip %s %s flags=0x%x "
                    "(bpf_xdp_attach OK, no prog_id query API)\n",
                    role, ifname, f);
            fflush(stderr);
            return 0;
        }
        fprintf(stderr,
                "[PROFILE-XDP] attach OK but validate failed %s %s flags=0x%x — retry\n",
                role, ifname, f);
        fflush(stderr);
        xdp_try_detach(ifindex, f);
    }
    // #region agent log
    agent_log_xdp("H4", "profile_iface_xdp.c:xdp_attach_prog",
                  "xdp attach failed after all attempts", ifname, errno, 0);
    // #endregion
    return -1;
}

static int open_bpf_object(const char *path, struct bpf_object **obj_out,
                           const char *prog_name, struct bpf_program **prog_out,
                           const char *map_name, struct bpf_map **map_out)
{
    char cwd[512];
    int missing = (access(path, F_OK) != 0);
    struct bpf_object *obj;

    cwd[0] = '\0';
    if (getcwd(cwd, sizeof(cwd)) == NULL)
        strncpy(cwd, "?", sizeof(cwd) - 1);

    if (missing) {
        fprintf(stderr,
                "[PROFILE-XDP] bpf open failed: %s (file missing, cwd=%s — run 'make' in repo root)\n",
                path, cwd);
        // #region agent log
        agent_log_xdp("H1", "profile_iface_xdp.c:open_bpf_object",
                      "bpf object file missing", path, ENOENT, 1);
        // #endregion
        return -1;
    }

    obj = bpf_object__open_file(path, NULL);

    if (libbpf_get_error(obj)) {
        int err = libbpf_get_error(obj);

        fprintf(stderr, "[PROFILE-XDP] bpf open failed: %s (%s, cwd=%s)\n",
                path, strerror(-err), cwd);
        // #region agent log
        agent_log_xdp("H3", "profile_iface_xdp.c:open_bpf_object",
                      "bpf_object__open_file failed", path, -err, 0);
        // #endregion
        return -1;
    }
    if (bpf_object__load(obj) != 0) {
        fprintf(stderr, "[PROFILE-XDP] bpf load failed: %s (verifier/kernel — check dmesg)\n", path);
        // #region agent log
        agent_log_xdp("H2", "profile_iface_xdp.c:open_bpf_object",
                      "bpf_object__load failed", path, errno, 0);
        // #endregion
        bpf_object__close(obj);
        return -1;
    }
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    struct bpf_map *map = bpf_object__find_map_by_name(obj, map_name);
    if (!prog || !map) {
        fprintf(stderr, "[PROFILE-XDP] bpf object %s missing prog=%s map=%s\n",
                path, prog_name, map_name);
        // #region agent log
        agent_log_xdp("H2", "profile_iface_xdp.c:open_bpf_object",
                      "bpf prog/map missing in object", path, 0, 0);
        // #endregion
        bpf_object__close(obj);
        return -1;
    }
    *obj_out = obj;
    *prog_out = prog;
    *map_out = map;
    return 0;
}

static int update_xsk_map_queue(struct xsk_socket *xsk, int map_fd, int queue_id)
{
    int key = queue_id;
    int fd = xsk_socket__fd(xsk);

    (void)xsk_socket__update_xskmap(xsk, map_fd);
    return bpf_map_update_elem(map_fd, &key, &fd, BPF_ANY);
}

static int update_xsk_map_iface(struct ne_iface *iface, int map_fd, const char *tag)
{
    for (int q = 0; q < iface->queue_count; q++) {
        int key = q;
        int fd;

        if (!iface->queues[q].xsk)
            return -1;
        if (update_xsk_map_queue(iface->queues[q].xsk, map_fd, q) != 0)
            return -1;
        if (bpf_map_lookup_elem(map_fd, &key, &fd) != 0) {
            fprintf(stderr, "[PROFILE-XDP] %s %s xsks_map[%d] bind FAILED\n",
                    tag, iface->ifname, q);
            return -1;
        }
        fprintf(stderr, "[PROFILE-XDP] %s %s xsks_map[%d]=fd%d\n",
                tag, iface->ifname, q, fd);
    }
    fflush(stderr);
    return 0;
}

static void update_wan_fake_ethertype(struct bpf_object *obj, uint16_t fake_ethertype_ipv4)
{
    if (!obj)
        return;
    if (fake_ethertype_ipv4 == 0)
        fake_ethertype_ipv4 = 0x88B5u;
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "wan_config_map");
    if (!map)
        return;
    int key = 0;
    (void)bpf_map_update_elem(bpf_map__fd(map), &key, &fake_ethertype_ipv4, BPF_ANY);
    fprintf(stderr, "[PROFILE-XDP] wan_config_map fake_ethertype=0x%04x\n",
            (unsigned)fake_ethertype_ipv4);
    fflush(stderr);
}

int profile_iface_xdp_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;
    const char *ifname;
    uint32_t existing_id = 0;
    int skip_attach;

    if (!p || !cfg || pair_li < 0 || pair_li >= p->local_count)
        return -1;

    ifname = p->locals[pair_li].ifname;
    skip_attach = lan_iface_has_kernel_xdp(ifname, &existing_id);

    if (skip_attach && p->bpf_locals[pair_li]) {
        map = bpf_object__find_map_by_name(p->bpf_locals[pair_li], "xsks_map");
        if (!map)
            return -1;
        fprintf(stderr,
                "[PROFILE-XDP] LAN %s xdp/id:%u — skip attach, refresh xsks_map (shared)\n",
                ifname, existing_id);
        return update_xsk_map_iface(&p->locals[pair_li], bpf_map__fd(map), "LAN");
    }

    if (skip_attach) {
        fprintf(stderr,
                "[PROFILE-XDP] LAN %s xdp/id:%u — skip attach (shared, other profile owns xdp)\n",
                ifname, existing_id);
        return 0;
    }

    fprintf(stderr, "[PROFILE-XDP] LAN %s bind ifindex=%d bpf=%s\n",
            ifname, p->locals[pair_li].ifindex, cfg->bpf_file);
    fflush(stderr);

    if (open_bpf_object(cfg->bpf_file, &p->bpf_locals[pair_li],
                        "xdp_redirect_prog", &prog, "xsks_map", &map) != 0)
        return -1;
    if (xdp_attach_prog(p->locals[pair_li].ifindex, bpf_program__fd(prog),
                        p->xdp_flags, ifname, "LAN") != 0)
        return -1;
    return update_xsk_map_iface(&p->locals[pair_li], bpf_map__fd(map), "LAN");
}

int profile_iface_xdp_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4)
{
    struct bpf_program *prog = NULL;
    struct bpf_map *map = NULL;

    if (!p || !cfg || dp_slot < 0 || dp_slot >= p->wan_count)
        return -1;
    if (open_bpf_object(cfg->bpf_wan_file, &p->bpf_wans[dp_slot],
                        "xdp_wan_redirect_prog", &prog, "wan_xsks_map", &map) != 0)
        return -1;
    update_wan_fake_ethertype(p->bpf_wans[dp_slot], fake_ethertype_ipv4);
    if (xdp_attach_prog(p->wans[dp_slot].ifindex, bpf_program__fd(prog),
                        p->xdp_flags, p->wans[dp_slot].ifname, "WAN") != 0)
        return -1;
    return update_xsk_map_iface(&p->wans[dp_slot], bpf_map__fd(map), "WAN");
}


static void init_fwd_local_meta(struct forwarder *fwd, int li,
                                const struct app_config *cfg, int cfg_local_idx)
{
    static const uint8_t zero_mac[MAC_LEN];

    memset(&fwd->locals[li], 0, sizeof(fwd->locals[li]));
    fwd->locals[li].ifindex = (int)if_nametoindex(cfg->locals[cfg_local_idx].ifname);
    strncpy(fwd->locals[li].ifname, cfg->locals[cfg_local_idx].ifname,
            sizeof(fwd->locals[li].ifname) - 1);
    memcpy(fwd->locals[li].src_mac, cfg->locals[cfg_local_idx].src_mac, MAC_LEN);
    memcpy(fwd->locals[li].dst_mac, zero_mac, MAC_LEN);
}

static void init_fwd_wan_meta(struct forwarder *fwd, int di,
                              const struct app_config *cfg, int cfg_wan_idx)
{
    memset(&fwd->wans[di], 0, sizeof(fwd->wans[di]));
    fwd->wans[di].ifindex = (int)if_nametoindex(cfg->wans[cfg_wan_idx].ifname);
    strncpy(fwd->wans[di].ifname, cfg->wans[cfg_wan_idx].ifname, sizeof(fwd->wans[di].ifname) - 1);
    memcpy(fwd->wans[di].src_mac, cfg->wans[cfg_wan_idx].src_mac, MAC_LEN);
    memcpy(fwd->wans[di].dst_mac, cfg->wans[cfg_wan_idx].dst_mac, MAC_LEN);
}

static int crypto_finish_reload(struct forwarder *fwd, struct app_config *cfg,
                                const struct app_config *old)
{
    if (local_hwaddr_prepare(cfg) != 0)
        return -1;
    fwd_wan_weight_blend_begin(old, cfg, fwd_crypto_profile_slot_for_id);
    if (fwd_crypto_ensure_profile_slots(cfg) != 0)
        return -1;
    fwd_crypto_snapshot_active_to_prev();
    int rc = fwd_crypto_rebuild(cfg);
    if (rc != 0)
        fwd_crypto_clear_grace();
    fwd_crypto_sync_flow_table_windows(fwd);
    fwd_crypto_cleanup_stale_profile_slots(cfg);
    fwd_wan_reset_on_init(fwd);
    return forwarder_should_stop() ? -1 : rc;
}

static int detach_removed_lan_rows(struct forwarder *fwd, const struct app_config *new_cfg)
{
    for (int li = 0; li < fwd->local_count; li++) {
        const char *ifname = fwd->pair.locals[li].ifname;

        if (!ne_pair_local_live(&fwd->pair, li))
            continue;
        if (lan_still_in_merged_cfg(new_cfg, ifname)) {
            fprintf(stderr,
                    "[PROFILE-XDP] REMOVE LAN row: %s other profile(s) still use — keep xdp/id\n",
                    ifname);
            continue;
        }
        uint32_t dropped = 0;
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            struct ne_packet pkt;
            while (ne_ring_try_pop(&fwd->worker_tx_local[li][w], &pkt) == 0) {
                ne_frame_free(&fwd->pair, pkt.addr);
                dropped++;
            }
        }
        fprintf(stderr,
                "[PROFILE-XDP] REMOVE LAN row: %s no profile left — detach xdp/id (flushed %u pkts)\n",
                ifname, dropped);
        ne_pair_unplumb_local(&fwd->pair, li);
    }
    return 0;
}

static int detach_removed_wan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                                 const struct app_config *old_cfg)
{
    for (int di = 0; di < fwd->wan_count; di++) {
        const char *ifname = fwd->pair.wans[di].ifname;

        if (!ne_pair_wan_live(&fwd->pair, di))
            continue;
        if (!wan_dataplane_dropped_from_merged(old_cfg, new_cfg, ifname))
            continue;
        uint32_t dropped = fwd_wan_flush_queue(fwd, di);
        fprintf(stderr,
                "[PROFILE-XDP] REMOVE WAN row: %s exclusive — detach xdp/id (flushed %u pkts)\n",
                ifname, dropped);
        ne_pair_unplumb_wan_dp(&fwd->pair, di);
    }
    return 0;
}

static int attach_new_lan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                               const struct app_config *old_cfg)
{
    for (int ci = 0; ci < new_cfg->local_count; ci++) {
        const char *ifname = new_cfg->locals[ci].ifname;

        if (!lan_is_new_to_merged(old_cfg, new_cfg, ifname)) {
            fprintf(stderr,
                    "[PROFILE-XDP] ADD LAN row: %s already used by other profile — skip xdp/id\n",
                    ifname);
            continue;
        }

        int li = fwd->local_count;
        if (li >= MAX_INTERFACES)
            return -1;
        if (ne_pair_plumb_local(&fwd->pair, new_cfg, ci, li) != 0)
            return -1;
        if (profile_iface_xdp_bind_local(&fwd->pair, new_cfg, li) != 0)
            return -1;
        fwd->pair.xdp_local_on[li] = 1;
        init_fwd_local_meta(fwd, li, new_cfg, ci);
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->worker_tx_local[li][w], NE_RING, 1) != 0)
                return -1;
        }
        fwd->local_count++;
        fprintf(stderr, "[PROFILE-XDP] ADD LAN row: %s first use — attach xdp/id (slot %d)\n",
                ifname, li);
    }
    return 0;
}

static int attach_new_wan_rows(struct forwarder *fwd, const struct app_config *new_cfg,
                              const struct app_config *old_cfg)
{
    for (int ci = 0; ci < new_cfg->wan_count; ci++) {
        const char *ifname = new_cfg->wans[ci].ifname;

        if (!new_cfg->wans[ci].dataplane)
            continue;
        if (!wan_is_new_dataplane_to_merged(old_cfg, new_cfg, ifname))
            continue;
        int di = fwd->wan_count;
        if (di >= MAX_INTERFACES)
            return -1;
        if (ne_pair_plumb_wan_dp(&fwd->pair, new_cfg, ci, di) != 0)
            return -1;
        if (profile_iface_xdp_bind_wan(&fwd->pair, new_cfg, di, new_cfg->fake_ethertype_ipv4) != 0)
            return -1;
        fwd->pair.xdp_wan_on[di] = 1;
        init_fwd_wan_meta(fwd, di, new_cfg, ci);
        fwd->wan_cfg_idx[di] = ci;
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->worker_tx_wan[di][w], NE_RING, 1) != 0)
                return -1;
        }
        fwd->wan_count++;
        fprintf(stderr, "[PROFILE-XDP] ADD WAN row: %s new — attach xdp/id (dp slot %d)\n",
                ifname, di);
    }
    return 0;
}

int profile_iface_xdp_reload_impl(struct forwarder *fwd, struct app_config *cfg,
                                  enum profile_iface_xdp_reload_mode mode)
{
    const struct app_config *old = fwd->cfg;

    if (!fwd || !cfg || !old || forwarder_should_stop())
        return -1;

    switch (mode) {
    case PROFILE_IFACE_XDP_REMOVE:
        if (!profile_iface_xdp_can_remove(old, cfg))
            return -1;
        detach_removed_lan_rows(fwd, cfg);
        detach_removed_wan_rows(fwd, cfg, old);
        break;
    case PROFILE_IFACE_XDP_ADD:
        if (!profile_iface_xdp_can_add(old, cfg))
            return -1;
        if (attach_new_lan_rows(fwd, cfg, old) != 0)
            return -1;
        if (attach_new_wan_rows(fwd, cfg, old) != 0)
            return -1;
        break;
    case PROFILE_IFACE_XDP_DELTA:
        if (!profile_iface_xdp_can_delta(old, cfg))
            return -1;
        detach_removed_lan_rows(fwd, cfg);
        detach_removed_wan_rows(fwd, cfg, old);
        if (attach_new_lan_rows(fwd, cfg, old) != 0)
            return -1;
        if (attach_new_wan_rows(fwd, cfg, old) != 0)
            return -1;
        break;
    default:
        return -1;
    }

    fwd->cfg = cfg;
    return crypto_finish_reload(fwd, cfg, old);
}

int profile_iface_xdp_apply_add(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!profile_iface_xdp_can_add(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, PROFILE_IFACE_XDP_ADD);
}

int profile_iface_xdp_apply_remove(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!profile_iface_xdp_can_remove(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, PROFILE_IFACE_XDP_REMOVE);
}

int profile_iface_xdp_apply_delta(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || !fwd->cfg || forwarder_should_stop())
        return -1;
    if (!profile_iface_xdp_can_delta(fwd->cfg, cfg))
        return -1;
    return forwarder_queue_profile_iface_xdp(fwd, cfg, PROFILE_IFACE_XDP_DELTA);
}