#include "../../inc/core/wan_admin.h"

#include <pthread.h>
#include <stdio.h>
#include <string.h>

#define WAN_ADMIN_MAX_DOWN (MAX_PROFILES * MAX_PROFILE_INTERFACES)

struct wan_admin_entry {
    int valid;
    int profile_id;
    char ifname[IF_NAMESIZE];
};

static struct wan_admin_entry g_down[WAN_ADMIN_MAX_DOWN];
static pthread_mutex_t g_wan_admin_mtx = PTHREAD_MUTEX_INITIALIZER;

static int profile_wan_pos(const struct profile_config *p, int cfg_wan)
{
    for (int i = 0; i < p->wan_count; i++) {
        if (p->wan_indices[i] == cfg_wan)
            return i;
    }
    return -1;
}

static const struct profile_config *profile_by_id(const struct app_config *cfg, int id)
{
    if (!cfg)
        return NULL;
    for (int i = 0; i < cfg->profile_count; i++) {
        if (cfg->profiles[i].id == id)
            return &cfg->profiles[i];
    }
    return NULL;
}

static int entry_index_locked(int profile_id, const char *ifname)
{
    for (int i = 0; i < WAN_ADMIN_MAX_DOWN; i++) {
        if (!g_down[i].valid)
            continue;
        if (g_down[i].profile_id == profile_id &&
            strcmp(g_down[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int alloc_entry_locked(void)
{
    for (int i = 0; i < WAN_ADMIN_MAX_DOWN; i++) {
        if (!g_down[i].valid)
            return i;
    }
    return -1;
}

static int is_down_locked(int profile_id, const char *ifname)
{
    return entry_index_locked(profile_id, ifname) >= 0;
}

int wan_admin_is_down(int profile_id, const char *ifname)
{
    if (!ifname || !ifname[0])
        return 0;
    pthread_mutex_lock(&g_wan_admin_mtx);
    int down = is_down_locked(profile_id, ifname);
    pthread_mutex_unlock(&g_wan_admin_mtx);
    return down;
}

int wan_admin_validate_wan(const struct app_config *cfg,
                             int profile_id, const char *ifname)
{
    if (!cfg || !ifname || !ifname[0])
        return -1;

    const struct profile_config *p = profile_by_id(cfg, profile_id);
    if (!p)
        return -1;

    for (int i = 0; i < p->wan_count; i++) {
        int wi = p->wan_indices[i];
        if (wi < 0 || wi >= cfg->wan_count)
            continue;
        if (strcmp(cfg->wans[wi].ifname, ifname) != 0)
            continue;
        if (!config_wan_live(cfg, wi))
            return -2;
        return 0;
    }
    return -1;
}

static int count_up_wans_locked(const struct profile_config *p,
                                const struct app_config *cfg)
{
    int n = 0;
    for (int i = 0; i < p->wan_count; i++) {
        int wi = p->wan_indices[i];
        if (wi < 0 || wi >= cfg->wan_count)
            continue;
        if (!is_down_locked(p->id, cfg->wans[wi].ifname))
            n++;
    }
    return n;
}

int wan_admin_down(int profile_id, const char *ifname)
{
    if (!ifname || !ifname[0])
        return -1;

    pthread_mutex_lock(&g_wan_admin_mtx);
    if (is_down_locked(profile_id, ifname)) {
        pthread_mutex_unlock(&g_wan_admin_mtx);
        return 0;
    }

    int slot = alloc_entry_locked();
    if (slot < 0) {
        pthread_mutex_unlock(&g_wan_admin_mtx);
        return -1;
    }

    g_down[slot].valid = 1;
    g_down[slot].profile_id = profile_id;
    strncpy(g_down[slot].ifname, ifname, sizeof(g_down[slot].ifname) - 1);
    g_down[slot].ifname[sizeof(g_down[slot].ifname) - 1] = '\0';
    pthread_mutex_unlock(&g_wan_admin_mtx);

    fprintf(stderr, "[WAN-ADMIN] DOWN profile=%d if=%s\n", profile_id, ifname);
    fflush(stderr);
    return 0;
}

int wan_admin_up(int profile_id, const char *ifname)
{
    if (!ifname || !ifname[0])
        return -1;

    pthread_mutex_lock(&g_wan_admin_mtx);
    int idx = entry_index_locked(profile_id, ifname);
    if (idx < 0) {
        pthread_mutex_unlock(&g_wan_admin_mtx);
        return 0;
    }
    g_down[idx].valid = 0;
    pthread_mutex_unlock(&g_wan_admin_mtx);

    fprintf(stderr, "[WAN-ADMIN] UP profile=%d if=%s (weights from DB)\n",
            profile_id, ifname);
    fflush(stderr);
    return 0;
}

int wan_admin_effective_weight(const struct profile_config *p,
                               const struct app_config *cfg,
                               int cfg_wan_idx)
{
    if (!p || !cfg || cfg_wan_idx < 0 || cfg_wan_idx >= cfg->wan_count)
        return 0;

    const char *ifname = cfg->wans[cfg_wan_idx].ifname;
    int pos = profile_wan_pos(p, cfg_wan_idx);
    if (pos < 0)
        return 0;

    pthread_mutex_lock(&g_wan_admin_mtx);

    if (is_down_locked(p->id, ifname)) {
        pthread_mutex_unlock(&g_wan_admin_mtx);
        return 0;
    }

    int db_self = p->wan_bandwidth_weight[pos];
    int sum_down = 0;
    int n_up = 0;

    for (int i = 0; i < p->wan_count; i++) {
        int wi = p->wan_indices[i];
        if (wi < 0 || wi >= cfg->wan_count)
            continue;
        if (is_down_locked(p->id, cfg->wans[wi].ifname)) {
            sum_down += p->wan_bandwidth_weight[i];
        } else {
            n_up++;
        }
    }

    if (n_up <= 0 || sum_down <= 0) {
        pthread_mutex_unlock(&g_wan_admin_mtx);
        return db_self;
    }

    int share = sum_down / n_up;
    int rem = sum_down % n_up;
    int up_rank = 0;

    for (int i = 0; i < p->wan_count; i++) {
        int wi = p->wan_indices[i];
        if (wi < 0 || wi >= cfg->wan_count)
            continue;
        if (is_down_locked(p->id, cfg->wans[wi].ifname))
            continue;
        if (wi == cfg_wan_idx)
            break;
        up_rank++;
    }

    int bonus = share + (up_rank < rem ? 1 : 0);
    int eff = db_self + bonus;

    pthread_mutex_unlock(&g_wan_admin_mtx);
    return eff > 0 ? eff : 1;
}

int wan_admin_would_leave_pool(const struct app_config *cfg,
                               int profile_id, const char *ifname)
{
    const struct profile_config *p = profile_by_id(cfg, profile_id);
    if (!p)
        return 1;

    pthread_mutex_lock(&g_wan_admin_mtx);
    if (!is_down_locked(profile_id, ifname)) {
        int up = count_up_wans_locked(p, cfg);
        pthread_mutex_unlock(&g_wan_admin_mtx);
        return up <= 1;
    }
    pthread_mutex_unlock(&g_wan_admin_mtx);
    return 0;
}
