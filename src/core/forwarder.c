#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/dataplane.h"

#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/dataplane_util.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static atomic_int running = 1;
struct forwarder *g_active_fwd;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;

struct pipe_thread_ctx {
    struct forwarder *fwd;
    struct ne_pipeline *pl;
    unsigned cpu_loc;
    unsigned cpu_mid;
    unsigned cpu_wan;
};

static const unsigned g_pipe_cpus[NE_PIPELINE_COUNT][3] = {
    { NE_CPU_LOC_A, NE_CPU_MID_A, NE_CPU_WAN_A },
    { NE_CPU_LOC_B, NE_CPU_MID_B, NE_CPU_WAN_B },
};

static void learn_lan_rx_batch(struct forwarder *fwd, struct ne_pipeline *pl,
                               struct ne_packet *batch, int n)
{
    for (int i = 0; i < n; i++) {
        int li = batch[i].local_idx < fwd->local_count ? (int)batch[i].local_idx : 0;
        uint8_t *pkt = ne_packet_data(&pl->pair, batch[i].addr);

        if (!pkt || batch[i].len < 14)
            continue;
        uint32_t src_ip = dp_src_ipv4(pkt, batch[i].len);
        if (src_ip)
            local_neigh_learn(li, src_ip, pkt + 6);
    }
}

static void tx_drain_local_burst(struct forwarder *fwd, struct ne_pipeline *pl, int li)
{
    for (int n = 0; n < 512; n++) {
        if (ne_ring_count(&pl->mid_to_local[li]) == 0)
            break;
        if (ne_tx_drain_local(&pl->pair, &pl->mid_to_local[li], li) <= 0)
            break;
    }
}

static void tx_drain_wan_burst(struct forwarder *fwd, struct ne_pipeline *pl, int wi)
{
    if (fwd_wan_is_stopped(wi))
        return;
    for (int n = 0; n < 512; n++) {
        if (ne_ring_count(&pl->mid_to_wan[wi]) == 0)
            break;
        if (ne_tx_drain_wan(&pl->pair, &pl->mid_to_wan[wi], wi) <= 0)
            break;
        fwd->wan_tx_stuck[wi] = 0;
    }
}

static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

void forwarder_pin_cpu(void)
{
    pin_cpu(NE_CPU_LOC_A);
}

static void init_iface_meta(struct xsk_interface *iface, const char *ifname,
                            const uint8_t src_mac[MAC_LEN],
                            const uint8_t dst_mac[MAC_LEN])
{
    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(ifname);
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = 0;
    iface->ring_size = NE_RING;
    iface->batch_size = NE_BATCH_SIZE;
    iface->frame_size = NE_FRAME;
    memcpy(iface->src_mac, src_mac, MAC_LEN);
    memcpy(iface->dst_mac, dst_mac, MAC_LEN);
}

static void *local_core_thread(void *arg)
{
    struct pipe_thread_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_pipeline *pl = ctx->pl;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(ctx->cpu_loc);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        ne_drain_cq_local(&pl->pair);
        ne_refill_fq_local(&pl->pair);
        for (int li = 0; li < fwd->local_count; li++)
            tx_drain_local_burst(fwd, pl, li);

        int rcvd = ne_recv_local(&pl->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }
        learn_lan_rx_batch(fwd, pl, batch, rcvd);
        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&pl->local_to_mid, &batch[i]) != 0)
                ne_frame_free(&pl->pair, batch[i].addr);
        }
        ne_recv_release_local(&pl->pair);
    }
    return NULL;
}

static void *wan_core_thread(void *arg)
{
    struct pipe_thread_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_pipeline *pl = ctx->pl;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(ctx->cpu_wan);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        ne_drain_cq_wan(&pl->pair);
        ne_refill_fq_wan(&pl->pair);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (fwd->wan_tx_cooldown[wi] > 0)
                fwd->wan_tx_cooldown[wi]--;
            tx_drain_wan_burst(fwd, pl, wi);
        }

        int rcvd = ne_recv_wan(&pl->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&pl->pair, batch[i].addr);
                continue;
            }
            if (ne_ring_try_push(&pl->wan_to_mid, &batch[i]) != 0)
                ne_frame_free(&pl->pair, batch[i].addr);
        }
        ne_recv_release_wan(&pl->pair);
    }
    return NULL;
}

static void mid_process_batches(struct forwarder *fwd, struct ne_pipeline *pl)
{
    struct ne_packet job;

    for (int round = 0; round < 16; round++) {
        int round_work = 0;
        for (int n = 0; n < NE_BATCH_SIZE; n++) {
            if (ne_ring_try_pop(&pl->wan_to_mid, &job) != 0)
                break;
            dataplane_process_wan(fwd, pl, job);
            round_work = 1;
        }
        for (int n = 0; n < NE_BATCH_SIZE; n++) {
            if (ne_ring_try_pop(&pl->local_to_mid, &job) != 0)
                break;
            dataplane_process_local(fwd, pl, job);
            round_work = 1;
        }
        if (!round_work)
            break;
    }
}

static void *middle_core_thread(void *arg)
{
    struct pipe_thread_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_pipeline *pl = ctx->pl;
    uint32_t gc_tick = 0;
    int is_primary = (pl->pair.shard_id == 0);

    pin_cpu(ctx->cpu_mid);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (is_primary) {
            if (pthread_mutex_trylock(&runtime_lock) != 0) {
                if (!atomic_load_explicit(&running, memory_order_acquire))
                    break;
                mid_process_batches(fwd, pl);
                sched_yield();
                continue;
            }
            if (!atomic_load_explicit(&running, memory_order_acquire)) {
                pthread_mutex_unlock(&runtime_lock);
                break;
            }
            if (fwd_reload_apply_if_pending()) {
                pthread_mutex_unlock(&runtime_lock);
                continue;
            }
            fwd_crypto_maybe_expire_prev_grace();
            fwd_wan_drain_tick(fwd);
            fwd_wan_weight_blend_tick();
            fwd_crypto_cleanup_stale_profile_slots(fwd->cfg);
            mid_process_batches(fwd, pl);
            did_work = 1;
            if (++gc_tick >= 8192) {
                fwd_crypto_frag_gc_tick();
                gc_tick = 0;
            }
            pthread_mutex_unlock(&runtime_lock);
        } else {
            mid_process_batches(fwd, pl);
            did_work = 1;
        }

        if (!did_work)
            sched_yield();
    }
    return NULL;
}

static int pipeline_init_rings(struct ne_pipeline *pl)
{
    if (ne_ring_init(&pl->local_to_mid, NE_RING) != 0 ||
        ne_ring_init(&pl->wan_to_mid, NE_RING) != 0)
        return -1;
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (ne_ring_init(&pl->mid_to_local[i], NE_RING) != 0)
            return -1;
        if (ne_ring_init(&pl->mid_to_wan[i], NE_RING) != 0)
            return -1;
    }
    return 0;
}

static void pipeline_destroy_rings(struct ne_pipeline *pl)
{
    ne_ring_destroy(&pl->local_to_mid);
    ne_ring_destroy(&pl->wan_to_mid);
    for (int i = 0; i < MAX_INTERFACES; i++) {
        ne_ring_destroy(&pl->mid_to_wan[i]);
        ne_ring_destroy(&pl->mid_to_local[i]);
    }
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0 || config_count_dataplane_wans(cfg) <= 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = config_count_dataplane_wans(cfg);
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;

    static const uint8_t zero_mac[MAC_LEN];
    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname,
                        cfg->locals[i].src_mac, zero_mac);
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        fwd->wan_cfg_idx[di] = ci;
        init_iface_meta(&fwd->wans[di], cfg->wans[ci].ifname,
                        cfg->wans[ci].src_mac, cfg->wans[ci].dst_mac);
    }

    interface_ip_xdp_off_config(cfg);
    interface_reset_redirect_maps();

    if (local_hwaddr_prepare(cfg) != 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    if (fwd_crypto_rebuild(cfg) != 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    fwd_crypto_reset_on_init();
    if (fwd_crypto_ensure_profile_slots(cfg) != 0)
        return -1;

    struct ne_pair pairs[NE_PIPELINE_COUNT];
    if (ne_pairs_open(pairs, cfg) != 0)
        return -1;
    if (forwarder_should_stop()) {
        ne_pairs_close(pairs);
        return -1;
    }

    for (uint32_t p = 0; p < NE_PIPELINE_COUNT; p++) {
        fwd->pipes[p].pair = pairs[p];
        if (pipeline_init_rings(&fwd->pipes[p]) != 0) {
            for (uint32_t j = 0; j <= p; j++)
                pipeline_destroy_rings(&fwd->pipes[j]);
            ne_pairs_close(pairs);
            memset(fwd, 0, sizeof(*fwd));
            return -1;
        }
    }

    (void)local_hwaddr_install(fwd);
    fwd_wan_reset_on_init(fwd);

    atomic_store_explicit(&running, 1, memory_order_release);
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (!fwd)
        return;
    for (uint32_t p = 0; p < NE_PIPELINE_COUNT; p++) {
        pipeline_destroy_rings(&fwd->pipes[p]);
        ne_pair_close(&fwd->pipes[p].pair);
    }
    fwd_crypto_cleanup_all_profile_slots();
}

void forwarder_run(struct forwarder *fwd)
{
    struct pipe_thread_ctx ctx[NE_PIPELINE_COUNT];
    pthread_t threads[NE_PIPELINE_COUNT * 3];
    int n_threads = 0;

    if (!fwd || forwarder_should_stop())
        return;

    g_active_fwd = fwd;

    for (uint32_t p = 0; p < NE_PIPELINE_COUNT; p++) {
        ctx[p].fwd = fwd;
        ctx[p].pl = &fwd->pipes[p];
        ctx[p].cpu_loc = g_pipe_cpus[p][0];
        ctx[p].cpu_mid = g_pipe_cpus[p][1];
        ctx[p].cpu_wan = g_pipe_cpus[p][2];

        if (pthread_create(&threads[n_threads++], NULL, local_core_thread, &ctx[p]) != 0)
            goto fail;
        fwd->pipes[p].local_thread = threads[n_threads - 1];

        if (pthread_create(&threads[n_threads++], NULL, middle_core_thread, &ctx[p]) != 0)
            goto fail;
        fwd->pipes[p].mid_thread = threads[n_threads - 1];

        if (pthread_create(&threads[n_threads++], NULL, wan_core_thread, &ctx[p]) != 0)
            goto fail;
        fwd->pipes[p].wan_thread = threads[n_threads - 1];
    }

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);

    for (int i = 0; i < n_threads; i++)
        pthread_join(threads[i], NULL);

    fwd->threads_started = 0;
    if (g_active_fwd == fwd)
        g_active_fwd = NULL;
    return;

fail:
    atomic_store_explicit(&running, 0, memory_order_release);
    for (int i = 0; i < n_threads; i++)
        pthread_join(threads[i], NULL);
    fwd->threads_started = 0;
    if (g_active_fwd == fwd)
        g_active_fwd = NULL;
}

void forwarder_stop(void)
{
    atomic_store_explicit(&running, 0, memory_order_release);
}

void forwarder_shutdown_resources(void)
{
    fwd_reload_shutdown();
}

int forwarder_should_stop(void)
{
    return atomic_load_explicit(&running, memory_order_acquire) == 0;
}
