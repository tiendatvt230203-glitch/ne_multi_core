#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/dataplane.h"
#include "../../inc/core/crypto_route.h"

#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"
#include "../../inc/crypto/pqc_l2_handshake.h"
#include "../../inc/crypto/crypto_layer2.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static atomic_int running = 1;
struct forwarder *g_active_fwd;
static pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;

static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

void forwarder_pin_cpu(void)
{
    pin_cpu(NE_CPU_MAIN);
}

#define IO_BURST_ROUNDS 8

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

struct worker_ctx {
    struct forwarder *fwd;
    int worker_idx;
};

static void worker_tick(struct forwarder *fwd)
{
    fwd_crypto_maybe_expire_prev_grace();
    fwd_wan_drain_tick(fwd);
    fwd_wan_weight_blend_tick();
    fwd_crypto_cleanup_stale_profile_slots(fwd->cfg);
}

static void *unified_worker_thread(void *arg)
{
    struct worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet batch[NE_BATCH_SIZE];
    uint32_t gc_tick = 0;
    uint32_t maint_tick = 0;
    uint64_t idle_loops = 0;
    uint64_t last_stats_ms = 0;
    int w = ctx->worker_idx;
    int is_primary = (w == 0);

    pin_cpu(dp_crypto_worker_cpu(w));
    dp_crypto_worker_bind(w);
    crypto_layer2_bind_worker_core((uint8_t)w);

    {
        int lq = 0, wq = 0;
        if (fwd->pair.local_count > 0)
            lq = fwd->pair.locals[0].queue_count;
        if (fwd->pair.wan_count > 0)
            wq = fwd->pair.wans[0].queue_count;
        fprintf(stderr, "[WORKER] %d started cpu=%u (need queue>=%d, local_q=%d wan_q=%d)\n",
                w, (unsigned)dp_crypto_worker_cpu(w), w, lq, wq);
        fflush(stderr);
    }

    // #region agent log
    {
        FILE *_df = fopen("/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-250a01.log", "a");
        if (_df) {
            struct timespec _ts;
            clock_gettime(CLOCK_REALTIME, &_ts);
            long _ms = (long)_ts.tv_sec * 1000L + _ts.tv_nsec / 1000000L;
            fprintf(_df,
                    "{\"sessionId\":\"250a01\",\"location\":\"forwarder.c:unified_worker_thread\","
                    "\"message\":\"worker started\",\"data\":{\"worker\":%d,\"cpu\":%u},"
                    "\"timestamp\":%ld,\"hypothesisId\":\"unified\",\"runId\":\"post-refactor\"}\n",
                    w, (unsigned)dp_crypto_worker_cpu(w), _ms);
            fclose(_df);
        }
    }
    // #endregion

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        for (int i = 0; i < IO_BURST_ROUNDS; i++)
            ne_drain_cq_worker(&fwd->pair, w);

        for (int i = 0; i < IO_BURST_ROUNDS; i++)
            ne_refill_fq_worker(&fwd->pair, w);

        int rcvd_local = ne_recv_local_worker(&fwd->pair, w, batch, NE_BATCH_SIZE);
        // #region agent log
        if (rcvd_local > 0) {
            static _Atomic int first_lan_recv;
            if (atomic_exchange(&first_lan_recv, 1) == 0)
                fprintf(stderr, "[DP-FIRST] lan recv worker=%d batch=%d\n", w, rcvd_local);
        }
        // #endregion
        for (int i = 0; i < rcvd_local; i++) {
            dataplane_process_local(fwd, batch[i]);
            did_work = 1;
        }
        if (rcvd_local > 0)
            ne_recv_release_local_worker(&fwd->pair, w);

        int rcvd_wan = ne_recv_wan_worker(&fwd->pair, w, batch, NE_BATCH_SIZE);
        // #region agent log
        if (rcvd_wan > 0) {
            static _Atomic int first_wan_recv;
            if (atomic_exchange(&first_wan_recv, 1) == 0)
                fprintf(stderr, "[DP-FIRST] wan recv worker=%d batch=%d\n", w, rcvd_wan);
            static _Atomic uint64_t wan_batch_core;
            if (atomic_fetch_add(&wan_batch_core, 1) < 100) {
                fprintf(stderr, "[DP-CORE] wan-batch worker=%d n=%d\n", w, rcvd_wan);
                fprintf(stderr, "[DP-FLOW] NE2 step=4-WAN-BATCH worker=%d n=%d\n",
                        w, rcvd_wan);
            }
        }
        // #endregion
        for (int i = 0; i < rcvd_wan; i++) {
            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            dataplane_process_wan(fwd, batch[i]);
            did_work = 1;
        }
        if (rcvd_wan > 0)
            ne_recv_release_wan_worker(&fwd->pair, w);

        // #region agent log
        if (rcvd_local > 0 || rcvd_wan > 0) {
            static _Atomic uint64_t recv_log_count;
            uint64_t rn = atomic_fetch_add(&recv_log_count, 1);
            if (rn < 200 || (rn & 0xFFFu) == 0)
                fprintf(stderr, "[WORKER] %d recv local=%d wan=%d\n", w, rcvd_local, rcvd_wan);
            if (rn < 64 || (rn & 0x3Fu) == 0) {
                FILE *_df = fopen("/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-250a01.log", "a");
                if (_df) {
                    struct timespec _ts;
                    clock_gettime(CLOCK_REALTIME, &_ts);
                    long _ms = (long)_ts.tv_sec * 1000L + _ts.tv_nsec / 1000000L;
                    fprintf(_df,
                            "{\"sessionId\":\"250a01\",\"location\":\"forwarder.c:worker_loop\","
                            "\"message\":\"recv batch\",\"data\":{\"worker\":%d,\"local\":%d,\"wan\":%d},"
                            "\"timestamp\":%ld,\"hypothesisId\":\"poll\",\"runId\":\"post-fix\"}\n",
                            w, rcvd_local, rcvd_wan, _ms);
                    fclose(_df);
                }
            }
        } else if ((++idle_loops & 0xFFFFFu) == 0) {
            FILE *_df = fopen("/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-250a01.log", "a");
            if (_df) {
                struct timespec _ts;
                clock_gettime(CLOCK_REALTIME, &_ts);
                long _ms = (long)_ts.tv_sec * 1000L + _ts.tv_nsec / 1000000L;
                fprintf(_df,
                        "{\"sessionId\":\"250a01\",\"location\":\"forwarder.c:worker_loop\","
                        "\"message\":\"busy poll idle\",\"data\":{\"worker\":%d,\"idle_loops\":%lu},"
                        "\"timestamp\":%ld,\"hypothesisId\":\"poll\",\"runId\":\"post-fix\"}\n",
                        w, (unsigned long)idle_loops, _ms);
                fclose(_df);
            }
        }
        // #endregion

        for (int i = 0; i < IO_BURST_ROUNDS; i++)
            ne_drain_cq_worker(&fwd->pair, w);

        if (is_primary) {
            struct timespec _now_ts;
            clock_gettime(CLOCK_MONOTONIC, &_now_ts);
            uint64_t now_ms = (uint64_t)_now_ts.tv_sec * 1000ULL +
                              (uint64_t)_now_ts.tv_nsec / 1000000ULL;
            if (now_ms - last_stats_ms >= 5000) {
                dataplane_dump_stats();
                last_stats_ms = now_ms;
            }

            if (pthread_mutex_trylock(&runtime_lock) != 0) {
                if (!atomic_load_explicit(&running, memory_order_acquire))
                    break;
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
            if ((++maint_tick & 1023u) == 0)
                worker_tick(fwd);
            pthread_mutex_unlock(&runtime_lock);
        }

        if (++gc_tick >= 2048) {
            fwd_crypto_frag_gc_worker_tick(w);
            gc_tick = 0;
        }

        (void)did_work;
    }
    return NULL;
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

    pqc_handshake_start_all_profiles(cfg);

    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
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
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
}

static void forwarder_join_workers(struct forwarder *fwd, int started)
{
    for (int w = 0; w < started; w++)
        pthread_join(fwd->worker_threads[w], NULL);
}

static void forwarder_abort_workers(struct forwarder *fwd, int started)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    forwarder_join_workers(fwd, started);
}

void forwarder_run(struct forwarder *fwd)
{
    struct worker_ctx ctx[NE_CRYPTO_WORKERS];
    int started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    g_active_fwd = fwd;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        ctx[w].fwd = fwd;
        ctx[w].worker_idx = w;
        if (pthread_create(&fwd->worker_threads[w], NULL, unified_worker_thread, &ctx[w]) != 0) {
            forwarder_abort_workers(fwd, started);
            return;
        }
        started++;
    }

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);

    forwarder_join_workers(fwd, started);
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
