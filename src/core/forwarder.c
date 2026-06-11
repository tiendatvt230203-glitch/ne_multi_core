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
    pin_cpu(NE_CPU_LOC);
}

#define IO_BURST_ROUNDS      16
#define IO_TX_BURST_MAX      64
#define POOL_LOW_WATERMARK   8192u

// #region agent log
static void io_dbg_log(const char *hypothesis_id, const char *location, const char *message,
                       uint32_t pool_free, uint32_t wan_r0, uint32_t wan_r1, uint32_t l2m_r0,
                       uint32_t l2m_r1, int wan_qcount, uint64_t bypass_cnt)
{
    FILE *f = fopen("/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-dfdcf7.log", "a");
    if (!f)
        return;
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"%s\",\"location\":\"%s\","
            "\"message\":\"%s\",\"data\":{\"pool_free\":%u,\"mid_wan_w0\":%u,"
            "\"mid_wan_w1\":%u,\"local_to_mid_w0\":%u,\"local_to_mid_w1\":%u,"
            "\"wan_qcount\":%d,\"bypass_fast\":%llu},\"timestamp\":%lld}\n",
            hypothesis_id, location, message, pool_free, wan_r0, wan_r1, l2m_r0, l2m_r1,
            wan_qcount, (unsigned long long)bypass_cnt,
            (long long)ts.tv_sec * 1000LL + ts.tv_nsec / 1000000LL);
    fclose(f);
}
// #endregion

static atomic_uint_fast64_t g_bypass_fast_total;

static void io_burst_refill_local(struct forwarder *fwd, int rx_worker)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_refill_fq_local_worker(&fwd->pair, rx_worker);
}

static void io_burst_refill_wan(struct forwarder *fwd, int rx_worker)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_refill_fq_wan_worker(&fwd->pair, rx_worker);
}

static void io_burst_drain_cq_local(struct forwarder *fwd, int tx_worker)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_drain_cq_local(&fwd->pair, tx_worker);
}

static void io_burst_drain_cq_wan(struct forwarder *fwd, int tx_worker)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_drain_cq_wan(&fwd->pair, tx_worker);
}

static void io_burst_tx_local(struct forwarder *fwd, int local_idx, int tx_worker)
{
    int nq = fwd->pair.locals[local_idx].queue_count;
    int ring_lo = tx_worker;
    int ring_hi = tx_worker + 1;

    if (nq > 0 && nq < (int)NE_CRYPTO_WORKERS) {
        if (tx_worker != 0)
            return;
        ring_lo = 0;
        ring_hi = (int)NE_CRYPTO_WORKERS;
    }

    for (int burst = 0; burst < IO_TX_BURST_MAX; burst++) {
        int sent = 0;
        for (int w = ring_lo; w < ring_hi; w++)
            sent += ne_tx_drain_local(&fwd->pair, &fwd->mid_to_local[local_idx][w],
                                      local_idx, tx_worker);
        if (sent <= 0)
            break;
    }
}

static void io_burst_tx_wan(struct forwarder *fwd, int wan_idx, int tx_worker)
{
    int nq = fwd->pair.wans[wan_idx].queue_count;
    int ring_lo = tx_worker;
    int ring_hi = tx_worker + 1;

    if (nq > 0 && nq < (int)NE_CRYPTO_WORKERS) {
        if (tx_worker != 0)
            return;
        ring_lo = 0;
        ring_hi = (int)NE_CRYPTO_WORKERS;
    }

    for (int burst = 0; burst < IO_TX_BURST_MAX; burst++) {
        int sent = 0;
        for (int w = ring_lo; w < ring_hi; w++)
            sent += ne_tx_drain_wan(&fwd->pair, &fwd->mid_to_wan[wan_idx][w],
                                    wan_idx, tx_worker);
        if (sent <= 0)
            break;
    }
}

struct io_worker_ctx {
    struct forwarder *fwd;
    int worker_idx;
    uint8_t cpu_id;
};

static uint8_t local_rx_cpu(int worker)
{
    return worker == 0 ? NE_CPU_LOC : NE_CPU_LOC_RX1;
}

static uint8_t local_tx_cpu(int worker)
{
    return worker == 0 ? NE_CPU_LOC_TX : NE_CPU_LOC_TX1;
}

static uint8_t wan_rx_cpu(int worker)
{
    return worker == 0 ? NE_CPU_WAN : NE_CPU_WAN_RX1;
}

static uint8_t wan_tx_cpu(int worker)
{
    return worker == 0 ? NE_CPU_WAN_TX : NE_CPU_WAN_TX1;
}

static void io_maybe_log_pool_low(struct forwarder *fwd, const char *where)
{
    uint32_t free = ne_pool_free_count(&fwd->pair);

    if (free >= POOL_LOW_WATERMARK)
        return;
    // #region agent log
    io_dbg_log("A", where, "pool_low", free, 0, 0, 0, 0, 0, 0);
    // #endregion
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

static void *local_rx_thread(void *arg)
{
    struct io_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int rx_worker = ctx->worker_idx;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_refill_local(fwd, rx_worker);
        io_maybe_log_pool_low(fwd, "forwarder.c:local_rx_thread");

        int rcvd = ne_recv_local_worker(&fwd->pair, batch, NE_BATCH_SIZE, rx_worker);
        if (rcvd <= 0) {
            ne_kick_rx_wakeup_local_worker(&fwd->pair, rx_worker);
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            int bp = dp_try_bypass_local_to_wan(fwd, &batch[i]);
            if (bp == 1) {
                atomic_fetch_add_explicit(&g_bypass_fast_total, 1, memory_order_relaxed);
                continue;
            }
            if (bp < 0) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            int wi = dp_crypto_pick_local_worker(ne_packet_data(&fwd->pair, batch[i].addr),
                                                 batch[i].len);
            if (ne_ring_try_push(&fwd->local_to_mid[wi], &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_local_worker(&fwd->pair, rx_worker);
    }
    return NULL;
}

static void *local_tx_thread(void *arg)
{
    struct io_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_worker = ctx->worker_idx;

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_drain_cq_local(fwd, tx_worker);
        for (int li = 0; li < fwd->local_count; li++)
            io_burst_tx_local(fwd, li, tx_worker);
        sched_yield();
    }
    return NULL;
}

static void *wan_rx_thread(void *arg)
{
    struct io_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int rx_worker = ctx->worker_idx;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_refill_wan(fwd, rx_worker);
        io_maybe_log_pool_low(fwd, "forwarder.c:wan_rx_thread");

        int rcvd = ne_recv_wan_worker(&fwd->pair, batch, NE_BATCH_SIZE, rx_worker);
        if (rcvd <= 0) {
            ne_kick_rx_wakeup_wan_worker(&fwd->pair, rx_worker);
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            int wi;
            int bp;
            const uint8_t *pkt;

            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            bp = dp_try_bypass_wan_to_local(fwd, &batch[i]);
            if (bp == 1) {
                atomic_fetch_add_explicit(&g_bypass_fast_total, 1, memory_order_relaxed);
                continue;
            }
            if (bp < 0) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            pkt = ne_packet_data(&fwd->pair, batch[i].addr);
            wi = dp_crypto_pick_wan_worker(fwd, pkt, batch[i].len);
            if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            if (ne_ring_try_push(&fwd->wan_to_mid[wi], &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_wan_worker(&fwd->pair, rx_worker);
    }
    return NULL;
}

static void *wan_tx_thread(void *arg)
{
    struct io_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_worker = ctx->worker_idx;
    uint32_t stat_tick = 0;

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_drain_cq_wan(fwd, tx_worker);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (fwd_wan_is_stopped(wi))
                continue;
            io_burst_tx_wan(fwd, wi, tx_worker);
            if (tx_worker == 0 && fwd_mid_to_wan_depth(fwd, wi) == 0)
                fwd->wan_tx_stuck[wi] = 0;
        }
        if (tx_worker == 0 && (++stat_tick & 8191u) == 0) {
            uint32_t w0 = 0, w1 = 0, l0 = 0, l1 = 0;
            int qcount = fwd->wan_count > 0 ? fwd->pair.wans[0].queue_count : 0;
            for (int wi = 0; wi < fwd->wan_count; wi++) {
                w0 += ne_ring_count(&fwd->mid_to_wan[wi][0]);
                w1 += ne_ring_count(&fwd->mid_to_wan[wi][1]);
            }
            l0 = ne_ring_count(&fwd->local_to_mid[0]);
            l1 = ne_ring_count(&fwd->local_to_mid[1]);
            // #region agent log
            io_dbg_log("BCDE", "forwarder.c:wan_tx_thread", "io_periodic",
                       ne_pool_free_count(&fwd->pair), w0, w1, l0, l1, qcount,
                       atomic_load_explicit(&g_bypass_fast_total, memory_order_relaxed));
            // #endregion
        }
        sched_yield();
    }
    return NULL;
}

struct crypto_worker_ctx {
    struct forwarder *fwd;
    int worker_idx;
    uint8_t cpu_id;
};

static void crypto_worker_tick(struct forwarder *fwd, int is_primary)
{
    if (!is_primary)
        return;
    fwd_crypto_maybe_expire_prev_grace();
    fwd_wan_drain_tick(fwd);
    fwd_wan_weight_blend_tick();
    fwd_crypto_cleanup_stale_profile_slots(fwd->cfg);
}

static void *crypto_worker_thread(void *arg)
{
    struct crypto_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    uint32_t maint_tick = 0;
    int is_primary = (ctx->worker_idx == 0);

    pin_cpu(ctx->cpu_id);
    dp_crypto_worker_bind(ctx->worker_idx);
    crypto_layer2_bind_worker_core(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (is_primary) {
            if (pthread_mutex_trylock(&runtime_lock) != 0) {
                if (!atomic_load_explicit(&running, memory_order_acquire))
                    break;
                if (ne_ring_try_pop(&fwd->wan_to_mid[ctx->worker_idx], &job) == 0) {
                    dataplane_process_wan(fwd, job);
                    did_work = 1;
                }
                if (ne_ring_try_pop(&fwd->local_to_mid[ctx->worker_idx], &job) == 0) {
                    dataplane_process_local(fwd, job);
                    did_work = 1;
                }
                if (!did_work)
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
            if ((++maint_tick & 1023u) == 0)
                crypto_worker_tick(fwd, 1);
        }

        if (ne_ring_try_pop(&fwd->wan_to_mid[ctx->worker_idx], &job) == 0) {
            dataplane_process_wan(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid[ctx->worker_idx], &job) == 0) {
            dataplane_process_local(fwd, job);
            did_work = 1;
        }
        if (++gc_tick >= 2048) {
            fwd_crypto_frag_gc_worker_tick(ctx->worker_idx);
            gc_tick = 0;
        }
        if (is_primary)
            pthread_mutex_unlock(&runtime_lock);

        if (!did_work)
            sched_yield();
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
    // #region agent log
    for (int wi = 0; wi < fwd->wan_count; wi++) {
        io_dbg_log("A", "forwarder.c:forwarder_init", "wan_queue_count",
                   ne_pool_free_count(&fwd->pair), 0, 0, 0, 0,
                   fwd->pair.wans[wi].queue_count, 0);
    }
    // #endregion
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (ne_ring_init(&fwd->local_to_mid[w], NE_RING) != 0 ||
            ne_ring_init(&fwd->wan_to_mid[w], NE_RING) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->local_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->mid_to_local[i][w], NE_RING) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->mid_to_wan[i][w], NE_RING) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
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
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        ne_ring_destroy(&fwd->local_to_mid[w]);
        ne_ring_destroy(&fwd->wan_to_mid[w]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            ne_ring_destroy(&fwd->mid_to_wan[i][w]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            ne_ring_destroy(&fwd->mid_to_local[i][w]);
    }
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
}

static void forwarder_join_started(struct forwarder *fwd, int local_rx_started, int local_tx_started,
                                   int crypto_started, int wan_tx_started, int wan_rx_started)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    for (int w = 0; w < local_rx_started; w++)
        pthread_join(fwd->local_rx_threads[w], NULL);
    for (int w = 0; w < local_tx_started; w++)
        pthread_join(fwd->local_tx_threads[w], NULL);
    for (int w = 0; w < crypto_started; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    for (int w = 0; w < wan_tx_started; w++)
        pthread_join(fwd->wan_tx_threads[w], NULL);
    for (int w = 0; w < wan_rx_started; w++)
        pthread_join(fwd->wan_rx_threads[w], NULL);
}

void forwarder_run(struct forwarder *fwd)
{
    struct crypto_worker_ctx crypto_ctx[NE_CRYPTO_WORKERS];
    struct io_worker_ctx local_rx_ctx[NE_CRYPTO_WORKERS];
    struct io_worker_ctx local_tx_ctx[NE_CRYPTO_WORKERS];
    struct io_worker_ctx wan_rx_ctx[NE_CRYPTO_WORKERS];
    struct io_worker_ctx wan_tx_ctx[NE_CRYPTO_WORKERS];
    int crypto_started = 0;
    int local_rx_started = 0, local_tx_started = 0, wan_tx_started = 0, wan_rx_started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    g_active_fwd = fwd;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        local_rx_ctx[w].fwd = fwd;
        local_rx_ctx[w].worker_idx = w;
        local_rx_ctx[w].cpu_id = local_rx_cpu(w);
        if (pthread_create(&fwd->local_rx_threads[w], NULL, local_rx_thread, &local_rx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, 0, 0, 0, 0);
            return;
        }
        local_rx_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        local_tx_ctx[w].fwd = fwd;
        local_tx_ctx[w].worker_idx = w;
        local_tx_ctx[w].cpu_id = local_tx_cpu(w);
        if (pthread_create(&fwd->local_tx_threads[w], NULL, local_tx_thread, &local_tx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, 0, 0, 0);
            return;
        }
        local_tx_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        crypto_ctx[w].fwd = fwd;
        crypto_ctx[w].worker_idx = w;
        crypto_ctx[w].cpu_id = dp_crypto_worker_cpu(w);
        if (pthread_create(&fwd->crypto_threads[w], NULL, crypto_worker_thread, &crypto_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, crypto_started, 0, 0);
            return;
        }
        crypto_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        wan_tx_ctx[w].fwd = fwd;
        wan_tx_ctx[w].worker_idx = w;
        wan_tx_ctx[w].cpu_id = wan_tx_cpu(w);
        if (pthread_create(&fwd->wan_tx_threads[w], NULL, wan_tx_thread, &wan_tx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, crypto_started,
                                   wan_tx_started, 0);
            return;
        }
        wan_tx_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        wan_rx_ctx[w].fwd = fwd;
        wan_rx_ctx[w].worker_idx = w;
        wan_rx_ctx[w].cpu_id = wan_rx_cpu(w);
        if (pthread_create(&fwd->wan_rx_threads[w], NULL, wan_rx_thread, &wan_rx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx_started, local_tx_started, crypto_started,
                                   wan_tx_started, wan_rx_started);
            return;
        }
        wan_rx_started++;
    }

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->local_rx_threads[w], NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->local_tx_threads[w], NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->wan_tx_threads[w], NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->wan_rx_threads[w], NULL);
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
