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
#include "../../inc/core/agent_debug.h"
#include "../../inc/crypto/crypto_layer2.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>

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

#define IO_BURST_ROUNDS   8
#define WAN_TX_BURST_MAX  64

static void io_burst_refill_local(struct forwarder *fwd)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_refill_fq_local(&fwd->pair);
}

static void io_burst_refill_wan(struct forwarder *fwd)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_refill_fq_wan(&fwd->pair);
}

static void io_burst_drain_cq_local(struct forwarder *fwd)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_drain_cq_local(&fwd->pair);
}

static void io_burst_drain_cq_wan(struct forwarder *fwd)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_drain_cq_wan(&fwd->pair);
}

static void io_burst_tx_wan(struct forwarder *fwd, int wan_idx)
{
    for (int burst = 0; burst < WAN_TX_BURST_MAX; burst++) {
        int sent = 0;
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            sent += ne_tx_drain_wan(&fwd->pair, &fwd->mid_to_wan[wan_idx][w], wan_idx);
        if (sent <= 0)
            break;
    }
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
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
    pin_cpu(NE_CPU_LOC);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_drain_cq_local(fwd);
        io_burst_refill_local(fwd);
        for (int li = 0; li < fwd->local_count; li++) {
            for (int burst = 0; burst < WAN_TX_BURST_MAX; burst++) {
                int sent = 0;
                for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
                    sent += ne_tx_drain_local(&fwd->pair, &fwd->mid_to_local[li][w], li);
                if (sent <= 0)
                    break;
            }
        }

        int rcvd = ne_recv_local(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            int wi = dp_crypto_pick_local_worker(ne_packet_data(&fwd->pair, batch[i].addr),
                                                 batch[i].len);
            if (ne_ring_try_push(&fwd->local_to_mid[wi], &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_local(&fwd->pair);
    }
    return NULL;
}

static void *wan_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
    pin_cpu(NE_CPU_WAN);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_drain_cq_wan(fwd);
        io_burst_refill_wan(fwd);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (fwd_wan_is_stopped(wi))
                continue;
            io_burst_tx_wan(fwd, wi);
            if (fwd_mid_to_wan_depth(fwd, wi) == 0)
                fwd->wan_tx_stuck[wi] = 0;
        }

        int rcvd = ne_recv_wan(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        for (int i = 0; i < rcvd; i++) {
            int wi;
            const uint8_t *pkt;

            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            pkt = ne_packet_data(&fwd->pair, batch[i].addr);
            wi = dp_crypto_pick_wan_worker(fwd, pkt, batch[i].len);
            if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS) {
                // #region agent log
                ne_dbg_inc("X");
                // #endregion
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            if (ne_ring_try_push(&fwd->wan_to_mid[wi], &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_wan(&fwd->pair);
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
            if (is_primary)
                ne_agent_debug_flush_tick(gc_tick);
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

void forwarder_run(struct forwarder *fwd)
{
    struct crypto_worker_ctx crypto_ctx[NE_CRYPTO_WORKERS];
    int crypto_started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    g_active_fwd = fwd;

    if (pthread_create(&fwd->local_thread, NULL, local_core_thread, fwd) != 0)
        return;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        crypto_ctx[w].fwd = fwd;
        crypto_ctx[w].worker_idx = w;
        crypto_ctx[w].cpu_id = dp_crypto_worker_cpu(w);
        if (pthread_create(&fwd->crypto_threads[w], NULL, crypto_worker_thread, &crypto_ctx[w]) != 0) {
            atomic_store_explicit(&running, 0, memory_order_release);
            pthread_join(fwd->local_thread, NULL);
            for (int j = 0; j < crypto_started; j++)
                pthread_join(fwd->crypto_threads[j], NULL);
            return;
        }
        crypto_started++;
    }

    if (pthread_create(&fwd->wan_thread, NULL, wan_core_thread, fwd) != 0) {
        atomic_store_explicit(&running, 0, memory_order_release);
        pthread_join(fwd->local_thread, NULL);
        for (int w = 0; w < crypto_started; w++)
            pthread_join(fwd->crypto_threads[w], NULL);
        return;
    }

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);
    pthread_join(fwd->local_thread, NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    pthread_join(fwd->wan_thread, NULL);
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
