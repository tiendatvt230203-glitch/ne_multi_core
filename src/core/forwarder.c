#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/dataplane.h"
#include "../../inc/core/crypto_route.h"

#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/cpu_map.h"
#include "../../inc/core/profile_iface_xdp.h"
#include "../../inc/crypto/pqc_l2_handshake.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>
#include <stdio.h>

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
#define IO_CQ_BURST_ROUNDS  64
#define IO_TX_BURST_MAX   64

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


static void io_burst_drain_cq(struct forwarder *fwd, int tx_slot)
{
    for (int i = 0; i < IO_CQ_BURST_ROUNDS; i++)
        ne_drain_cq_all(&fwd->pair, tx_slot);
}

static int io_burst_tx_local(struct forwarder *fwd, int local_idx, int tx_slot)
{
    struct ne_ring *rings[1] = { &fwd->mid_to_local[local_idx][tx_slot] };
    int total = 0;

    if (!ne_pair_local_live(&fwd->pair, local_idx))
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;

    for (int burst = 0; burst < IO_TX_BURST_MAX; burst++) {
        int sent = ne_tx_drain_local_all(&fwd->pair, rings, 1,
                                         local_idx, tx_slot);
        if (sent <= 0)
            break;
        total += sent;
    }
    return total;
}

static int io_burst_tx_wan(struct forwarder *fwd, int wan_idx, int tx_slot)
{
    struct ne_ring *rings[1] = { &fwd->mid_to_wan[wan_idx][tx_slot] };
    int total = 0;

    if (!ne_pair_wan_live(&fwd->pair, wan_idx))
        return 0;
    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return 0;

    for (int burst = 0; burst < IO_TX_BURST_MAX; burst++) {
        int sent = ne_tx_drain_wan_all(&fwd->pair, rings, 1,
                                       wan_idx, tx_slot);
        if (sent <= 0)
            break;
        total += sent;
    }
    return total;
}

struct io_tx_slot_ctx {
    struct forwarder *fwd;
    int tx_slot;
    uint8_t cpu_id;
};

static void *local_rx_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(NE_CPU_LOC);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_refill_local(fwd);

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

static int io_burst_tx_slot(struct forwarder *fwd, int tx_slot)
{
    int sent = 0;

    for (int wi = 0; wi < fwd->wan_count; wi++) {
        if (fwd_wan_is_stopped(wi))
            continue;
        sent += io_burst_tx_wan(fwd, wi, tx_slot);
        if (tx_slot == 0 && fwd_mid_to_wan_depth(fwd, wi) == 0)
            fwd->wan_tx_stuck[wi] = 0;
    }
    for (int li = 0; li < fwd->local_count; li++)
        sent += io_burst_tx_local(fwd, li, tx_slot);
    return sent;
}

static void *tx_thread(void *arg)
{
    struct io_tx_slot_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    int tx_slot = ctx->tx_slot;

    pin_cpu(ctx->cpu_id);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_drain_cq(fwd, tx_slot);
        if (io_burst_tx_slot(fwd, tx_slot) <= 0)
            sched_yield();
        else
            io_burst_drain_cq(fwd, tx_slot);
    }
    return NULL;
}

static void *wan_rx_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(NE_CPU_WAN);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        io_burst_refill_wan(fwd);

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
    if (ne_cpu_map_validate() != 0)
        return -1;
    ne_cpu_map_log();

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

    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        fwd->wan_cfg_idx[di] = ci;
        strncpy(fwd->wans[di].ifname, cfg->wans[ci].ifname, sizeof(fwd->wans[di].ifname) - 1);
        fwd->wans[di].ifname[sizeof(fwd->wans[di].ifname) - 1] = '\0';
        fwd->wans[di].ifindex = (int)if_nametoindex(cfg->wans[ci].ifname);
        memcpy(fwd->wans[di].src_mac, cfg->wans[ci].src_mac, MAC_LEN);
        memcpy(fwd->wans[di].dst_mac, cfg->wans[ci].dst_mac, MAC_LEN);
    }

    profile_iface_xdp_prepare_init(cfg);

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
    if (profile_iface_xdp_attach_init(&fwd->pair, cfg) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (ne_ring_init(&fwd->local_to_mid[w], NE_RING, 0) != 0 ||
            ne_ring_init(&fwd->wan_to_mid[w], NE_RING, 0) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->local_count; i++) {
        for (int t = 0; t < (int)NE_TX_SLOTS; t++) {
            if (ne_ring_init(&fwd->mid_to_local[i][t], NE_RING, 0) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int t = 0; t < (int)NE_TX_SLOTS; t++) {
            if (ne_ring_init(&fwd->mid_to_wan[i][t], NE_RING, 0) != 0) {
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
        for (int t = 0; t < (int)NE_TX_SLOTS; t++)
            ne_ring_destroy(&fwd->mid_to_wan[i][t]);
    }
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int t = 0; t < (int)NE_TX_SLOTS; t++)
            ne_ring_destroy(&fwd->mid_to_local[i][t]);
    }
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
}

static void forwarder_join_started(struct forwarder *fwd, int local_rx, int tx_started,
                                   int crypto_started, int wan_rx)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    if (local_rx)
        pthread_join(fwd->local_thread, NULL);
    for (int w = 0; w < tx_started; w++)
        pthread_join(fwd->tx_threads[w], NULL);
    for (int w = 0; w < crypto_started; w++)
        pthread_join(fwd->crypto_threads[w], NULL);
    if (wan_rx)
        pthread_join(fwd->wan_thread, NULL);
}

void forwarder_run(struct forwarder *fwd)
{
    struct crypto_worker_ctx crypto_ctx[NE_CRYPTO_WORKERS];
    struct io_tx_slot_ctx tx_ctx[NE_TX_SLOTS];
    int crypto_started = 0;
    int local_rx = 0, tx_started = 0, wan_rx = 0;

    if (!fwd || forwarder_should_stop())
        return;

    g_active_fwd = fwd;

    if (pthread_create(&fwd->local_thread, NULL, local_rx_thread, fwd) != 0)
        return;
    local_rx = 1;

    for (int w = 0; w < (int)NE_TX_SLOTS; w++) {
        tx_ctx[w].fwd = fwd;
        tx_ctx[w].tx_slot = w;
        tx_ctx[w].cpu_id = ne_cpu_tx_local[w];
        if (pthread_create(&fwd->tx_threads[w], NULL, tx_thread, &tx_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx, tx_started, 0, 0);
            return;
        }
        tx_started++;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        crypto_ctx[w].fwd = fwd;
        crypto_ctx[w].worker_idx = w;
        crypto_ctx[w].cpu_id = dp_crypto_worker_cpu(w);
        if (pthread_create(&fwd->crypto_threads[w], NULL, crypto_worker_thread, &crypto_ctx[w]) != 0) {
            forwarder_join_started(fwd, local_rx, tx_started, crypto_started, 0);
            return;
        }
        crypto_started++;
    }

    if (pthread_create(&fwd->wan_thread, NULL, wan_rx_thread, fwd) != 0) {
        forwarder_join_started(fwd, local_rx, tx_started, crypto_started, 0);
        return;
    }
    wan_rx = 1;

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);
    pthread_join(fwd->local_thread, NULL);
    for (int w = 0; w < (int)NE_TX_SLOTS; w++)
        pthread_join(fwd->tx_threads[w], NULL);
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
