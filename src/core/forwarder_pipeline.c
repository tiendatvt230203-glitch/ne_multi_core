#include "../../inc/core/forwarder_pipeline.h"

#include "../../inc/core/crypto_route.h"
#include "../../inc/core/dataplane.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/main_diag.h"

#include "../../inc/crypto/crypto_layer2.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

extern atomic_int running;
extern pthread_mutex_t runtime_lock;

#define IO_BURST_ROUNDS   8
#define IO_TX_BURST_MAX   64

static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static void io_burst_refill(struct forwarder *fwd)
{
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_refill_fq_local(&fwd->pair);
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_refill_fq_wan(&fwd->pair);
}

static void worker_drain_tx(struct forwarder *fwd, int wi)
{
    int tx_slot = wi;

    if (tx_slot < 0 || tx_slot >= (int)NE_TX_SLOTS)
        return;

    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_drain_cq_local(&fwd->pair, tx_slot);
    for (int i = 0; i < IO_BURST_ROUNDS; i++)
        ne_drain_cq_wan(&fwd->pair, tx_slot);

    for (int burst = 0; burst < IO_TX_BURST_MAX; burst++) {
        int sent = 0;

        for (int li = 0; li < fwd->local_count; li++) {
            if (!ne_pair_local_live(&fwd->pair, li))
                continue;
            sent += ne_tx_drain_local(&fwd->pair, &fwd->worker_tx_local[li][wi],
                                      li, tx_slot);
        }
        for (int di = 0; di < fwd->wan_count; di++) {
            if (!ne_pair_wan_live(&fwd->pair, di) || fwd_wan_is_stopped(di))
                continue;
            sent += ne_tx_drain_wan(&fwd->pair, &fwd->worker_tx_wan[di][wi],
                                    di, tx_slot);
            if (tx_slot == 0 && fwd_wan_tx_depth(fwd, di) == 0)
                fwd->wan_tx_stuck[di] = 0;
        }
        if (sent <= 0)
            break;
    }
}

static int ingress_dispatch_local(struct forwarder *fwd, struct ne_packet *pkt)
{
    int wi = dp_crypto_pick_local_worker(ne_packet_data(&fwd->pair, pkt->addr), pkt->len);

    if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS)
        wi = 0;
    if (ne_ring_try_push(&fwd->worker_ingress[wi], pkt) != 0)
        return -1;
    return 0;
}

static int ingress_dispatch_wan(struct forwarder *fwd, struct ne_packet *pkt)
{
    const uint8_t *raw = ne_packet_data(&fwd->pair, pkt->addr);
    int wi = dp_crypto_pick_wan_worker(fwd, raw, pkt->len);

    if (wi < 0 || wi >= (int)NE_CRYPTO_WORKERS)
        return -1;
    if (ne_ring_try_push(&fwd->worker_ingress[wi], pkt) != 0)
        return -1;
    return 0;
}

static void *ingress_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];

    pin_cpu(NE_CPU_INGRESS);
    fprintf(stderr,
            "[PIPELINE] ingress core %u: AF_XDP recv LAN+WAN, dispatch to workers 1-%u\n",
            NE_CPU_INGRESS, NE_CPU_WORKER3);
    fflush(stderr);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_recv = 0;

        io_burst_refill(fwd);

        int rcvd = ne_recv_local(&fwd->pair, batch, NE_BATCH_SIZE);
        for (int i = 0; i < rcvd; i++) {
            if (ingress_dispatch_local(fwd, &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        if (rcvd > 0) {
            ne_recv_release_local(&fwd->pair);
            did_recv = 1;
        }

        rcvd = ne_recv_wan(&fwd->pair, batch, NE_BATCH_SIZE);
        for (int i = 0; i < rcvd; i++) {
            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            if (ingress_dispatch_wan(fwd, &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        if (rcvd > 0) {
            ne_recv_release_wan(&fwd->pair);
            did_recv = 1;
        }

        if (!did_recv)
            sched_yield();
    }
    return NULL;
}

struct pipeline_worker_ctx {
    struct forwarder *fwd;
    int worker_idx;
    uint8_t cpu_id;
};

static void worker_maint_tick(struct forwarder *fwd)
{
    fwd_crypto_maybe_expire_prev_grace();
    fwd_wan_drain_tick(fwd);
    fwd_wan_weight_blend_tick();
    fwd_crypto_cleanup_stale_profile_slots(fwd->cfg);
}

static void *pipeline_worker_thread(void *arg)
{
    struct pipeline_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    uint32_t maint_tick = 0;
    int is_primary = (ctx->worker_idx == 0);

    pin_cpu(ctx->cpu_id);
    dp_crypto_worker_bind(ctx->worker_idx);
    crypto_layer2_bind_worker_core(ctx->cpu_id);

    fprintf(stderr, "[PIPELINE] worker %d core %u: ingress ring + crypto + AF_XDP TX\n",
            ctx->worker_idx, ctx->cpu_id);
    fflush(stderr);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (is_primary) {
            if (pthread_mutex_trylock(&runtime_lock) != 0) {
                if (!atomic_load_explicit(&running, memory_order_acquire))
                    break;
                if (ne_ring_try_pop(&fwd->worker_ingress[ctx->worker_idx], &job) == 0) {
                    if (job.dir == NE_DIR_WAN)
                        dataplane_process_wan(fwd, job);
                    else
                        dataplane_process_local(fwd, job);
                    did_work = 1;
                }
                worker_drain_tx(fwd, ctx->worker_idx);
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
                worker_maint_tick(fwd);
        }

        if (ne_ring_try_pop(&fwd->worker_ingress[ctx->worker_idx], &job) == 0) {
            if (job.dir == NE_DIR_WAN)
                dataplane_process_wan(fwd, job);
            else
                dataplane_process_local(fwd, job);
            did_work = 1;
        }

        worker_drain_tx(fwd, ctx->worker_idx);

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

static void pipeline_join_started(struct forwarder *fwd, int ingress_on, int workers_started)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    if (ingress_on)
        pthread_join(fwd->ingress_thread, NULL);
    for (int w = 0; w < workers_started; w++)
        pthread_join(fwd->worker_threads[w], NULL);
}

void forwarder_pipeline_run(struct forwarder *fwd)
{
    struct pipeline_worker_ctx wctx[NE_CRYPTO_WORKERS];
    int ingress_on = 0;
    int workers_started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    if (pthread_create(&fwd->ingress_thread, NULL, ingress_thread, fwd) != 0)
        return;
    ingress_on = 1;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        wctx[w].fwd = fwd;
        wctx[w].worker_idx = w;
        wctx[w].cpu_id = dp_crypto_worker_cpu(w);
        if (pthread_create(&fwd->worker_threads[w], NULL, pipeline_worker_thread, &wctx[w]) != 0) {
            pipeline_join_started(fwd, ingress_on, workers_started);
            return;
        }
        workers_started++;
    }

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);

    pthread_join(fwd->ingress_thread, NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->worker_threads[w], NULL);
    fwd->threads_started = 0;
}
