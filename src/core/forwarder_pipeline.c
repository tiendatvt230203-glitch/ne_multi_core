#include "../../inc/core/forwarder_pipeline.h"

#include "../../inc/core/crypto_route.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/dataplane.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"

#include "../../inc/crypto/crypto_layer2.h"

#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

extern atomic_int running;
extern pthread_mutex_t runtime_lock;

#define IO_TX_BURST_MAX   64
#define IO_FQ_TOUCH_IDLE  128u
#define WORKER_STATS_EVERY 500000u

// #region agent log
#define AGENT_LOG_PATH "/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-dfdcf7.log"

static void agent_log_worker_io(int wi, uint8_t cpu_id, uint64_t local_pkts,
                                uint64_t wan_pkts, uint64_t relay_pkts, uint64_t loops)
{
    FILE *f = fopen(AGENT_LOG_PATH, "a");

    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"H4\",\"location\":\"forwarder_pipeline.c:worker_io\","
            "\"message\":\"worker queue-slot stats\",\"data\":{\"worker\":%d,\"cpu\":%u,\"local_pkts\":%llu,"
            "\"wan_pkts\":%llu,\"relay_pkts\":%llu,\"loops\":%llu},\"timestamp\":%ld}\n",
            wi, (unsigned)cpu_id, (unsigned long long)local_pkts,
            (unsigned long long)wan_pkts, (unsigned long long)relay_pkts,
            (unsigned long long)loops, (long)(time(NULL) * 1000));
    fclose(f);
}
// #endregion

static void pin_cpu(unsigned int cpu)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

static void worker_touch_fq_slot(struct forwarder *fwd, int wi)
{
    ne_refill_fq_local_slot(&fwd->pair, wi);
    ne_refill_fq_wan_slot(&fwd->pair, wi);
}

static int worker_drain_tx(struct forwarder *fwd, int wi)
{
    int total_sent = 0;

    if (wi < 0 || wi >= (int)NE_TX_SLOTS)
        return 0;

    for (int burst = 0; burst < IO_TX_BURST_MAX; burst++) {
        int sent = 0;

        for (int li = 0; li < fwd->local_count; li++) {
            if (!ne_pair_local_live(&fwd->pair, li))
                continue;
            sent += ne_tx_drain_local(&fwd->pair, &fwd->worker_tx_local[li][wi],
                                      li, wi);
        }
        for (int di = 0; di < fwd->wan_count; di++) {
            int wan_sent;

            if (!ne_pair_wan_live(&fwd->pair, di) || fwd_wan_is_stopped(di))
                continue;
            wan_sent = ne_tx_drain_wan(&fwd->pair, &fwd->worker_tx_wan[di][wi],
                                       di, wi);
            if (wan_sent > 0)
                dp_agent_log_wan_tx(wi, di, 0, wan_sent);
            sent += wan_sent;
            if (wi == 0 && fwd_wan_tx_depth(fwd, di) == 0)
                fwd->wan_tx_stuck[di] = 0;
        }
        total_sent += sent;
        if (sent <= 0)
            break;
    }
    return total_sent;
}

static void worker_recycle_tx_slot(struct forwarder *fwd, int wi)
{
    ne_drain_cq_local(&fwd->pair, wi);
    ne_drain_cq_wan(&fwd->pair, wi);
    worker_touch_fq_slot(fwd, wi);
}

static int worker_relay_ingress(struct forwarder *fwd, int target, struct ne_packet *pkt)
{
    struct ne_packet relay = *pkt;
    const uint8_t *src;
    uint8_t *dst;

    if (target < 0 || target >= (int)NE_CRYPTO_WORKERS)
        return -1;
    if (!pkt || pkt->len == 0 || pkt->len > fwd->pair.frame_size)
        return -1;
    src = ne_packet_data(&fwd->pair, pkt->addr);
    if (!src)
        return -1;
    if (ne_frame_alloc(&fwd->pair, &relay.addr) != 0) {
        // #region agent log
        dp_agent_log_drop("H-F", "forwarder_pipeline.c:relay", "relay_alloc_fail",
                          (uint32_t)target, pkt->len, (uint16_t)pkt->dir, 0);
        // #endregion
        return -1;
    }
    dst = ne_packet_data(&fwd->pair, relay.addr);
    memcpy(dst, src, pkt->len);
    if (ne_ring_try_push(&fwd->worker_ingress[target], &relay) != 0) {
        ne_frame_free(&fwd->pair, relay.addr);
        // #region agent log
        dp_agent_log_drop("H-F", "forwarder_pipeline.c:relay", "relay_ring_full",
                          (uint32_t)target, pkt->len, (uint16_t)pkt->dir, 0);
        // #endregion
        return -1;
    }
    /* RX frame returned to pool; relay owns an independent copy. */
    ne_frame_free(&fwd->pair, pkt->addr);
    return 0;
}

static int worker_handle_local(struct forwarder *fwd, int wi, struct ne_packet *pkt)
{
    int target = dp_crypto_pick_local_worker(ne_packet_data(&fwd->pair, pkt->addr), pkt->len);

    if (target < 0 || target >= (int)NE_CRYPTO_WORKERS)
        target = wi;
    if (target == wi) {
        dataplane_process_local(fwd, *pkt);
        return 0;
    }
    if (worker_relay_ingress(fwd, target, pkt) != 0) {
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    return 1;
}

static int worker_handle_wan(struct forwarder *fwd, int wi, struct ne_packet *pkt)
{
    const uint8_t *raw = ne_packet_data(&fwd->pair, pkt->addr);
    int target = dp_crypto_pick_wan_worker(fwd, raw, pkt->len);

    if (target < 0 || target >= (int)NE_CRYPTO_WORKERS) {
        // #region agent log
        uint8_t core_id = 0;
        uint32_t eth = 0;

        if (pkt->len >= 16)
            eth = ((uint32_t)raw[12] << 24) | ((uint32_t)raw[13] << 16) |
                  ((uint32_t)raw[14] << 8) | raw[15];
        (void)crypto_layer2_read_core_id(raw, pkt->len, &core_id);
        dp_agent_log_drop("H3", "forwarder_pipeline.c:wan_target", "invalid_core_id",
                          (uint32_t)core_id, eth, (uint16_t)target, (uint16_t)wi);
        // #endregion
        if (target < 0)
            target = wi;
        else {
            ne_frame_free(&fwd->pair, pkt->addr);
            return -1;
        }
    }
    if (target == wi) {
        // #region agent log
        uint8_t core_id = 0;

        (void)crypto_layer2_read_core_id(raw, pkt->len, &core_id);
        dp_agent_log_wan_route("direct", core_id, wi, target, pkt->len);
        // #endregion
        dataplane_process_wan(fwd, *pkt);
        return 0;
    }
    // #region agent log
    {
        uint8_t core_id = 0;

        (void)crypto_layer2_read_core_id(raw, pkt->len, &core_id);
        dp_agent_log_wan_route("relay", core_id, wi, target, pkt->len);
    }
    // #endregion
    if (worker_relay_ingress(fwd, target, pkt) != 0) {
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    return 1;
}

static int worker_recv_slot(struct forwarder *fwd, int wi, uint64_t *local_pkts,
                            uint64_t *wan_pkts, uint64_t *relay_pkts)
{
    struct ne_packet batch[NE_BATCH_SIZE];
    int did_recv = 0;
    int rcvd;
    static uint32_t recv_log_budget = 8;

    rcvd = ne_recv_local_slot(&fwd->pair, batch, NE_BATCH_SIZE, wi);
    if (rcvd > 0 && recv_log_budget > 0) {
        recv_log_budget--;
        fprintf(stderr, "[PIPELINE] worker %d recv LAN batch=%d\n", wi, rcvd);
        fflush(stderr);
    }
    for (int i = 0; i < rcvd; i++) {
        int r = worker_handle_local(fwd, wi, &batch[i]);

        if (r > 0)
            (*relay_pkts)++;
        if (r == 0)
            (*local_pkts)++;
    }
    if (rcvd > 0) {
        ne_recv_release_local_slot(&fwd->pair, wi);
        did_recv = 1;
    }

    rcvd = ne_recv_wan_slot(&fwd->pair, batch, NE_BATCH_SIZE, wi);
    if (rcvd > 0 && recv_log_budget > 0) {
        recv_log_budget--;
        fprintf(stderr, "[PIPELINE] worker %d recv WAN batch=%d\n", wi, rcvd);
        fflush(stderr);
    }
    for (int i = 0; i < rcvd; i++) {
        if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
            ne_frame_free(&fwd->pair, batch[i].addr);
            continue;
        }
        // #region agent log
        {
            const uint8_t *raw = ne_packet_data(&fwd->pair, batch[i].addr);
            uint8_t core_id = 0;
            uint16_t eth_type = 0;

            if (batch[i].len >= 14)
                eth_type = ((uint16_t)raw[12] << 8) | raw[13];
            (void)crypto_layer2_read_core_id(raw, batch[i].len, &core_id);
            dp_agent_log_wan_recv(wi, (int)batch[i].wan_idx, batch[i].len, core_id, eth_type);
        }
        // #endregion
        int r = worker_handle_wan(fwd, wi, &batch[i]);

        if (r > 0)
            (*relay_pkts)++;
        if (r == 0)
            (*wan_pkts)++;
    }
    if (rcvd > 0) {
        ne_recv_release_wan_slot(&fwd->pair, wi);
        did_recv = 1;
    }

    return did_recv;
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

static void *coordinator_thread(void *arg)
{
    struct forwarder *fwd = arg;
    uint32_t maint_tick = 0;

    pin_cpu(NE_CPU_INGRESS);
    fprintf(stderr,
            "[PIPELINE] coordinator core %u: BPF redirect in kernel, reload/maint only (no AF_XDP)\n",
            NE_CPU_INGRESS);
    fflush(stderr);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        pthread_mutex_lock(&runtime_lock);
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
        pthread_mutex_unlock(&runtime_lock);
        sched_yield();
    }
    return NULL;
}

static void *pipeline_worker_thread(void *arg)
{
    struct pipeline_worker_ctx *ctx = arg;
    struct forwarder *fwd = ctx->fwd;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    uint32_t idle_ticks = 0;
    uint64_t local_pkts = 0;
    uint64_t wan_pkts = 0;
    uint64_t relay_pkts = 0;
    uint64_t loops = 0;
    int wi = ctx->worker_idx;

    pin_cpu(ctx->cpu_id);
    dp_crypto_worker_bind(wi);
    crypto_layer2_bind_worker_core(ctx->cpu_id);

    fprintf(stderr,
            "[PIPELINE] worker %d core %u: XSK queue q%%%d==%d, recv+FQ+CQ+crypto+TX\n",
            wi, ctx->cpu_id, (int)NE_TX_SLOTS, wi);
    fflush(stderr);
    worker_touch_fq_slot(fwd, wi);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;
        int did_recv = 0;
        int sent;

        if (ne_ring_try_pop(&fwd->worker_ingress[wi], &job) == 0) {
            if (job.dir == NE_DIR_WAN)
                dataplane_process_wan(fwd, job);
            else
                dataplane_process_local(fwd, job);
            did_work = 1;
        }

        did_recv = worker_recv_slot(fwd, wi, &local_pkts, &wan_pkts, &relay_pkts);
        if (did_recv) {
            did_work = 1;
            worker_touch_fq_slot(fwd, wi);
        } else if ((++idle_ticks & (IO_FQ_TOUCH_IDLE - 1)) == 0) {
            worker_touch_fq_slot(fwd, wi);
        }

        sent = worker_drain_tx(fwd, wi);
        if (sent > 0) {
            did_work = 1;
            idle_ticks = 0;
            worker_recycle_tx_slot(fwd, wi);
        }

        if (did_work)
            idle_ticks = 0;

        if (++gc_tick >= 2048) {
            fwd_crypto_frag_gc_worker_tick(wi);
            gc_tick = 0;
        }

        loops++;
        if ((loops % WORKER_STATS_EVERY) == 0)
            agent_log_worker_io(wi, ctx->cpu_id, local_pkts, wan_pkts, relay_pkts, loops);

        if (!did_work)
            sched_yield();
    }

    agent_log_worker_io(wi, ctx->cpu_id, local_pkts, wan_pkts, relay_pkts, loops);
    return NULL;
}

static void pipeline_join_started(struct forwarder *fwd, int coord_on, int workers_started)
{
    atomic_store_explicit(&running, 0, memory_order_release);
    if (coord_on)
        pthread_join(fwd->coordinator_thread, NULL);
    for (int w = 0; w < workers_started; w++)
        pthread_join(fwd->worker_threads[w], NULL);
}

void forwarder_pipeline_run(struct forwarder *fwd)
{
    struct pipeline_worker_ctx wctx[NE_CRYPTO_WORKERS];
    int coord_on = 0;
    int workers_started = 0;

    if (!fwd || forwarder_should_stop())
        return;

    fprintf(stderr,
            "[PIPELINE] core %u coordinator + %u workers on cores %u-%u (each owns XSK queue slot)\n",
            NE_CPU_INGRESS, NE_CRYPTO_WORKERS, NE_CPU_WORKER0, NE_CPU_WORKER3);
    fprintf(stderr,
            "[PIPELINE] BPF redirect: LAN/WAN L2 0x88b5 via rx_queue_index; core_id relay in userspace\n");
    fflush(stderr);

    if (pthread_create(&fwd->coordinator_thread, NULL, coordinator_thread, fwd) != 0)
        return;
    coord_on = 1;

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        wctx[w].fwd = fwd;
        wctx[w].worker_idx = w;
        wctx[w].cpu_id = dp_crypto_worker_cpu(w);
        if (pthread_create(&fwd->worker_threads[w], NULL, pipeline_worker_thread, &wctx[w]) != 0) {
            pipeline_join_started(fwd, coord_on, workers_started);
            return;
        }
        workers_started++;
    }

    fwd->threads_started = 1;
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);

    pthread_join(fwd->coordinator_thread, NULL);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        pthread_join(fwd->worker_threads[w], NULL);
    fwd->threads_started = 0;
}
