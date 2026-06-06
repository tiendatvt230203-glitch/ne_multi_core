#include "../../inc/core/forwarder.h"
#include "../../inc/routing/wan_pick.h"
#include "../../inc/runtime/reload.h"
#include "../../inc/crypto/runtime.h"
#include "../../inc/pipeline/pipeline.h"

#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>

static uint8_t g_trace_lan_rx;
static uint8_t g_trace_lan_ring_full;
static uint8_t g_trace_mid_egr;
static uint8_t g_trace_wan_rx;

atomic_int running = 1;
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

static void *local_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet batch[NE_BATCH_SIZE];
    pin_cpu(NE_CPU_LOC);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        ne_drain_cq_local(&fwd->pair);
        ne_refill_fq_local(&fwd->pair);
        for (int pass = 0; pass < 4; pass++) {
            for (int li = 0; li < fwd->local_count; li++)
                (void)ne_tx_drain_local(&fwd->pair, &fwd->mid_to_local[li], li);
        }

        int rcvd = ne_recv_local(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        if (!g_trace_lan_rx) {
            g_trace_lan_rx = 1;
            fprintf(stderr,
                    "[TRACE] LAN-RX first: pkts=%d li=%u len=%u "
                    "(XDP->AF_XDP OK — packet entered local core)\n",
                    rcvd, (unsigned)batch[0].local_idx, (unsigned)batch[0].len);
            fflush(stderr);
        }

        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->local_to_mid, &batch[i]) != 0) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                if (!g_trace_lan_ring_full) {
                    g_trace_lan_ring_full = 1;
                    fprintf(stderr,
                            "[TRACE] LAN-RX DROP: local_to_mid ring full "
                            "(mid core not draining — egress never runs)\n");
                    fflush(stderr);
                }
            }
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
        ne_drain_cq_wan(&fwd->pair);
        ne_refill_fq_wan(&fwd->pair);
        for (int wi = 0; wi < fwd->wan_count; wi++) {
            if (fwd_wan_is_stopped(wi))
                continue;
            if (fwd->wan_tx_cooldown[wi] > 0)
                fwd->wan_tx_cooldown[wi]--;
            uint32_t before = ne_ring_count(&fwd->mid_to_wan[wi]);
            uint64_t no_free_before = fwd->pair.wans[wi].tx_no_free;
            int sent = ne_tx_drain_wan(&fwd->pair, &fwd->mid_to_wan[wi], wi);
            if (sent > 0) {
                fwd->wan_tx_stuck[wi] = 0;
            } else if (before > 0 && fwd->pair.wans[wi].tx_no_free != no_free_before) {
                uint64_t stuck = __sync_add_and_fetch(&fwd->wan_tx_stuck[wi], 1);
                if (before >= fwd->mid_to_wan[wi].cap && stuck >= 1024) {
                    (void)fwd_wan_flush_queue(fwd, wi);
                    fwd->wan_tx_cooldown[wi] = 65535;
                    fwd->wan_tx_stuck[wi] = 0;
                }
            }
        }

        int rcvd = ne_recv_wan(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }

        if (!g_trace_wan_rx) {
            g_trace_wan_rx = 1;
            fprintf(stderr,
                    "[TRACE] WAN-RX first: pkts=%d wi=%u len=%u\n",
                    rcvd, (unsigned)batch[0].wan_idx, (unsigned)batch[0].len);
            fflush(stderr);
        }

        for (int i = 0; i < rcvd; i++) {
            if (batch[i].wan_idx < MAX_INTERFACES && fwd_wan_is_stopped(batch[i].wan_idx)) {
                ne_frame_free(&fwd->pair, batch[i].addr);
                continue;
            }
            if (ne_ring_try_push(&fwd->wan_to_mid, &batch[i]) != 0)
                ne_frame_free(&fwd->pair, batch[i].addr);
        }
        ne_recv_release_wan(&fwd->pair);
    }
    return NULL;
}

static void *middle_core_thread(void *arg)
{
    struct forwarder *fwd = arg;
    struct ne_packet job;
    uint32_t gc_tick = 0;
    pin_cpu(NE_CPU_MID);

    while (atomic_load_explicit(&running, memory_order_acquire)) {
        int did_work = 0;

        if (pthread_mutex_trylock(&runtime_lock) != 0) {
            if (!atomic_load_explicit(&running, memory_order_acquire))
                break;
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
        if (ne_ring_try_pop(&fwd->wan_to_mid, &job) == 0) {
            pipeline_ingress(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid, &job) == 0) {
            if (!g_trace_mid_egr) {
                g_trace_mid_egr = 1;
                fprintf(stderr,
                        "[TRACE] MID->egress first: li=%u len=%u "
                        "(packet reached egress — expect [EGR-WAN] next)\n",
                        (unsigned)job.local_idx, (unsigned)job.len);
                fflush(stderr);
            }
            pipeline_egress(fwd, job);
            did_work = 1;
        }
        if (++gc_tick >= 8192) {
            fwd_crypto_frag_gc_tick();
            gc_tick = 0;
        }
        pthread_mutex_unlock(&runtime_lock);

        if (!did_work)
            sched_yield();
    }
    return NULL;
}

void forwarder_run(struct forwarder *fwd)
{
    if (!fwd || forwarder_should_stop())
        return;

    g_active_fwd = fwd;

    if (pthread_create(&fwd->local_thread, NULL, local_core_thread, fwd) != 0)
        return;
    if (pthread_create(&fwd->mid_thread, NULL, middle_core_thread, fwd) != 0) {
        atomic_store_explicit(&running, 0, memory_order_release);
        pthread_join(fwd->local_thread, NULL);
        return;
    }
    if (pthread_create(&fwd->wan_thread, NULL, wan_core_thread, fwd) != 0) {
        atomic_store_explicit(&running, 0, memory_order_release);
        pthread_join(fwd->local_thread, NULL);
        pthread_join(fwd->mid_thread, NULL);
        return;
    }

    fwd->threads_started = 1;
    fprintf(stderr,
            "[TRACE] dataplane trace ON — watch [TRACE] LAN-RX / MID->egress / [EGR-WAN]\n");
    fflush(stderr);
    if (fwd->cfg)
        main_diag_log_dataplane_ready(fwd->cfg);
    pthread_join(fwd->local_thread, NULL);
    pthread_join(fwd->mid_thread, NULL);
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
