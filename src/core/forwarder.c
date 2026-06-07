#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/dataplane.h"

#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/main_diag.h"
#include "../../inc/core/interface.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
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
        ne_drain_cq_local(&fwd->pair);
        ne_refill_fq_local(&fwd->pair);
        for (int li = 0; li < fwd->local_count; li++)
            (void)ne_tx_drain_local(&fwd->pair, &fwd->mid_to_local[li], li);

        int rcvd = ne_recv_local(&fwd->pair, batch, NE_BATCH_SIZE);
        if (rcvd <= 0) {
            sched_yield();
            continue;
        }
        for (int i = 0; i < rcvd; i++) {
            if (ne_ring_try_push(&fwd->local_to_mid, &batch[i]) != 0)
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
            } else if (before > 0) {
                if (fwd->pair.wans[wi].tx_no_free != no_free_before) {
                    fprintf(stderr,
                            "[WAN-TX] %s: %u pkts queued, XDP TX ring blocked\n",
                            fwd->pair.wans[wi].ifname, before);
                    fflush(stderr);
                }
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
            dataplane_process_wan(fwd, job);
            did_work = 1;
        }
        if (ne_ring_try_pop(&fwd->local_to_mid, &job) == 0) {
            dataplane_process_local(fwd, job);
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

    /* PQC wire path uses HARDCODED_KEY in crypto_pqc_layer.h; HS optional for later. */
    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    if (ne_ring_init(&fwd->local_to_mid, NE_RING) != 0 ||
        ne_ring_init(&fwd->wan_to_mid, NE_RING) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }
    for (int i = 0; i < fwd->local_count; i++) {
        if (ne_ring_init(&fwd->mid_to_local[i], NE_RING) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        if (ne_ring_init(&fwd->mid_to_wan[i], NE_RING) != 0) {
            forwarder_cleanup(fwd);
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
    ne_ring_destroy(&fwd->local_to_mid);
    ne_ring_destroy(&fwd->wan_to_mid);
    for (int i = 0; i < MAX_INTERFACES; i++)
        ne_ring_destroy(&fwd->mid_to_wan[i]);
    for (int i = 0; i < MAX_INTERFACES; i++)
        ne_ring_destroy(&fwd->mid_to_local[i]);
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
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
