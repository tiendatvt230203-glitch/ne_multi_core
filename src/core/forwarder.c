#include "../../inc/core/forwarder.h"
#include "../../inc/core/forwarder_wan.h"
#include "../../inc/core/forwarder_reload.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/forwarder_pipeline.h"
#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/profile_iface_xdp.h"
#include "../../inc/crypto/pqc_l2_handshake.h"

#include <net/if.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <string.h>

atomic_int running = 1;
pthread_mutex_t runtime_lock = PTHREAD_MUTEX_INITIALIZER;

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

void forwarder_pin_cpu(void)
{
    cpu_set_t cpuset;

    CPU_ZERO(&cpuset);
    CPU_SET(NE_CPU_INGRESS, &cpuset);
    (void)pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0 || config_count_dataplane_wans(cfg) <= 0)
        return -1;
    atomic_store_explicit(&running, 1, memory_order_release);
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
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
        if (ne_ring_init(&fwd->worker_ingress[w], NE_INGRESS_RING, 1) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->local_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->worker_tx_local[i][w], NE_RING, 1) != 0) {
                forwarder_cleanup(fwd);
                return -1;
            }
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            if (ne_ring_init(&fwd->worker_tx_wan[i][w], NE_RING, 1) != 0) {
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
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        ne_ring_destroy(&fwd->worker_ingress[w]);
    for (int i = 0; i < MAX_INTERFACES; i++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++) {
            ne_ring_destroy(&fwd->worker_tx_wan[i][w]);
            ne_ring_destroy(&fwd->worker_tx_local[i][w]);
        }
    }
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
}

void forwarder_run(struct forwarder *fwd)
{
    if (!fwd || forwarder_should_stop())
        return;
    forwarder_pipeline_run(fwd);
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
