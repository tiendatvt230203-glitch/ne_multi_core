#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"
#include "crypto_route.h"
#include "flow_table.h"

struct forwarder {
    struct app_config *cfg;

    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;
    int wan_cfg_idx[MAX_INTERFACES]; /* dataplane slot -> cfg->wans[] index */

    struct ne_pair pair;
    struct ne_ring local_to_mid[NE_CRYPTO_WORKERS];
    struct ne_ring wan_to_mid[NE_CRYPTO_WORKERS];
    struct ne_ring mid_to_wan[MAX_INTERFACES][NE_CRYPTO_WORKERS];
    struct ne_ring mid_to_local[MAX_INTERFACES][NE_CRYPTO_WORKERS];

    pthread_t local_rx_threads[NE_CRYPTO_WORKERS];
    pthread_t local_tx_threads[NE_CRYPTO_WORKERS];
    pthread_t crypto_threads[NE_CRYPTO_WORKERS];
    pthread_t wan_tx_threads[NE_CRYPTO_WORKERS];
    pthread_t wan_rx_threads[NE_CRYPTO_WORKERS];
    int threads_started;

    uint64_t wan_tx_stuck[MAX_INTERFACES];
    uint32_t wan_tx_cooldown[MAX_INTERFACES];

    int io_bypass_only;
    int io_default_wan_dp;
};

static inline uint32_t fwd_mid_to_wan_depth(const struct forwarder *fwd, int wan_dp)
{
    uint32_t d = 0;
    if (!fwd || wan_dp < 0)
        return 0;
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        d += ne_ring_count(&fwd->mid_to_wan[wan_dp][w]);
    return d;
}

void forwarder_pin_cpu(void);
int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
#define FORWARDER_WAN_DRAIN_SEC 5

int forwarder_same_topology(const struct app_config *a, const struct app_config *b);
int forwarder_is_wan_only_removal(const struct app_config *old, const struct app_config *new);
int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg);
int forwarder_reload_wan_removal(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_stop(void);
void forwarder_shutdown_resources(void);
int forwarder_should_stop(void);

#endif