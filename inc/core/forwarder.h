#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"
#include "crypto_route.h"

struct forwarder {
    struct app_config *cfg;

    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;
    int wan_cfg_idx[MAX_INTERFACES]; /* dataplane slot -> cfg->wans[] index */

    struct ne_pair pair;
    struct ne_ring local_to_mid[NE_CRYPTO_WORKERS][NE_IO_SLOTS];
    struct ne_ring wan_to_mid[NE_CRYPTO_WORKERS][NE_IO_SLOTS];
    struct ne_ring mid_to_wan[MAX_INTERFACES][NE_IO_SLOTS][NE_CRYPTO_WORKERS];
    struct ne_ring mid_to_local[MAX_INTERFACES][NE_IO_SLOTS][NE_CRYPTO_WORKERS];

    pthread_t io_shard_threads[NE_IO_SLOTS];
    pthread_t crypto_threads[NE_CRYPTO_WORKERS];
    int threads_started;

    uint64_t wan_tx_stuck[MAX_INTERFACES];
    uint32_t wan_tx_cooldown[MAX_INTERFACES];
};

static inline uint32_t fwd_mid_to_wan_depth(const struct forwarder *fwd, int wan_dp)
{
    uint32_t d = 0;
    if (!fwd || wan_dp < 0)
        return 0;
    for (int s = 0; s < (int)NE_IO_SLOTS; s++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            d += ne_ring_count(&fwd->mid_to_wan[wan_dp][s][w]);
    }
    return d;
}

void forwarder_pin_cpu(void);
int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
#define FORWARDER_WAN_DRAIN_SEC 5

void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_stop(void);
void forwarder_shutdown_resources(void);
int forwarder_should_stop(void);

#endif
