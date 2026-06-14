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
    pthread_t worker_threads[NE_CRYPTO_WORKERS];
    int threads_started;
};

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
