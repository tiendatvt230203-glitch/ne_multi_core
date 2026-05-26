#ifndef FORWARDER_H
#define FORWARDER_H

#include "interface.h"
#include "flow_table.h"

struct forwarder {
    struct app_config *cfg;

    struct xsk_interface locals[MAX_INTERFACES];
    int local_count;
    struct xsk_interface wans[MAX_INTERFACES];
    int wan_count;

    struct ne_pair pair;
    struct ne_ring local_to_mid;
    struct ne_ring wan_to_mid;
    struct ne_ring mid_to_wan[MAX_INTERFACES];
    struct ne_ring mid_to_local;
    struct flow_table wan_flow_table;
    int wan_flow_table_ready;

    pthread_t local_thread;
    pthread_t mid_thread;
    pthread_t wan_thread;
    int threads_started;

    uint64_t local_to_wan;
    uint64_t wan_to_local;
    uint64_t total_dropped;
    uint64_t dropped_bad_ip;
    uint64_t dropped_no_local_match;
    uint64_t dropped_local_tx_fail;
    uint64_t dropped_ring_full;
    uint64_t local_rx_to_mid;
    uint64_t wan_rx_to_mid;
    uint64_t dropped_no_wan;
    uint64_t dropped_wan_l2;
    uint64_t dropped_policy_not_ready;
    uint64_t dropped_encrypt_fail;
    uint64_t dropped_wan_congested;
    uint64_t local_bypass_to_wan;
    uint64_t local_encrypted_to_wan;
    uint64_t local_split_to_wan;
    uint64_t wan_tx_stuck[MAX_INTERFACES];
    uint64_t wan_tx_flushes[MAX_INTERFACES];
    uint64_t wan_tx_dropped[MAX_INTERFACES];
    uint32_t wan_tx_cooldown[MAX_INTERFACES];
};

void forwarder_pin_cpu(void);
int forwarder_init(struct forwarder *fwd, struct app_config *cfg);
int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg);
void forwarder_cleanup(struct forwarder *fwd);
void forwarder_run(struct forwarder *fwd);
void forwarder_stop(void);
int forwarder_should_stop(void);
void forwarder_print_stats(struct forwarder *fwd);

#endif
