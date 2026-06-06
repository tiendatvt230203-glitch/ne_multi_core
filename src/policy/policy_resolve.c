#include "../../inc/policy/policy.h"

#include <stddef.h>

int policy_resolve_egress(const struct app_config *cfg, int local_idx, int flow_ok,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port, uint8_t proto,
                          int *profile_idx, const struct crypto_policy **cp)
{
    const struct crypto_policy *best = NULL;
    int best_pi = -1;
    int best_pri = 0x7fffffff;
    int best_id = 0x7fffffff;

    if (!cfg || !profile_idx || !cp)
        return -1;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        int found = 0;
        const struct crypto_policy *c;

        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++) {
            if (p->local_indices[i] == local_idx)
                found = 1;
        }
        if (!found)
            continue;

        /*
         * flow_ok=0: still run policy select with zero flow fields so catch-all
         * bypass (src_any/dst_any) matches — required for L2 wire non-IPv4.
         */
        c = policy_select_in_profile((struct app_config *)cfg, pi,
                                     flow_ok ? src_ip : 0,
                                     flow_ok ? dst_ip : 0,
                                     flow_ok ? src_port : 0,
                                     flow_ok ? dst_port : 0,
                                     flow_ok ? proto : 0);
        if (!c)
            continue;

        if (!best || c->priority < best_pri || (c->priority == best_pri && c->id < best_id)) {
            best = c;
            best_pi = pi;
            best_pri = c->priority;
            best_id = c->id;
        }
    }

    if (!best)
        return -1;

    *profile_idx = best_pi;
    *cp = best;
    return 0;
}
