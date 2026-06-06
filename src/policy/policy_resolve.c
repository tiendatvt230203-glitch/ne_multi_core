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

        c = flow_ok
            ? policy_select_in_profile((struct app_config *)cfg, pi,
                                       src_ip, dst_ip, src_port, dst_port, proto)
            : NULL;
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
