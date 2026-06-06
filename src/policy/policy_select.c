#include "../../inc/policy/policy.h"

#include <stddef.h>

const struct crypto_policy *policy_select_in_profile(struct app_config *cfg,
                                                     int profile_idx,
                                                     uint32_t src_ip, uint32_t dst_ip,
                                                     uint16_t src_port, uint16_t dst_port,
                                                     uint8_t protocol)
{
    if (!cfg || profile_idx < 0 || profile_idx >= cfg->profile_count)
        return NULL;

    const struct profile_config *p = &cfg->profiles[profile_idx];
    const struct crypto_policy *best = NULL;
    int best_priority = 0x7fffffff;
    int best_id = 0x7fffffff;

    for (int i = 0; i < p->policy_count; i++) {
        int pi = p->policy_indices[i];
        if (pi < 0 || pi >= cfg->policy_count)
            continue;

        const struct crypto_policy *cp = &cfg->policies[pi];
        int matched = policy_match_packet(cp, src_ip, dst_ip, src_port, dst_port, protocol);
        if (!matched)
            matched = policy_match_packet(cp, dst_ip, src_ip, dst_port, src_port, protocol);
        if (!matched)
            continue;

        if (!best ||
            cp->priority < best_priority ||
            (cp->priority == best_priority && cp->id < best_id)) {
            best = cp;
            best_priority = cp->priority;
            best_id = cp->id;
        }
    }

    return best;
}

int policy_profile_for_local(const struct app_config *cfg, int local_idx)
{
    if (!cfg || local_idx < 0 || local_idx >= cfg->local_count)
        return -1;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++) {
            if (p->local_indices[i] == local_idx)
                return pi;
        }
    }
    return -1;
}
