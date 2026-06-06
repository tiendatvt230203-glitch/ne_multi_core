#include "../../inc/policy/policy.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stddef.h>

static uint8_t g_policy_miss_logged;

static const char *policy_action_label(int action)
{
    switch (action) {
    case POLICY_ACTION_BYPASS:      return "bypass";
    case POLICY_ACTION_ENCRYPT_L2:  return "L2";
    case POLICY_ACTION_ENCRYPT_L3:  return "L3";
    case POLICY_ACTION_ENCRYPT_L4:  return "L4";
    default:                        return "?";
    }
}

void policy_log_egress_miss(const struct app_config *cfg, int local_idx, int flow_ok,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
    char sip[INET_ADDRSTRLEN] = "non-ipv4";
    char dip[INET_ADDRSTRLEN] = "non-ipv4";
    struct in_addr addr;
    int profiles_with_local = 0;

    if (g_policy_miss_logged || !cfg)
        return;
    g_policy_miss_logged = 1;

    if (flow_ok) {
        addr.s_addr = src_ip;
        (void)inet_ntop(AF_INET, &addr, sip, sizeof(sip));
        addr.s_addr = dst_ip;
        (void)inet_ntop(AF_INET, &addr, dip, sizeof(dip));
    }

    fprintf(stderr,
            "[EGR-WAN] DROP no_policy_match: li=%d if=%s flow_ok=%d "
            "5tuple=%s:%u -> %s:%u proto=%u active_profiles=%d\n",
            local_idx,
            (local_idx >= 0 && local_idx < cfg->local_count)
                ? cfg->locals[local_idx].ifname : "?",
            flow_ok, sip, (unsigned)src_port, dip, (unsigned)dst_port,
            (unsigned)proto, cfg->profile_count);
    fflush(stderr);

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        int has_local = 0;

        if (!p->enabled)
            continue;
        for (int i = 0; i < p->local_count; i++) {
            if (p->local_indices[i] == local_idx) {
                has_local = 1;
                break;
            }
        }
        if (!has_local)
            continue;

        profiles_with_local++;
        fprintf(stderr,
                "[EGR-WAN]   profile id=%d name=%s policy_rules=%d\n",
                p->id, p->name, p->policy_count);
        fflush(stderr);

        for (int i = 0; i < p->policy_count; i++) {
            int idx = p->policy_indices[i];
            const struct crypto_policy *cp;

            if (idx < 0 || idx >= cfg->policy_count)
                continue;
            cp = &cfg->policies[idx];
            fprintf(stderr,
                    "[EGR-WAN]     rule id=%d prio=%d action=%s "
                    "src_any=%d dst_any=%d dst_port=%d..%d proto=%u "
                    "match=%d\n",
                    cp->id, cp->priority, policy_action_label(cp->action),
                    cp->src_any, cp->dst_any,
                    cp->dst_port_from, cp->dst_port_to,
                    (unsigned)cp->protocol,
                    policy_match_packet(cp,
                                        flow_ok ? src_ip : 0,
                                        flow_ok ? dst_ip : 0,
                                        flow_ok ? src_port : 0,
                                        flow_ok ? dst_port : 0,
                                        flow_ok ? proto : 0));
            fflush(stderr);
        }
    }

    if (!profiles_with_local) {
        fprintf(stderr,
                "[EGR-WAN]   no enabled profile binds li=%d — check ne_lan in DB\n",
                local_idx);
        fflush(stderr);
    }
}

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
