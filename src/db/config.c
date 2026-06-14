#include "../../inc/core/config.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <netinet/in.h>
int parse_mac(const char *str, uint8_t *mac) {
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x",
               &values[0], &values[1], &values[2],
               &values[3], &values[4], &values[5]) != 6) {
        return -1;
    }
    for (int i = 0; i < 6; i++) {
        mac[i] = (uint8_t)values[i];
    }
    return 0;
}

static uint32_t ipv4_prefix_to_mask_be(int prefix_len) {
    if (prefix_len <= 0)
        return 0;
    if (prefix_len >= 32)
        return htonl(0xFFFFFFFFu);
    return htonl(0xFFFFFFFFu << (32 - prefix_len));
}

static int ipv4_mask_be_is_contiguous(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    if (m == 0)
        return 1;
    uint32_t inv = ~m;
    return (inv & (inv + 1u)) == 0;
}

static int parse_ipv4_netmask_be(const char *s, uint32_t *mask_out) {
    struct in_addr a;

    if (!s || !mask_out || !s[0])
        return -1;
    if (inet_pton(AF_INET, s, &a) != 1)
        return -1;
    if (!ipv4_mask_be_is_contiguous(a.s_addr))
        return -1;
    *mask_out = a.s_addr;
    return 0;
}

static int parse_ip_cidr(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    char buf[128];
    const char *ip_part;
    const char *suffix = NULL;

    if (!str || !ip || !netmask)
        return -1;

    strncpy(buf, str, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    if (slash) {
        *slash = '\0';
        suffix = slash + 1;
        while (*suffix == ' ' || *suffix == '\t')
            suffix++;
        if (!suffix[0])
            return -1;
    }

    ip_part = buf;
    while (*ip_part == ' ' || *ip_part == '\t')
        ip_part++;

    struct in_addr addr;
    if (inet_pton(AF_INET, ip_part, &addr) != 1)
        return -1;

    *ip = addr.s_addr;

    if (suffix) {
        if (strchr(suffix, '.')) {
            if (parse_ipv4_netmask_be(suffix, netmask) != 0)
                return -1;
        } else {
            char *end = NULL;
            long plen = strtol(suffix, &end, 10);
            if (!end || *end != '\0' || plen < 0 || plen > 32)
                return -1;
            *netmask = ipv4_prefix_to_mask_be((int)plen);
        }
    } else {
        *netmask = ipv4_prefix_to_mask_be(32);
    }

    if (network)
        *network = *ip & *netmask;

    return 0;
}

static int parse_hex_bytes(const char *str, uint8_t *out, int expected_len) {
    int len = strlen(str);
    if (len != expected_len * 2)
        return -1;

    for (int i = 0; i < expected_len; i++) {
        unsigned int val;
        if (sscanf(str + i * 2, "%2x", &val) != 1)
            return -1;
        out[i] = (uint8_t)val;
    }
    return 0;
}

static int config_validate_wan_profile_exclusive(struct app_config *cfg)
{
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *pa = &cfg->profiles[pi];
        for (int wi = 0; wi < pa->wan_count; wi++) {
            int wan_idx = pa->wan_indices[wi];
            if (wan_idx < 0 || wan_idx >= cfg->wan_count)
                continue;
            if (!cfg->wans[wan_idx].dataplane)
                continue;
            for (int pj = pi + 1; pj < cfg->profile_count; pj++) {
                const struct profile_config *pb = &cfg->profiles[pj];
                for (int wj = 0; wj < pb->wan_count; wj++) {
                    if (pb->wan_indices[wj] != wan_idx)
                        continue;
                    fprintf(stderr,
                            "[VALIDATE] WAN %s dataplane already used by profile %d — "
                            "profile %d cannot add/share it\n",
                            cfg->wans[wan_idx].ifname, pa->id, pb->id);
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int config_profile_uses_policy(const struct app_config *cfg, int profile_idx,
                                      int policy_idx)
{
    if (profile_idx < 0 || profile_idx >= cfg->profile_count)
        return 0;
    const struct profile_config *p = &cfg->profiles[profile_idx];
    for (int i = 0; i < p->policy_count; i++) {
        if (p->policy_indices[i] == policy_idx)
            return 1;
    }
    return 0;
}

static void config_log_policy_profile_owners(const struct app_config *cfg, int policy_idx,
                                             const char *label)
{
    int first = 1;

    fprintf(stderr, "%s profile(s):", label);
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        if (!config_profile_uses_policy(cfg, pi, policy_idx))
            continue;
        fprintf(stderr, "%s %d", first ? "" : ",", cfg->profiles[pi].id);
        first = 0;
    }
    if (first)
        fprintf(stderr, " (none)");
    fprintf(stderr, "\n");
}

static int config_validate_policy_ids_per_profile(struct app_config *cfg)
{
    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        for (int i = 0; i < p->policy_count; i++) {
            int pai = p->policy_indices[i];
            if (pai < 0 || pai >= cfg->policy_count)
                continue;
            const struct crypto_policy *a = &cfg->policies[pai];
            for (int j = i + 1; j < p->policy_count; j++) {
                int paj = p->policy_indices[j];
                if (paj < 0 || paj >= cfg->policy_count)
                    continue;
                const struct crypto_policy *b = &cfg->policies[paj];
                if (a->db_id > 0 && a->db_id == b->db_id) {
                    fprintf(stderr,
                            "[VALIDATE] profile %d: duplicate policy db_id=%d "
                            "(pkt_tag %d vs %d in same profile)\n",
                            p->id, a->db_id, a->id, b->id);
                    return -1;
                }
                if (a->id == b->id) {
                    fprintf(stderr,
                            "[VALIDATE] profile %d: duplicate policy pkt_tag=%d "
                            "(db_id %d vs %d in same profile)\n",
                            p->id, a->id, a->db_id, b->db_id);
                    return -1;
                }
            }
        }
    }
    return 0;
}

static int config_validate_policy_ids(struct app_config *cfg)
{
    for (int i = 0; i < cfg->policy_count; i++) {
        const struct crypto_policy *a = &cfg->policies[i];
        for (int j = i + 1; j < cfg->policy_count; j++) {
            const struct crypto_policy *b = &cfg->policies[j];
            if (a->db_id > 0 && a->db_id == b->db_id) {
                fprintf(stderr,
                        "[VALIDATE] duplicate policy db_id=%d (pkt_tag %d vs %d)\n",
                        a->db_id, a->id, b->id);
                config_log_policy_profile_owners(cfg, i, "[VALIDATE] db_id owner");
                config_log_policy_profile_owners(cfg, j, "[VALIDATE] db_id conflict");
                return -1;
            }
            if (a->id == b->id) {
                fprintf(stderr,
                        "[VALIDATE] duplicate policy pkt_tag=%d (db_id %d vs %d)\n",
                        a->id, a->db_id, b->db_id);
                config_log_policy_profile_owners(cfg, i, "[VALIDATE] pkt_tag owner");
                config_log_policy_profile_owners(cfg, j, "[VALIDATE] pkt_tag conflict");
                return -1;
            }
        }
    }
    return config_validate_policy_ids_per_profile(cfg);
}

int config_validate(struct app_config *cfg) {
    if (cfg->global_frame_size == 0) {
        fprintf(stderr, "[GLOBAL] frame_size not specified\n");
        return -1;
    }

    if (cfg->global_batch_size == 0) {
        fprintf(stderr, "[GLOBAL] batch_size not specified\n");
        return -1;
    }

    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];

        if (local->ifname[0] == '\0') {
            fprintf(stderr, "LOCAL[%d]: interface not specified\n", i);
            return -1;
        }
        if (local->umem_mb == 0) {
            fprintf(stderr, "LOCAL %s: umem_mb not specified\n", local->ifname);
            return -1;
        }
        if (local->ring_size == 0) {
            fprintf(stderr, "LOCAL %s: ring_size not specified\n", local->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (local->ring_size * 2 * local->frame_size) / (1024 * 1024);
        if (local->umem_mb < min_umem_mb) {
            fprintf(stderr, "LOCAL %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    local->ifname, local->umem_mb, local->ring_size, min_umem_mb);
            return -1;
        }
        if (local->netmask == 0) {
            fprintf(stderr, "LOCAL %s: subnet not configured\n", local->ifname);
            return -1;
        }
    }

    for (int i = 0; i < cfg->local_count; i++) {
        const struct local_config *a = &cfg->locals[i];
        for (int j = i + 1; j < cfg->local_count; j++) {
            const struct local_config *b = &cfg->locals[j];
            if (a->network == b->network && a->netmask == b->netmask) {
                fprintf(stderr,
                        "LOCAL %s and %s: duplicate subnet (LAN subnets must differ)\n",
                        a->ifname, b->ifname);
                return -1;
            }
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        struct wan_config *wan = &cfg->wans[i];

        if (wan->ifname[0] == '\0') {
            fprintf(stderr, "WAN[%d]: interface not specified\n", i);
            return -1;
        }

        if (wan->umem_mb == 0) {
            fprintf(stderr, "WAN %s: umem_mb not specified\n", wan->ifname);
            return -1;
        }

        if (wan->ring_size == 0) {
            fprintf(stderr, "WAN %s: ring_size not specified\n", wan->ifname);
            return -1;
        }

        if (wan->window_size == 0) {
            fprintf(stderr, "WAN %s: window_kb not specified\n", wan->ifname);
            return -1;
        }

        uint32_t min_umem_mb = (wan->ring_size * 2 * wan->frame_size) / (1024 * 1024);
        if (wan->umem_mb < min_umem_mb) {
            fprintf(stderr, "WAN %s: umem_mb=%d too small for ring_size=%d (min: %d)\n",
                    wan->ifname, wan->umem_mb, wan->ring_size, min_umem_mb);
            return -1;
        }
    }

    if (config_validate_wan_profile_exclusive(cfg) != 0)
        return -1;
    if (config_validate_policy_ids(cfg) != 0)
        return -1;

    return 0;
}

int config_find_local_for_ip(struct app_config *cfg, uint32_t dest_ip) {
    for (int i = 0; i < cfg->local_count; i++) {
        struct local_config *local = &cfg->locals[i];
        if ((dest_ip & local->netmask) == local->network) {
            return i;
        }
    }
    return -1;
}

static int cidr_match_with_negate(int any_flag, int negate,
                                    uint32_t ip, uint32_t net, uint32_t mask) {
    if (any_flag)
        return 1;
    int in_cidr = ((ip & mask) == (net & mask));
    return negate ? !in_cidr : in_cidr;
}

int config_select_profile_for_local(const struct app_config *cfg, int local_idx) {
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

static int crypto_policy_match_packet(const struct crypto_policy *cp,
                                      uint32_t src_ip, uint32_t dst_ip,
                                      uint16_t src_port, uint16_t dst_port,
                                      uint8_t protocol) {
    if (!cidr_match_with_negate(cp->src_any, cp->src_negate, src_ip, cp->src_net, cp->src_mask))
        return 0;
    if (!cidr_match_with_negate(cp->dst_any, cp->dst_negate, dst_ip, cp->dst_net, cp->dst_mask))
        return 0;

#if !CRYPTO_POLICY_MATCH_IP_ONLY
    if (cp->src_port_from >= 0 && cp->src_port_to >= 0) {
        if ((int)src_port < cp->src_port_from || (int)src_port > cp->src_port_to)
            return 0;
    }
    if (cp->dst_port_from >= 0 && cp->dst_port_to >= 0) {
        if ((int)dst_port < cp->dst_port_from || (int)dst_port > cp->dst_port_to)
            return 0;
    }
#endif

    if (cp->protocol == POLICY_PROTO_TCP_UDP) {
        if (protocol != 6 && protocol != 17)
            return 0;
    } else if (cp->protocol != POLICY_PROTO_ANY && cp->protocol != protocol) {
        return 0;
    }

    return 1;
}

const struct crypto_policy *config_select_crypto_policy(struct app_config *cfg, int profile_idx,
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
        int matched = crypto_policy_match_packet(cp, src_ip, dst_ip, src_port, dst_port, protocol);
        if (!matched)
            matched = crypto_policy_match_packet(cp, dst_ip, src_ip, dst_port, src_port, protocol);
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

int parse_ip_cidr_pub(const char *str, uint32_t *ip, uint32_t *netmask, uint32_t *network) {
    return parse_ip_cidr(str, ip, netmask, network);
}

int parse_hex_bytes_pub(const char *str, uint8_t *out, int expected_len) {
    return parse_hex_bytes(str, out, expected_len);
}