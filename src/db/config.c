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

static void format_profiles_for_policy(const struct app_config *cfg, int policy_idx,
                                       char *buf, size_t buflen)
{
    size_t pos = 0;

    if (!buf || buflen == 0)
        return;
    buf[0] = '\0';
    if (!cfg || policy_idx < 0 || policy_idx >= cfg->policy_count)
        return;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        for (int k = 0; k < p->policy_count; k++) {
            if (p->policy_indices[k] != policy_idx)
                continue;
            int n = snprintf(buf + pos, buflen - pos, "%s%d(%s)",
                               pos ? ", " : "", p->id, p->name);
            if (n < 0 || (size_t)n >= buflen - pos)
                return;
            pos += (size_t)n;
        }
    }
}

static int config_validate_wan_profile_exclusivity(struct app_config *cfg) {
    struct wan_owner_entry {
        char ifname[IF_NAMESIZE];
        int profile_id;
        char profile_name[64];
    } owners[MAX_INTERFACES];
    int owner_count = 0;

    for (int pi = 0; pi < cfg->profile_count; pi++) {
        const struct profile_config *p = &cfg->profiles[pi];
        for (int wi = 0; wi < p->wan_count; wi++) {
            int widx = p->wan_indices[wi];
            const struct wan_config *wan;
            int found = -1;

            if (widx < 0 || widx >= cfg->wan_count)
                continue;
            wan = &cfg->wans[widx];
            if (!wan->dataplane)
                continue;

            for (int oi = 0; oi < owner_count; oi++) {
                if (strcmp(owners[oi].ifname, wan->ifname) == 0) {
                    found = oi;
                    break;
                }
            }

            if (found >= 0) {
                if (owners[found].profile_id != p->id) {
                    fprintf(stderr,
                            "[CONFIG][VALIDATE] WAN dataplane %s conflict: profile %d (%s) vs profile %d (%s)\n",
                            wan->ifname,
                            owners[found].profile_id, owners[found].profile_name,
                            p->id, p->name);
                    return -1;
                }
                continue;
            }

            if (owner_count >= MAX_INTERFACES) {
                fprintf(stderr, "[CONFIG][VALIDATE] WAN owner table full\n");
                return -1;
            }
            strncpy(owners[owner_count].ifname, wan->ifname, sizeof(owners[owner_count].ifname) - 1);
            owners[owner_count].profile_id = p->id;
            strncpy(owners[owner_count].profile_name, p->name,
                    sizeof(owners[owner_count].profile_name) - 1);
            owner_count++;
        }
    }

    fprintf(stderr, "[CONFIG][VALIDATE] WAN dataplane exclusivity OK (%d ifname(s), %d profile(s))\n",
            owner_count, cfg->profile_count);
    return 0;
}

static int config_validate_policy_id_uniqueness(struct app_config *cfg) {
    for (int i = 0; i < cfg->policy_count; i++) {
        for (int j = i + 1; j < cfg->policy_count; j++) {
            const struct crypto_policy *a = &cfg->policies[i];
            const struct crypto_policy *b = &cfg->policies[j];
            char prof_a[160];
            char prof_b[160];

            if (a->db_id > 0 && a->db_id == b->db_id) {
                format_profiles_for_policy(cfg, i, prof_a, sizeof(prof_a));
                format_profiles_for_policy(cfg, j, prof_b, sizeof(prof_b));
                fprintf(stderr,
                        "[CONFIG][VALIDATE] policy db_id=%d duplicated: "
                        "slot[%d] wire=%d profiles{%s} vs slot[%d] wire=%d profiles{%s}\n",
                        a->db_id, i, a->id, prof_a, j, b->id, prof_b);
                return -1;
            }
            if (a->id == b->id) {
                format_profiles_for_policy(cfg, i, prof_a, sizeof(prof_a));
                format_profiles_for_policy(cfg, j, prof_b, sizeof(prof_b));
                fprintf(stderr,
                        "[CONFIG][VALIDATE] policy wire id=%d duplicated: "
                        "slot[%d] db_id=%d profiles{%s} vs slot[%d] db_id=%d profiles{%s}\n",
                        a->id, i, a->db_id, prof_a, j, b->db_id, prof_b);
                return -1;
            }
        }
    }

    fprintf(stderr, "[CONFIG][VALIDATE] policy id uniqueness OK (%d policy row(s))\n",
            cfg->policy_count);
    return 0;
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

    if (config_validate_wan_profile_exclusivity(cfg) != 0)
        return -1;

    if (config_validate_policy_id_uniqueness(cfg) != 0)
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

static uint32_t flow_hash_u32(uint32_t src_ip, uint32_t dst_ip,
                              uint16_t src_port, uint16_t dst_port, uint8_t protocol) {
    uint32_t h = src_ip ^ dst_ip ^ ((uint32_t)src_port << 16) ^ dst_port ^ protocol;
    h ^= h >> 16;
    h *= 0x7feb352dU;
    h ^= h >> 15;
    h *= 0x846ca68bU;
    h ^= h >> 16;
    return h;
}

int config_select_wan_for_profile(struct app_config *cfg, int profile_idx,
                                  uint32_t src_ip, uint32_t dst_ip,
                                  uint16_t src_port, uint16_t dst_port,
                                  uint8_t protocol) {
    if (!cfg)
        return -1;
    if (profile_idx < 0 || profile_idx >= cfg->profile_count)
        return -1;

    struct profile_config *p = &cfg->profiles[profile_idx];
    if (p->wan_count <= 0)
        return -1;

    uint32_t h = flow_hash_u32(src_ip, dst_ip, src_port, dst_port, protocol);

    int sumw = 0;
    for (int i = 0; i < p->wan_count; i++) {
        int w = p->wan_bandwidth_weight[i];
        if (w > 0)
            sumw += w;
    }

    if (sumw <= 0) {
        int slot = (int)(h % (uint32_t)p->wan_count);
        int wan_idx = p->wan_indices[slot];
        if (wan_idx < 0 || wan_idx >= cfg->wan_count)
            return -1;
        return wan_idx;
    }

    uint32_t r = h % (uint32_t)sumw;
    int acc = 0;
    for (int i = 0; i < p->wan_count; i++) {
        int w = p->wan_bandwidth_weight[i];
        if (w <= 0)
            continue;
        acc += w;
        if (r < (uint32_t)acc) {
            int wan_idx = p->wan_indices[i];
            if (wan_idx < 0 || wan_idx >= cfg->wan_count)
                return -1;
            return wan_idx;
        }
    }

    int wan_idx = p->wan_indices[p->wan_count - 1];
    if (wan_idx < 0 || wan_idx >= cfg->wan_count)
        return -1;
    return wan_idx;
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