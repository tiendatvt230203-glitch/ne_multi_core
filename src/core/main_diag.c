#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../../inc/core/config.h"

static const char *policy_action_name(int action) {
    switch (action) {
    case POLICY_ACTION_BYPASS:
        return "bypass";
    case POLICY_ACTION_ENCRYPT_L2:
        return "L2";
    case POLICY_ACTION_ENCRYPT_L3:
        return "L3";
    case POLICY_ACTION_ENCRYPT_L4:
        return "L4";
    default:
        return "?";
    }
}

static const char *policy_proto_str(uint8_t proto) {
    if (proto == POLICY_PROTO_ANY)
        return "any";
    if (proto == 6)
        return "tcp";
    if (proto == 17)
        return "udp";
    if (proto == 1)
        return "icmp";
    static char buf[16];
    snprintf(buf, sizeof(buf), "proto%u", (unsigned)proto);
    return buf;
}

static const char *crypto_mode_str(int mode) {
    if (mode == CRYPTO_MODE_GCM) {
        return "gcm";
    }
    if (mode == CRYPTO_MODE_CTR) {
        return "ctr";
    }
    if (mode == CRYPTO_MODE_PQC) {
        return "pqc-gcm";
    }
    return "?";
}

static int ipv4_netmask_to_prefix(uint32_t mask_be) {
    uint32_t m = ntohl(mask_be);
    int p = 0;
    while (m & 0x80000000U) {
        p++;
        m <<= 1;
    }
    return p;
}

static void ipv4_format_cidr(char *out, size_t outsz, uint32_t net_be, uint32_t mask_be) {
    char ip[INET_ADDRSTRLEN];
    struct in_addr a = { .s_addr = net_be };
    if (!inet_ntop(AF_INET, &a, ip, sizeof(ip)))
        snprintf(out, outsz, "?");
    else
        snprintf(out, outsz, "%s/%d", ip, ipv4_netmask_to_prefix(mask_be));
}

static void policy_port_str(char *out, size_t outsz, int from, int to) {
    if (from < 0 || to < 0)
        snprintf(out, outsz, "any");
    else if (from == to)
        snprintf(out, outsz, "%d", from);
    else
        snprintf(out, outsz, "%d-%d", from, to);
}

static void policy_cidr_field(char *out, size_t outsz, int any, int negate,
                              uint32_t net_be, uint32_t mask_be) {
    if (any) {
        snprintf(out, outsz, "any");
        return;
    }
    char cidr[48];
    ipv4_format_cidr(cidr, sizeof(cidr), net_be, mask_be);
    if (negate)
        snprintf(out, outsz, "!%s", cidr);
    else
        snprintf(out, outsz, "%s", cidr);
}

static void fmt_mac(char *out, size_t outsz, const uint8_t mac[MAC_LEN]) {
    int zero = !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
    if (zero)
        snprintf(out, outsz, "(none)");
    else
        snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void log_interface_names(const struct app_config *cfg) {
    fprintf(stderr, "[WAN] ");
    for (int i = 0; i < cfg->wan_count; i++)
        fprintf(stderr, "%s%s", i ? ", " : "", cfg->wans[i].ifname);
    fprintf(stderr, "\n");

    fprintf(stderr, "[LAN] ");
    for (int i = 0; i < cfg->local_count; i++)
        fprintf(stderr, "%s%s", i ? ", " : "", cfg->locals[i].ifname);
    fprintf(stderr, "\n");
}

static void log_wan_dst_macs(const struct app_config *cfg) {
    for (int i = 0; i < cfg->wan_count; i++) {
        const struct wan_config *w = &cfg->wans[i];
        char dst_mac[32];
        fmt_mac(dst_mac, sizeof(dst_mac), w->dst_mac);
        fprintf(stderr, "[WAN] %s dst_mac=%s\n", w->ifname, dst_mac);
    }
}

static void log_local_dst_macs(const struct app_config *cfg) {
    for (int i = 0; i < cfg->local_count; i++) {
        const struct local_config *l = &cfg->locals[i];
        char dst_mac[32];
        fmt_mac(dst_mac, sizeof(dst_mac), l->dst_mac);
        fprintf(stderr, "[LAN] %s dst_mac=%s\n", l->ifname, dst_mac);
    }
}

static void log_profile_policies(const struct app_config *cfg) {
    for (int pr = 0; pr < cfg->profile_count; pr++) {
        const struct profile_config *p = &cfg->profiles[pr];
        fprintf(stderr, "[PROFILE] id=%d name=\"%s\"\n", p->id, p->name);

        for (int j = 0; j < p->policy_count; j++) {
            int pix = p->policy_indices[j];
            if (pix < 0 || pix >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pix];
            char src_c[72], dst_c[72], sp[24], dp[24];
            policy_cidr_field(src_c, sizeof(src_c), cp->src_any, cp->src_negate,
                              cp->src_net, cp->src_mask);
            policy_cidr_field(dst_c, sizeof(dst_c), cp->dst_any, cp->dst_negate,
                              cp->dst_net, cp->dst_mask);
            policy_port_str(sp, sizeof(sp), cp->src_port_from, cp->src_port_to);
            policy_port_str(dp, sizeof(dp), cp->dst_port_from, cp->dst_port_to);

            if (cp->action == POLICY_ACTION_BYPASS) {
                fprintf(stderr,
                        "  policy db_id=%d prio=%d bypass  %s  src=%s dst=%s  sport=%s dport=%s\n",
                        cp->db_id,
                        cp->priority,
                        policy_proto_str(cp->protocol),
                        src_c,
                        dst_c,
                        sp,
                        dp);
                continue;
            }
            if (cp->crypto_mode == CRYPTO_MODE_PQC) {
                fprintf(stderr,
                        "  policy db_id=%d wire_id=%d prio=%d %s  %s\n"
                        "    match: %s  src=%s dst=%s  sport=%s dport=%s\n",
                        cp->db_id, cp->id, cp->priority,
                        policy_action_name(cp->action),
                        crypto_mode_str(cp->crypto_mode),
                        policy_proto_str(cp->protocol), src_c, dst_c, sp, dp);
            }
            else {
                    fprintf(stderr,  
                    "  policy db_id=%d wire_id=%d prio=%d %s  %s-%u nonce=%d\n"
                    "    match: %s  src=%s dst=%s  sport=%s dport=%s\n",
                    cp->db_id,
                    cp->id,
                    cp->priority,
                    policy_action_name(cp->action),
                    crypto_mode_str(cp->crypto_mode),
                    (unsigned)cp->aes_bits,
                    cp->nonce_size,
                    policy_proto_str(cp->protocol),
                    src_c,
                    dst_c,
                    sp,
                    dp);
            }
        }
    }
}

void main_diag_log_loaded_config(struct app_config *cfg, int config_id) {
    (void)config_id;
    if (!cfg)
        return;
    log_interface_names(cfg);
    log_profile_policies(cfg);
}

void main_diag_log_link_macs(struct app_config *cfg) {
    if (!cfg)
        return;
    log_wan_dst_macs(cfg);
    log_local_dst_macs(cfg);
}
