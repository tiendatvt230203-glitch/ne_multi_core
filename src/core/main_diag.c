#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

#include "../../inc/core/config.h"

#define DIAG_TBL_N  12

static void fmt_mac(char *out, size_t outsz, const uint8_t mac[6]) {
    int zero = !(mac[0] | mac[1] | mac[2] | mac[3] | mac[4] | mac[5]);
    if (zero)
        snprintf(out, outsz, "(waiting)");
    else
        snprintf(out, outsz, "%02x:%02x:%02x:%02x:%02x:%02x",
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void tbl_hline(const int *w, int n) {
    fputc('+', stderr);
    for (int i = 0; i < n; i++) {
        for (int j = 0; j < w[i] + 2; j++)
            fputc('-', stderr);
        fputc('+', stderr);
    }
    fputc('\n', stderr);
}

static void tbl_row(const int *w, int n, const char *cols[]) {
    fputc('|', stderr);
    for (int i = 0; i < n; i++) {
        fprintf(stderr, " %-*s |", w[i], cols[i] ? cols[i] : "");
    }
    fputc('\n', stderr);
}

static const char *policy_action_name(int action) {
    switch (action) {
    case POLICY_ACTION_BYPASS: return "bypass";
    case POLICY_ACTION_ENCRYPT_L2: return "L2";
    case POLICY_ACTION_ENCRYPT_L3: return "L3";
    case POLICY_ACTION_ENCRYPT_L4: return "L4";
    default: return "?";
    }
}

static const char *policy_proto_str(uint8_t proto) {
    if (proto == POLICY_PROTO_ANY) return "any";
    if (proto == POLICY_PROTO_TCP_UDP) return "tcp/udp";
    if (proto == 6) return "tcp";
    if (proto == 17) return "udp";
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
        snprintf(out, outsz, "*");
    else if (from == to)
        snprintf(out, outsz, "%d", from);
    else
        snprintf(out, outsz, "%d-%d", from, to);
}

static void policy_cidr_field(char *out, size_t outsz, int any, int negate,
                              uint32_t net_be, uint32_t mask_be) {
    if (any) {
        snprintf(out, outsz, "*");
        return;
    }
    char cidr[48];
    ipv4_format_cidr(cidr, sizeof(cidr), net_be, mask_be);
    if (negate)
        snprintf(out, outsz, "!%s", cidr);
    else
        snprintf(out, outsz, "%s", cidr);
}

static void policy_crypto_label(const struct crypto_policy *cp, char *out, size_t outsz) {
    if (cp->action == POLICY_ACTION_BYPASS) {
        snprintf(out, outsz, "bypass");
        return;
    }
    if (cp->crypto_mode == CRYPTO_MODE_PQC) {
        snprintf(out, outsz, "pqc");
        return;
    }
    snprintf(out, outsz, "%s-%u",
             cp->crypto_mode == CRYPTO_MODE_GCM ? "gcm" : "ctr",
             (unsigned)cp->aes_bits);
}

static void print_iface_table(const struct app_config *cfg) {
    static const int w[DIAG_TBL_N] = { 14, 12, 20, 20, 0, 0, 0, 0 };
    static const char *hdr[DIAG_TBL_N] = {
        "role", "interface", "client_mac", "note", "", "", "", ""
    };

    fprintf(stderr, "\n  [interfaces]\n");
    tbl_hline(w, 4);
    tbl_row(w, 4, hdr);
    tbl_hline(w, 4);

    for (int i = 0; i < cfg->local_count; i++) {
        char client[32], c0[32], c1[32], c2[32], c3[32];
        fmt_mac(client, sizeof(client), cfg->locals[i].dst_mac);
        snprintf(c0, sizeof(c0), "lan");
        snprintf(c1, sizeof(c1), "%s", cfg->locals[i].ifname);
        snprintf(c2, sizeof(c2), "%s", client);
        snprintf(c3, sizeof(c3), "bridge FDB");
        const char *row[DIAG_TBL_N] = { c0, c1, c2, c3, "", "", "", "" };
        tbl_row(w, 4, row);
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        const struct wan_config *wan = &cfg->wans[i];
        char c0[32], c1[32], c2[32], c3[32];
        char peer[32];
        fmt_mac(peer, sizeof(peer), wan->dst_mac);
        snprintf(c0, sizeof(c0), "%s", wan->dataplane ? "wan-traffic" : "wan-handshake");
        snprintf(c1, sizeof(c1), "%s", wan->ifname);
        snprintf(c2, sizeof(c2), "%s", peer);
        snprintf(c3, sizeof(c3), "%s", wan->dataplane ? "dataplane" : "PQC only");
        const char *row[DIAG_TBL_N] = { c0, c1, c2, c3, "", "", "", "" };
        tbl_row(w, 4, row);
    }
    tbl_hline(w, 4);
}

static void print_policy_table(const struct app_config *cfg) {
    static const int w[DIAG_TBL_N] = {
        6, 5, 6, 10, 5, 8, 18, 18, 7, 7, 0, 0
    };
    static const char *hdr[DIAG_TBL_N] = {
        "db_id", "wire", "layer", "crypto", "prio", "proto",
        "src", "dst", "sport", "dport", "", ""
    };

    fprintf(stderr, "\n  [policies] count=%d\n", cfg->policy_count);
    tbl_hline(w, 10);
    tbl_row(w, 10, hdr);
    tbl_hline(w, 10);

    for (int pr = 0; pr < cfg->profile_count; pr++) {
        const struct profile_config *p = &cfg->profiles[pr];
        for (int j = 0; j < p->policy_count; j++) {
            int pix = p->policy_indices[j];
            if (pix < 0 || pix >= cfg->policy_count)
                continue;
            const struct crypto_policy *cp = &cfg->policies[pix];
            char c0[8], c1[8], c2[8], c3[12], c4[8], c5[12];
            char c6[20], c7[20], c8[12], c9[12];
            char src_c[48], dst_c[48];

            snprintf(c0, sizeof(c0), "%d", cp->db_id);
            snprintf(c1, sizeof(c1), "%d", cp->id);
            snprintf(c2, sizeof(c2), "%s", policy_action_name(cp->action));
            policy_crypto_label(cp, c3, sizeof(c3));
            snprintf(c4, sizeof(c4), "%d", cp->priority);
            snprintf(c5, sizeof(c5), "%s", policy_proto_str(cp->protocol));
            policy_cidr_field(src_c, sizeof(src_c), cp->src_any, cp->src_negate,
                              cp->src_net, cp->src_mask);
            policy_cidr_field(dst_c, sizeof(dst_c), cp->dst_any, cp->dst_negate,
                              cp->dst_net, cp->dst_mask);
            snprintf(c6, sizeof(c6), "%s", src_c);
            snprintf(c7, sizeof(c7), "%s", dst_c);
            policy_port_str(c8, sizeof(c8), cp->src_port_from, cp->src_port_to);
            policy_port_str(c9, sizeof(c9), cp->dst_port_from, cp->dst_port_to);

            const char *row[DIAG_TBL_N] = {
                c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, "", ""
            };
            tbl_row(w, 10, row);
        }
    }
    tbl_hline(w, 10);
}

void main_diag_log_config_summary(struct app_config *cfg, int trigger_profile_id,
                                  int is_reload) {
    if (!cfg)
        return;

    fprintf(stderr, "\n");
    if (is_reload) {
        fprintf(stderr, "+-- RELOAD profile %d (dataplane up, decrypt grace 3s) --+\n",
                trigger_profile_id);
    } else {
        fprintf(stderr, "+-- CONFIG profile %d --+\n", trigger_profile_id);
    }
    fprintf(stderr, "| profiles: %-3d | policies: %-3d |\n",
            cfg->profile_count, cfg->policy_count);
    print_iface_table(cfg);
    print_policy_table(cfg);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_dataplane_ready(struct app_config *cfg) {
    if (!cfg)
        return;

    fprintf(stderr, "+-- DATAPLANE ready --+\n");
    print_iface_table(cfg);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void main_diag_log_lan_client_mac(const char *ifname,
                                  const uint8_t client_mac[6],
                                  const char *event) {
    static const int w[DIAG_TBL_N] = { 12, 12, 20, 10, 0, 0, 0, 0 };
    static const char *hdr[DIAG_TBL_N] = {
        "event", "interface", "client_mac", "", "", "", "", ""
    };
    char client[32], c0[16], c1[16], c2[32];

    fmt_mac(client, sizeof(client), client_mac);
    snprintf(c0, sizeof(c0), "%s", event && event[0] ? event : "change");
    snprintf(c1, sizeof(c1), "%s", ifname ? ifname : "?");
    snprintf(c2, sizeof(c2), "%s", client);

    fprintf(stderr, "\n  [LAN-FDB]\n");
    tbl_hline(w, 3);
    tbl_row(w, 3, hdr);
    tbl_hline(w, 3);
    const char *row[DIAG_TBL_N] = { c0, c1, c2, "", "", "", "", "" };
    tbl_row(w, 3, row);
    tbl_hline(w, 3);
    fflush(stderr);
}
