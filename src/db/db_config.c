#include "../../inc/db/db_config.h"
#include "../../inc/db/db_env.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <libpq-fe.h>
#include <strings.h>
#include <openssl/sha.h>

static int str_is_any(const char *v) {
    if (!v) return 1;
    while (*v == ' ' || *v == '\t') v++;
    return (v[0] == '\0' || strcasecmp(v, "any") == 0 || strcmp(v, "*") == 0);
}

static int parse_port_range(const char *v, int *from_out, int *to_out) {
    if (str_is_any(v)) {
        *from_out = -1;
        *to_out = -1;
        return 0;
    }
    int a = -1, b = -1;
    if (sscanf(v, "%d-%d", &a, &b) == 2 && a >= 0 && b >= a && b <= 65535) {
        *from_out = a;
        *to_out = b;
        return 0;
    }
    if (sscanf(v, "%d", &a) == 1 && a >= 0 && a <= 65535) {
        *from_out = a;
        *to_out = a;
        return 0;
    }
    return -1;
}

static int parse_ipv4_addr(const char *v, uint32_t *out_ip) {
    if (!v || !out_ip || v[0] == '\0')
        return -1;
    char buf[64];
    strncpy(buf, v, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    char *slash = strchr(buf, '/');
    if (slash)
        *slash = '\0';
    struct in_addr a;
    if (inet_pton(AF_INET, buf, &a) != 1)
        return -1;
    *out_ip = a.s_addr;
    return 0;
}

static uint8_t parse_protocol_name(const char *v) {
    if (str_is_any(v)) return POLICY_PROTO_ANY;
    if (strcasecmp(v, "tcp") == 0) return 6;
    if (strcasecmp(v, "udp") == 0) return 17;
    if (strcasecmp(v, "icmp") == 0) return 1;
    if (strcasecmp(v, "ospf") == 0) return 89;
    return (uint8_t)atoi(v);
}

#define NE_KEY_WIRE_MAP_MAX 64

struct ne_key_wire_entry {
    uint8_t key[AES_KEY_LEN];
    int key_len;
    int wire_id;
    int valid;
};

static int alloc_wire_policy_id(int db_row_id, uint8_t *used);

static int ne_wire_id_for_encrypt_key(struct ne_key_wire_entry *map, int map_sz,
                                      uint8_t *wire_used,
                                      const uint8_t *key, int key_len,
                                      int db_policy_id) {
    if (!key || key_len <= 0)
        return alloc_wire_policy_id(db_policy_id, wire_used);

    for (int i = 0; i < map_sz; i++) {
        if (!map[i].valid)
            continue;
        if (map[i].key_len == key_len && memcmp(map[i].key, key, (size_t)key_len) == 0)
            return map[i].wire_id;
    }

    int wire_id = alloc_wire_policy_id(db_policy_id, wire_used);
    if (wire_id < 0)
        return -1;

    for (int i = 0; i < map_sz; i++) {
        if (!map[i].valid) {
            map[i].valid = 1;
            map[i].wire_id = wire_id;
            map[i].key_len = key_len;
            memcpy(map[i].key, key, (size_t)key_len);
            return wire_id;
        }
    }
    return wire_id;
}

static int alloc_wire_policy_id(int db_row_id, uint8_t *used) {
    if (db_row_id >= 1 && db_row_id <= 255 && !used[(size_t)db_row_id]) {
        used[(size_t)db_row_id] = 1;
        return db_row_id;
    }
    for (int j = 1; j <= 255; j++) {
        if (!used[(size_t)j]) {
            used[(size_t)j] = 1;
            if (db_row_id < 1 || db_row_id > 255)
                fprintf(stderr,
                        "[DB CRYPTO] policy db id=%d not in wire range 1..255; assigned wire id=%d\n",
                        db_row_id, j);
            else
                fprintf(stderr,
                        "[DB CRYPTO] policy db id=%d: wire id %d already in use; assigned wire id=%d\n",
                        db_row_id, db_row_id, j);
            return j;
        }
    }
    return -1;
}

static int parse_action_name(const char *v) {
    if (!v) return POLICY_ACTION_BYPASS;
    if (strcasecmp(v, "bypass") == 0) return POLICY_ACTION_BYPASS;
    if (strcasecmp(v, "L2") == 0 || strcasecmp(v, "encrypt_l2") == 0 || strcasecmp(v, "encrypt l2") == 0)
        return POLICY_ACTION_ENCRYPT_L2;
    if (strcasecmp(v, "L3") == 0 || strcasecmp(v, "encrypt_l3") == 0 || strcasecmp(v, "encrypt l3") == 0)
        return POLICY_ACTION_ENCRYPT_L3;
    if (strcasecmp(v, "L4") == 0 || strcasecmp(v, "encrypt_l4") == 0 || strcasecmp(v, "encrypt l4") == 0)
        return POLICY_ACTION_ENCRYPT_L4;
    return atoi(v);
}

static int parse_cidr_any_or_negated(const char *v_in, int *any_out, int *neg_out,
                                     uint32_t *net_out, uint32_t *mask_out) {
    if (!any_out || !neg_out || !net_out || !mask_out)
        return -1;

    *any_out = 1;
    *neg_out = 0;
    *net_out = 0;
    *mask_out = 0;

    if (str_is_any(v_in)) {
        *any_out = 1;
        return 0;
    }

    while (*v_in == ' ' || *v_in == '\t') v_in++;
    if (v_in[0] == '!') {
        *neg_out = 1;
        v_in++;
        while (*v_in == ' ' || *v_in == '\t') v_in++;
    }

    uint32_t ip = 0, mask = 0, net = 0;
    if (parse_ip_cidr_pub(v_in, &ip, &mask, &net) != 0) {
        return -1;
    }
    *any_out = 0;
    *net_out = net;
    *mask_out = mask;
    return 0;
}

static void trim_spaces_inplace(char *s) {
    if (!s)
        return;
    size_t len = strlen(s);
    size_t start = 0;
    while (start < len && (s[start] == ' ' || s[start] == '\t'))
        start++;
    size_t end = len;
    while (end > start && (s[end - 1] == ' ' || s[end - 1] == '\t'))
        end--;
    if (start > 0 && end > start)
        memmove(s, s + start, end - start);
    if (end <= start) {
        s[0] = '\0';
        return;
    }
    s[end - start] = '\0';
}

#define MAX_CIDR_LIST_ITEMS 32
#define MAX_CIDR_ITEM_LEN 96

static int split_cidr_list(const char *input, char out[][MAX_CIDR_ITEM_LEN], int max_out) {
    if (!input || !out || max_out <= 0)
        return -1;

    char buf[1024];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';
    trim_spaces_inplace(buf);
    if (buf[0] == '\0')
        return -1;

    int count = 0;
    char *saveptr = NULL;
    for (char *tok = strtok_r(buf, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        if (count >= max_out)
            return -1;
        trim_spaces_inplace(tok);
        if (tok[0] == '\0')
            return -1;
        strncpy(out[count], tok, MAX_CIDR_ITEM_LEN - 1);
        out[count][MAX_CIDR_ITEM_LEN - 1] = '\0';
        count++;
    }
    return (count > 0) ? count : -1;
}

static int ne_fill_nullable_list(const char *joined, int pq_null,
                                 char out[][MAX_CIDR_ITEM_LEN], int max_out) {
    if (!out || max_out <= 0)
        return -1;
    if (pq_null || !joined || !joined[0]) {
        out[0][0] = '\0';
        return 1;
    }
    int n = split_cidr_list(joined, out, max_out);
    if (n < 0) {
        out[0][0] = '\0';
        return -1;
    }
    return n;
}

static int ne_parse_method(const char *v, int pq_null, int *crypto_mode_out, int *aes_bits_out) {
    if (pq_null || !v || !v[0]) {
        *crypto_mode_out = CRYPTO_MODE_GCM;
        *aes_bits_out = 128;
        return 0;
    }
    if (strcasecmp(v, "aes-gcm-128") == 0) {
        *crypto_mode_out = CRYPTO_MODE_GCM;
        *aes_bits_out = 128;
        return 0;
    }
    if (strcasecmp(v, "aes-gcm-256") == 0) {
        *crypto_mode_out = CRYPTO_MODE_GCM;
        *aes_bits_out = 256;
        return 0;
    }
    if (strcasecmp(v, "aes-ctr-128") == 0) {
        *crypto_mode_out = CRYPTO_MODE_CTR;
        *aes_bits_out = 128;
        return 0;
    }
    if (strcasecmp(v, "aes-ctr-256") == 0) {
        *crypto_mode_out = CRYPTO_MODE_CTR;
        *aes_bits_out = 256;
        return 0;
    }

    if (strcasecmp(v, "pqc-gcm") == 0) {
        *crypto_mode_out = CRYPTO_MODE_PQC;
        *aes_bits_out = 256;
        return 0;
    }
    /* BE validates method; default for unexpected values */
    *crypto_mode_out = CRYPTO_MODE_GCM;
    *aes_bits_out = 128;
    return 0;
}

static void ne_fill_policy_key(const char *enc_key, int enc_null, int key_len_bytes, uint8_t *out) {
    
    memset(out, 0, AES_KEY_LEN);
    if (enc_null || !enc_key || !enc_key[0])
        return;
    if (parse_hex_bytes_pub(enc_key, out, key_len_bytes) == 0)
        return;
    unsigned char md[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)enc_key, strlen(enc_key), md);
    memcpy(out, md, (size_t)key_len_bytes);
}

static void ne_cidr_buf_with_invert(char *buf, size_t bufsz, const char *tok, int invert_db) {
    int max_body = (int)((bufsz > 2) ? bufsz - 2 : 0);
    if (invert_db && tok[0] != '!')
        snprintf(buf, bufsz, "!%.*s", max_body, tok);
    else
        snprintf(buf, bufsz, "%.*s", (int)(bufsz - 1), tok);
}

static int find_local_index_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0) return i;
    }
    return -1;
}

static int find_wan_index_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0) return i;
    }
    return -1;
}

static void profile_append_wans_from_rows(struct app_config *cfg,
                                            struct profile_config *p,
                                            PGresult *res) {
    if (!res || PQresultStatus(res) != PGRES_TUPLES_OK)
        return;
    int ifn_col = PQfnumber(res, "ifname");
    int wcol = PQfnumber(res, "bandwidth_weight_percent");
    if (wcol < 0)
        wcol = PQfnumber(res, "weight");
    if (ifn_col < 0)
        return;
    int rows = PQntuples(res);
    for (int r = 0; r < rows && p->wan_count < MAX_PROFILE_INTERFACES; r++) {
        const char *ifname = PQgetvalue(res, r, ifn_col);
        int wi = find_wan_index_by_ifname(cfg, ifname);
        if (wi >= 0) {
            int weight = 1;
            if (wcol >= 0 && !PQgetisnull(res, r, wcol)) {
                const char *wstr = PQgetvalue(res, r, wcol);
                if (wstr && wstr[0]) {
                    int parsed = atoi(wstr);
                    if (parsed > 0)
                        weight = parsed;
                }
            }
            p->wan_indices[p->wan_count] = wi;
            p->wan_bandwidth_weight[p->wan_count] = weight;
            p->wan_count++;
        } else {
            fprintf(stderr,
                    "[DB] profile \"%s\": ne_wan.interface=%s not in merged WAN list — row skipped\n",
                    p->name, ifname);
        }
    }
}

static int load_profiles_and_policies(struct app_config *cfg, PGconn *conn, int profile_id) {
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT id, name, 1 AS enabled FROM ne_profiles WHERE id = $1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK || PQntuples(res) == 0) {
        fprintf(stderr, "[DB] ne_profiles id=%d not found\n", profile_id);
        PQclear(res);
        return -1;
    }

    int col_id = PQfnumber(res, "id");
    int col_name = PQfnumber(res, "name");
    int col_en = PQfnumber(res, "enabled");
    if (col_id < 0 || col_name < 0 || col_en < 0) {
        fprintf(stderr, "[DB] ne_profiles row missing expected columns\n");
        PQclear(res);
        return -1;
    }

    struct profile_config *p = &cfg->profiles[cfg->profile_count];
    memset(p, 0, sizeof(*p));
    p->id = atoi(PQgetvalue(res, 0, col_id));
    strncpy(p->name, PQgetvalue(res, 0, col_name), sizeof(p->name) - 1);
    p->enabled = atoi(PQgetvalue(res, 0, col_en));
    cfg->profile_count++;
    PQclear(res);

    res = PQexecParams(conn,
        "SELECT interface AS ifname FROM ne_lan WHERE profile_id = $1 ORDER BY created_at",
        1, NULL, params, NULL, NULL, 0);
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        int rows = PQntuples(res);
        for (int r = 0; r < rows && p->local_count < MAX_PROFILE_INTERFACES; r++) {
            const char *ifname = PQgetvalue(res, r, 0);
            int li = find_local_index_by_ifname(cfg, ifname);
            if (li >= 0)
                p->local_indices[p->local_count++] = li;
        }
    }
    PQclear(res);

    res = PQexecParams(conn,
        "SELECT interface AS ifname, weight AS bandwidth_weight_percent "
        "FROM ne_wan WHERE profile_id = $1 ORDER BY created_at",
        1, NULL, params, NULL, NULL, 0);
    profile_append_wans_from_rows(cfg, p, res);
    PQclear(res);

    res = PQexecParams(conn,
        "SELECT id, priority, action::text, proto::text, "
        "array_to_string(src_ip, ','), invert_src_ip, "
        "array_to_string(dst_ip, ','), invert_dst_ip, "
        "array_to_string(src_port, ','), "
        "array_to_string(dst_port, ','), "
        "method::text, encryption_key, nonce "
        "FROM ne_policies WHERE profile_id = $1 ORDER BY priority ASC, id ASC",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] ne_policies query failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }

    uint8_t wire_id_used[256];
    struct ne_key_wire_entry key_wire_map[NE_KEY_WIRE_MAP_MAX];
    memset(wire_id_used, 0, sizeof(wire_id_used));
    memset(key_wire_map, 0, sizeof(key_wire_map));
    wire_id_used[0] = 1;

    int rows = PQntuples(res);
    for (int r = 0; r < rows; r++) {
        struct crypto_policy cp_base;
        memset(&cp_base, 0, sizeof(cp_base));

        int db_policy_id = atoi(PQgetvalue(res, r, 0));
        cp_base.db_id = db_policy_id;
        cp_base.priority = atoi(PQgetvalue(res, r, 1));
        cp_base.action = parse_action_name(PQgetvalue(res, r, 2));

        int proto_null = PQgetisnull(res, r, 3);
        cp_base.protocol = parse_protocol_name(proto_null ? NULL : PQgetvalue(res, r, 3));

        const char *src_joined = PQgetvalue(res, r, 4);
        int invert_src = (strcmp(PQgetvalue(res, r, 5), "t") == 0);
        const char *dst_joined = PQgetvalue(res, r, 6);
        int invert_dst = (strcmp(PQgetvalue(res, r, 7), "t") == 0);
        const char *sport_joined = PQgetvalue(res, r, 8);
        const char *dport_joined = PQgetvalue(res, r, 9);
        int method_null = PQgetisnull(res, r, 10);
        const char *method_txt = method_null ? NULL : PQgetvalue(res, r, 10);
        int enc_null = PQgetisnull(res, r, 11);
        const char *enc_key = enc_null ? NULL : PQgetvalue(res, r, 11);
        int nonce_null = PQgetisnull(res, r, 12);
        
        if (cp_base.action == POLICY_ACTION_BYPASS) {
            cp_base.crypto_mode = CRYPTO_MODE_GCM;
            cp_base.aes_bits = 128;
            cp_base.nonce_size = 12;
            memset(cp_base.key, 0, sizeof(cp_base.key));
            cp_base.id = 0;
        } else {
            (void)ne_parse_method(method_txt, method_null, &cp_base.crypto_mode, &cp_base.aes_bits);
            if (cp_base.crypto_mode == CRYPTO_MODE_PQC) {
                cp_base.aes_bits = 256;
                cp_base.nonce_size = 12;
                
                int wire_id = ne_wire_id_for_encrypt_key(
                    key_wire_map, NE_KEY_WIRE_MAP_MAX, wire_id_used,
                    NULL, 0, db_policy_id
                );
                if (wire_id < 0) {
                    fprintf(stderr, "[DB CRYPTO] no free wire policy id (max 255 policies)\n");
                    PQclear(res);
                    return -1;
                }
                cp_base.id = wire_id;
            }
            else {
                cp_base.nonce_size = nonce_null ? 12 : atoi(PQgetvalue(res, r, 12));
                if (cp_base.aes_bits != 256)
                    cp_base.aes_bits = 128;
                if (cp_base.nonce_size <= 0)
                    cp_base.nonce_size = 12;
                int key_len = (cp_base.aes_bits == 256) ? 32 : 16;
                ne_fill_policy_key(enc_key, enc_null, key_len, cp_base.key);
                {
                    int wire_id = ne_wire_id_for_encrypt_key(key_wire_map, NE_KEY_WIRE_MAP_MAX,
                                                            wire_id_used,
                                                            cp_base.key, key_len,
                                                            db_policy_id);
                    if (wire_id < 0) {
                        fprintf(stderr, "[DB CRYPTO] no free wire policy id (max 255 policies)\n");
                        PQclear(res);
                        return -1;
                    }
                    cp_base.id = wire_id;
                }
            }
        }

        char src_items[MAX_CIDR_LIST_ITEMS][MAX_CIDR_ITEM_LEN];
        char dst_items[MAX_CIDR_LIST_ITEMS][MAX_CIDR_ITEM_LEN];
        char sp_items[MAX_CIDR_LIST_ITEMS][MAX_CIDR_ITEM_LEN];
        char dp_items[MAX_CIDR_LIST_ITEMS][MAX_CIDR_ITEM_LEN];

        int src_n = ne_fill_nullable_list(src_joined, PQgetisnull(res, r, 4), src_items, MAX_CIDR_LIST_ITEMS);
        int dst_n = ne_fill_nullable_list(dst_joined, PQgetisnull(res, r, 6), dst_items, MAX_CIDR_LIST_ITEMS);
        int sp_n = ne_fill_nullable_list(sport_joined, PQgetisnull(res, r, 8), sp_items, MAX_CIDR_LIST_ITEMS);
        int dp_n = ne_fill_nullable_list(dport_joined, PQgetisnull(res, r, 9), dp_items, MAX_CIDR_LIST_ITEMS);
        if (src_n <= 0 || dst_n <= 0 || sp_n <= 0 || dp_n <= 0) {
            fprintf(stderr, "[DB CRYPTO] policy id=%d has invalid match list\n", db_policy_id);
            PQclear(res);
            return -1;
        }

        for (int si = 0; si < src_n; si++) {
            for (int di = 0; di < dst_n; di++) {
                for (int spi = 0; spi < sp_n; spi++) {
                    for (int dpi = 0; dpi < dp_n; dpi++) {
                        if (cfg->policy_count >= MAX_CRYPTO_POLICIES || p->policy_count >= MAX_CRYPTO_POLICIES) {
                            fprintf(stderr, "[DB CRYPTO] policy expansion overflow id=%d\n", db_policy_id);
                            PQclear(res);
                            return -1;
                        }

                        struct crypto_policy *cp = &cfg->policies[cfg->policy_count];
                        *cp = cp_base;

                        if (parse_port_range(sp_items[spi], &cp->src_port_from, &cp->src_port_to) != 0) {
                            cp->src_port_from = -1;
                            cp->src_port_to = -1;
                        }
                        if (parse_port_range(dp_items[dpi], &cp->dst_port_from, &cp->dst_port_to) != 0) {
                            cp->dst_port_from = -1;
                            cp->dst_port_to = -1;
                        }

                        char src_buf[MAX_CIDR_ITEM_LEN + 2];
                        char dst_buf[MAX_CIDR_ITEM_LEN + 2];
                        ne_cidr_buf_with_invert(src_buf, sizeof(src_buf), src_items[si], invert_src);
                        ne_cidr_buf_with_invert(dst_buf, sizeof(dst_buf), dst_items[di], invert_dst);

                        if (parse_cidr_any_or_negated(src_buf, &cp->src_any, &cp->src_negate,
                                                      &cp->src_net, &cp->src_mask) != 0) {
                            cp->src_any = 1;
                            cp->src_negate = 0;
                            cp->src_net = 0;
                            cp->src_mask = 0;
                        }
                        if (parse_cidr_any_or_negated(dst_buf, &cp->dst_any, &cp->dst_negate,
                                                      &cp->dst_net, &cp->dst_mask) != 0) {
                            cp->dst_any = 1;
                            cp->dst_negate = 0;
                            cp->dst_net = 0;
                            cp->dst_mask = 0;
                        }

                        p->policy_indices[p->policy_count++] = cfg->policy_count;
                        cfg->policy_count++;
                    }
                }
            }
        }
    }
    PQclear(res);

    return 0;
}

static int load_local_rows(struct app_config *cfg, PGresult *res) {
    int nrows = PQntuples(res);
    if (nrows == 0) {
        fprintf(stderr, "[DB] No LAN (ne_lan) for this profile\n");
        return -1;
    }
    if (nrows > MAX_INTERFACES) {
        fprintf(stderr, "[DB] Too many LAN rows (%d > %d)\n", nrows, MAX_INTERFACES);
        return -1;
    }

    for (int row = 0; row < nrows; row++) {
        struct local_config *loc = &cfg->locals[cfg->local_count];
        memset(loc, 0, sizeof(*loc));

        loc->frame_size  = cfg->global_frame_size;
        loc->batch_size  = cfg->global_batch_size;
        loc->umem_mb     = DEFAULT_UMEM_MB_LOCAL;
        loc->ring_size   = DEFAULT_RING_SIZE;
        loc->queue_count = DEFAULT_QUEUE_COUNT;

        const char *v = PQgetvalue(res, row, PQfnumber(res, "ifname"));
        if (!v || v[0] == '\0') {
            fprintf(stderr, "[DB LOCAL][%d] ifname not specified\n", row);
            return -1;
        }
        strncpy(loc->ifname, v, IF_NAMESIZE - 1);
        loc->ip = 0;
        loc->netmask = 0;
        loc->network = 0;

        cfg->local_count++;
    }
    return 0;
}

static int load_wan_rows(struct app_config *cfg, PGresult *res) {
    int nrows = PQntuples(res);
    if (nrows == 0) {
        fprintf(stderr, "[DB] No WAN (ne_wan) for this profile\n");
        return -1;
    }
    if (nrows > MAX_INTERFACES) {
        fprintf(stderr, "[DB] Too many WAN rows (%d > %d)\n", nrows, MAX_INTERFACES);
        return -1;
    }

    for (int row = 0; row < nrows; row++) {
        struct wan_config *wan = &cfg->wans[cfg->wan_count];
        memset(wan, 0, sizeof(*wan));

        wan->frame_size   = cfg->global_frame_size;
        wan->batch_size   = cfg->global_batch_size;
        wan->window_size  = (uint32_t)(WAN_REORDER_WINDOW_KB * 1024U);
        wan->umem_mb      = DEFAULT_UMEM_MB_WAN;
        wan->ring_size    = DEFAULT_RING_SIZE_WAN;
        wan->queue_count  = DEFAULT_QUEUE_COUNT;

        const char *v = PQgetvalue(res, row, PQfnumber(res, "ifname"));
        if (!v || v[0] == '\0') {
            fprintf(stderr, "[DB WAN][%d] ifname not specified\n", row);
            return -1;
        }
        strncpy(wan->ifname, v, IF_NAMESIZE - 1);

        v = PQgetvalue(res, row, PQfnumber(res, "dst_ip"));
        if (v && v[0] != '\0')
            (void)parse_ipv4_addr(v, &wan->dst_ip);
        if (wan->dst_ip != 0) {
            memset(wan->src_mac, 0, MAC_LEN);
            memset(wan->dst_mac, 0, MAC_LEN);
        }

        int src_mac_col = PQfnumber(res, "src_mac");
        int dst_mac_col = PQfnumber(res, "dst_mac");
        if (src_mac_col >= 0) {
            v = PQgetvalue(res, row, src_mac_col);
            if (v && v[0] != '\0')
                (void)parse_mac(v, wan->src_mac);
        }
        if (dst_mac_col >= 0) {
            v = PQgetvalue(res, row, dst_mac_col);
            if (v && v[0] != '\0')
                (void)parse_mac(v, wan->dst_mac);
        }

        cfg->wan_count++;
    }
    return 0;
}

static int db_verify_profile_id(PGconn *conn, int profile_id) {
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT 1 FROM ne_profiles WHERE id = $1",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] ne_profiles lookup failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }
    if (PQntuples(res) == 0) {
        fprintf(stderr, "[DB] ne_profiles id=%d not found\n", profile_id);
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int db_load_lan_for_profile(PGconn *conn, struct app_config *cfg, int profile_id) {
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT interface AS ifname FROM ne_lan WHERE profile_id = $1 ORDER BY created_at",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] ne_lan query failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }

    if (load_local_rows(cfg, res) != 0) {
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int db_load_wan_for_profile(PGconn *conn, struct app_config *cfg, int profile_id) {
    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
        "SELECT interface AS ifname, dst_ip::text AS dst_ip FROM ne_wan WHERE profile_id = $1 ORDER BY created_at",
        1, NULL, params, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[DB] ne_wan query failed: %s\n", PQresultErrorMessage(res));
        PQclear(res);
        return -1;
    }

    if (load_wan_rows(cfg, res) != 0) {
        PQclear(res);
        return -1;
    }
    PQclear(res);
    return 0;
}

static int apply_crypto_derived_from_policies(struct app_config *cfg) {
    cfg->crypto_enabled = 0;
    cfg->encrypt_layer = 0;
    cfg->fake_protocol = 0;
    cfg->fake_ethertype_ipv4 = 0;
    cfg->crypto_mode = CRYPTO_MODE_CTR;
    cfg->aes_bits = 128;
    cfg->nonce_size = 12;
    memset(cfg->crypto_key, 0, sizeof(cfg->crypto_key));

    if (cfg->policy_count <= 0)
        return 0;

    int has_l2 = 0, has_l3 = 0, has_l4 = 0;
    int first_key_pi = -1;

    for (int pi = 0; pi < cfg->policy_count && pi < MAX_CRYPTO_POLICIES; pi++) {
        const struct crypto_policy *cp = &cfg->policies[pi];
        if (!cp) continue;
        if (cp->action == POLICY_ACTION_ENCRYPT_L2) has_l2 = 1;
        else if (cp->action == POLICY_ACTION_ENCRYPT_L3) has_l3 = 1;
        else if (cp->action == POLICY_ACTION_ENCRYPT_L4) has_l4 = 1;

        if (cp->action != POLICY_ACTION_BYPASS) {
            int nonzero = 0;
            for (int k = 0; k < AES_KEY_LEN; k++) {
                if (cp->key[k] != 0) { nonzero = 1; break; }
            }
            if (nonzero && first_key_pi < 0)
                first_key_pi = pi;
        }
    }

    cfg->crypto_enabled = (has_l2 || has_l3 || has_l4) ? 1 : 0;
    if (cfg->crypto_enabled) {
        if (has_l3 || has_l4) cfg->encrypt_layer = 3;
        else if (has_l2) cfg->encrypt_layer = 2;
        else cfg->encrypt_layer = 4;
    }

    if (cfg->crypto_enabled && first_key_pi >= 0) {
        const struct crypto_policy *cp = &cfg->policies[first_key_pi];
        cfg->crypto_mode = cp->crypto_mode;
        cfg->aes_bits = (cp->aes_bits == 256) ? 256 : 128;
        cfg->nonce_size = (cp->nonce_size > 0) ? cp->nonce_size : 12;
        memcpy(cfg->crypto_key, cp->key, sizeof(cfg->crypto_key));
    }

    if (has_l3 || has_l4) {
        cfg->fake_protocol = 99;
    }
    if (has_l2) {
        cfg->fake_ethertype_ipv4 = 0x88b5;
    }

    return 0;
}

static int fetch_config_from_db(struct app_config *cfg, PGconn *conn, int profile_id) {
    if (db_verify_profile_id(conn, profile_id) != 0)
        return -1;
    if (db_load_lan_for_profile(conn, cfg, profile_id) != 0)
        return -1;
    if (db_load_wan_for_profile(conn, cfg, profile_id) != 0)
        return -1;
    if (load_profiles_and_policies(cfg, conn, profile_id) != 0)
        return -1;
    return 0;
}

int config_load_from_db(struct app_config *cfg, int profile_id, const char *conn_str) {
    (void)conn_str;

    if (!cfg) {
        fprintf(stderr, "[DB] Null pointer argument (cfg)\n");
        return -1;
    }

    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    memset(cfg, 0, sizeof(*cfg));
    strncpy(cfg->bpf_file, "bpf/xdp_redirect.o", sizeof(cfg->bpf_file) - 1);
    strncpy(cfg->bpf_wan_file, "bpf/xdp_wan_redirect.o", sizeof(cfg->bpf_wan_file) - 1);
    cfg->global_frame_size = DEFAULT_FRAME_SIZE;
    cfg->global_batch_size = DEFAULT_BATCH_SIZE;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] Connection failed: %s\n", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    if (fetch_config_from_db(cfg, conn, profile_id) != 0) {
        PQfinish(conn);
        return -1;
    }

    PQfinish(conn);

    if (apply_crypto_derived_from_policies(cfg) != 0)
        return -1;

    return config_validate(cfg);
}
