#include "../../inc/db/db_runtime.h"

#include "../../inc/db/db_config.h"
#include "../../inc/db/db_env.h"

#include <libpq-fe.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

int ne_profile_id_exists(int profile_id) {
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[DB] connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char id_str[32];
    snprintf(id_str, sizeof(id_str), "%d", profile_id);
    const char *params[1] = { id_str };

    PGresult *res = PQexecParams(conn,
                                 "SELECT 1 FROM ne_profiles WHERE id = $1",
                                 1, NULL, params, NULL, NULL, 0);
    int ok = 0;
    if (PQresultStatus(res) == PGRES_TUPLES_OK && PQntuples(res) > 0)
        ok = 1;

    PQclear(res);
    PQfinish(conn);
    return ok ? 0 : -1;
}

int run_db_check(const char *const *keywords, const char *const *values, int only_id) {
    PGconn *conn = PQconnectdbParams(keywords, values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[CHECK] DB connection failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    char where_buf[64] = {0};
    if (only_id >= 0)
        snprintf(where_buf, sizeof(where_buf), "WHERE p.id = %d", only_id);

    char sql[4096];
    snprintf(sql, sizeof(sql),
             "SELECT p.id, "
             "COUNT(DISTINCT pol.id) AS policies, "
             "COUNT(DISTINCT lan.id) AS lan_rows, "
             "COUNT(DISTINCT wan.id) AS wan_rows "
             "FROM ne_profiles p "
             "LEFT JOIN ne_policies pol ON pol.profile_id = p.id "
             "LEFT JOIN ne_lan lan ON lan.profile_id = p.id "
             "LEFT JOIN ne_wan wan ON wan.profile_id = p.id "
             "%s "
             "GROUP BY p.id "
             "ORDER BY p.id;",
             where_buf);

    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] summary query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    int rows = PQntuples(res);
    if (rows == 0) {
        fprintf(stderr, "[CHECK] no ne_profiles row%s\n", (only_id >= 0) ? " for requested id" : "");
        PQclear(res);
        PQfinish(conn);
        return 1;
    }

    fprintf(stdout, "[CHECK] NE profile summary (ne_profiles / ne_lan / ne_wan / ne_policies):\n");
    for (int i = 0; i < rows; i++) {
        fprintf(stdout,
                "  profile_id=%s policies=%s lan=%s wan=%s\n",
                PQgetvalue(res, i, 0), PQgetvalue(res, i, 1), PQgetvalue(res, i, 2),
                PQgetvalue(res, i, 3));
    }
    PQclear(res);

    snprintf(sql, sizeof(sql),
             "SELECT id, COUNT(*) AS c FROM ne_policies GROUP BY id HAVING COUNT(*) > 1 ORDER BY id;");
    res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[CHECK] duplicate ne_policies.id query failed: %s", PQresultErrorMessage(res));
        PQclear(res);
        PQfinish(conn);
        return 1;
    }
    if (PQntuples(res) > 0) {
        fprintf(stdout, "[CHECK][WARN] duplicated ne_policies.id:\n");
        for (int i = 0; i < PQntuples(res); i++)
            fprintf(stdout, "  id=%s count=%s\n", PQgetvalue(res, i, 0), PQgetvalue(res, i, 1));
    } else {
        fprintf(stdout, "[CHECK] ne_policies.id uniqueness: OK\n");
    }
    PQclear(res);

    PQfinish(conn);
    return 0;
}

static int find_local_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->local_count; i++) {
        if (strcmp(cfg->locals[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int find_wan_by_ifname(const struct app_config *cfg, const char *ifname) {
    for (int i = 0; i < cfg->wan_count; i++) {
        if (strcmp(cfg->wans[i].ifname, ifname) == 0)
            return i;
    }
    return -1;
}

static int append_local_unique(struct app_config *dst, const struct local_config *src_loc) {
    int idx = find_local_by_ifname(dst, src_loc->ifname);
    if (idx >= 0)
        return idx;
    if (dst->local_count >= MAX_INTERFACES)
        return -1;
    dst->locals[dst->local_count] = *src_loc;
    return dst->local_count++;
}

static int append_wan_unique(struct app_config *dst, const struct wan_config *src_wan) {
    int idx = find_wan_by_ifname(dst, src_wan->ifname);
    if (idx >= 0)
        return idx;
    if (dst->wan_count >= MAX_INTERFACES)
        return -1;
    dst->wans[dst->wan_count] = *src_wan;
    return dst->wan_count++;
}

static void collect_used_wire_ids(const struct app_config *dst, uint8_t used[256]) {
    memset(used, 0, 256);
    for (int i = 0; i < dst->policy_count; i++) {
        int wid = dst->policies[i].id;
        if (wid >= 1 && wid <= 255)
            used[(size_t)wid] = 1;
    }
}

static int append_policy_unique(struct app_config *dst, const struct crypto_policy *src_cp) {
    if (!dst || !src_cp)
        return -1;

    if (dst->policy_count >= MAX_CRYPTO_POLICIES)
        return -1;

    struct crypto_policy cp = *src_cp;
    uint8_t used[256];
    collect_used_wire_ids(dst, used);
    int wid = cp.id;
    if (wid < 1 || wid > 255 || used[(size_t)wid]) {
        int found = -1;
        for (int j = 1; j <= 255; j++) {
            if (!used[(size_t)j]) {
                found = j;
                break;
            }
        }
        if (found < 0)
            return -1;
        cp.id = found;
    }

    dst->policies[dst->policy_count] = cp;
    return dst->policy_count++;
}

static int merge_one_config(struct app_config *dst, const struct app_config *src) {
    int local_map[MAX_INTERFACES];
    int wan_map[MAX_INTERFACES];
    int policy_map[MAX_CRYPTO_POLICIES];
    memset(local_map, -1, sizeof(local_map));
    memset(wan_map, -1, sizeof(wan_map));
    memset(policy_map, -1, sizeof(policy_map));

    for (int i = 0; i < src->local_count; i++) {
        local_map[i] = append_local_unique(dst, &src->locals[i]);
        if (local_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->wan_count; i++) {
        wan_map[i] = append_wan_unique(dst, &src->wans[i]);
        if (wan_map[i] < 0)
            return -1;
    }
    for (int i = 0; i < src->policy_count; i++) {
        policy_map[i] = append_policy_unique(dst, &src->policies[i]);
        if (policy_map[i] < 0)
            return -1;
    }

    for (int pi = 0; pi < src->profile_count; pi++) {
        if (dst->profile_count >= MAX_PROFILES)
            return -1;
        struct profile_config *dp = &dst->profiles[dst->profile_count++];
        const struct profile_config *sp = &src->profiles[pi];
        memset(dp, 0, sizeof(*dp));
        dp->id = sp->id;
        strncpy(dp->name, sp->name, sizeof(dp->name) - 1);
        dp->enabled = sp->enabled;

        for (int i = 0; i < sp->local_count; i++) {
            int sli = sp->local_indices[i];
            if (sli < 0 || sli >= src->local_count)
                continue;
            if (dp->local_count >= MAX_PROFILE_INTERFACES)
                break;
            dp->local_indices[dp->local_count++] = local_map[sli];
        }
        for (int i = 0; i < sp->wan_count; i++) {
            int swi = sp->wan_indices[i];
            if (swi < 0 || swi >= src->wan_count)
                continue;
            if (dp->wan_count >= MAX_PROFILE_INTERFACES)
                break;
            dp->wan_indices[dp->wan_count] = wan_map[swi];
            dp->wan_bandwidth_weight[dp->wan_count] = sp->wan_bandwidth_weight[i];
            dp->wan_count++;
        }
        for (int i = 0; i < sp->policy_count && i < MAX_CRYPTO_POLICIES; i++) {
            int spi = sp->policy_indices[i];
            if (spi < 0 || spi >= src->policy_count)
                continue;
            if (dp->policy_count >= MAX_CRYPTO_POLICIES)
                break;
            dp->policy_indices[dp->policy_count++] = policy_map[spi];
        }
    }
    return 0;
}

int build_merged_config(struct app_config *out_cfg, const int *ids, int id_count, const char *db_pass) {
    (void)db_pass;
    struct app_config merged;
    memset(&merged, 0, sizeof(merged));
    strncpy(merged.bpf_file, "bpf/xdp_redirect.o", sizeof(merged.bpf_file) - 1);
    strncpy(merged.bpf_wan_file, "bpf/xdp_wan_redirect.o", sizeof(merged.bpf_wan_file) - 1);
    merged.global_frame_size = DEFAULT_FRAME_SIZE;
    merged.global_batch_size = DEFAULT_BATCH_SIZE;

    for (int i = 0; i < id_count; i++) {
        struct app_config tmp;
        if (config_load_from_db(&tmp, ids[i], NULL) != 0)
            return -1;
        if (merge_one_config(&merged, &tmp) != 0)
            return -1;
    }

    merged.crypto_enabled = (merged.policy_count > 0) ? 1 : 0;
    if (merged.crypto_enabled) {
        merged.encrypt_layer = 3;
        merged.fake_protocol = 99;
        merged.fake_ethertype_ipv4 = 0x88b5;
        merged.crypto_mode = merged.policies[0].crypto_mode;
        merged.aes_bits = merged.policies[0].aes_bits;
        merged.nonce_size = merged.policies[0].nonce_size;
        memcpy(merged.crypto_key, merged.policies[0].key, sizeof(merged.crypto_key));
    }

    if (config_validate(&merged) != 0)
        return -1;
    *out_cfg = merged;
    return 0;
}
