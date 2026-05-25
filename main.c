#include <bpf/libbpf.h>
#include <libpq-fe.h>
#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <sys/select.h>
#include <unistd.h>
#include <pthread.h>

#include "config.h"
#include "db_env.h"
#include "db_runtime.h"
#include "forwarder.h"
#include "interface.h"
#include "main_diag.h"

#define NOTIFY_CHANNEL "xdp_start"
#define MAX_ACTIVE_PROFILE_IDS 32

static volatile sig_atomic_t g_stop_requested = 0;
static volatile sig_atomic_t g_stop_logged = 0;

static void on_stop_signal(int sig) {
    (void)sig;
    g_stop_requested = 1;
    forwarder_stop();
    if (!g_stop_logged) {
        g_stop_logged = 1;
        fprintf(stderr, "\n[STOP] shutting down (Ctrl+C / SIGTERM)\n");
    }
}

static int parse_notify_profile_id(const char *payload) {
    if (!payload || !*payload)
        return -1;
    char *end = NULL;
    long v = strtol(payload, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;
    return (int)v;
}

struct runtime_state {
    pthread_t thread;
    int has_thread;
    int running;
    struct forwarder fwd;
    struct app_config cfg_slots[2];
    int active_slot;
};

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage:\n"
            "  %s                    daemon, wait NOTIFY xdp_start\n"
            "  %s -id <profile_id>   notify daemon (load / unload / no-op)\n",
            prog, prog);
}

static int parse_profile_id_token(const char *token, int *out_id) {
    if (!token || !*token)
        return -1;
    char *end = NULL;
    long v = strtol(token, &end, 10);
    if (!end || *end != '\0' || v <= 0 || v > INT_MAX)
        return -1;
    *out_id = (int)v;
    return 0;
}

static int parse_startup_profile_id(int argc, char **argv, int *out_id) {
    *out_id = -1;

    for (int i = 1; i < argc; i++) {
        const char *arg = argv[i];

        if (strcmp(arg, "-id") == 0 || strcmp(arg, "--id") == 0) {
            if (*out_id >= 0) {
                fprintf(stderr, "[FATAL] -id specified more than once\n");
                return -1;
            }
            if (i + 1 >= argc) {
                fprintf(stderr, "[FATAL] -id requires ne_profiles.id\n");
                return -1;
            }
            if (parse_profile_id_token(argv[++i], out_id) != 0) {
                fprintf(stderr, "[FATAL] invalid ne_profiles.id: %s\n", argv[i]);
                return -1;
            }
            continue;
        }

        if (strncmp(arg, "-id=", 4) == 0 || strncmp(arg, "--id=", 5) == 0) {
            if (*out_id >= 0) {
                fprintf(stderr, "[FATAL] -id specified more than once\n");
                return -1;
            }
            const char *id_str = (arg[1] == '-') ? strchr(arg, '=') + 1 : arg + 4;
            if (parse_profile_id_token(id_str, out_id) != 0) {
                fprintf(stderr, "[FATAL] invalid ne_profiles.id: %s\n", id_str);
                return -1;
            }
            continue;
        }

        fprintf(stderr, "[FATAL] unknown option: %s\n", arg);
        return -1;
    }
    return 0;
}

/* 1 = newly added, 0 = already in set, -1 = error (set full) */
static int active_ids_add(int *active_ids, int *active_id_count, int id) {
    for (int i = 0; i < *active_id_count; i++) {
        if (active_ids[i] == id)
            return 0;
    }
    if (*active_id_count >= MAX_ACTIVE_PROFILE_IDS) {
        fprintf(stderr, "[WARN] active profile set is full, ignoring id=%d\n", id);
        return -1;
    }
    active_ids[(*active_id_count)++] = id;
    return 1;
}

static int active_ids_remove(int *active_ids, int *active_id_count, int id) {
    int w = 0;
    int removed = 0;

    for (int i = 0; i < *active_id_count; i++) {
        if (active_ids[i] == id) {
            removed = 1;
            continue;
        }
        active_ids[w++] = active_ids[i];
    }
    *active_id_count = w;
    return removed;
}

static int libbpf_print_silent(enum libbpf_print_level level,
                               const char *format,
                               va_list args) {
    (void)level;
    (void)format;
    (void)args;
    return 0;
}

static int notify_profile_load(int profile_id) {
    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0)
        return -1;

    PGconn *conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "[ERR] DB: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return -1;
    }

    char sql[96];
    snprintf(sql, sizeof(sql), "SELECT pg_notify('%s', '%d')", NOTIFY_CHANNEL, profile_id);
    PGresult *res = PQexec(conn, sql);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "[ERR] pg_notify failed: %s", PQerrorMessage(conn));
        PQclear(res);
        PQfinish(conn);
        return -1;
    }
    PQclear(res);
    PQfinish(conn);
    return 0;
}

static void *forwarder_thread_main(void *arg) {
    forwarder_pin_cpu();
    struct runtime_state *rt = (struct runtime_state *)arg;
    if (forwarder_init(&rt->fwd, &rt->cfg_slots[rt->active_slot]) != 0) {
        if (forwarder_should_stop())
            fprintf(stderr, "[STOP] forwarder init aborted\n");
        else
            fprintf(stderr, "[FATAL] forwarder_init failed\n");
        rt->running = 0;
        return NULL;
    }
    if (forwarder_should_stop()) {
        fprintf(stderr, "[STOP] forwarder init aborted\n");
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    main_diag_log_link_macs(&rt->cfg_slots[rt->active_slot]);
    if (forwarder_should_stop()) {
        forwarder_cleanup(&rt->fwd);
        rt->running = 0;
        return NULL;
    }
    rt->running = 1;
    forwarder_run(&rt->fwd);
    forwarder_cleanup(&rt->fwd);
    rt->running = 0;
    return NULL;
}

static int runtime_start(struct runtime_state *rt, const struct app_config *cfg) {
    rt->active_slot = 0;
    rt->cfg_slots[rt->active_slot] = *cfg;
    rt->running = 0;
    if (pthread_create(&rt->thread, NULL, forwarder_thread_main, rt) != 0) {
        fprintf(stderr, "[FATAL] failed to create forwarder thread\n");
        return -1;
    }
    rt->has_thread = 1;
    return 0;
}

static int apply_active_configs(struct runtime_state *rt, const int *active_ids,
                                int active_id_count, int trigger_id,
                                int after_delete) {
    struct app_config *merged_cfg = calloc(1, sizeof(*merged_cfg));
    if (!merged_cfg) {
        fprintf(stderr, "[FATAL] out of memory building merged config\n");
        return -1;
    }
    if (build_merged_config(merged_cfg, active_ids, active_id_count, NULL) != 0) {
        free(merged_cfg);
        return -1;
    }

    if (after_delete)
        fprintf(stderr, "[LOAD] active after delete:");
    else
        fprintf(stderr, "[LOAD] notify profile %d | active:", trigger_id);
    for (int i = 0; i < active_id_count; i++)
        fprintf(stderr, " %d", active_ids[i]);
    fprintf(stderr, "\n");
    main_diag_log_loaded_config(merged_cfg, trigger_id);

    if (!rt->has_thread) {
        int rc = runtime_start(rt, merged_cfg);
        free(merged_cfg);
        return rc != 0 ? -1 : 0;
    }

    int next_slot = 1 - rt->active_slot;
    rt->cfg_slots[next_slot] = *merged_cfg;
    free(merged_cfg);
    if (forwarder_reload_config(&rt->fwd, &rt->cfg_slots[next_slot]) == 0) {
        rt->active_slot = next_slot;
        return 0;
    }
    return -1;
}

static void runtime_detach_xdp_from_config(const struct runtime_state *rt) {
    if (!rt)
        return;
    const struct app_config *cfg = &rt->cfg_slots[rt->active_slot];
    if (cfg->local_count == 0 && cfg->wan_count == 0)
        return;
    interface_xdp_detach_all_from_config(cfg);
    for (int i = 0; i < cfg->local_count; i++)
        fprintf(stderr, "[STOP] XDP detached LAN %s\n", cfg->locals[i].ifname);
    for (int i = 0; i < cfg->wan_count; i++)
        fprintf(stderr, "[STOP] XDP detached WAN %s\n", cfg->wans[i].ifname);
}

static int runtime_stop_forwarder(struct runtime_state *rt) {
    if (!rt->has_thread)
        return 0;

    forwarder_stop();
    pthread_join(rt->thread, NULL);
    runtime_detach_xdp_from_config(rt);
    rt->has_thread = 0;
    rt->running = 0;
    return 0;
}

/* 0 = loaded, 1 = already active (no reload), -1 = error */
static int load_profile_and_run(struct runtime_state *rt,
                                int *active_ids,
                                int *active_id_count,
                                int profile_id) {
    if (!rt->has_thread)
        *active_id_count = 0;

    int added = active_ids_add(active_ids, active_id_count, profile_id);
    if (added < 0)
        return -1;
    if (added == 0)
        return 1;

    if (apply_active_configs(rt, active_ids, *active_id_count, profile_id, 0) != 0) {
        active_ids_remove(active_ids, active_id_count, profile_id);
        return -1;
    }
    return 0;
}

static int handle_profile_notify(struct runtime_state *rt,
                                 int *active_ids,
                                 int *active_id_count,
                                 int profile_id) {
    if (ne_profile_id_exists(profile_id) == 0) {
        int lr = load_profile_and_run(rt, active_ids, active_id_count, profile_id);
        if (lr == 1)
            return 0;
        if (lr != 0) {
            fprintf(stderr, "[ERR] profile %d: load failed\n", profile_id);
            return -1;
        }
        return 0;
    }

    if (!active_ids_remove(active_ids, active_id_count, profile_id)) {
        fprintf(stderr, "[DELETE] profile %d (not in DB)\n", profile_id);
        return 0;
    }

    fprintf(stderr, "[DELETE] profile %d removed\n", profile_id);

    if (*active_id_count == 0)
        return runtime_stop_forwarder(rt);

    if (apply_active_configs(rt, active_ids, *active_id_count, profile_id, 1) != 0) {
        fprintf(stderr, "[ERR] profile %d: unload reload failed\n", profile_id);
        return -1;
    }
    return 0;
}

int main(int argc, char **argv) {
    setbuf(stderr, NULL);

    if (argc == 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--version") == 0) {
        fprintf(stderr, "network-encryptor\n");
        return 0;
    }

    int profile_id = -1;
    if (parse_startup_profile_id(argc, argv, &profile_id) != 0) {
        usage(argv[0]);
        return 1;
    }

    if (profile_id >= 0) {
        if (load_ne_env() != 0) {
            fprintf(stderr, "[FATAL] DB env not loaded from " NE_ENV_FILE "\n");
            return 1;
        }
        int exists = (ne_profile_id_exists(profile_id) == 0);
        if (notify_profile_load(profile_id) != 0)
            return 1;
        if (exists)
            fprintf(stderr, "[LOAD] notify profile %d\n", profile_id);
        else
            fprintf(stderr, "[DELETE] notify profile %d (not in DB)\n", profile_id);
        return 0;
    }

    if (argc > 1) {
        fprintf(stderr, "[FATAL] unknown arguments (got %d)\n", argc - 1);
        usage(argv[0]);
        return 1;
    }

    if (load_ne_env() != 0) {
        fprintf(stderr, "[FATAL] DB env not loaded from " NE_ENV_FILE "\n");
        return 1;
    }

    struct ne_postgres_conn pg;
    if (ne_postgres_conn_fill(&pg) != 0) {
        fprintf(stderr,
                "[FATAL] Missing POSTGRES_SERVER/PORT/USER/DB/PASSWORD in " NE_ENV_FILE "\n");
        return 1;
    }

    libbpf_set_print(libbpf_print_silent);

    struct sigaction sa = { .sa_handler = on_stop_signal };
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    forwarder_pin_cpu();
    PGconn *listen_conn = PQconnectdbParams(pg.keywords, pg.values, 0);
    if (PQstatus(listen_conn) != CONNECTION_OK) {
        fprintf(stderr, "[FATAL] DB connection failed: %s", PQerrorMessage(listen_conn));
        fprintf(stderr,
                "[DB] tried host=%s port=%s dbname=%s user=%s (from " NE_ENV_FILE ")\n",
                pg.values[0], pg.values[1], pg.values[2], pg.values[3]);
        PQfinish(listen_conn);
        return 1;
    }
    PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));

    fprintf(stderr, "[DAEMON] listening %s — use %s -id <id>\n", NOTIFY_CHANNEL, argv[0]);

    /* forwarder is ~585 KiB; keep runtime off the main-thread stack (avoids segfault on small stacks). */
    struct runtime_state *rt = calloc(1, sizeof(*rt));
    if (!rt) {
        fprintf(stderr, "[FATAL] out of memory for runtime state\n");
        PQfinish(listen_conn);
        return 1;
    }

    int active_ids[MAX_ACTIVE_PROFILE_IDS];
    int active_id_count = 0;

    while (!g_stop_requested) {
        int pq_fd = PQsocket(listen_conn);
        if (pq_fd < 0) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
            usleep(200000);
            continue;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(pq_fd, &rfds);

        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        int sr = select(pq_fd + 1, &rfds, NULL, NULL, &tv);
        if (sr < 0) {
            if (errno == EINTR)
                continue;
            usleep(200000);
            continue;
        }
        if (sr == 0)
            continue;

        if (!FD_ISSET(pq_fd, &rfds))
            continue;

        PQconsumeInput(listen_conn);
        PGnotify *notify;
        while ((notify = PQnotifies(listen_conn)) != NULL) {
            int id = parse_notify_profile_id(notify->extra);
            if (id <= 0) {
                fprintf(stderr,
                        "[WARN] ignoring NOTIFY with invalid id payload: \"%s\"\n",
                        notify->extra ? notify->extra : "");
            } else {
                (void)handle_profile_notify(rt, active_ids, &active_id_count, id);
            }
            PQfreemem(notify);
        }

        if (PQstatus(listen_conn) != CONNECTION_OK) {
            PQreset(listen_conn);
            PQclear(PQexec(listen_conn, "LISTEN " NOTIFY_CHANNEL));
        }
    }

    if (rt->has_thread) {
        runtime_stop_forwarder(rt);
    }
    free(rt);
    PQfinish(listen_conn);
    return 0;
}
