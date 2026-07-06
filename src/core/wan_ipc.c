#include "../../inc/core/wan_ipc.h"
#include "../../inc/core/wan_admin.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#define WAN_IPC_SOCKET_PATH "/var/run/network-encryptor-wan.sock"
#define WAN_IPC_RESP_MAX 256

static wan_ipc_cfg_fn g_cfg_fn;
static volatile int g_wan_ipc_running;

static void ipc_write_str(int fd, const char *msg)
{
    if (!msg)
        return;
    size_t len = strlen(msg);
    if (len > 0)
        (void)write(fd, msg, len);
}

static int handle_wan_command(const char *verb, int profile_id, const char *ifname,
                              char *err, size_t errsz)
{
    const struct app_config *cfg = g_cfg_fn ? g_cfg_fn() : NULL;

    if (!cfg) {
        snprintf(err, errsz, "dataplane not ready");
        return -1;
    }

    int v = wan_admin_validate_wan(cfg, profile_id, ifname);
    if (v == -2) {
        snprintf(err, errsz, "interface not in dataplane pool (dst_ip or weight=0)");
        return -1;
    }
    if (v != 0) {
        snprintf(err, errsz, "profile %d has no WAN %s", profile_id, ifname);
        return -1;
    }

    if (strcmp(verb, "DOWN") == 0) {
        if (wan_admin_would_leave_pool(cfg, profile_id, ifname)) {
            snprintf(err, errsz, "cannot DOWN last active WAN in profile %d", profile_id);
            return -1;
        }
        if (wan_admin_down(profile_id, ifname) != 0) {
            snprintf(err, errsz, "admin down failed");
            return -1;
        }
        return 0;
    }

    if (strcmp(verb, "UP") == 0) {
        if (wan_admin_up(profile_id, ifname) != 0) {
            snprintf(err, errsz, "admin up failed");
            return -1;
        }
        return 0;
    }

    snprintf(err, errsz, "unknown verb");
    return -1;
}

static void *wan_ipc_listener(void *arg)
{
    (void)arg;
    unlink(WAN_IPC_SOCKET_PATH);

    int listen_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        perror("[WAN-IPC] socket failed");
        return NULL;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, WAN_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("[WAN-IPC] bind failed");
        close(listen_fd);
        return NULL;
    }

    if (listen(listen_fd, 8) < 0) {
        perror("[WAN-IPC] listen failed");
        close(listen_fd);
        return NULL;
    }

    chmod(WAN_IPC_SOCKET_PATH, 0660);
    fprintf(stderr, "[WAN-IPC] listening %s (DOWN|UP <profile_id> <ifname>)\n",
            WAN_IPC_SOCKET_PATH);
    fflush(stderr);

    while (g_wan_ipc_running) {
        int client_fd = accept(listen_fd, NULL, NULL);
        if (client_fd < 0) {
            if (!g_wan_ipc_running)
                break;
            usleep(100000);
            continue;
        }

        char buf[192];
        memset(buf, 0, sizeof(buf));
        ssize_t n = read(client_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            char verb[16];
            int profile_id = -1;
            char ifname[IF_NAMESIZE];

            memset(verb, 0, sizeof(verb));
            memset(ifname, 0, sizeof(ifname));

            if (sscanf(buf, "%15s %d %15s", verb, &profile_id, ifname) == 3) {
                char err[WAN_IPC_RESP_MAX];
                memset(err, 0, sizeof(err));
                if (handle_wan_command(verb, profile_id, ifname, err, sizeof(err)) == 0) {
                    ipc_write_str(client_fd, "OK\n");
                } else {
                    char resp[WAN_IPC_RESP_MAX];
                    snprintf(resp, sizeof(resp), "ERR %s\n", err[0] ? err : "failed");
                    ipc_write_str(client_fd, resp);
                }
            } else {
                ipc_write_str(client_fd,
                              "ERR usage: DOWN|UP <profile_id> <ifname>\n");
            }
        }
        close(client_fd);
    }

    close(listen_fd);
    unlink(WAN_IPC_SOCKET_PATH);
    return NULL;
}

void wan_ipc_set_cfg_provider(wan_ipc_cfg_fn fn)
{
    g_cfg_fn = fn;
}

void wan_ipc_start_server(void)
{
    if (g_wan_ipc_running)
        return;
    g_wan_ipc_running = 1;
    pthread_t tid;
    if (pthread_create(&tid, NULL, wan_ipc_listener, NULL) != 0) {
        g_wan_ipc_running = 0;
        fprintf(stderr, "[WAN-IPC] failed to start listener thread\n");
        return;
    }
    pthread_detach(tid);
}

void wan_ipc_cleanup(void)
{
    g_wan_ipc_running = 0;
    unlink(WAN_IPC_SOCKET_PATH);
}

static int run_wan_ipc_client(const char *verb, int profile_id, const char *ifname)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, WAN_IPC_SOCKET_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr,
                "Error: daemon not running (no socket %s)\n",
                WAN_IPC_SOCKET_PATH);
        close(fd);
        return 1;
    }

    char cmd[128];
    snprintf(cmd, sizeof(cmd), "%s %d %s\n", verb, profile_id, ifname);
    if (write(fd, cmd, strlen(cmd)) < 0) {
        perror("write");
        close(fd);
        return 1;
    }

    char resp[WAN_IPC_RESP_MAX];
    memset(resp, 0, sizeof(resp));
    ssize_t n = read(fd, resp, sizeof(resp) - 1);
    if (n > 0)
        printf("%s", resp);
    else
        fprintf(stderr, "Error: no response from daemon\n");

    close(fd);
    return (n > 0 && strncmp(resp, "OK", 2) == 0) ? 0 : 1;
}

int wan_ipc_handle_cli(int argc, char **argv)
{
    for (int i = 1; i < argc; i++) {
        int is_down = (strcmp(argv[i], "-wan-down") == 0);
        int is_up = (strcmp(argv[i], "-wan-up") == 0);

        if ((is_down || is_up) && i + 2 < argc) {
            int profile_id = atoi(argv[i + 1]);
            const char *ifname = argv[i + 2];
            if (profile_id <= 0 || !ifname || !ifname[0]) {
                fprintf(stderr, "Usage: %s -wan-down|-wan-up <profile_id> <ifname>\n",
                        argv[0]);
                return 1;
            }
            return run_wan_ipc_client(is_down ? "DOWN" : "UP", profile_id, ifname);
        }
    }
    return -1;
}
