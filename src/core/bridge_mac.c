#include "../../inc/core/bridge_mac.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/main_diag.h"
#include "../../inc/core/config.h"
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <ctype.h>
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <linux/rtnetlink.h>

#define BRIDGE_MAC_NL_BUF 8192

static inline int mac_is_zero(const uint8_t mac[MAC_LEN]) {
    for (int i = 0; i < MAC_LEN; i++) {
        if (mac[i] != 0)
            return 0;
    }
    return 1;
}

static inline int mac_is_broadcast(const uint8_t mac[MAC_LEN]) {
    for (int i = 0; i < MAC_LEN; i++) {
        if (mac[i] != 0xFF)
            return 0;
    }
    return 1;
}

static inline int mac_is_multicast(const uint8_t mac[MAC_LEN]) {
    return (mac[0] & 0x01) != 0;
}

static int mac_is_valid_dst(const uint8_t mac[MAC_LEN]) {
    return !mac_is_zero(mac) && !mac_is_broadcast(mac) && !mac_is_multicast(mac);
}

static int mac_is_own_local(const struct app_config *cfg, int li, const uint8_t mac[MAC_LEN]) {
    if (!cfg || li < 0 || li >= cfg->local_count || !mac)
        return 0;
    if (mac_is_zero(cfg->locals[li].src_mac))
        return 0;
    return memcmp(cfg->locals[li].src_mac, mac, MAC_LEN) == 0;
}

static int read_local_iface_hwaddr(const char *ifname, uint8_t mac[MAC_LEN]) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    if ((unsigned int)ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER)
        return -1;
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LEN);
    return 0;
}

static int ifname_is_safe(const char *ifname) {
    if (!ifname || !ifname[0])
        return 0;
    for (const unsigned char *p = (const unsigned char *)ifname; *p; p++) {
        if (!(isalnum(*p) || *p == '_' || *p == '-' || *p == '.'))
            return 0;
    }
    return 1;
}

static int fdb_line_matches_local_dst(const char *line) {
    if (!line || !strstr(line, " master "))
        return 0;
    if (strstr(line, " self") || strstr(line, " permanent") || strstr(line, " vlan "))
        return 0;
    return 1;
}

static int mac_load_once_from_bridge_cmd(struct app_config *cfg, int li) {
    struct local_config *loc = &cfg->locals[li];
    if (!ifname_is_safe(loc->ifname))
        return 0;

    char cmd[256];
    snprintf(cmd, sizeof(cmd), "bridge fdb show dev %s", loc->ifname);
    FILE *fp = popen(cmd, "r");
    if (!fp)
        return 0;

    char line[512];
    int loaded = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (!fdb_line_matches_local_dst(line))
            continue;

        char mac_tok[48];
        if (sscanf(line, "%47s", mac_tok) != 1)
            continue;

        uint8_t mac[MAC_LEN];
        if (parse_mac(mac_tok, mac) != 0 || !mac_is_valid_dst(mac))
            continue;
        if (mac_is_own_local(cfg, li, mac))
            continue;

        memcpy(loc->dst_mac, mac, MAC_LEN);
        loaded = 1;
        break;
    }
    pclose(fp);
    return loaded;
}

static int bridge_mac_prepare_impl(struct app_config *cfg) {
    if (!cfg || cfg->local_count <= 0)
        return 0;

    for (int i = 0; i < cfg->local_count; i++) {
        (void)read_local_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);
        memset(cfg->locals[i].dst_mac, 0, MAC_LEN);
        (void)mac_load_once_from_bridge_cmd(cfg, i);
    }
    return 0;
}

int bridge_mac_prepare(struct app_config *cfg) {
    return bridge_mac_prepare_impl(cfg);
}

static void bridge_mac_copy_local_macs(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return;
    for (int i = 0; i < fwd->local_count && i < fwd->cfg->local_count; i++) {
        memcpy(fwd->locals[i].src_mac, fwd->cfg->locals[i].src_mac, MAC_LEN);
        memcpy(fwd->locals[i].dst_mac, fwd->cfg->locals[i].dst_mac, MAC_LEN);
    }
}

int bridge_mac_install(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg)
        return -1;
    bridge_mac_copy_local_macs(fwd);
    return 0;
}

int bridge_mac_local_for_dmac(struct forwarder *fwd,
                              const uint8_t *pkt, uint32_t pkt_len) {
    if (!fwd || !fwd->cfg || !pkt || pkt_len < sizeof(struct ether_header))
        return -1;

    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (!mac_is_valid_dst(eth->ether_dhost))
        return -1;

    for (int i = 0; i < fwd->local_count; i++) {
        if (mac_is_zero(fwd->locals[i].dst_mac))
            continue;
        if (memcmp(eth->ether_dhost, fwd->locals[i].dst_mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

struct bridge_mac_ifslot {
    int ifindex;
    int li;
};

static struct {
    pthread_t thread;
    int thread_active;
    int nl_fd;
    atomic_int run;
    pthread_mutex_t lock;
    int lock_ready;
    struct bridge_mac_ifslot slots[MAX_INTERFACES];
    int slot_count;
} g_mac_watch = { .nl_fd = -1 };

static void bridge_mac_refresh_ifslots(struct forwarder *fwd) {
    g_mac_watch.slot_count = 0;
    if (!fwd || !fwd->cfg)
        return;

    for (int i = 0; i < fwd->cfg->local_count && g_mac_watch.slot_count < MAX_INTERFACES; i++) {
        int idx = (int)if_nametoindex(fwd->cfg->locals[i].ifname);
        if (idx <= 0)
            continue;
        int n = g_mac_watch.slot_count++;
        g_mac_watch.slots[n].ifindex = idx;
        g_mac_watch.slots[n].li = i;
    }
}

static int bridge_mac_li_for_ifindex(int target_idx) {
    for (int i = 0; i < g_mac_watch.slot_count; i++) {
        if (g_mac_watch.slots[i].ifindex == target_idx)
            return g_mac_watch.slots[i].li;
    }
    return -1;
}

static void apply_fdb_mac_locked(struct forwarder *fwd, int li, const uint8_t mac[MAC_LEN],
                                 int log_events) {
    if (!fwd || !fwd->cfg || li < 0 || li >= fwd->cfg->local_count)
        return;

    char ifname[IF_NAMESIZE];
    uint8_t prev[MAC_LEN];
    int was_empty;
    int changed;

    pthread_mutex_lock(&g_mac_watch.lock);
    memcpy(prev, fwd->cfg->locals[li].dst_mac, MAC_LEN);
    was_empty = mac_is_zero(prev);
    changed = memcmp(prev, mac, MAC_LEN) != 0;
    memcpy(fwd->cfg->locals[li].dst_mac, mac, MAC_LEN);
    if (li < fwd->local_count)
        memcpy(fwd->locals[li].dst_mac, mac, MAC_LEN);
    snprintf(ifname, sizeof(ifname), "%s", fwd->cfg->locals[li].ifname);
    pthread_mutex_unlock(&g_mac_watch.lock);

    if (log_events && changed) {
        const char *ev = was_empty ? "learned" : "updated";
        main_diag_log_lan_client_mac(ifname, mac, ev);
    }
}

static void parse_fdb_message(struct nlmsghdr *nlh, struct forwarder *fwd, int log_events) {
    struct ndmsg *ndm = (struct ndmsg *)NLMSG_DATA(nlh);
    int li = bridge_mac_li_for_ifindex(ndm->ndm_ifindex);

    if (li < 0)
        return;
    if (ndm->ndm_state & NUD_PERMANENT)
        return;

    struct rtattr *rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
    int rta_len = (int)nlh->nlmsg_len - (int)NLMSG_LENGTH(sizeof(struct ndmsg));
    unsigned char *mac = NULL;

    while (RTA_OK(rta, rta_len)) {
        if (rta->rta_type == NDA_LLADDR) {
            mac = (unsigned char *)RTA_DATA(rta);
            break;
        }
        rta = RTA_NEXT(rta, rta_len);
    }

    if (!mac)
        return;

    uint8_t m[MAC_LEN];
    memcpy(m, mac, MAC_LEN);
    if (!mac_is_valid_dst(m) || mac_is_own_local(fwd->cfg, li, m))
        return;

    apply_fdb_mac_locked(fwd, li, m, log_events);
}

static int nl_send_bridge_fdb_dump(int nl_fd) {
    struct {
        struct nlmsghdr nlh;
        struct ndmsg ndm;
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nlh.nlmsg_type = RTM_GETNEIGH;
    req.ndm.ndm_family = AF_BRIDGE;

    return send(nl_fd, &req, req.nlh.nlmsg_len, 0) == (ssize_t)req.nlh.nlmsg_len ? 0 : -1;
}

static void nl_phase1_dump_fdb(int nl_fd, struct forwarder *fwd) {
    char buffer[BRIDGE_MAC_NL_BUF];
    int end_of_dump = 0;

    if (nl_send_bridge_fdb_dump(nl_fd) != 0)
        return;

    while (!end_of_dump && atomic_load(&g_mac_watch.run)) {
        ssize_t status = recv(nl_fd, buffer, sizeof(buffer), 0);
        if (status < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(nlh, status)) {
            if (nlh->nlmsg_type == NLMSG_DONE) {
                end_of_dump = 1;
                break;
            }
            if (nlh->nlmsg_type == RTM_NEWNEIGH)
                parse_fdb_message(nlh, fwd, 0);
            nlh = NLMSG_NEXT(nlh, status);
        }
    }
}

static void *bridge_mac_watch_thread(void *arg) {
    struct forwarder *fwd = (struct forwarder *)arg;
    int nl_fd = g_mac_watch.nl_fd;
    char buffer[BRIDGE_MAC_NL_BUF];

    nl_phase1_dump_fdb(nl_fd, fwd);

    while (atomic_load(&g_mac_watch.run)) {
        ssize_t status = recv(nl_fd, buffer, sizeof(buffer), 0);
        if (status < 0) {
            if (!atomic_load(&g_mac_watch.run))
                break;
            continue;
        }

        struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
        while (NLMSG_OK(nlh, status)) {
            if (nlh->nlmsg_type == RTM_NEWNEIGH)
                parse_fdb_message(nlh, fwd, 1);
            nlh = NLMSG_NEXT(nlh, status);
        }
    }
    return NULL;
}

void bridge_mac_watch_stop(void) {
    if (!g_mac_watch.thread_active)
        return;

    atomic_store(&g_mac_watch.run, 0);
    if (g_mac_watch.nl_fd >= 0)
        shutdown(g_mac_watch.nl_fd, SHUT_RDWR);

    pthread_join(g_mac_watch.thread, NULL);
    g_mac_watch.thread_active = 0;

    if (g_mac_watch.nl_fd >= 0) {
        close(g_mac_watch.nl_fd);
        g_mac_watch.nl_fd = -1;
    }
    g_mac_watch.slot_count = 0;
}

void bridge_mac_watch_start(struct forwarder *fwd) {
    if (!fwd || !fwd->cfg || fwd->cfg->local_count <= 0)
        return;

    bridge_mac_watch_stop();

    int nl_fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nl_fd < 0)
        return;

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_NEIGH;

    if (bind(nl_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        close(nl_fd);
        return;
    }

    if (!g_mac_watch.lock_ready) {
        pthread_mutex_init(&g_mac_watch.lock, NULL);
        g_mac_watch.lock_ready = 1;
    }

    g_mac_watch.nl_fd = nl_fd;
    bridge_mac_refresh_ifslots(fwd);
    atomic_store(&g_mac_watch.run, 1);

    if (pthread_create(&g_mac_watch.thread, NULL, bridge_mac_watch_thread, fwd) != 0) {
        atomic_store(&g_mac_watch.run, 0);
        close(nl_fd);
        g_mac_watch.nl_fd = -1;
        return;
    }
    g_mac_watch.thread_active = 1;
}
