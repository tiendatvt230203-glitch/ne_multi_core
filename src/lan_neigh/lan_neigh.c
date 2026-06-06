#include "../../inc/lan_neigh/lan_neigh.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/main_diag.h"

#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LAN_NEIGH_TABLE_SIZE 4096
#define LAN_NEIGH_ARP_TIMEOUT_MS 400
#define LAN_NEIGH_ARP_RETRIES    2

#define ARP_FRAME_LEN 42

struct lan_neigh_entry {
    uint32_t ip;
    uint8_t mac[MAC_LEN];
    uint8_t local_idx;
    uint8_t pad[3];
    time_t last_seen;
};

static struct lan_neigh_entry lan_table[LAN_NEIGH_TABLE_SIZE];
static pthread_mutex_t lan_lock = PTHREAD_MUTEX_INITIALIZER;
static int lan_arp_sock = -1;
static int local_ifindex[MAX_INTERFACES];

static inline int mac_is_zero(const uint8_t mac[MAC_LEN])
{
    static const uint8_t z[MAC_LEN];
    return memcmp(mac, z, MAC_LEN) == 0;
}

static inline int mac_is_multicast(const uint8_t mac[MAC_LEN])
{
    return (mac[0] & 0x01) != 0;
}

static inline int ip_in_local_subnet(const struct app_config *cfg, int li, uint32_t ip)
{
    if (!cfg || li < 0 || li >= cfg->local_count)
        return 0;
    const struct local_config *loc = &cfg->locals[li];
    if (loc->netmask == 0)
        return 1;
    return (ip & loc->netmask) == loc->network;
}

static uint32_t lan_neigh_hash(int local_idx, uint32_t ip)
{
    uint32_t h = ip ^ ((uint32_t)local_idx * 0x9e3779b1U);
    h ^= h >> 16;
    h *= 0x7feb352dU;
    h ^= h >> 15;
    h *= 0x846ca68bU;
    h ^= h >> 16;
    return h & (LAN_NEIGH_TABLE_SIZE - 1);
}

static int read_iface_ifindex(const char *ifname)
{
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, IFNAMSIZ, "%s", ifname);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        close(fd);
        return -1;
    }
    close(fd);
    return ifr.ifr_ifindex;
}

static int ensure_arp_sock(void)
{
    if (lan_arp_sock >= 0)
        return 0;

    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0)
        return -1;

    int flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0)
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    lan_arp_sock = fd;
    return 0;
}

static void close_arp_sock(void)
{
    if (lan_arp_sock >= 0) {
        close(lan_arp_sock);
        lan_arp_sock = -1;
    }
}

static int arp_send_request(int ifindex, const uint8_t sha[MAC_LEN], uint32_t tip_be)
{
    uint8_t frame[ARP_FRAME_LEN];

    memset(frame, 0xff, MAC_LEN);
    memcpy(frame + MAC_LEN, sha, MAC_LEN);
    frame[12] = 0x08;
    frame[13] = 0x06;

    uint16_t *arp16 = (uint16_t *)(frame + 14);
    arp16[0] = htons(ARPHRD_ETHER);
    arp16[1] = htons(ETH_P_IP);
    arp16[2] = htons(ARPOP_REQUEST);
    frame[18] = MAC_LEN;
    frame[19] = 4;
    memcpy(frame + 20, sha, MAC_LEN);
    memset(frame + 26, 0, 4);
    memset(frame + 30, 0, MAC_LEN);
    memcpy(frame + 36, &tip_be, 4);

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_halen = MAC_LEN;
    memset(sll.sll_addr, 0xff, MAC_LEN);

    if (sendto(lan_arp_sock, frame, sizeof(frame), 0,
               (struct sockaddr *)&sll, sizeof(sll)) < 0)
        return -1;
    return 0;
}

static int local_idx_from_ifindex(int ifindex)
{
    if (ifindex <= 0)
        return -1;
    for (int i = 0; i < MAX_INTERFACES; i++) {
        if (local_ifindex[i] == ifindex)
            return i;
    }
    return -1;
}

static int arp_wait_reply(uint32_t tip_be, uint8_t mac_out[MAC_LEN], int *ifindex_out)
{
    uint8_t buf[256];
    int elapsed = 0;

    while (elapsed < LAN_NEIGH_ARP_TIMEOUT_MS) {
        struct pollfd pfd = { .fd = lan_arp_sock, .events = POLLIN };
        int pr = poll(&pfd, 1, 50);
        if (pr < 0)
            return -1;
        if (pr == 0) {
            elapsed += 50;
            continue;
        }

        struct sockaddr_ll sll;
        socklen_t slen = sizeof(sll);
        ssize_t n = recvfrom(lan_arp_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sll, &slen);
        if (n < (ssize_t)ARP_FRAME_LEN)
            continue;

        if (buf[12] != 0x08 || buf[13] != 0x06)
            continue;

        uint16_t op = ntohs(*(const uint16_t *)(buf + 20));
        if (op != ARPOP_REPLY)
            continue;

        uint32_t sip;
        memcpy(&sip, buf + 28, 4);
        if (sip != tip_be)
            continue;

        memcpy(mac_out, buf + 22, MAC_LEN);
        if (mac_is_zero(mac_out) || mac_is_multicast(mac_out))
            continue;
        if (ifindex_out)
            *ifindex_out = (int)sll.sll_ifindex;
        return 0;
    }
    return -1;
}

static void arp_drain_socket(void)
{
    uint8_t trash[256];
    struct sockaddr_ll sll;
    socklen_t slen;

    while (1) {
        slen = sizeof(sll);
        if (recvfrom(lan_arp_sock, trash, sizeof(trash), 0,
                     (struct sockaddr *)&sll, &slen) <= 0)
            break;
    }
}

static int arp_probe_all(const struct app_config *cfg, uint32_t ip,
                         int *li_out, uint8_t mac_out[MAC_LEN])
{
    int reply_ifindex = 0;
    int sent = 0;

    if (!cfg || !li_out || !mac_out)
        return -1;
    if (ensure_arp_sock() != 0)
        return -1;

    arp_drain_socket();

    for (int i = 0; i < cfg->local_count; i++) {
        if (!ip_in_local_subnet(cfg, i, ip))
            continue;
        if (i >= MAX_INTERFACES || local_ifindex[i] <= 0)
            continue;
        if (mac_is_zero(cfg->locals[i].src_mac))
            continue;
        if (arp_send_request(local_ifindex[i], cfg->locals[i].src_mac, ip) == 0)
            sent++;
    }
    if (!sent)
        return -1;

    for (int attempt = 0; attempt < LAN_NEIGH_ARP_RETRIES; attempt++) {
        if (arp_wait_reply(ip, mac_out, &reply_ifindex) != 0)
            continue;

        int li = local_idx_from_ifindex(reply_ifindex);
        if (li < 0) {
            for (int i = 0; i < cfg->local_count; i++) {
                if (!ip_in_local_subnet(cfg, i, ip))
                    continue;
                li = i;
                break;
            }
        }
        if (li < 0 || li >= cfg->local_count)
            return -1;

        *li_out = li;
        return 0;
    }
    return -1;
}

static int read_iface_hwaddr(const char *ifname, uint8_t mac[MAC_LEN])
{
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

void lan_neigh_reset(void)
{
    pthread_mutex_lock(&lan_lock);
    memset(lan_table, 0, sizeof(lan_table));
    pthread_mutex_unlock(&lan_lock);
    memset(local_ifindex, 0, sizeof(local_ifindex));
    close_arp_sock();
}

int lan_neigh_prepare(struct app_config *cfg)
{
    if (!cfg)
        return -1;

    lan_neigh_reset();
    for (int i = 0; i < cfg->local_count; i++) {
        memset(cfg->locals[i].dst_mac, 0, MAC_LEN);
        (void)read_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);
        if (i < MAX_INTERFACES)
            local_ifindex[i] = read_iface_ifindex(cfg->locals[i].ifname);
    }
    return 0;
}

int lan_neigh_install(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    for (int i = 0; i < fwd->cfg->local_count; i++) {
        uint8_t hw[MAC_LEN];
        if (read_iface_hwaddr(fwd->cfg->locals[i].ifname, hw) == 0)
            memcpy(fwd->cfg->locals[i].src_mac, hw, MAC_LEN);
        if (i < fwd->local_count)
            memcpy(fwd->locals[i].src_mac, fwd->cfg->locals[i].src_mac, MAC_LEN);
        if (i < MAX_INTERFACES)
            local_ifindex[i] = read_iface_ifindex(fwd->cfg->locals[i].ifname);
    }
    main_diag_log_local_port_macs(fwd->cfg);
    return 0;
}

void lan_neigh_learn(int local_idx, uint32_t ip, const uint8_t mac[MAC_LEN],
                     const struct app_config *cfg)
{
    if (!cfg || !mac || local_idx < 0 || local_idx >= cfg->local_count)
        return;
    if (ip == 0 || ip == 0xffffffffu || mac_is_zero(mac) || mac_is_multicast(mac))
        return;
    if (!ip_in_local_subnet(cfg, local_idx, ip))
        return;
    if (memcmp(mac, cfg->locals[local_idx].src_mac, MAC_LEN) == 0)
        return;

    uint32_t idx = lan_neigh_hash(local_idx, ip);
    time_t now = time(NULL);
    char ifname[IF_NAMESIZE];
    uint8_t old_mac[MAC_LEN];
    int mac_changed = 0;
    int is_new = 0;

    memset(old_mac, 0, sizeof(old_mac));
    snprintf(ifname, sizeof(ifname), "%s", cfg->locals[local_idx].ifname);

    pthread_mutex_lock(&lan_lock);
    for (uint32_t probe = 0; probe < LAN_NEIGH_TABLE_SIZE; probe++) {
        struct lan_neigh_entry *e = &lan_table[(idx + probe) & (LAN_NEIGH_TABLE_SIZE - 1)];

        if (e->ip == 0) {
            e->ip = ip;
            e->local_idx = (uint8_t)local_idx;
            memcpy(e->mac, mac, MAC_LEN);
            e->last_seen = now;
            is_new = 1;
            mac_changed = 1;
            break;
        }
        if (e->ip == ip) {
            memcpy(old_mac, e->mac, MAC_LEN);
            if (e->local_idx != (uint8_t)local_idx)
                mac_changed = 1;
            e->local_idx = (uint8_t)local_idx;
            if (memcmp(e->mac, mac, MAC_LEN) != 0) {
                memcpy(e->mac, mac, MAC_LEN);
                mac_changed = 1;
            }
            e->last_seen = now;
            break;
        }
    }
    pthread_mutex_unlock(&lan_lock);

    if (!mac_changed)
        return;
    if (is_new)
        main_diag_log_lan_neigh_event(ifname, ip, old_mac, mac, "learned");
    else
        main_diag_log_lan_neigh_event(ifname, ip, old_mac, mac, "detached");
}

int lan_neigh_lookup(int local_idx, uint32_t ip, uint8_t mac_out[MAC_LEN])
{
    if (!mac_out || local_idx < 0)
        return -1;

    uint32_t idx = lan_neigh_hash(local_idx, ip);
    int found = -1;

    pthread_mutex_lock(&lan_lock);
    for (uint32_t probe = 0; probe < LAN_NEIGH_TABLE_SIZE; probe++) {
        const struct lan_neigh_entry *e = &lan_table[(idx + probe) & (LAN_NEIGH_TABLE_SIZE - 1)];
        if (e->ip == 0)
            break;
        if (e->ip == ip && e->local_idx == (uint8_t)local_idx) {
            memcpy(mac_out, e->mac, MAC_LEN);
            found = 0;
            break;
        }
    }
    pthread_mutex_unlock(&lan_lock);
    return found;
}

int lan_neigh_lookup_by_ip(uint32_t ip, int *local_idx_out, uint8_t mac_out[MAC_LEN])
{
    if (!local_idx_out || !mac_out || ip == 0)
        return -1;

    int found = -1;

    pthread_mutex_lock(&lan_lock);
    for (int i = 0; i < LAN_NEIGH_TABLE_SIZE; i++) {
        const struct lan_neigh_entry *e = &lan_table[i];
        if (e->ip == 0)
            continue;
        if (e->ip == ip) {
            *local_idx_out = (int)e->local_idx;
            memcpy(mac_out, e->mac, MAC_LEN);
            found = 0;
            break;
        }
    }
    pthread_mutex_unlock(&lan_lock);
    return found;
}

int lan_neigh_resolve(struct forwarder *fwd, uint32_t ip,
                      int *local_idx_out, uint8_t mac_out[MAC_LEN])
{
    if (!fwd || !fwd->cfg || !local_idx_out || !mac_out || ip == 0)
        return -1;

    const struct app_config *cfg = fwd->cfg;
    int li = -1;

    if (lan_neigh_lookup_by_ip(ip, &li, mac_out) == 0 && li >= 0 && li < cfg->local_count) {
        main_diag_log_lan_neigh_resolve(cfg->locals[li].ifname, ip, mac_out, "cached");
        *local_idx_out = li;
        return 0;
    }

    {
        int li_arp = -1;

        if (arp_probe_all(cfg, ip, &li_arp, mac_out) == 0 && li_arp >= 0 &&
            li_arp < cfg->local_count) {
            lan_neigh_learn(li_arp, ip, mac_out, cfg);
            main_diag_log_lan_neigh_resolve(cfg->locals[li_arp].ifname, ip, mac_out, "arp");
            *local_idx_out = li_arp;
            return 0;
        }
    }

    main_diag_log_lan_neigh_resolve("(any)", ip, NULL, "miss");
    return -1;
}

int lan_neigh_is_own_src(const struct forwarder *fwd, int local_idx,
                         const uint8_t *pkt, uint32_t pkt_len)
{
    if (!fwd || local_idx < 0 || local_idx >= fwd->local_count || !pkt || pkt_len < 14)
        return 0;
    return memcmp(pkt + MAC_LEN, fwd->locals[local_idx].src_mac, MAC_LEN) == 0;
}

void lan_neigh_gc_tick(void)
{
    time_t now = time(NULL);

    pthread_mutex_lock(&lan_lock);
    for (int i = 0; i < LAN_NEIGH_TABLE_SIZE; i++) {
        struct lan_neigh_entry *e = &lan_table[i];
        if (e->ip == 0)
            continue;
        if ((time_t)(now - e->last_seen) > LAN_NEIGH_TIMEOUT_SEC)
            memset(e, 0, sizeof(*e));
    }
    pthread_mutex_unlock(&lan_lock);
}
