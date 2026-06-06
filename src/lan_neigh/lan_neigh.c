#include "../../inc/lan_neigh/lan_neigh.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/main_diag.h"

#include <net/if.h>
#include <net/if_arp.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define LAN_NEIGH_TABLE_SIZE 4096

struct lan_neigh_entry {
    uint32_t ip;
    uint8_t mac[MAC_LEN];
    uint8_t local_idx;
    uint8_t pad[3];
    time_t last_seen;
};

static struct lan_neigh_entry lan_table[LAN_NEIGH_TABLE_SIZE];
static pthread_mutex_t lan_lock = PTHREAD_MUTEX_INITIALIZER;

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
}

int lan_neigh_prepare(struct app_config *cfg)
{
    if (!cfg)
        return -1;

    lan_neigh_reset();
    for (int i = 0; i < cfg->local_count; i++) {
        memset(cfg->locals[i].dst_mac, 0, MAC_LEN);
        (void)read_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);
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
        if (e->ip == ip && e->local_idx == (uint8_t)local_idx) {
            memcpy(old_mac, e->mac, MAC_LEN);
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
