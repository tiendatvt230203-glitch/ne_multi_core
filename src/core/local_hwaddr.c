#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/forwarder.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define LAN_NEIGH_CAP 2048u

struct lan_neigh_entry {
    uint32_t ip;
    uint8_t mac[MAC_LEN];
    uint8_t local_idx;
    uint8_t used;
};

static struct lan_neigh_entry lan_neigh[LAN_NEIGH_CAP];

static uint32_t neigh_hash(int local_idx, uint32_t ip)
{
    uint32_t h = (uint32_t)local_idx * 0x9e3779b1u ^ ip;
    h ^= h >> 16;
    return h % LAN_NEIGH_CAP;
}

void local_neigh_reset(void)
{
    memset(lan_neigh, 0, sizeof(lan_neigh));
}

void local_neigh_learn(int local_idx, uint32_t ip, const uint8_t mac[MAC_LEN])
{
    static const uint8_t bcast[MAC_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    static const uint8_t zero[MAC_LEN];
    uint32_t slot, i;

    if (!mac || local_idx < 0 || ip == 0)
        return;
    if (memcmp(mac, zero, MAC_LEN) == 0 || memcmp(mac, bcast, MAC_LEN) == 0)
        return;

    slot = neigh_hash(local_idx, ip);
    for (i = 0; i < LAN_NEIGH_CAP; i++) {
        struct lan_neigh_entry *e = &lan_neigh[(slot + i) % LAN_NEIGH_CAP];
        if (!e->used) {
            e->used = 1;
            e->local_idx = (uint8_t)local_idx;
            e->ip = ip;
            memcpy(e->mac, mac, MAC_LEN);
            return;
        }
        if (e->local_idx == (uint8_t)local_idx && e->ip == ip) {
            memcpy(e->mac, mac, MAC_LEN);
            return;
        }
    }
}

static int local_neigh_lookup(int local_idx, uint32_t ip, uint8_t mac_out[MAC_LEN])
{
    uint32_t slot, i;

    if (!mac_out || local_idx < 0 || ip == 0)
        return -1;
    slot = neigh_hash(local_idx, ip);
    for (i = 0; i < LAN_NEIGH_CAP; i++) {
        const struct lan_neigh_entry *e = &lan_neigh[(slot + i) % LAN_NEIGH_CAP];
        if (!e->used)
            return -1;
        if (e->local_idx == (uint8_t)local_idx && e->ip == ip) {
            memcpy(mac_out, e->mac, MAC_LEN);
            return 0;
        }
    }
    return -1;
}

static int kernel_arp_lookup(const char *ifname, uint32_t ip, uint8_t mac_out[MAC_LEN])
{
    int fd;
    struct arpreq req;

    if (!ifname || !ifname[0] || !mac_out || ip == 0)
        return -1;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    memset(&req, 0, sizeof(req));
    struct sockaddr_in *sin = (struct sockaddr_in *)&req.arp_pa;
    sin->sin_family = AF_INET;
    sin->sin_addr.s_addr = ip;
    snprintf(req.arp_dev, sizeof(req.arp_dev), "%s", ifname);

    if (ioctl(fd, SIOCGARP, &req) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    if (!(req.arp_flags & ATF_COM))
        return -1;
    if ((unsigned int)req.arp_ha.sa_family != ARPHRD_ETHER)
        return -1;
    memcpy(mac_out, req.arp_ha.sa_data, MAC_LEN);
    return 0;
}

int local_neigh_resolve(int local_idx, const char *ifname, uint32_t ip,
                        uint8_t mac_out[MAC_LEN])
{
    if (!mac_out || local_idx < 0 || ip == 0)
        return -1;
    if (local_neigh_lookup(local_idx, ip, mac_out) == 0)
        return 0;
    if (kernel_arp_lookup(ifname, ip, mac_out) == 0) {
        local_neigh_learn(local_idx, ip, mac_out);
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

int local_hwaddr_prepare(struct app_config *cfg)
{
    if (!cfg || cfg->local_count <= 0)
        return 0;

    for (int i = 0; i < cfg->local_count; i++)
        (void)read_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);
    return 0;
}

int local_hwaddr_install(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    local_neigh_reset();
    for (int i = 0; i < fwd->cfg->local_count; i++) {
        (void)read_iface_hwaddr(fwd->cfg->locals[i].ifname, fwd->cfg->locals[i].src_mac);
        if (i < fwd->local_count)
            memcpy(fwd->locals[i].src_mac, fwd->cfg->locals[i].src_mac, MAC_LEN);
    }
    return 0;
}
