#include "../../inc/core/local_hwaddr.h"
#include "../../inc/core/forwarder.h"

#include <net/if.h>
#include <net/if_arp.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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

static void bridge_wan_hwaddr(struct wan_config *wan)
{
    static const uint8_t zero[MAC_LEN];

    if (!wan || wan->dst_ip != 0)
        return;
    if (memcmp(wan->src_mac, zero, MAC_LEN) != 0)
        return;
    (void)read_iface_hwaddr(wan->ifname, wan->src_mac);
}

int local_hwaddr_prepare(struct app_config *cfg)
{
    if (!cfg)
        return 0;

    for (int i = 0; i < cfg->local_count; i++)
        (void)read_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);
    for (int i = 0; i < cfg->wan_count; i++)
        bridge_wan_hwaddr(&cfg->wans[i]);
    return 0;
}

int local_hwaddr_install(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    for (int i = 0; i < fwd->cfg->local_count; i++) {
        (void)read_iface_hwaddr(fwd->cfg->locals[i].ifname, fwd->cfg->locals[i].src_mac);
        if (i < fwd->local_count)
            memcpy(fwd->locals[i].src_mac, fwd->cfg->locals[i].src_mac, MAC_LEN);
    }
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = fwd->wan_cfg_idx[di];
        if (ci < 0 || ci >= fwd->cfg->wan_count)
            continue;
        bridge_wan_hwaddr(&fwd->cfg->wans[ci]);
        memcpy(fwd->wans[di].src_mac, fwd->cfg->wans[ci].src_mac, MAC_LEN);
    }
    return 0;
}
