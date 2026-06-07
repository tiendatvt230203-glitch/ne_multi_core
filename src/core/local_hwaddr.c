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

    for (int i = 0; i < fwd->cfg->local_count; i++) {
        (void)read_iface_hwaddr(fwd->cfg->locals[i].ifname, fwd->cfg->locals[i].src_mac);
        if (i < fwd->local_count)
            memcpy(fwd->locals[i].src_mac, fwd->cfg->locals[i].src_mac, MAC_LEN);
    }
    return 0;
}
