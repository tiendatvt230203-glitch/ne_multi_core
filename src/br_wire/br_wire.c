#include "../../inc/br_wire/br_wire.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/main_diag.h"

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

static int wan_cfg_for_br_id(const struct app_config *cfg, int br_id)
{
    if (!cfg || br_id < 0)
        return -1;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (!cfg->wans[i].dataplane)
            continue;
        if (cfg->wans[i].br_id == br_id)
            return i;
    }
    return -1;
}

static int br_wire_build_maps(struct forwarder *fwd)
{
    if (!fwd || !fwd->cfg)
        return -1;

    for (int i = 0; i < MAX_INTERFACES; i++) {
        fwd->local_to_wan_dp[i] = -1;
        fwd->wan_dp_to_local[i] = -1;
    }

    for (int li = 0; li < fwd->local_count; li++) {
        int ci = wan_cfg_for_br_id(fwd->cfg, fwd->cfg->locals[li].br_id);
        int dp = config_wan_cfg_to_dp(fwd->cfg, ci);
        if (dp < 0)
            return -1;
        fwd->local_to_wan_dp[li] = dp;
        fwd->wan_dp_to_local[dp] = li;
    }
    return 0;
}

int config_br_validate(const struct app_config *cfg)
{
    int dp_wans = 0;

    if (!cfg)
        return -1;

    for (int i = 0; i < cfg->wan_count; i++) {
        if (cfg->wans[i].dataplane)
            dp_wans++;
    }

    if (cfg->local_count <= 0 || dp_wans <= 0) {
        fprintf(stderr, "[BR] need at least one LAN and one dataplane WAN\n");
        return -1;
    }
    if (cfg->local_count != dp_wans) {
        fprintf(stderr, "[BR] LAN count (%d) must equal dataplane WAN count (%d)\n",
                cfg->local_count, dp_wans);
        return -1;
    }

    for (int li = 0; li < cfg->local_count; li++) {
        int br = cfg->locals[li].br_id;
        int wi = wan_cfg_for_br_id(cfg, br);
        if (wi < 0) {
            fprintf(stderr, "[BR] LAN %s br_id=%d has no matching dataplane WAN\n",
                    cfg->locals[li].ifname, br);
            return -1;
        }
        for (int lj = li + 1; lj < cfg->local_count; lj++) {
            if (cfg->locals[lj].br_id == br) {
                fprintf(stderr, "[BR] duplicate br_id=%d on LAN %s and %s\n",
                        br, cfg->locals[li].ifname, cfg->locals[lj].ifname);
                return -1;
            }
        }
    }

    for (int i = 0; i < cfg->wan_count; i++) {
        if (!cfg->wans[i].dataplane)
            continue;
        int br = cfg->wans[i].br_id;
        int found = 0;
        for (int li = 0; li < cfg->local_count; li++) {
            if (cfg->locals[li].br_id == br) {
                found = 1;
                break;
            }
        }
        if (!found) {
            fprintf(stderr, "[BR] WAN %s br_id=%d has no matching LAN\n",
                    cfg->wans[i].ifname, br);
            return -1;
        }
    }
    return 0;
}

int br_wire_prepare(struct app_config *cfg)
{
    if (!cfg)
        return -1;
    if (config_br_validate(cfg) != 0)
        return -1;

    for (int i = 0; i < cfg->local_count; i++) {
        memset(cfg->locals[i].dst_mac, 0, MAC_LEN);
        (void)read_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);
    }
    for (int i = 0; i < cfg->wan_count; i++) {
        if (cfg->wans[i].dst_ip != 0)
            continue;
        uint8_t hw[MAC_LEN];
        if (read_iface_hwaddr(cfg->wans[i].ifname, hw) == 0)
            memcpy(cfg->wans[i].src_mac, hw, MAC_LEN);
    }
    return 0;
}

int br_wire_install(struct forwarder *fwd)
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
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = fwd->wan_cfg_idx[di];
        if (ci < 0 || ci >= fwd->cfg->wan_count)
            continue;
        uint8_t hw[MAC_LEN];
        if (read_iface_hwaddr(fwd->cfg->wans[ci].ifname, hw) == 0) {
            memcpy(fwd->cfg->wans[ci].src_mac, hw, MAC_LEN);
            memcpy(fwd->wans[di].src_mac, hw, MAC_LEN);
        }
    }

    if (br_wire_build_maps(fwd) != 0)
        return -1;

    main_diag_log_br_wire_table(fwd->cfg);
    fprintf(stderr, "[BR-WIRE] dataplane ready (no per-packet trace)\n");
    fflush(stderr);
    return 0;
}

int br_wire_wan_dp_for_local(const struct forwarder *fwd, int local_idx)
{
    if (!fwd || local_idx < 0 || local_idx >= fwd->local_count)
        return -1;
    return fwd->local_to_wan_dp[local_idx];
}

int br_wire_local_for_wan_dp(const struct forwarder *fwd, int wan_dp)
{
    if (!fwd || wan_dp < 0 || wan_dp >= fwd->wan_count)
        return -1;
    return fwd->wan_dp_to_local[wan_dp];
}
