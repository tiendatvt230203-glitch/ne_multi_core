#include "../../inc/core/bridge_mac.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/core/config.h"
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

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

static void log_local_dst_mac(const char *ifname, const uint8_t dst[MAC_LEN]) {
    uint8_t loc[MAC_LEN];
    if (read_local_iface_hwaddr(ifname, loc) == 0) {
        fprintf(stderr,
                "[LOCAL-MAC] %s local %02x:%02x:%02x:%02x:%02x:%02x dst %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                loc[0], loc[1], loc[2], loc[3], loc[4], loc[5],
                dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
    } else {
        fprintf(stderr,
                "[LOCAL-MAC] %s dst %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                dst[0], dst[1], dst[2], dst[3], dst[4], dst[5]);
    }
}

static int mac_set_fdb_dst(struct app_config *cfg, int li, const uint8_t mac[MAC_LEN]) {
    if (!cfg || li < 0 || li >= cfg->local_count || !mac_is_valid_dst(mac))
        return -1;
    if (mac_is_own_local(cfg, li, mac)) {
        fprintf(stderr,
                "[LOCAL-MAC] %s ignoring own interface MAC from bridge fdb\n",
                cfg->locals[li].ifname);
        return -1;
    }
    memcpy(cfg->locals[li].dst_mac, mac, MAC_LEN);
    log_local_dst_mac(cfg->locals[li].ifname, mac);
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

static int mac_load_from_bridge_fdb(struct app_config *cfg) {
    if (!cfg)
        return 0;

    int loaded = 0;
    for (int li = 0; li < cfg->local_count; li++) {
        struct local_config *loc = &cfg->locals[li];
        if (!ifname_is_safe(loc->ifname))
            continue;

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "bridge fdb show dev %s", loc->ifname);
        FILE *fp = popen(cmd, "r");
        if (!fp) {
            fprintf(stderr, "[LOCAL-MAC] %s bridge fdb command failed\n", loc->ifname);
            continue;
        }

        char line[512];
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

            if (mac_set_fdb_dst(cfg, li, mac) == 0) {
                fprintf(stderr,
                        "[LOCAL-MAC] %s dst %02x:%02x:%02x:%02x:%02x:%02x loaded from bridge fdb\n",
                        loc->ifname,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                loaded++;
                break;
            }
        }
        pclose(fp);

        if (mac_is_zero(loc->dst_mac)) {
            fprintf(stderr,
                    "[LOCAL-MAC] %s no dst MAC found in bridge fdb\n",
                    loc->ifname);
        }
    }

    return loaded;
}

static int bridge_mac_prepare_impl(struct app_config *cfg) {
    if (!cfg || cfg->local_count <= 0)
        return 0;

    for (int i = 0; i < cfg->local_count; i++)
        (void)read_local_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);

    (void)mac_load_from_bridge_fdb(cfg);
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

