#include "../../inc/core/bridge_mac.h"
#include "../../inc/core/forwarder.h"
#include "../../inc/crypto/packet_crypto.h"
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

#ifndef NE_DEFAULT_FAKE_ETHERTYPE_IPV4
#define NE_DEFAULT_FAKE_ETHERTYPE_IPV4 0x88B5u
#endif

static int g_peer_macs_ready;

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

static int mac_is_valid_peer(const uint8_t mac[MAC_LEN]) {
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

static void log_local_peer_mac(const char *ifname, const uint8_t peer[MAC_LEN]) {
    uint8_t loc[MAC_LEN];
    if (read_local_iface_hwaddr(ifname, loc) == 0) {
        fprintf(stderr,
                "[LOCAL-MAC] %s local %02x:%02x:%02x:%02x:%02x:%02x peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                loc[0], loc[1], loc[2], loc[3], loc[4], loc[5],
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    } else {
        fprintf(stderr,
                "[LOCAL-MAC] %s peer %02x:%02x:%02x:%02x:%02x:%02x\n",
                ifname,
                peer[0], peer[1], peer[2], peer[3], peer[4], peer[5]);
    }
}

static int mac_set_peer(struct app_config *cfg, int li, const uint8_t mac[MAC_LEN]) {
    if (!cfg || li < 0 || li >= cfg->local_count || !mac_is_valid_peer(mac))
        return -1;
    if (mac_is_own_local(cfg, li, mac)) {
        fprintf(stderr,
                "[LOCAL-MAC] %s ignoring own interface MAC as peer\n",
                cfg->locals[li].ifname);
        return -1;
    }
    memcpy(cfg->locals[li].dst_mac, mac, MAC_LEN);
    log_local_peer_mac(cfg->locals[li].ifname, mac);
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

static int read_bridge_master(const char *ifname, char *out, size_t out_sz) {
    if (!ifname || !out || out_sz == 0)
        return -1;

    char path[256];
    snprintf(path, sizeof(path), "/sys/class/net/%s/master", ifname);

    char link_buf[256];
    ssize_t n = readlink(path, link_buf, sizeof(link_buf) - 1);
    if (n <= 0)
        return -1;
    link_buf[n] = '\0';

    char *name = strrchr(link_buf, '/');
    name = name ? name + 1 : link_buf;
    if (!name[0])
        return -1;

    size_t len = strlen(name);
    if (len >= out_sz)
        len = out_sz - 1;
    memcpy(out, name, len);
    out[len] = '\0';
    return 0;
}

static int fdb_line_matches_master(const char *line, const char *bridge_name) {
    if (!line || !strstr(line, " master "))
        return 0;
    if (strstr(line, " self") || strstr(line, " permanent") || strstr(line, " vlan "))
        return 0;
    if (!bridge_name || !bridge_name[0])
        return 1;

    char needle[96];
    snprintf(needle, sizeof(needle), " master %s", bridge_name);
    return strstr(line, needle) != NULL;
}

static int mac_load_from_bridge_fdb(struct app_config *cfg) {
    if (!cfg)
        return 0;

    int loaded = 0;
    for (int li = 0; li < cfg->local_count; li++) {
        struct local_config *loc = &cfg->locals[li];
        if (!ifname_is_safe(loc->ifname))
            continue;

        char bridge_name[IF_NAMESIZE] = {0};
        (void)read_bridge_master(loc->ifname, bridge_name, sizeof(bridge_name));

        char cmd[256];
        snprintf(cmd, sizeof(cmd), "bridge fdb show dev %s", loc->ifname);
        FILE *fp = popen(cmd, "r");
        if (!fp) {
            fprintf(stderr, "[LOCAL-MAC] %s bridge fdb command failed\n", loc->ifname);
            continue;
        }

        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (!fdb_line_matches_master(line, bridge_name))
                continue;

            char mac_tok[48];
            if (sscanf(line, "%47s", mac_tok) != 1)
                continue;

            uint8_t mac[MAC_LEN];
            if (parse_mac(mac_tok, mac) != 0 || !mac_is_valid_peer(mac))
                continue;
            if (mac_is_own_local(cfg, li, mac))
                continue;

            if (mac_set_peer(cfg, li, mac) == 0) {
                fprintf(stderr,
                        "[LOCAL-MAC] %s remote-peer %02x:%02x:%02x:%02x:%02x:%02x loaded from bridge fdb%s%s\n",
                        loc->ifname,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                        bridge_name[0] ? " master " : "",
                        bridge_name[0] ? bridge_name : "");
                loaded++;
                break;
            }
        }
        pclose(fp);

        if (mac_is_zero(loc->dst_mac)) {
            fprintf(stderr,
                    "[LOCAL-MAC] %s no peer MAC found in bridge fdb%s%s\n",
                    loc->ifname,
                    bridge_name[0] ? " master " : "",
                    bridge_name[0] ? bridge_name : "");
        }
    }

    return loaded;
}

static int bridge_mac_prepare_impl(struct app_config *cfg) {
    if (!cfg || cfg->local_count <= 0)
        return 0;
    if (g_peer_macs_ready)
        return 0;

    for (int i = 0; i < cfg->local_count; i++)
        (void)read_local_iface_hwaddr(cfg->locals[i].ifname, cfg->locals[i].src_mac);

    (void)mac_load_from_bridge_fdb(cfg);

    for (int i = 0; i < cfg->local_count; i++) {
        if (!mac_is_zero(cfg->locals[i].dst_mac))
            continue;
        fprintf(stderr,
                "[LOCAL-MAC] %s peer unknown; will learn from first LAN packet\n",
                cfg->locals[i].ifname);
    }

    g_peer_macs_ready = 1;
    return 0;
}

static int ne_rx_ipv4_header_csum_ok(const uint8_t *ip, int ihl) {
    uint32_t sum = 0;
    for (int i = 0; i < ihl; i += 2) {
        uint16_t w = ((uint16_t)ip[i] << 8);
        if (i + 1 < ihl)
            w |= ip[i + 1];
        sum += w;
    }
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return ((uint16_t)sum) == 0xffff;
}

void bridge_wan_rx_normalize_eth_ipv4(uint8_t *pkt, uint32_t pkt_len) {
    if (!pkt || pkt_len < 14 + 20)
        return;
    uint16_t et = ((uint16_t)pkt[12] << 8) | pkt[13];
    if (et == 0x0800 || et == 0x8100)
        return;

    const uint8_t *iph = pkt + 14;
    if ((iph[0] >> 4) != 4)
        return;
    int ihl = (iph[0] & 0x0F) * 4;
    if (ihl < 20 || ihl > 60 || pkt_len < 14 + (uint32_t)ihl)
        return;
    uint16_t tot = ((uint16_t)iph[2] << 8) | iph[3];
    if (tot < (uint16_t)ihl || pkt_len < 14 + (uint32_t)tot)
        return;
    if (!ne_rx_ipv4_header_csum_ok(iph, ihl))
        return;

    uint16_t fake4 = packet_crypto_get_fake_ethertype_ipv4();
    if (fake4 == 0)
        fake4 = NE_DEFAULT_FAKE_ETHERTYPE_IPV4;
    if (pkt[12] != (uint8_t)(fake4 >> 8))
        return;

    pkt[12] = 0x08;
    pkt[13] = 0x00;
}

int config_wan_bridge_mode(const struct app_config *cfg) {
    if (!cfg || cfg->wan_count <= 0)
        return 0;
    for (int i = 0; i < cfg->wan_count; i++) {
        if (cfg->wans[i].dst_ip == 0)
            return 1;
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

void bridge_mac_shutdown(void) {
    g_peer_macs_ready = 0;
}

void bridge_mac_learn_rx(struct forwarder *fwd, int local_idx,
                         const uint8_t *pkt, uint32_t pkt_len) {
    if (!fwd || !fwd->cfg || local_idx < 0 ||
        local_idx >= fwd->cfg->local_count ||
        !pkt || pkt_len < sizeof(struct ether_header))
        return;
}

int bridge_mac_local_for_dmac(struct forwarder *fwd,
                              const uint8_t *pkt, uint32_t pkt_len) {
    if (!fwd || !fwd->cfg || !pkt || pkt_len < sizeof(struct ether_header))
        return -1;

    const struct ether_header *eth = (const struct ether_header *)pkt;
    if (!mac_is_valid_peer(eth->ether_dhost))
        return -1;

    for (int i = 0; i < fwd->cfg->local_count; i++) {
        if (mac_is_zero(fwd->cfg->locals[i].dst_mac))
            continue;
        if (memcmp(eth->ether_dhost, fwd->cfg->locals[i].dst_mac, MAC_LEN) == 0)
            return i;
    }
    return -1;
}

void bridge_mac_sync_cfg_to_iface(struct forwarder *fwd) {
    bridge_mac_copy_local_macs(fwd);
}
