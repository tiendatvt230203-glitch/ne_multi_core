#include "../../inc/core/forwarder.h"
#include "../../inc/routing/wan_pick.h"
#include "../../inc/crypto/runtime.h"
#include "../../inc/lan_neigh/lan_neigh.h"
#include "../../inc/core/interface.h"

#include <net/if.h>
#include <stdatomic.h>
#include <string.h>

extern atomic_int running;

static void init_iface_meta(struct xsk_interface *iface, const char *ifname,
                            const uint8_t src_mac[MAC_LEN],
                            const uint8_t dst_mac[MAC_LEN])
{
    memset(iface, 0, sizeof(*iface));
    iface->ifindex = if_nametoindex(ifname);
    strncpy(iface->ifname, ifname, sizeof(iface->ifname) - 1);
    iface->ifname[sizeof(iface->ifname) - 1] = '\0';
    iface->queue_count = 0;
    iface->ring_size = NE_RING;
    iface->batch_size = NE_BATCH_SIZE;
    iface->frame_size = NE_FRAME;
    memcpy(iface->src_mac, src_mac, MAC_LEN);
    memcpy(iface->dst_mac, dst_mac, MAC_LEN);
}

int forwarder_init(struct forwarder *fwd, struct app_config *cfg)
{
    if (!fwd || !cfg || cfg->local_count <= 0 || config_count_dataplane_wans(cfg) <= 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    memset(fwd, 0, sizeof(*fwd));
    fwd->cfg = cfg;
    fwd->local_count = cfg->local_count;
    fwd->wan_count = config_count_dataplane_wans(cfg);
    if (fwd->local_count > MAX_INTERFACES)
        fwd->local_count = MAX_INTERFACES;
    if (fwd->wan_count > MAX_INTERFACES)
        fwd->wan_count = MAX_INTERFACES;

    for (int i = 0; i < fwd->local_count; i++)
        init_iface_meta(&fwd->locals[i], cfg->locals[i].ifname,
                        cfg->locals[i].src_mac, cfg->locals[i].dst_mac);
    for (int di = 0; di < fwd->wan_count; di++) {
        int ci = config_wan_dp_to_cfg(cfg, di);
        if (ci < 0)
            return -1;
        fwd->wan_cfg_idx[di] = ci;
        init_iface_meta(&fwd->wans[di], cfg->wans[ci].ifname,
                        cfg->wans[ci].src_mac, cfg->wans[ci].dst_mac);
    }

    interface_ip_xdp_off_config(cfg);
    interface_reset_redirect_maps();

    if (lan_neigh_prepare(cfg) != 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    if (fwd_crypto_rebuild(cfg) != 0)
        return -1;
    if (forwarder_should_stop())
        return -1;

    fwd_crypto_reset_on_init();
    if (fwd_crypto_ensure_profile_slots(cfg) != 0)
        return -1;

    if (ne_pair_open(&fwd->pair, cfg) != 0)
        return -1;
    if (forwarder_should_stop()) {
        forwarder_cleanup(fwd);
        return -1;
    }

    if (ne_ring_init(&fwd->local_to_mid, NE_RING) != 0 ||
        ne_ring_init(&fwd->wan_to_mid, NE_RING) != 0) {
        forwarder_cleanup(fwd);
        return -1;
    }
    for (int i = 0; i < fwd->local_count; i++) {
        if (ne_ring_init(&fwd->mid_to_local[i], NE_RING) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }
    for (int i = 0; i < fwd->wan_count; i++) {
        if (ne_ring_init(&fwd->mid_to_wan[i], NE_RING) != 0) {
            forwarder_cleanup(fwd);
            return -1;
        }
    }

    (void)lan_neigh_install(fwd);
    fwd_wan_reset_on_init(fwd);

    atomic_store_explicit(&running, 1, memory_order_release);
    return 0;
}

void forwarder_cleanup(struct forwarder *fwd)
{
    if (!fwd)
        return;
    lan_neigh_reset();
    ne_ring_destroy(&fwd->local_to_mid);
    ne_ring_destroy(&fwd->wan_to_mid);
    for (int i = 0; i < MAX_INTERFACES; i++)
        ne_ring_destroy(&fwd->mid_to_wan[i]);
    for (int i = 0; i < MAX_INTERFACES; i++)
        ne_ring_destroy(&fwd->mid_to_local[i]);
    fwd_crypto_cleanup_all_profile_slots();
    ne_pair_close(&fwd->pair);
}
