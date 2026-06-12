#ifndef PROFILE_IFACE_XDP_H
#define PROFILE_IFACE_XDP_H

#include "config.h"
#include "forwarder.h"

/*
 * Incremental XDP for profile / LAN-row / WAN-row changes (merged active profiles).
 *
 * LAN row ADD (independent or via new profile):
 *   Another active profile already uses this ifname -> skip (xdp/id already on NIC).
 *   First use in merged config                         -> plumb + attach xdp/id.
 *
 * LAN row REMOVE:
 *   Any other active profile still references ifname -> keep xdp/id.
 *   No profile left with this ifname                 -> detach xdp/id.
 *
 * WAN row ADD:
 *   Always new (WAN is per-profile) -> plumb + attach xdp/id.
 *
 * WAN row REMOVE:
 *   WAN left merged config -> detach xdp/id immediately (no share check).
 */

enum profile_iface_xdp_reload_mode {
    PROFILE_IFACE_XDP_ADD = 10,
    PROFILE_IFACE_XDP_REMOVE = 11,
    PROFILE_IFACE_XDP_DELTA = 12,
};

int profile_iface_xdp_can_add(const struct app_config *old, const struct app_config *new);
int profile_iface_xdp_can_remove(const struct app_config *old, const struct app_config *new);
int profile_iface_xdp_can_delta(const struct app_config *old, const struct app_config *new);

int profile_iface_xdp_apply_add(struct forwarder *fwd, struct app_config *cfg);
int profile_iface_xdp_apply_remove(struct forwarder *fwd, struct app_config *cfg);
int profile_iface_xdp_apply_delta(struct forwarder *fwd, struct app_config *cfg);

/* ne_pair_open: BPF/XDP bind after AF_XDP queues exist. */
int profile_iface_xdp_bind_local(struct ne_pair *p, const struct app_config *cfg, int pair_li);
int profile_iface_xdp_bind_wan(struct ne_pair *p, const struct app_config *cfg, int dp_slot,
                               uint16_t fake_ethertype_ipv4);

/* Mid-core reload worker (called from forwarder_reload). */
int profile_iface_xdp_reload_impl(struct forwarder *fwd, struct app_config *cfg,
                                  enum profile_iface_xdp_reload_mode mode);

#endif
