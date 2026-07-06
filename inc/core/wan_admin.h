#ifndef WAN_ADMIN_H
#define WAN_ADMIN_H

#include "config.h"

int wan_admin_is_down(int profile_id, const char *ifname);

int wan_admin_down(int profile_id, const char *ifname);
int wan_admin_up(int profile_id, const char *ifname);

/* DB weight + equal share of admin-down WAN weights (runtime only). */
int wan_admin_effective_weight(const struct profile_config *p,
                               const struct app_config *cfg,
                               int cfg_wan_idx);

int wan_admin_validate_wan(const struct app_config *cfg,
                             int profile_id, const char *ifname);

/* Returns 1 if DOWN would leave zero usable WANs in the profile. */
int wan_admin_would_leave_pool(const struct app_config *cfg,
                               int profile_id, const char *ifname);

#endif
