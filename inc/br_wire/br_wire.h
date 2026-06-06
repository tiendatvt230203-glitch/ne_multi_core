#ifndef BR_WIRE_H
#define BR_WIRE_H

#include "../core/config.h"

struct forwarder;

int br_wire_prepare(struct app_config *cfg);
int br_wire_install(struct forwarder *fwd);

int br_wire_wan_dp_for_local(const struct forwarder *fwd, int local_idx);
int br_wire_local_for_wan_dp(const struct forwarder *fwd, int wan_dp);

#endif
