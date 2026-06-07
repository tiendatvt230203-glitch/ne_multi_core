#ifndef FORWARDER_RELOAD_H
#define FORWARDER_RELOAD_H

#include "config.h"
#include "forwarder.h"

int forwarder_same_topology(const struct app_config *a, const struct app_config *b);
int forwarder_is_wan_only_removal(const struct app_config *old, const struct app_config *new);

int forwarder_reload_config(struct forwarder *fwd, struct app_config *cfg);
int forwarder_reload_wan_removal(struct forwarder *fwd, struct app_config *cfg);

/* Called from middle core while holding forwarder runtime lock. */
int fwd_reload_apply_if_pending(void);

void fwd_reload_shutdown(void);

#endif
