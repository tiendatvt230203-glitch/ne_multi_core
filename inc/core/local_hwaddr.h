#ifndef LOCAL_HWADDR_H
#define LOCAL_HWADDR_H

#include "config.h"

struct forwarder;

int local_hwaddr_prepare(struct app_config *cfg);
int local_hwaddr_install(struct forwarder *fwd);

#endif
