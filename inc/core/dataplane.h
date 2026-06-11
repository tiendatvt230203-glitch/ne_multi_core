#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "forwarder.h"

void dataplane_process_local(struct forwarder *fwd, struct ne_packet job);
void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job);

/* 1=handled on IO fast path, 0=use normal crypto-worker path, -1=dropped */
int dp_try_bypass_local_to_wan(struct forwarder *fwd, struct ne_packet *job);
int dp_try_bypass_wan_to_local(struct forwarder *fwd, struct ne_packet *job);

#endif
