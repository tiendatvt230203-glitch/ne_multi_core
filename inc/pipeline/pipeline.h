#ifndef PIPELINE_H
#define PIPELINE_H

#include "../core/forwarder.h"
#include "../core/interface.h"

void pipeline_egress(struct forwarder *fwd, struct ne_packet job);
void pipeline_ingress(struct forwarder *fwd, struct ne_packet job);

#endif
