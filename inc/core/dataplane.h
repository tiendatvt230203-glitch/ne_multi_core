#ifndef DATAPLANE_H
#define DATAPLANE_H

#include "../pipeline/pipeline.h"

static inline void dataplane_process_local(struct forwarder *fwd, struct ne_packet job)
{
    pipeline_egress(fwd, job);
}

static inline void dataplane_process_wan(struct forwarder *fwd, struct ne_packet job)
{
    pipeline_ingress(fwd, job);
}

#endif
