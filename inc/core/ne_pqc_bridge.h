#ifndef NE_PQC_BRIDGE_H
#define NE_PQC_BRIDGE_H

#include <stdbool.h>
#include "config.h"

/* NE wiring around vendor PQC (src/crypto/pqc_*.c). Do not add APIs to vendor files. */

void ne_pqc_runtime_setup_profiles(struct app_config *cfg);
void ne_pqc_start_handshakes(struct app_config *cfg);

int ne_pqc_ensure_profile_binding(int profile_id);
int ne_pqc_default_local_fingerprint(char out_fp[16]);
bool ne_pqc_profile_binding_key_ready(int profile_id);

#endif
