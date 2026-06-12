#include "../../inc/core/frag_bench.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int frag_only_mode;

void ne_frag_only_init_from_env(void)
{
    const char *v = getenv("NE_FRAG_ONLY");

    frag_only_mode = 0;
    if (!v || !*v || strcmp(v, "0") == 0)
        return;
    if (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0) {
        frag_only_mode = 1;
        fprintf(stderr,
                "[FRAG_ONLY] L2 encrypt policy: split+reassemble only (no crypto)\n");
    }
}

int ne_frag_only_active(void)
{
    return frag_only_mode;
}
