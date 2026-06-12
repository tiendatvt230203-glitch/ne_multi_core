#include "../../inc/core/frag_bench.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static int frag_only_mode;

void ne_frag_only_enable(void)
{
    if (frag_only_mode)
        return;
    frag_only_mode = 1;
    fprintf(stderr,
            "[FRAG_ONLY] L2 encrypt policy: split+reassemble only (no crypto)\n");
}

void ne_frag_only_init_from_env(void)
{
    const char *v;

    if (frag_only_mode)
        return;
    v = getenv("NE_FRAG_ONLY");
    if (!v || !*v || strcmp(v, "0") == 0)
        return;
    if (strcmp(v, "1") == 0 || strcasecmp(v, "true") == 0 || strcasecmp(v, "yes") == 0)
        ne_frag_only_enable();
}

int ne_frag_only_active(void)
{
    return frag_only_mode;
}
