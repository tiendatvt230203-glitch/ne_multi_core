#include "../../inc/core/cpu_map.h"

#include <stdio.h>
#include <string.h>

const uint8_t ne_cpu_rx_lan[NE_CLUSTER_RX_LAN] = { NE_CPU_RX_LAN0 };
const uint8_t ne_cpu_rx_wan[NE_CLUSTER_RX_WAN] = { NE_CPU_RX_WAN0 };
const uint8_t ne_cpu_tx[NE_CLUSTER_TX] = { NE_CPU_TX0, NE_CPU_TX1 };
const uint8_t ne_cpu_crypto[NE_CLUSTER_CRYPTO] = {
    NE_CPU_CRYPTO0, NE_CPU_CRYPTO1, NE_CPU_CRYPTO2,
    NE_CPU_CRYPTO3, NE_CPU_CRYPTO4, NE_CPU_CRYPTO5,
};

static void mark_cpu(uint8_t seen[256], uint8_t cpu, const char *label, int *dup)
{
    if (seen[cpu]) {
        fprintf(stderr, "[CPU-MAP] duplicate core %u (%s)\n", (unsigned)cpu, label);
        *dup = 1;
    }
    seen[cpu] = 1;
}

int ne_cpu_map_validate(void)
{
    uint8_t seen[256];
    int dup = 0;
    char label[32];

    memset(seen, 0, sizeof(seen));
    for (uint32_t i = 0; i < NE_CLUSTER_RX_LAN; i++) {
        snprintf(label, sizeof(label), "rx_lan[%u]", i);
        mark_cpu(seen, ne_cpu_rx_lan[i], label, &dup);
    }
    for (uint32_t i = 0; i < NE_CLUSTER_RX_WAN; i++) {
        snprintf(label, sizeof(label), "rx_wan[%u]", i);
        mark_cpu(seen, ne_cpu_rx_wan[i], label, &dup);
    }
    for (uint32_t i = 0; i < NE_CLUSTER_TX; i++) {
        snprintf(label, sizeof(label), "tx[%u]", i);
        mark_cpu(seen, ne_cpu_tx[i], label, &dup);
    }
    for (uint32_t i = 0; i < NE_CLUSTER_CRYPTO; i++) {
        snprintf(label, sizeof(label), "crypto[%u]", i);
        mark_cpu(seen, ne_cpu_crypto[i], label, &dup);
    }
    return dup ? -1 : 0;
}

void ne_cpu_map_log(void)
{
    fprintf(stderr, "[CPU] rx_lan=%u", (unsigned)NE_CLUSTER_RX_LAN);
    for (uint32_t i = 0; i < NE_CLUSTER_RX_LAN; i++)
        fprintf(stderr, " %u", (unsigned)ne_cpu_rx_lan[i]);
    fputc('\n', stderr);

    fprintf(stderr, "[CPU] rx_wan=%u", (unsigned)NE_CLUSTER_RX_WAN);
    for (uint32_t i = 0; i < NE_CLUSTER_RX_WAN; i++)
        fprintf(stderr, " %u", (unsigned)ne_cpu_rx_wan[i]);
    fputc('\n', stderr);

    fprintf(stderr, "[CPU] tx=%u", (unsigned)NE_CLUSTER_TX);
    for (uint32_t i = 0; i < NE_CLUSTER_TX; i++)
        fprintf(stderr, " %u", (unsigned)ne_cpu_tx[i]);
    fputc('\n', stderr);

    fprintf(stderr, "[CPU] crypto=%u", (unsigned)NE_CLUSTER_CRYPTO);
    for (uint32_t i = 0; i < NE_CLUSTER_CRYPTO; i++)
        fprintf(stderr, " %u", (unsigned)ne_cpu_crypto[i]);
    fputc('\n', stderr);
}
