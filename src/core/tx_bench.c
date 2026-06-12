#include "../../inc/core/tx_bench.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

// #region agent log
#define AGENT_TX_BENCH_LOG "/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-dfdcf7.log"
// #endregion

static enum ne_tx_bench_dir bench_dir;
static uint32_t bench_pkt_len;
static int bench_inited;

void ne_tx_bench_init_from_env(void)
{
    const char *v = getenv("NE_TX_BENCH");

    bench_dir = NE_TX_BENCH_OFF;
    bench_pkt_len = 64;

    if (!v || !*v || strcmp(v, "0") == 0)
        return;

    if (strcmp(v, "1") == 0 || strcasecmp(v, "wan") == 0)
        bench_dir = NE_TX_BENCH_WAN;
    else if (strcasecmp(v, "local") == 0)
        bench_dir = NE_TX_BENCH_LOCAL;
    else
        return;

    v = getenv("NE_TX_BENCH_LEN");
    if (v && *v) {
        long n = strtol(v, NULL, 10);
        if (n >= 64 && n <= 1500)
            bench_pkt_len = (uint32_t)n;
    }

    bench_inited = 1;
    fprintf(stderr,
            "[TX_BENCH] enabled dir=%s pkt_len=%u (RX/crypto off — pure AF_XDP COPY TX)\n",
            bench_dir == NE_TX_BENCH_WAN ? "wan" : "local", bench_pkt_len);
}

int ne_tx_bench_active(void)
{
    return bench_inited && bench_dir != NE_TX_BENCH_OFF;
}

enum ne_tx_bench_dir ne_tx_bench_direction(void)
{
    return bench_dir;
}

uint32_t ne_tx_bench_pkt_len(void)
{
    return bench_pkt_len;
}

void ne_tx_bench_log_pps(const char *dir, int tx_slot, uint64_t sent_delta,
                         uint64_t tx_no_free_delta, uint32_t pool_avail)
{
    FILE *f = fopen(AGENT_TX_BENCH_LOG, "a");
    struct timespec ts;

    if (!f)
        return;
    clock_gettime(CLOCK_REALTIME, &ts);
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"TX_BENCH\","
            "\"location\":\"tx_bench.c\",\"message\":\"tx_bench_pps\","
            "\"timestamp\":%lld,\"data\":{\"dir\":\"%s\",\"tx_slot\":%d,"
            "\"sent_1s\":%llu,\"pps\":%llu,\"tx_no_free_1s\":%llu,"
            "\"pool_avail\":%u,\"pkt_len\":%u}}\n",
            (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000, dir, tx_slot,
            (unsigned long long)sent_delta, (unsigned long long)sent_delta,
            (unsigned long long)tx_no_free_delta, pool_avail, bench_pkt_len);
    fclose(f);
}
