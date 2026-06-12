#ifndef TX_BENCH_H
#define TX_BENCH_H

#include <stdint.h>

enum ne_tx_bench_dir {
    NE_TX_BENCH_OFF = 0,
    NE_TX_BENCH_WAN = 1,
    NE_TX_BENCH_LOCAL = 2,
};

void ne_tx_bench_init_from_env(void);
int ne_tx_bench_active(void);
enum ne_tx_bench_dir ne_tx_bench_direction(void);
uint32_t ne_tx_bench_pkt_len(void);

void ne_tx_bench_log_pps(const char *dir, int tx_slot, uint64_t sent_delta,
                         uint64_t tx_no_free_delta, uint32_t pool_avail);

#endif
