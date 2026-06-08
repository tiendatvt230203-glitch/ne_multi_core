#ifndef DEBUG_PERF_H
#define DEBUG_PERF_H

#include "forwarder.h"

/* Bật: export NE_DEBUG_PERF=1
 * Log NDJSON: export NE_DEBUG_LOG=/path/debug-dfdcf7.log (mặc định: .cursor/debug-dfdcf7.log) */

void dbg_perf_local_rx(int n);
void dbg_perf_local_recv_call(void);
void dbg_perf_local_push_fail(void);
void dbg_perf_local_idle(void);
void dbg_perf_local_tx(int n);

void dbg_perf_wan_rx(int n);
void dbg_perf_wan_recv_call(void);
void dbg_perf_wan_tx(int n);
void dbg_perf_wan_push_fail(void);
void dbg_perf_wan_idle(void);
void dbg_perf_wan_tx_stuck(void);

void dbg_perf_mid_pop_local(void);
void dbg_perf_mid_pop_wan(void);
void dbg_perf_mid_local(int worker, int bypass, int encrypt);
void dbg_perf_mid_wan(int worker, int decrypt, int passthrough);
void dbg_perf_mid_idle(int worker);

void dbg_perf_tick(struct forwarder *fwd);

#endif
