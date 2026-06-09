#include "../../inc/core/agent_debug.h"

#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

// #region agent log
static _Atomic uint64_t ne_dbg_cnt_a;
static _Atomic uint64_t ne_dbg_cnt_b;
static _Atomic uint64_t ne_dbg_cnt_d;
static _Atomic uint64_t ne_dbg_cnt_e;
static _Atomic uint64_t ne_dbg_cnt_m;
static _Atomic uint64_t ne_dbg_cnt_x;

void ne_dbg_inc(const char *hypothesis_id)
{
    if (!hypothesis_id || !hypothesis_id[0])
        return;
    switch (hypothesis_id[0]) {
    case 'A': atomic_fetch_add_explicit(&ne_dbg_cnt_a, 1, memory_order_relaxed); break;
    case 'B': atomic_fetch_add_explicit(&ne_dbg_cnt_b, 1, memory_order_relaxed); break;
    case 'D': atomic_fetch_add_explicit(&ne_dbg_cnt_d, 1, memory_order_relaxed); break;
    case 'E': atomic_fetch_add_explicit(&ne_dbg_cnt_e, 1, memory_order_relaxed); break;
    case 'M': atomic_fetch_add_explicit(&ne_dbg_cnt_m, 1, memory_order_relaxed); break;
    case 'X': atomic_fetch_add_explicit(&ne_dbg_cnt_x, 1, memory_order_relaxed); break;
    default: break;
    }
}

void ne_agent_debug_flush_tick(unsigned tick)
{
    if ((tick & 4095u) != 0)
        return;

    FILE *f = fopen("/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-dfdcf7.log", "a");
    if (!f)
        return;

    uint64_t a = atomic_load_explicit(&ne_dbg_cnt_a, memory_order_relaxed);
    uint64_t b = atomic_load_explicit(&ne_dbg_cnt_b, memory_order_relaxed);
    uint64_t d = atomic_load_explicit(&ne_dbg_cnt_d, memory_order_relaxed);
    uint64_t e = atomic_load_explicit(&ne_dbg_cnt_e, memory_order_relaxed);
    uint64_t m = atomic_load_explicit(&ne_dbg_cnt_m, memory_order_relaxed);
    uint64_t x = atomic_load_explicit(&ne_dbg_cnt_x, memory_order_relaxed);

    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"location\":\"agent_debug.c:flush\","
            "\"message\":\"pkt_counters\",\"data\":{"
            "\"A_encrypt\":%llu,\"B_decrypt_ok\":%llu,\"D_frag\":%llu,\"E_decrypt_fail\":%llu,"
            "\"M_core_match\":%llu,\"X_core_mismatch\":%llu},"
            "\"timestamp\":%lld}\n",
            (unsigned long long)a, (unsigned long long)b,
            (unsigned long long)d, (unsigned long long)e,
            (unsigned long long)m, (unsigned long long)x,
            (long long)time(NULL) * 1000LL);
    fclose(f);
}
// #endregion
