#include "../../inc/core/debug_perf.h"

#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DBG_LOG_DEFAULT "/tmp/ne-debug-dfdcf7.log"
#define DBG_SESSION     "dfdcf7"

static int perf_on = -1;
static uint64_t last_tick_ms;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;

static atomic_uint_fast64_t c_loc_rx;
static atomic_uint_fast64_t c_loc_recv_calls;
static atomic_uint_fast64_t c_loc_push_fail;
static atomic_uint_fast64_t c_loc_idle;
static atomic_uint_fast64_t c_loc_tx;
static atomic_uint_fast64_t c_wan_rx;
static atomic_uint_fast64_t c_wan_recv_calls;
static atomic_uint_fast64_t c_wan_tx;
static atomic_uint_fast64_t c_wan_push_fail;
static atomic_uint_fast64_t c_wan_idle;
static atomic_uint_fast64_t c_wan_tx_stuck;
static atomic_uint_fast64_t c_mid_pop_local;
static atomic_uint_fast64_t c_mid_pop_wan;
static atomic_uint_fast64_t c_mid_bypass;
static atomic_uint_fast64_t c_mid_encrypt;
static atomic_uint_fast64_t c_mid_decrypt;
static atomic_uint_fast64_t c_mid_wan_pass;
static atomic_uint_fast64_t c_mid_idle[2];

static int perf_enabled(void)
{
    if (perf_on < 0) {
        const char *ev = getenv("NE_DEBUG_PERF");
        perf_on = (ev && ev[0] == '1' && ev[1] == '\0') ? 1 : 0;
    }
    return perf_on;
}

static const char *log_path(void)
{
    const char *p = getenv("NE_DEBUG_LOG");
    return (p && p[0]) ? p : DBG_LOG_DEFAULT;
}

static uint64_t mono_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
}

static uint64_t xchg_zero(atomic_uint_fast64_t *c)
{
    return atomic_exchange(c, 0);
}

static void write_line(const char *hypothesis_id, const char *msg, const char *json_data)
{
    FILE *f;
    uint64_t ts = mono_ms();

    pthread_mutex_lock(&log_lock);
    f = fopen(log_path(), "a");
    if (f) {
        fprintf(f,
                "{\"sessionId\":\"%s\",\"timestamp\":%llu,\"hypothesisId\":\"%s\","
                "\"location\":\"debug_perf.c\",\"message\":\"%s\",\"data\":%s}\n",
                DBG_SESSION, (unsigned long long)ts, hypothesis_id, msg, json_data);
        fclose(f);
    }
    pthread_mutex_unlock(&log_lock);
}

void dbg_perf_local_rx(int n)
{
    if (perf_enabled() && n > 0)
        atomic_fetch_add(&c_loc_rx, (uint64_t)n);
}

void dbg_perf_local_recv_call(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_loc_recv_calls, 1);
}

void dbg_perf_local_push_fail(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_loc_push_fail, 1);
}

void dbg_perf_local_idle(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_loc_idle, 1);
}

void dbg_perf_local_tx(int n)
{
    if (perf_enabled() && n > 0)
        atomic_fetch_add(&c_loc_tx, (uint64_t)n);
}

void dbg_perf_wan_rx(int n)
{
    if (perf_enabled() && n > 0)
        atomic_fetch_add(&c_wan_rx, (uint64_t)n);
}

void dbg_perf_wan_recv_call(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_wan_recv_calls, 1);
}

void dbg_perf_wan_tx(int n)
{
    if (perf_enabled() && n > 0)
        atomic_fetch_add(&c_wan_tx, (uint64_t)n);
}

void dbg_perf_wan_push_fail(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_wan_push_fail, 1);
}

void dbg_perf_wan_idle(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_wan_idle, 1);
}

void dbg_perf_wan_tx_stuck(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_wan_tx_stuck, 1);
}

void dbg_perf_mid_pop_local(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_mid_pop_local, 1);
}

void dbg_perf_mid_pop_wan(void)
{
    if (perf_enabled())
        atomic_fetch_add(&c_mid_pop_wan, 1);
}

void dbg_perf_mid_local(int worker, int bypass, int encrypt)
{
    (void)worker;
    if (!perf_enabled())
        return;
    if (bypass)
        atomic_fetch_add(&c_mid_bypass, 1);
    if (encrypt)
        atomic_fetch_add(&c_mid_encrypt, 1);
}

void dbg_perf_mid_wan(int worker, int decrypt, int passthrough)
{
    (void)worker;
    if (!perf_enabled())
        return;
    if (decrypt)
        atomic_fetch_add(&c_mid_decrypt, 1);
    if (passthrough)
        atomic_fetch_add(&c_mid_wan_pass, 1);
}

void dbg_perf_mid_idle(int worker)
{
    if (perf_enabled() && worker >= 0 && worker < 2)
        atomic_fetch_add(&c_mid_idle[worker], 1);
}

void dbg_perf_tick(struct forwarder *fwd)
{
    uint64_t now, dt;
    uint64_t loc_rx, loc_tx, wan_rx, wan_tx;
    uint64_t loc_calls, wan_calls;
    uint64_t mid_pop_l, mid_pop_w;
    uint64_t bypass, encrypt, decrypt, wan_pass;
    uint64_t loc_idle, wan_idle;
    uint64_t loc_pf, wan_pf, wan_stuck;
    uint64_t mid_idle0, mid_idle1;
    uint64_t loc_rx_pps, wan_tx_pps, mid_bypass_pps, mid_pop_l_pps;
    uint64_t loc_avg_batch, wan_avg_batch;
    uint32_t l2m0 = 0, m2w = 0, w2m0 = 0, m2l = 0;
    char buf[1536];

    if (!perf_enabled() || !fwd)
        return;

    now = mono_ms();
    if (last_tick_ms == 0) {
        last_tick_ms = now;
        return;
    }
    dt = now - last_tick_ms;
    if (dt < 1000)
        return;
    last_tick_ms = now;

    loc_rx = xchg_zero(&c_loc_rx);
    loc_calls = xchg_zero(&c_loc_recv_calls);
    loc_tx = xchg_zero(&c_loc_tx);
    wan_rx = xchg_zero(&c_wan_rx);
    wan_calls = xchg_zero(&c_wan_recv_calls);
    wan_tx = xchg_zero(&c_wan_tx);
    mid_pop_l = xchg_zero(&c_mid_pop_local);
    mid_pop_w = xchg_zero(&c_mid_pop_wan);
    bypass = xchg_zero(&c_mid_bypass);
    encrypt = xchg_zero(&c_mid_encrypt);
    decrypt = xchg_zero(&c_mid_decrypt);
    wan_pass = xchg_zero(&c_mid_wan_pass);
    loc_idle = xchg_zero(&c_loc_idle);
    wan_idle = xchg_zero(&c_wan_idle);
    loc_pf = xchg_zero(&c_loc_push_fail);
    wan_pf = xchg_zero(&c_wan_push_fail);
    wan_stuck = xchg_zero(&c_wan_tx_stuck);
    mid_idle0 = xchg_zero(&c_mid_idle[0]);
    mid_idle1 = xchg_zero(&c_mid_idle[1]);

    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        l2m0 += ne_ring_count(&fwd->local_to_mid[w]);
    for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
        w2m0 += ne_ring_count(&fwd->wan_to_mid[w]);
    for (int wi = 0; wi < fwd->wan_count; wi++)
        m2w += fwd_mid_to_wan_depth(fwd, wi);
    for (int li = 0; li < fwd->local_count; li++) {
        for (int w = 0; w < (int)NE_CRYPTO_WORKERS; w++)
            m2l += ne_ring_count(&fwd->mid_to_local[li][w]);
    }

    loc_rx_pps = loc_rx * 1000 / dt;
    wan_tx_pps = wan_tx * 1000 / dt;
    mid_bypass_pps = bypass * 1000 / dt;
    mid_pop_l_pps = mid_pop_l * 1000 / dt;
    loc_avg_batch = loc_calls ? loc_rx / loc_calls : 0;
    wan_avg_batch = wan_calls ? wan_rx / wan_calls : 0;

    snprintf(buf, sizeof(buf),
             "{\"dt_ms\":%llu,"
             "\"loc_rx_pps\":%llu,\"loc_tx_pps\":%llu,\"wan_rx_pps\":%llu,\"wan_tx_pps\":%llu,"
             "\"loc_avg_batch\":%llu,\"wan_avg_batch\":%llu,"
             "\"mid_pop_local_pps\":%llu,\"mid_pop_wan_pps\":%llu,"
             "\"mid_bypass_pps\":%llu,\"mid_encrypt_pps\":%llu,\"mid_decrypt_pps\":%llu,"
             "\"loc_idle\":%llu,\"wan_idle\":%llu,\"mid_idle0\":%llu,\"mid_idle1\":%llu,"
             "\"loc_push_fail\":%llu,\"wan_push_fail\":%llu,\"wan_tx_stuck\":%llu,"
             "\"ring_l2m\":%u,\"ring_m2w\":%u,\"ring_w2m\":%u,\"ring_m2l\":%u}",
             (unsigned long long)dt,
             (unsigned long long)loc_rx_pps,
             (unsigned long long)(loc_tx * 1000 / dt),
             (unsigned long long)(wan_rx * 1000 / dt),
             (unsigned long long)wan_tx_pps,
             (unsigned long long)loc_avg_batch,
             (unsigned long long)wan_avg_batch,
             (unsigned long long)mid_pop_l_pps,
             (unsigned long long)(mid_pop_w * 1000 / dt),
             (unsigned long long)mid_bypass_pps,
             (unsigned long long)(encrypt * 1000 / dt),
             (unsigned long long)(decrypt * 1000 / dt),
             (unsigned long long)loc_idle, (unsigned long long)wan_idle,
             (unsigned long long)mid_idle0, (unsigned long long)mid_idle1,
             (unsigned long long)loc_pf, (unsigned long long)wan_pf,
             (unsigned long long)wan_stuck,
             l2m0, m2w, w2m0, m2l);

    write_line("SUMMARY", "per_sec_throughput", buf);

    /* TX core 11: mid_to_wan đầy hoặc wan_tx < loc_rx */
    if (m2w > NE_RING / 4 || (loc_rx_pps > 50000 && wan_tx_pps + loc_rx_pps / 20 < loc_rx_pps))
        write_line("TX11", "wan_tx_bottleneck",
                   "{\"ring_m2w_high\":true,\"hint\":\"core11 TX hoặc XDP wakeup\"}");
    /* RX core 0: batch nhỏ, loc_rx thấp */
    if (loc_avg_batch > 0 && loc_avg_batch < 24 && loc_rx_pps < 280000)
        write_line("RX0", "local_rx_small_batch",
                   "{\"loc_avg_batch_low\":true,\"hint\":\"core0 RX không fill batch 64\"}");
    /* Mid: pop_local < loc_rx hoặc ring_l2m tích */
    if (l2m0 > NE_RING / 4 ||
        (loc_rx_pps > 50000 && mid_pop_l_pps + loc_rx_pps / 20 < loc_rx_pps))
        write_line("MID", "mid_slower_than_rx",
                   "{\"ring_l2m_high\":true,\"hint\":\"core3/4 pop 1 gói/vòng\"}");
    /* Ring đầy giữa các hop */
    if (loc_pf > 0 || wan_pf > 0)
        write_line("RING", "ring_push_fail",
                   "{\"push_fail\":true,\"hint\":\"ring overflow giữa hop\"}");
    if (wan_stuck > 100)
        write_line("TX11", "wan_tx_ring_full", "{\"wan_tx_stuck\":true}");
    /* Chuỗi cân bằng — trần đồng bộ */
    if (loc_rx_pps > 50000 &&
        loc_rx_pps <= wan_tx_pps + loc_rx_pps / 20 &&
        loc_rx_pps <= mid_pop_l_pps + loc_rx_pps / 20 &&
        l2m0 < NE_RING / 8 && m2w < NE_RING / 8)
        write_line("SYNC", "balanced_pipeline_cap",
                   "{\"hint\":\"cả chuỗi cùng trần ~200K, không backlog\"}");
    if (encrypt > 0 && decrypt > 0 &&
        (encrypt * 1000 / dt) < (bypass * 1000 / dt) * 8 / 10)
        write_line("CRYPTO", "encrypt_slower_than_bypass", "{\"encrypt_lt_bypass\":true}");
}
