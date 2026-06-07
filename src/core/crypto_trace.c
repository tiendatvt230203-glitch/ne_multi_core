#include "../../inc/core/crypto_trace.h"

#include <arpa/inet.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FLOW_LOG_SLOTS 8192u
#define FLOW_LOG_PROBE 32u

struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t proto;
    uint8_t _pad;
};

struct flow_slot {
    struct flow_key key;
    uint8_t used;
};

static int trace_enabled = -1;
static struct flow_slot enc_slots[FLOW_LOG_SLOTS];
static struct flow_slot dec_slots[FLOW_LOG_SLOTS];
static pthread_mutex_t enc_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t dec_lock = PTHREAD_MUTEX_INITIALIZER;

static void trace_init_once(void)
{
    const char *ev = getenv("NE_CRYPTO_TRACE");
    /* Mặc định tắt; bật khi debug: export NE_CRYPTO_TRACE=1 */
    trace_enabled = (ev && ev[0] == '1' && ev[1] == '\0') ? 1 : 0;
}

static int trace_on(void)
{
    if (trace_enabled < 0)
        trace_init_once();
    return trace_enabled;
}

static uint32_t flow_hash(const struct flow_key *k)
{
    uint32_t h = 2166136261u;
    const uint8_t *b = (const uint8_t *)k;
    size_t i;

    for (i = 0; i < sizeof(*k); i++) {
        h ^= b[i];
        h *= 16777619u;
    }
    return h;
}

static int flow_key_equal(const struct flow_key *a, const struct flow_key *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

static int flow_first_time(struct flow_slot *slots, pthread_mutex_t *lock,
                           uint32_t src_ip, uint32_t dst_ip,
                           uint16_t src_port, uint16_t dst_port, uint8_t proto)
{
    struct flow_key key;
    uint32_t idx;
    uint32_t i;

    memset(&key, 0, sizeof(key));
    key.src_ip = src_ip;
    key.dst_ip = dst_ip;
    key.src_port = src_port;
    key.dst_port = dst_port;
    key.proto = proto;
    idx = flow_hash(&key) % FLOW_LOG_SLOTS;

    pthread_mutex_lock(lock);
    for (i = 0; i < FLOW_LOG_PROBE; i++) {
        uint32_t slot = (idx + i) % FLOW_LOG_SLOTS;
        struct flow_slot *s = &slots[slot];

        if (!s->used) {
            s->key = key;
            s->used = 1;
            pthread_mutex_unlock(lock);
            return 1;
        }
        if (flow_key_equal(&s->key, &key)) {
            pthread_mutex_unlock(lock);
            return 0;
        }
    }
    pthread_mutex_unlock(lock);
    return 0;
}

static void fmt_ip(char *buf, size_t bufsz, uint32_t ip)
{
    struct in_addr a;

    a.s_addr = ip;
    if (!inet_ntop(AF_INET, &a, buf, (socklen_t)bufsz))
        snprintf(buf, bufsz, "0.0.0.0");
}

void crypto_trace_encrypt(const char *layer,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto, uint8_t core_id)
{
    char sip[32], dip[32];

    if (!trace_on())
        return;
    if (!flow_first_time(enc_slots, &enc_lock, src_ip, dst_ip, src_port, dst_port, proto))
        return;

    fmt_ip(sip, sizeof(sip), src_ip);
    fmt_ip(dip, sizeof(dip), dst_ip);
    fprintf(stderr,
            "[CRYPTO-ENC] core=%u %s:%u -> %s:%u proto=%u %s\n",
            (unsigned)core_id, sip, (unsigned)src_port, dip, (unsigned)dst_port,
            (unsigned)proto, layer ? layer : "");
    fflush(stderr);
}

void crypto_trace_decrypt(const char *layer,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port,
                          uint8_t proto,
                          uint8_t wire_core_id, uint8_t handler_core_id)
{
    char sip[32], dip[32];

    if (!trace_on())
        return;
    if (!flow_first_time(dec_slots, &dec_lock, src_ip, dst_ip, src_port, dst_port, proto))
        return;

    fmt_ip(sip, sizeof(sip), src_ip);
    fmt_ip(dip, sizeof(dip), dst_ip);
    fprintf(stderr,
            "[CRYPTO-DEC] wire=%u handler=%u %s:%u -> %s:%u proto=%u %s\n",
            (unsigned)wire_core_id, (unsigned)handler_core_id,
            sip, (unsigned)src_port, dip, (unsigned)dst_port,
            (unsigned)proto, layer ? layer : "");
    fflush(stderr);
}

void crypto_trace_maybe_summary(void)
{
}
