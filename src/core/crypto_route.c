#include "../../inc/core/crypto_route.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_layer2.h"

#include <arpa/inet.h>
#include <stddef.h>

static const uint8_t ne_worker_cpus[NE_CRYPTO_WORKERS] = { 0, 1, 2, 3 };

static __thread int tls_crypto_worker_idx;

void dp_crypto_worker_bind(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        worker_idx = 0;
    tls_crypto_worker_idx = worker_idx;
}

int dp_crypto_current_worker_idx(void)
{
    return tls_crypto_worker_idx;
}

static void normalize_flow_5tuple_host(uint32_t *src_ip, uint32_t *dst_ip,
                                       uint16_t *src_port, uint16_t *dst_port)
{
    uint32_t a, b;

    if (!src_ip || !dst_ip || !src_port || !dst_port)
        return;

    a = ntohl(*src_ip);
    b = ntohl(*dst_ip);
    if (a > b || (a == b && *src_port > *dst_port)) {
        uint32_t tmp_ip = *src_ip;
        *src_ip = *dst_ip;
        *dst_ip = tmp_ip;

        uint16_t tmp_p = *src_port;
        *src_port = *dst_port;
        *dst_port = tmp_p;
    }
}

uint8_t dp_crypto_flow_core_id(uint32_t src_ip, uint32_t dst_ip,
                               uint16_t src_port, uint16_t dst_port,
                               uint8_t protocol)
{
    uint32_t hash;

    normalize_flow_5tuple_host(&src_ip, &dst_ip, &src_port, &dst_port);
    hash = src_ip ^ dst_ip;
    hash ^= ((uint32_t)src_port << 16) | dst_port;
    hash ^= protocol;
    hash ^= (hash >> 16);
    hash *= 0x85ebca6bU;
    hash ^= (hash >> 13);
    hash *= 0xc2b2ae35U;
    hash ^= (hash >> 16);
    return (uint8_t)(hash % NE_CRYPTO_WORKERS);
}

uint8_t dp_crypto_worker_cpu(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return ne_worker_cpus[0];
    return ne_worker_cpus[worker_idx];
}

int dp_crypto_l2_affinity_ok(const uint8_t *pkt, uint32_t len)
{
    uint8_t core_id;

    if (crypto_layer2_read_core_id(pkt, len, &core_id) != 0)
        return 1;
    if (core_id >= NE_CRYPTO_WORKERS)
        return 0;
    return (int)core_id == dp_crypto_current_worker_idx();
}

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t core_id = 0;

    if (!fwd || !pkt)
        return 0;

    if (!fwd->cfg || !fwd->cfg->crypto_enabled)
        return 0;

    if (!fwd_crypto_has_l2_marker(pkt, len)) {
        if (!frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx))
            return 0;
    }

    if (crypto_layer2_read_core_id(pkt, len, &core_id) != 0)
        return -1;
    if (core_id >= NE_CRYPTO_WORKERS)
        return -1;
    return (int)core_id;
}
