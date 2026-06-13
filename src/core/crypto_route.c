#include "../../inc/core/crypto_route.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_layer2.h"

#include <arpa/inet.h>
#include <stddef.h>

static const uint8_t ne_crypto_cpus[NE_CRYPTO_WORKERS] = {
    NE_CPU_WORKER0,
    NE_CPU_WORKER1,
    NE_CPU_WORKER2,
    NE_CPU_WORKER3,
};

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

uint8_t dp_crypto_worker_cpu(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return NE_CPU_WORKER0;
    return ne_crypto_cpus[worker_idx];
}

int dp_crypto_worker_idx_for_cpu(uint8_t cpu_id)
{
    for (int i = 0; i < (int)NE_CRYPTO_WORKERS; i++) {
        if (ne_crypto_cpus[i] == cpu_id)
            return i;
    }
    return -1;
}

int dp_crypto_pick_local_worker(const uint8_t *pkt, uint32_t len)
{
    uint32_t src_ip = 0, dst_ip = 0;
    uint16_t src_port = 0, dst_port = 0;
    uint8_t proto = 0;
    uint32_t key;

    if (!pkt || len < 14)
        return 0;

    if (dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                      &src_port, &dst_port, &proto) != 0) {
        /* Không parse được 5-tuple: dùng byte L2 + len, tránh MAC-only cố định. */
        key = len;
        for (uint32_t i = 0; i < 14 && i < len; i++)
            key = key * 31u + pkt[i];
        return (int)((key >> 8) % NE_CRYPTO_WORKERS);
    }

    /* src^dst đổi theo connection: forward (src đổi) và return (dst đổi). */
    key = (uint32_t)(src_port ^ dst_port);
    key ^= ntohl(src_ip) ^ ntohl(dst_ip) ^ (uint32_t)proto;
    key *= 0x9E3779B1u;
    return (int)((key >> 15) % NE_CRYPTO_WORKERS);
}

int dp_crypto_pick_wan_worker(struct forwarder *fwd, const uint8_t *pkt, uint32_t len)
{
    uint16_t pid = 0;
    uint8_t fidx = 0;
    uint8_t core_id = 0;
    int wi;

    if (!fwd || !pkt)
        return 0;

    if (!fwd->cfg || !fwd->cfg->crypto_enabled)
        return 0;

    /* Fast path: almost all L2 crypto has fake ethertype + policy byte. */
    if (!fwd_crypto_has_l2_marker(pkt, len)) {
        if (!frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx))
            return 0;
    }

    /* L2 crypto: must land on the worker that owns frag_table for this core_id.
     * Fallback to worker 0 caused intermittent decrypt/reassembly hangs. */
    if (crypto_layer2_read_core_id(pkt, len, &core_id) != 0)
        return -1;

    wi = dp_crypto_worker_idx_for_cpu(core_id);
    if (wi < 0)
        return -1;
    return wi;
}
