#include "../../inc/core/crypto_route.h"
#include "../../inc/core/interface.h"
#include "../../inc/core/dataplane_util.h"
#include "../../inc/core/forwarder_crypto_runtime.h"
#include "../../inc/core/fragment.h"
#include "../../inc/crypto/crypto_layer2.h"

#include <stddef.h>

static const uint8_t ne_crypto_cpus[NE_CRYPTO_WORKERS] = {
    NE_CPU_MID,
    NE_CPU_CRYPTO_AUX,
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

static uint32_t flow_hash_mix(uint32_t h, uint32_t v)
{
    h ^= v;
    h *= 0x01000193u;
    return h;
}

uint8_t dp_crypto_worker_cpu(int worker_idx)
{
    if (worker_idx < 0 || worker_idx >= (int)NE_CRYPTO_WORKERS)
        return NE_CPU_MID;
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
    uint32_t h = 0x811c9dc5u;

    if (pkt && len >= 14 && dp_parse_flow((void *)pkt, len, &src_ip, &dst_ip,
                                          &src_port, &dst_port, &proto) == 0) {
        h = flow_hash_mix(h, src_ip);
        h = flow_hash_mix(h, dst_ip);
        h = flow_hash_mix(h, (uint32_t)src_port | ((uint32_t)dst_port << 16));
        h = flow_hash_mix(h, proto);
    } else if (pkt && len > 0) {
        uint32_t n = len < 14 ? len : 14;
        for (uint32_t i = 0; i < n; i++)
            h = flow_hash_mix(h, pkt[i]);
        h = flow_hash_mix(h, len);
    }

    return (int)(h % NE_CRYPTO_WORKERS);
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

    if (!frag_is_fragment_l2(fwd->cfg, pkt, len, &pid, &fidx) &&
        !fwd_crypto_has_l2_marker(pkt, len))
        return 0;

    if (crypto_layer2_read_core_id(pkt, len, &core_id) != 0)
        return 0;

    wi = dp_crypto_worker_idx_for_cpu(core_id);
    if (wi < 0)
        return 0;
    return wi;
}
