#include "../../inc/policy/policy.h"

static int cidr_match_with_negate(int any_flag, int negate,
                                  uint32_t ip, uint32_t net, uint32_t mask)
{
    if (any_flag)
        return 1;
    int in_cidr = ((ip & mask) == (net & mask));
    return negate ? !in_cidr : in_cidr;
}

int policy_match_packet(const struct crypto_policy *cp,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t protocol)
{
    if (!cp)
        return 0;
    if (!cidr_match_with_negate(cp->src_any, cp->src_negate, src_ip, cp->src_net, cp->src_mask))
        return 0;
    if (!cidr_match_with_negate(cp->dst_any, cp->dst_negate, dst_ip, cp->dst_net, cp->dst_mask))
        return 0;

#if !CRYPTO_POLICY_MATCH_IP_ONLY
    if (cp->src_port_from >= 0 && cp->src_port_to >= 0) {
        if ((int)src_port < cp->src_port_from || (int)src_port > cp->src_port_to)
            return 0;
    }
    if (cp->dst_port_from >= 0 && cp->dst_port_to >= 0) {
        if ((int)dst_port < cp->dst_port_from || (int)dst_port > cp->dst_port_to)
            return 0;
    }
#endif

    if (cp->protocol == POLICY_PROTO_TCP_UDP) {
        if (protocol != 6 && protocol != 17)
            return 0;
    } else if (cp->protocol != POLICY_PROTO_ANY && cp->protocol != protocol) {
        return 0;
    }

    return 1;
}
