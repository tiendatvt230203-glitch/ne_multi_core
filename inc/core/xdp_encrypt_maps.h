#ifndef XDP_ENCRYPT_MAPS_H
#define XDP_ENCRYPT_MAPS_H

#include <stdint.h>

#define MAX_PROFILES_BPF 32
#define MAX_ENCRYPT_PACK_BPF 128

#define XDP_RULE_SRC_ANY 1u
#define XDP_RULE_DST_ANY 2u
#define XDP_RULE_SRC_NEG 4u
#define XDP_RULE_DST_NEG 8u

struct xdp_encrypt_rule_user {
    uint32_t src_net;
    uint32_t src_mask;
    uint32_t dst_net;
    uint32_t dst_mask;
    uint32_t flags;
    uint8_t protocol;
    uint8_t pad[3];
    int32_t src_port_from;
    int32_t src_port_to;
    int32_t dst_port_from;
    int32_t dst_port_to;
};

struct xdp_profile_meta_user {
    uint32_t enabled;
    uint32_t enc_start;
    uint32_t enc_num;
};

struct xdp_encrypt_ctrl_user {
    uint32_t profile_count;
    uint32_t require_filter;
};

#endif
