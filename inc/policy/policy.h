#ifndef POLICY_H
#define POLICY_H

#include "../core/config.h"

#define POLICY_CIDR_LIST_MAX   32
#define POLICY_CIDR_ITEM_LEN   96

int policy_match_packet(const struct crypto_policy *cp,
                        uint32_t src_ip, uint32_t dst_ip,
                        uint16_t src_port, uint16_t dst_port,
                        uint8_t protocol);

const struct crypto_policy *policy_select_in_profile(struct app_config *cfg,
                                                     int profile_idx,
                                                     uint32_t src_ip, uint32_t dst_ip,
                                                     uint16_t src_port, uint16_t dst_port,
                                                     uint8_t protocol);

int policy_profile_for_local(const struct app_config *cfg, int local_idx);

int policy_resolve_egress(const struct app_config *cfg, int local_idx, int flow_ok,
                          uint32_t src_ip, uint32_t dst_ip,
                          uint16_t src_port, uint16_t dst_port, uint8_t proto,
                          int *profile_idx, const struct crypto_policy **cp);

void policy_log_egress_miss(const struct app_config *cfg, int local_idx, int flow_ok,
                            uint32_t src_ip, uint32_t dst_ip,
                            uint16_t src_port, uint16_t dst_port, uint8_t proto);

int policy_expand_cartesian(struct app_config *cfg, struct profile_config *prof,
                            const struct crypto_policy *base,
                            int invert_src, int invert_dst,
                            const char src_items[][POLICY_CIDR_ITEM_LEN], int src_n,
                            const char dst_items[][POLICY_CIDR_ITEM_LEN], int dst_n,
                            const char sp_items[][POLICY_CIDR_ITEM_LEN], int sp_n,
                            const char dp_items[][POLICY_CIDR_ITEM_LEN], int dp_n);

#endif
