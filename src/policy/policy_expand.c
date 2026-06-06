#include "../../inc/policy/policy.h"

#include <stdio.h>
#include <string.h>

static int str_is_any(const char *v)
{
    if (!v)
        return 1;
    while (*v == ' ' || *v == '\t')
        v++;
    return (v[0] == '\0');
}

static int parse_port_range(const char *v, int *from_out, int *to_out)
{
    if (str_is_any(v)) {
        *from_out = -1;
        *to_out = -1;
        return 0;
    }
    int a = -1, b = -1;
    if (sscanf(v, "%d-%d", &a, &b) == 2 && a >= 0 && b >= a && b <= 65535) {
        *from_out = a;
        *to_out = b;
        return 0;
    }
    if (sscanf(v, "%d", &a) == 1 && a >= 0 && a <= 65535) {
        *from_out = a;
        *to_out = a;
        return 0;
    }
    return -1;
}

static int parse_cidr_any_or_negated(const char *v_in, int *any_out, int *neg_out,
                                     uint32_t *net_out, uint32_t *mask_out)
{
    if (!any_out || !neg_out || !net_out || !mask_out)
        return -1;

    *any_out = 1;
    *neg_out = 0;
    *net_out = 0;
    *mask_out = 0;

    if (str_is_any(v_in))
        return 0;

    while (*v_in == ' ' || *v_in == '\t')
        v_in++;
    if (v_in[0] == '!') {
        *neg_out = 1;
        v_in++;
        while (*v_in == ' ' || *v_in == '\t')
            v_in++;
    }

    uint32_t ip = 0, mask = 0, net = 0;
    if (parse_ip_cidr_pub(v_in, &ip, &mask, &net) != 0)
        return -1;

    *any_out = 0;
    *net_out = net;
    *mask_out = mask;
    return 0;
}

static void cidr_buf_with_invert(char *buf, size_t bufsz, const char *tok, int invert_db)
{
    int max_body = (int)((bufsz > 2) ? bufsz - 2 : 0);
    if (invert_db && tok[0] != '!')
        snprintf(buf, bufsz, "!%.*s", max_body, tok);
    else
        snprintf(buf, bufsz, "%.*s", (int)(bufsz - 1), tok);
}

int policy_expand_cartesian(struct app_config *cfg, struct profile_config *prof,
                            const struct crypto_policy *base,
                            int invert_src, int invert_dst,
                            const char src_items[][POLICY_CIDR_ITEM_LEN], int src_n,
                            const char dst_items[][POLICY_CIDR_ITEM_LEN], int dst_n,
                            const char sp_items[][POLICY_CIDR_ITEM_LEN], int sp_n,
                            const char dp_items[][POLICY_CIDR_ITEM_LEN], int dp_n)
{
    if (!cfg || !prof || !base || src_n <= 0 || dst_n <= 0 || sp_n <= 0 || dp_n <= 0)
        return -1;

    for (int si = 0; si < src_n; si++) {
        for (int di = 0; di < dst_n; di++) {
            for (int spi = 0; spi < sp_n; spi++) {
                for (int dpi = 0; dpi < dp_n; dpi++) {
                    if (cfg->policy_count >= MAX_CRYPTO_POLICIES ||
                        prof->policy_count >= MAX_CRYPTO_POLICIES)
                        return -1;

                    struct crypto_policy *cp = &cfg->policies[cfg->policy_count];
                    *cp = *base;

                    if (parse_port_range(sp_items[spi], &cp->src_port_from, &cp->src_port_to) != 0) {
                        cp->src_port_from = -1;
                        cp->src_port_to = -1;
                    }
                    if (parse_port_range(dp_items[dpi], &cp->dst_port_from, &cp->dst_port_to) != 0) {
                        cp->dst_port_from = -1;
                        cp->dst_port_to = -1;
                    }

                    char src_buf[POLICY_CIDR_ITEM_LEN + 2];
                    char dst_buf[POLICY_CIDR_ITEM_LEN + 2];
                    cidr_buf_with_invert(src_buf, sizeof(src_buf), src_items[si], invert_src);
                    cidr_buf_with_invert(dst_buf, sizeof(dst_buf), dst_items[di], invert_dst);

                    if (parse_cidr_any_or_negated(src_buf, &cp->src_any, &cp->src_negate,
                                                  &cp->src_net, &cp->src_mask) != 0) {
                        cp->src_any = 1;
                        cp->src_negate = 0;
                        cp->src_net = 0;
                        cp->src_mask = 0;
                    }
                    if (parse_cidr_any_or_negated(dst_buf, &cp->dst_any, &cp->dst_negate,
                                                  &cp->dst_net, &cp->dst_mask) != 0) {
                        cp->dst_any = 1;
                        cp->dst_negate = 0;
                        cp->dst_net = 0;
                        cp->dst_mask = 0;
                    }

                    prof->policy_indices[prof->policy_count++] = cfg->policy_count;
                    cfg->policy_count++;
                }
            }
        }
    }
    return 0;
}
