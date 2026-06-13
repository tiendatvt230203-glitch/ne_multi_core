#include "../../inc/core/dataplane_util.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

// #region agent log
#define DP_AGENT_LOG_LOCAL "/home/tiendat/Downloads/NE/network-encryptor/.cursor/debug-dfdcf7.log"
#define DP_AGENT_LOG_CWD   ".cursor/debug-dfdcf7.log"

void dp_agent_log_drop(const char *hypothesis_id, const char *path,
                       const char *reason, uint32_t a, uint32_t b, uint16_t c, uint16_t d)
{
    static uint32_t budget = 40;
    FILE *f;

    if (budget == 0)
        return;
    budget--;
    fprintf(stderr,
            "[DATAPLANE] drop %s reason=%s a=%u b=%u c=%u d=%u\n",
            path, reason, a, b, (unsigned)c, (unsigned)d);
    f = fopen(DP_AGENT_LOG_CWD, "a");
    if (!f)
        f = fopen(DP_AGENT_LOG_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"%s\",\"location\":\"%s\","
            "\"message\":\"dataplane drop\",\"data\":{\"reason\":\"%s\",\"a\":%u,"
            "\"b\":%u,\"c\":%u,\"d\":%u},\"timestamp\":%ld}\n",
            hypothesis_id, path, reason, a, b, (unsigned)c, (unsigned)d,
            (long)(time(NULL) * 1000));
    fclose(f);
}

int dp_dest_is_nonunicast(const struct forwarder *fwd, uint32_t dest_ip)
{
    if (!fwd || !fwd->cfg || dest_ip == 0 || dest_ip == htonl(0xFFFFFFFFu))
        return 1;
    if ((ntohl(dest_ip) & 0xF0000000u) == 0xE0000000u)
        return 1;
    for (int i = 0; i < fwd->cfg->local_count; i++) {
        const struct local_config *local = &fwd->cfg->locals[i];
        uint32_t bcast = local->network | ~local->netmask;

        if (dest_ip == bcast)
            return 1;
    }
    return 0;
}

void dp_agent_log_fwd(const char *path, uint32_t dst_host, uint16_t dst_port, uint32_t len)
{
    static uint32_t budget = 20;
    FILE *f;

    if (budget == 0)
        return;
    budget--;
    fprintf(stderr,
            "[DATAPLANE] fwd %s dst=%u.%u.%u.%u dport=%u len=%u\n",
            path,
            (dst_host >> 24) & 0xFFu, (dst_host >> 16) & 0xFFu,
            (dst_host >> 8) & 0xFFu, dst_host & 0xFFu,
            (unsigned)dst_port, len);
    f = fopen(DP_AGENT_LOG_CWD, "a");
    if (!f)
        f = fopen(DP_AGENT_LOG_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"H6\",\"location\":\"%s\","
            "\"message\":\"dataplane forward\",\"data\":{\"dst_host\":%u,\"dport\":%u,"
            "\"len\":%u},\"timestamp\":%ld}\n",
            path, dst_host, (unsigned)dst_port, len, (long)(time(NULL) * 1000));
    fclose(f);
}

void dp_agent_log_encrypt_wan(uint8_t core_id, int wi, int wan_dp,
                              uint32_t dst_host, uint16_t dst_port, uint32_t len)
{
    static uint32_t budget = 40;
    FILE *f;

    if (budget == 0)
        return;
    budget--;
    fprintf(stderr,
            "[DATAPLANE] encrypt_wan core_id=%u wi=%d wan=%d dst=%u.%u.%u.%u dport=%u len=%u\n",
            (unsigned)core_id, wi, wan_dp,
            (dst_host >> 24) & 0xFFu, (dst_host >> 16) & 0xFFu,
            (dst_host >> 8) & 0xFFu, dst_host & 0xFFu,
            (unsigned)dst_port, len);
    f = fopen(DP_AGENT_LOG_CWD, "a");
    if (!f)
        f = fopen(DP_AGENT_LOG_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"H-B\",\"location\":"
            "\"dataplane_local.c:encrypt_wan\",\"message\":\"encrypt wan push\","
            "\"data\":{\"core_id\":%u,\"wi\":%d,\"wan_dp\":%d,\"dst_host\":%u,"
            "\"dport\":%u,\"len\":%u},\"timestamp\":%ld}\n",
            (unsigned)core_id, wi, wan_dp, dst_host, (unsigned)dst_port, len,
            (long)(time(NULL) * 1000));
    fclose(f);
}

void dp_agent_log_wan_recv(int wi, int wan_dp, uint32_t len, uint8_t core_id, uint16_t eth_type)
{
    static uint32_t budget = 50;
    FILE *f;

    if (budget == 0)
        return;
    budget--;
    fprintf(stderr,
            "[DATAPLANE] wan_recv wi=%d wan=%d len=%u core_id=%u eth=0x%04x\n",
            wi, wan_dp, len, (unsigned)core_id, (unsigned)eth_type);
    f = fopen(DP_AGENT_LOG_CWD, "a");
    if (!f)
        f = fopen(DP_AGENT_LOG_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"H-C\",\"location\":"
            "\"forwarder_pipeline.c:wan_recv\",\"message\":\"wan recv\","
            "\"data\":{\"wi\":%d,\"wan_dp\":%d,\"len\":%u,\"core_id\":%u,"
            "\"eth_type\":%u},\"timestamp\":%ld}\n",
            wi, wan_dp, len, (unsigned)core_id, (unsigned)eth_type,
            (long)(time(NULL) * 1000));
    fclose(f);
}

void dp_agent_log_wan_tx(int wi, int wan_dp, uint32_t len, int sent)
{
    static uint32_t budget = 40;
    FILE *f;

    if (budget == 0 || sent <= 0)
        return;
    budget--;
    fprintf(stderr,
            "[DATAPLANE] wan_tx wi=%d wan=%d len=%u sent=%d\n",
            wi, wan_dp, len, sent);
    f = fopen(DP_AGENT_LOG_CWD, "a");
    if (!f)
        f = fopen(DP_AGENT_LOG_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"H-E\",\"location\":"
            "\"forwarder_pipeline.c:wan_tx\",\"message\":\"wan xsk tx\","
            "\"data\":{\"wi\":%d,\"wan_dp\":%d,\"len\":%u,\"sent\":%d},"
            "\"timestamp\":%ld}\n",
            wi, wan_dp, len, sent, (long)(time(NULL) * 1000));
    fclose(f);
}

void dp_agent_log_wan_route(const char *event, uint8_t core_id,
                            int recv_wi, int target_wi, uint32_t pkt_len)
{
    static uint32_t budget = 60;
    FILE *f;

    if (budget == 0)
        return;
    budget--;
    fprintf(stderr,
            "[DATAPLANE] wan_route event=%s core_id=%u recv_wi=%d target_wi=%d len=%u\n",
            event, (unsigned)core_id, recv_wi, target_wi, pkt_len);
    f = fopen(DP_AGENT_LOG_CWD, "a");
    if (!f)
        f = fopen(DP_AGENT_LOG_LOCAL, "a");
    if (!f)
        return;
    fprintf(f,
            "{\"sessionId\":\"dfdcf7\",\"hypothesisId\":\"H-A\",\"location\":"
            "\"forwarder_pipeline.c:wan_route\",\"message\":\"wan route\","
            "\"data\":{\"event\":\"%s\",\"core_id\":%u,\"recv_wi\":%d,"
            "\"target_wi\":%d,\"len\":%u},\"timestamp\":%ld}\n",
            event, (unsigned)core_id, recv_wi, target_wi, pkt_len,
            (long)(time(NULL) * 1000));
    fclose(f);
}
// #endregion

int dp_parse_flow(void *pkt_data, uint32_t pkt_len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto)
{
    if (!pkt_data || pkt_len < sizeof(struct ether_header) + sizeof(struct iphdr))
        return -1;

    struct ether_header *eth = pkt_data;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return -1;

    struct iphdr *ip = (struct iphdr *)((uint8_t *)pkt_data + sizeof(*eth));
    uint32_t ihl = (uint32_t)ip->ihl * 4U;
    if (ihl < sizeof(struct iphdr) || pkt_len < sizeof(*eth) + ihl)
        return -1;

    *src_ip = ip->saddr;
    *dst_ip = ip->daddr;
    *proto = ip->protocol;
    *src_port = 0;
    *dst_port = 0;

    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        uint8_t *l4 = (uint8_t *)pkt_data + sizeof(*eth) + ihl;
        if (pkt_len < (uint32_t)(l4 - (uint8_t *)pkt_data + 4))
            return -1;
        uint16_t *ports = (uint16_t *)l4;
        *src_port = ntohs(ports[0]);
        *dst_port = ntohs(ports[1]);
    }
    return 0;
}

uint32_t dp_dest_ipv4(void *pkt, uint32_t len)
{
    uint32_t src = 0, dst = 0;
    uint16_t sp = 0, dp = 0;
    uint8_t proto = 0;
    if (dp_parse_flow(pkt, len, &src, &dst, &sp, &dp, &proto) != 0)
        return 0;
    return dst;
}

int dp_write_l2_src_only(uint8_t *pkt, uint32_t len, const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_write_l2(uint8_t *pkt, uint32_t len,
                const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN],
                int allow_empty_src)
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0)
        return -1;
    if (!allow_empty_src && memcmp(src, zero, MAC_LEN) == 0)
        return -1;
    memcpy(pkt, dst, MAC_LEN);
    memcpy(pkt + MAC_LEN, src, MAC_LEN);
    return 0;
}

int dp_apply_wan_l2(uint8_t *pkt, uint32_t len,
                    const uint8_t dst[MAC_LEN], const uint8_t src[MAC_LEN])
{
    static const uint8_t zero[MAC_LEN];

    if (!pkt || len < sizeof(struct ether_header))
        return -1;
    if (memcmp(dst, zero, MAC_LEN) == 0 || memcmp(src, zero, MAC_LEN) == 0)
        return 0;
    return dp_write_l2(pkt, len, dst, src, 0);
}

int dp_ring_push(struct forwarder *fwd, struct ne_ring *ring, struct ne_packet *pkt)
{
    if (pkt->len > fwd->pair.frame_size || ne_ring_try_push(ring, pkt) != 0) {
        ne_frame_free(&fwd->pair, pkt->addr);
        return -1;
    }
    return 0;
}
