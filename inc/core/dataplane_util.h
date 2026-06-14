#ifndef DATAPLANE_UTIL_H
#define DATAPLANE_UTIL_H

#include "forwarder.h"

int dp_parse_flow(void *pkt, uint32_t len,
                  uint32_t *src_ip, uint32_t *dst_ip,
                  uint16_t *src_port, uint16_t *dst_port, uint8_t *proto);

uint32_t dp_dest_ipv4(void *pkt, uint32_t len);

#endif
