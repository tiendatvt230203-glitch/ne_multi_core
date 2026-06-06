#ifndef INTERFACE_INTERNAL_H
#define INTERFACE_INTERNAL_H

#include "../core/interface.h"

int ne_pool_init(struct ne_pool *p, uint32_t cap);
void ne_pool_destroy(struct ne_pool *p);
uint32_t ne_pool_push(struct ne_pool *p, const uint64_t *addrs, uint32_t n);
uint32_t ne_pool_pop(struct ne_pool *p, uint64_t *addrs, uint32_t n);

#endif
