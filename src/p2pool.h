#ifndef P2POOL_H
#define P2POOL_H

#include "ckpool.h"
#include "libckpool.h"

// Get P2Pool network difficulty via JSON-RPC
bool get_p2pool_difficulty(connsock_t *cs, double *difficulty);

#endif /* P2POOL_H */ 