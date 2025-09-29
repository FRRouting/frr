/* Infiot Egress tracking
 * Copyright (C) 2023 Infiot Inc
 *
 * This file is part of GNU Zebra.
 */
#ifndef _ZEBRA_EGRESS_H
#define _ZEBRA_EGRESS_H

#include <zebra.h>
#include "hook.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct infiot_egress_t_ {
	int size;
	uint32_t nexthop[30];
	uint16_t cost[30];
	uint32_t dest;
	TAILQ_ENTRY(infiot_egress_t_) egress_q_entries;
}infiot_egress;

struct infiot_egress_hook {
	int size;
	uint32_t nexthop[30];
	uint16_t cost[30];
	uint32_t dest;
};

DECLARE_HOOK(egress_update, (struct infiot_egress_hook * rn, const char *reason),
	     (rn, reason));
#ifdef __cplusplus
}
#endif

#endif
