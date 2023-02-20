// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP Conditional advertisement
 * Copyright (C) 2020  Samsung R&D Institute India - Bangalore.
 *			Madhurilatha Kuruganti
 */

#ifndef _FRR_BGP_CONDITION_ADV_H
#define _FRR_BGP_CONDITION_ADV_H
#include <zebra.h>
#include "prefix.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Macro to log debug message */
#define bgp_cond_adv_debug(...)                                                \
	do {                                                                   \
		if (BGP_DEBUG(cond_adv, COND_ADV))                             \
			zlog_debug("" __VA_ARGS__);                            \
	} while (0)

/* Polling time for monitoring condition-map routes in route table */
#define DEFAULT_CONDITIONAL_ROUTES_POLL_TIME 60

extern void bgp_conditional_adv_enable(struct peer *peer, afi_t afi,
				       safi_t safi);
extern void bgp_conditional_adv_disable(struct peer *peer, afi_t afi,
					safi_t safi);
extern int peer_advertise_map_set(struct peer *peer, afi_t afi, safi_t safi,
				  const char *advertise_name,
				  struct route_map *advertise_map,
				  const char *condition_name,
				  struct route_map *condition_map,
				  bool condition);
extern int peer_advertise_map_unset(struct peer *peer, afi_t afi, safi_t safi,
				    const char *advertise_name,
				    struct route_map *advertise_map,
				    const char *condition_name,
				    struct route_map *condition_map,
				    bool condition);
#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CONDITION_ADV_H */
