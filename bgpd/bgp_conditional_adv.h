/*
 * BGP Conditional advertisement
 * Copyright (C) 2020  Samsung R&D Institute India - Bangalore.
 *			Madhurilatha Kuruganti
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

/* Polling time for monitoring condition-map routes in route table */
#define DEFAULT_CONDITIONAL_ROUTES_POLL_TIME 60

extern void bgp_conditional_adv_enable(struct peer *peer, afi_t afi,
				       safi_t safi);
extern void bgp_conditional_adv_disable(struct peer *peer, afi_t afi,
					safi_t safi);
#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CONDITION_ADV_H */
