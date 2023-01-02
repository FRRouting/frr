/* Opaque data for Zebra from other daemons.
 *
 * Copyright (C) 2021 Donatas Abraitis <donatas.abraitis@gmail.com>
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef FRR_ROUTE_OPAQUE_H
#define FRR_ROUTE_OPAQUE_H

#include "assert.h"
#include "zclient.h"

/* copied from bgpd/bgp_community.h */
#define COMMUNITY_SIZE 4
/* copied from bgpd/bgp_lcommunity.h */
#define LCOMMUNITY_SIZE 12
/* copied from bgpd/bgp_route.h */
#define BGP_MAX_SELECTION_REASON_STR_BUF 32

struct bgp_zebra_opaque {
	char aspath[256];

	/* Show at least 10 communities AA:BB */
	char community[COMMUNITY_SIZE * 20];

	/* Show at least 10 large-communities AA:BB:CC */
	char lcommunity[LCOMMUNITY_SIZE * 30];

	/* 32 bytes seems enough because of
	 * bgp_path_selection_confed_as_path which is
	 * `Confederation based AS Path`.
	 */
	char selection_reason[BGP_MAX_SELECTION_REASON_STR_BUF];
};

struct ospf_zebra_opaque {
	char path_type[32];
	char area_id[INET_ADDRSTRLEN];
	char tag[16];
};

static_assert(sizeof(struct bgp_zebra_opaque) <= ZAPI_MESSAGE_OPAQUE_LENGTH,
              "BGP opaque data shouldn't be larger than zebra's buffer");
static_assert(sizeof(struct ospf_zebra_opaque) <= ZAPI_MESSAGE_OPAQUE_LENGTH,
              "OSPF opaque data shouldn't be larger than zebra's buffer");

#endif /* FRR_ROUTE_OPAQUE_H */
