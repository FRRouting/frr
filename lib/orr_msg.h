/*
 * Structures common to BGP, OSPF and ISIS for BGP Optimal Route Reflection
 * Copyright (C) 2021 Samsung R&D Institute India - Bangalore.
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

#ifndef _FRR_ORR_MSG_H
#define _FRR_ORR_MSG_H

#ifdef __cplusplus
extern "C" {
#endif

/* Library code */
DEFINE_MTYPE_STATIC(LIB, ORR_MSG_INFO, "ORR Msg info");

/* REVISIT: Need to check if we can use zero length array */
#define ORR_MAX_PREFIX 100

struct orr_prefix_metric {
	struct prefix prefix;
	uint32_t metric;
};

/* BGP-IGP Register for IGP metric */
struct orr_igp_metric_reg {
	bool reg;
	uint8_t proto;
	safi_t safi;
	struct prefix prefix;
};

/* IGP-BGP message structures */
struct orr_igp_metric_info {
	/* IGP instance data. */
	uint8_t proto;
	uint32_t instId;

	safi_t safi;

	/* IGP metric from Active Root. */
	struct prefix root;
	uint32_t num_entries;
	struct orr_prefix_metric nexthop[ORR_MAX_PREFIX];
};

/* BGP ORR Root node */
struct orr_root {
	afi_t afi;
	safi_t safi;

	/* MPLS_TE prefix and router ID */
	struct prefix prefix;
	struct in_addr router_id;

	/* Advertising OSPF Router ID. */
	struct in_addr adv_router;

	/* BGP-ORR Received LSAs */
	struct ospf_lsa *router_lsa_rcvd;

	/* Routing tables from root node */
	struct route_table *old_table; /* Old routing table. */
	struct route_table *new_table; /* Current routing table. */

	struct route_table *old_rtrs; /* Old ABR/ASBR RT. */
	struct route_table *new_rtrs; /* New ABR/ASBR RT. */
};

/* Prototypes. */

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ORR_MSG_H */
