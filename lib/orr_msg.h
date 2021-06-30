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

typedef enum orr_igp {
	ORR_IGP_NONE = 0,
	ORR_IGP_ISIS,
	ORR_IGP_OSPF,
	ORR_IGP_OSPF6,
	ORR_IGP_MAX
} orr_igp;

/* BGP-IGP Register for IGP metric */
struct orr_igp_metric_reg {
	safi_t safi;
	struct prefix prefix;
};

/* IGP-BGP message structures */
struct orr_igp_metric_info {
	/* IGP instance data. */
	orr_igp igp;
	uint32_t instId;

	safi_t safi;

	/* IGP metric from Active Root. */
	struct prefix root;
	uint32_t num_entries;
	struct {
		uint32_t metric;
		struct prefix prefix;
	} nexthop[0];
};

/* Prototypes. */

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ORR_MSG_H */
