/*
 * OSPF BGP-IGP IGP metric update handling routines
 * Copyright (C) 2021 Samsung R&D Institute India - Bangalore.
 * 			Madhurilatha Kuruganti
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

#ifndef _ZEBRA_OSPF_ORR_H
#define _ZEBRA_OSPF_ORR_H

#define BGP_OSPF_LSINFINITY 65535

/* Macro to log debug message */
#define ospf_orr_debug(...)                                                    \
	do {                                                                   \
		if (IS_DEBUG_OSPF_ORR)                                         \
			zlog_debug("[OSPF-ORR] "__VA_ARGS__);                  \
	} while (0)


extern int ospf_orr_igp_metric_register(struct orr_igp_metric_reg orr_reg);
extern void ospf_orr_igp_metric_send_update(struct orr_root *root,
					    unsigned short instance);
extern void ospf_orr_root_table_update(struct ospf_lsa *lsa, bool add);
extern struct orr_root *ospf_get_orr(struct ospf *ospf, afi_t afi, safi_t safi);
extern void ospf_orr_root_update_rcvd_lsa(struct ospf_lsa *lsa);
extern void ospf_orr_route_install(struct orr_root *root,
				   struct route_table *rt);

#endif /* _ZEBRA_OSPF_ORR_H */
