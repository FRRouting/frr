/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/*
 * File:	vnc_zebra.h
 */

#ifndef _QUAGGA_BGP_VNC_ZEBRA_H
#define _QUAGGA_BGP_VNC_ZEBRA_H

#include "lib/zebra.h"

extern void vnc_zebra_add_prefix(struct bgp *bgp,
				 struct rfapi_import_table *import_table,
				 struct route_node *rn);

extern void vnc_zebra_del_prefix(struct bgp *bgp,
				 struct rfapi_import_table *import_table,
				 struct route_node *rn);

extern void vnc_zebra_add_nve(struct bgp *bgp, struct rfapi_descriptor *rfd);

extern void vnc_zebra_del_nve(struct bgp *bgp, struct rfapi_descriptor *rfd);

extern void vnc_zebra_add_group(struct bgp *bgp,
				struct rfapi_nve_group_cfg *rfg);

extern void vnc_zebra_del_group(struct bgp *bgp,
				struct rfapi_nve_group_cfg *rfg);

extern void vnc_zebra_reexport_group_afi(struct bgp *bgp,
					 struct rfapi_nve_group_cfg *rfg,
					 afi_t afi);

extern int vnc_redistribute_set(struct bgp *bgp, afi_t afi, int type);

extern int vnc_redistribute_unset(struct bgp *bgp, afi_t afi, int type);

#endif /* _QUAGGA_BGP_VNC_ZEBRA_H */
