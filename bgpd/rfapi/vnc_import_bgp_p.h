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

#ifndef _QUAGGA_RFAPI_VNC_IMPORT_BGP_P_H_
#define _QUAGGA_RFAPI_VNC_IMPORT_BGP_P_H_

#include "lib/zebra.h"
#include "lib/prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

extern void vnc_import_bgp_exterior_add_route_interior(
	struct bgp *bgp, struct rfapi_import_table *it,
	struct route_node *rn_interior, /* VPN IT node */
	struct bgp_info *bi_interior);  /* VPN IT route */

extern void vnc_import_bgp_exterior_del_route_interior(
	struct bgp *bgp, struct rfapi_import_table *it,
	struct route_node *rn_interior, /* VPN IT node */
	struct bgp_info *bi_interior);  /* VPN IT route */

extern void
vnc_import_bgp_exterior_redist_enable_it(struct bgp *bgp, afi_t afi,
					 struct rfapi_import_table *it_only);

#endif /* _QUAGGA_RFAPI_VNC_IMPORT_BGP_P_H_ */
