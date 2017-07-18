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

#ifndef _QUAGGA_RFAPI_VNC_IMPORT_BGP_H_
#define _QUAGGA_RFAPI_VNC_IMPORT_BGP_H_

#include "lib/zebra.h"
#include "lib/prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

#define VALID_INTERIOR_TYPE(type)                                              \
	(((type) == ZEBRA_ROUTE_BGP) || ((type) == ZEBRA_ROUTE_BGP_DIRECT))

extern uint32_t calc_local_pref(struct attr *attr, struct peer *peer);

extern int vnc_prefix_cmp(void *pfx1, void *pfx2);

extern void vnc_import_bgp_add_route(struct bgp *bgp, struct prefix *prefix,
				     struct bgp_info *info);

extern void vnc_import_bgp_del_route(struct bgp *bgp, struct prefix *prefix,
				     struct bgp_info *info);

extern void vnc_import_bgp_redist_enable(struct bgp *bgp, afi_t afi);

extern void vnc_import_bgp_redist_disable(struct bgp *bgp, afi_t afi);

extern void vnc_import_bgp_exterior_redist_enable(struct bgp *bgp, afi_t afi);

extern void vnc_import_bgp_exterior_redist_disable(struct bgp *bgp, afi_t afi);


extern void vnc_import_bgp_exterior_add_route(
	struct bgp *bgp,	/* exterior instance, we hope */
	struct prefix *prefix,  /* unicast prefix */
	struct bgp_info *info); /* unicast info */

extern void
vnc_import_bgp_exterior_del_route(struct bgp *bgp,
				  struct prefix *prefix,  /* unicast prefix */
				  struct bgp_info *info); /* unicast info */

extern void vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix_rd *prd, /* RD */
	struct bgp_table *table_rd,		/* per-rd VPN route table */
	struct prefix *prefix,			/* VPN prefix */
	struct bgp_info *bi);			/* new VPN host route */

extern void vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix_rd *prd, /* RD */
	struct bgp_table *table_rd,		/* per-rd VPN route table */
	struct prefix *prefix,			/* VPN prefix */
	struct bgp_info *bi);			/* old VPN host route */

#endif /* _QUAGGA_RFAPI_VNC_IMPORT_BGP_H_ */
