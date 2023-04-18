// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
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

extern int vnc_prefix_cmp(const void *pfx1, const void *pfx2);

extern void vnc_import_bgp_add_route(struct bgp *bgp,
				     const struct prefix *prefix,
				     struct bgp_path_info *info);

extern void vnc_import_bgp_del_route(struct bgp *bgp,
				     const struct prefix *prefix,
				     struct bgp_path_info *info);

extern void vnc_import_bgp_redist_enable(struct bgp *bgp, afi_t afi);

extern void vnc_import_bgp_redist_disable(struct bgp *bgp, afi_t afi);

extern void vnc_import_bgp_exterior_redist_enable(struct bgp *bgp, afi_t afi);

extern void vnc_import_bgp_exterior_redist_disable(struct bgp *bgp, afi_t afi);


extern void vnc_import_bgp_exterior_add_route(
	struct bgp *bgp,	     /* exterior instance, we hope */
	const struct prefix *prefix, /* unicast prefix */
	struct bgp_path_info *info); /* unicast info */

extern void vnc_import_bgp_exterior_del_route(
	struct bgp *bgp, const struct prefix *prefix, /* unicast prefix */
	struct bgp_path_info *info);		      /* unicast info */

extern void vnc_import_bgp_add_vnc_host_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix_rd *prd, /* RD */
	struct bgp_table *table_rd,		/* per-rd VPN route table */
	const struct prefix *prefix,		/* VPN prefix */
	struct bgp_path_info *bpi);		/* new VPN host route */

extern void vnc_import_bgp_del_vnc_host_route_mode_resolve_nve(
	struct bgp *bgp, struct prefix_rd *prd, /* RD */
	struct bgp_table *table_rd,		/* per-rd VPN route table */
	const struct prefix *prefix,		/* VPN prefix */
	struct bgp_path_info *bpi);		/* old VPN host route */

#endif /* _QUAGGA_RFAPI_VNC_IMPORT_BGP_H_ */
