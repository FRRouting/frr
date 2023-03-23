// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

#ifndef _QUAGGA_RFAPI_VNC_IMPORT_BGP_P_H_
#define _QUAGGA_RFAPI_VNC_IMPORT_BGP_P_H_

#include "lib/zebra.h"
#include "lib/prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

extern void vnc_import_bgp_exterior_add_route_interior(
	struct bgp *bgp, struct rfapi_import_table *it,
	struct agg_node *rn_interior,	/* VPN IT node */
	struct bgp_path_info *bpi_interior); /* VPN IT route */

extern void vnc_import_bgp_exterior_del_route_interior(
	struct bgp *bgp, struct rfapi_import_table *it,
	struct agg_node *rn_interior,	/* VPN IT node */
	struct bgp_path_info *bpi_interior); /* VPN IT route */

extern void
vnc_import_bgp_exterior_redist_enable_it(struct bgp *bgp, afi_t afi,
					 struct rfapi_import_table *it_only);

#endif /* _QUAGGA_RFAPI_VNC_IMPORT_BGP_P_H_ */
