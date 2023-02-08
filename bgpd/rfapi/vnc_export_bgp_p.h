// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

#ifndef _QUAGGA_RFAPI_VNC_EXPORT_BGP_P_H_
#define _QUAGGA_RFAPI_VNC_EXPORT_BGP_P_H_

#include "lib/zebra.h"
#include "lib/prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"

#include "rfapi_private.h"

extern void vnc_direct_bgp_add_route_ce(struct bgp *bgp, struct agg_node *rn,
					struct bgp_path_info *bpi);

extern void vnc_direct_bgp_del_route_ce(struct bgp *bgp, struct agg_node *rn,
					struct bgp_path_info *bpi);

extern void vnc_direct_bgp_add_prefix(struct bgp *bgp,
				      struct rfapi_import_table *import_table,
				      struct agg_node *rn);

extern void vnc_direct_bgp_del_prefix(struct bgp *bgp,
				      struct rfapi_import_table *import_table,
				      struct agg_node *rn);

extern void vnc_direct_bgp_add_nve(struct bgp *bgp,
				   struct rfapi_descriptor *rfd);

extern void vnc_direct_bgp_del_nve(struct bgp *bgp,
				   struct rfapi_descriptor *rfd);

extern void vnc_direct_bgp_add_group(struct bgp *bgp,
				     struct rfapi_nve_group_cfg *rfg);

extern void vnc_direct_bgp_del_group(struct bgp *bgp,
				     struct rfapi_nve_group_cfg *rfg);

extern void vnc_direct_bgp_reexport_group_afi(struct bgp *bgp,
					      struct rfapi_nve_group_cfg *rfg,
					      afi_t afi);


extern void vnc_direct_bgp_rh_add_route(struct bgp *bgp, afi_t afi,
					const struct prefix *prefix,
					struct peer *peer, struct attr *attr);


extern void vnc_direct_bgp_rh_del_route(struct bgp *bgp, afi_t afi,
					const struct prefix *prefix,
					struct peer *peer);

extern void vnc_direct_bgp_reexport(struct bgp *bgp, afi_t afi);

#endif /* _QUAGGA_RFAPI_VNC_EXPORT_BGP_P_H_ */
