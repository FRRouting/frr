// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

/*
 * File:	vnc_zebra.h
 */

#ifndef _QUAGGA_BGP_VNC_ZEBRA_H
#define _QUAGGA_BGP_VNC_ZEBRA_H

#include "lib/zebra.h"

extern void vnc_zebra_add_prefix(struct bgp *bgp,
				 struct rfapi_import_table *import_table,
				 struct agg_node *rn);

extern void vnc_zebra_del_prefix(struct bgp *bgp,
				 struct rfapi_import_table *import_table,
				 struct agg_node *rn);

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
