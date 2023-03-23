// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

#ifndef _QUAGGA_RFAPI_VNC_EXPORT_BGP_H_
#define _QUAGGA_RFAPI_VNC_EXPORT_BGP_H_

#include "lib/zebra.h"
#include "lib/prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"


extern void vnc_direct_bgp_rh_reexport(struct bgp *bgp, afi_t afi);

extern void vnc_export_bgp_prechange(struct bgp *bgp);

extern void vnc_export_bgp_postchange(struct bgp *bgp);

extern void vnc_export_bgp_enable(struct bgp *bgp, afi_t afi);

extern void vnc_export_bgp_disable(struct bgp *bgp, afi_t afi);

#endif /* _QUAGGA_RFAPI_VNC_EXPORT_BGP_H_ */
