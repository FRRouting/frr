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
