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
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 */
#ifndef _QUAGGA_BGP_RFAPI_AP_H
#define _QUAGGA_BGP_RFAPI_AP_H

/* TBD delete some of these #includes */

#include <errno.h>

#include "zebra.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "memory.h"
#include "routemap.h"
#include "log.h"
#include "linklist.h"
#include "command.h"
#include "stream.h"

#include "bgpd.h"

#include "bgp_rfapi_cfg.h"
#include "rfapi.h"
#include "rfapi_backend.h"

#include "bgp_route.h"
#include "bgp_aspath.h"
#include "bgp_advertise.h"

#include "rfapi_import.h"
#include "rfapi_private.h"
#include "rfapi_monitor.h"
#include "rfapi_vty.h"
#include "vnc_export_bgp.h"
#include "vnc_export_bgp_p.h"
#include "vnc_zebra.h"
#include "vnc_import_bgp.h"
#include "rfapi_rib.h"


extern void
rfapiApInit (struct rfapi_advertised_prefixes *ap);

extern void
rfapiApRelease (struct rfapi_advertised_prefixes *ap);

extern int
rfapiApCount (struct rfapi_descriptor *rfd);


extern int
rfapiApCountAll (struct bgp *bgp);

extern void
rfapiApReadvertiseAll (struct bgp *bgp, struct rfapi_descriptor *rfd);

extern void
rfapiApWithdrawAll (struct bgp *bgp, struct rfapi_descriptor *rfd);

extern int
rfapiApAdd (
  struct bgp			*bgp,
  struct rfapi_descriptor	*rfd,
  struct prefix			*pfx_ip,
  struct prefix			*pfx_eth,
  struct prefix_rd		*prd,
  uint32_t			lifetime,
  uint8_t			cost,
  struct rfapi_l2address_option	*l2o);       /* other options TBD */

extern int
rfapiApDelete (
  struct bgp			*bgp,
  struct rfapi_descriptor	*rfd,
  struct prefix			*pfx_ip,
  struct prefix			*pfx_eth,
  int				*advertise_tunnel); /* out */


#endif /* _QUAGGA_BGP_RFAPI_AP_H */
