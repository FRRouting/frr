// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */
#ifndef _QUAGGA_BGP_RFAPI_AP_H
#define _QUAGGA_BGP_RFAPI_AP_H

/* TBD delete some of these #includes */

#include <errno.h>

#include "lib/zebra.h"
#include "lib/prefix.h"
#include "lib/table.h"
#include "lib/vty.h"
#include "lib/memory.h"
#include "lib/routemap.h"
#include "lib/log.h"
#include "lib/linklist.h"
#include "lib/command.h"
#include "lib/stream.h"

#include "bgpd/bgpd.h"

#include "bgp_rfapi_cfg.h"
#include "rfapi.h"
#include "rfapi_backend.h"

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_advertise.h"

#include "rfapi_import.h"
#include "rfapi_private.h"
#include "rfapi_monitor.h"
#include "rfapi_vty.h"
#include "vnc_export_bgp.h"
#include "vnc_export_bgp_p.h"
#include "vnc_zebra.h"
#include "vnc_import_bgp.h"
#include "rfapi_rib.h"


extern void rfapiApInit(struct rfapi_advertised_prefixes *ap);

extern void rfapiApRelease(struct rfapi_advertised_prefixes *ap);

extern int rfapiApCount(struct rfapi_descriptor *rfd);


extern int rfapiApCountAll(struct bgp *bgp);

extern void rfapiApReadvertiseAll(struct bgp *bgp,
				  struct rfapi_descriptor *rfd);

extern void rfapiApWithdrawAll(struct bgp *bgp, struct rfapi_descriptor *rfd);

extern int
rfapiApAdd(struct bgp *bgp, struct rfapi_descriptor *rfd, struct prefix *pfx_ip,
	   struct prefix *pfx_eth, struct prefix_rd *prd, uint32_t lifetime,
	   uint8_t cost,
	   struct rfapi_l2address_option *l2o); /* other options TBD */

extern int rfapiApDelete(struct bgp *bgp, struct rfapi_descriptor *rfd,
			 struct prefix *pfx_ip, struct prefix *pfx_eth,
			 struct prefix_rd *prd,
			 int *advertise_tunnel); /* out */


#endif /* _QUAGGA_BGP_RFAPI_AP_H */
