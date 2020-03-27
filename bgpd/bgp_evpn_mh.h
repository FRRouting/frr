/* EVPN header for multihoming procedures
 *
 * Copyright (C) 2019 Cumulus Networks
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 */

#ifndef _FRR_BGP_EVPN_MH_H
#define _FRR_BGP_EVPN_MH_H

#include "vxlan.h"
#include "bgpd.h"
#include "bgp_evpn.h"
#include "bgp_evpn_private.h"

extern unsigned int esi_hash_keymake(const void *p);
extern bool esi_cmp(const void *p1, const void *p2);
extern int install_uninstall_route_in_es(struct bgp *bgp, struct evpnes *es,
					 afi_t afi, safi_t safi,
					 struct prefix_evpn *evp,
					 struct bgp_path_info *pi, int install);
int process_type4_route(struct peer *peer, afi_t afi, safi_t safi,
			       struct attr *attr, uint8_t *pfx, int psize,
			       uint32_t addpath_id);
extern int bgp_evpn_local_es_add(struct bgp *bgp, esi_t *esi,
				 struct ipaddr *originator_ip);
extern int bgp_evpn_local_es_del(struct bgp *bgp, esi_t *esi,
				 struct ipaddr *originator_ip);
#endif /* _FRR_BGP_EVPN_MH_H */
