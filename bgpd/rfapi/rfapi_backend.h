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

#ifndef _QUAGGA_BGP_RFAPI_BACKEND_H
#define _QUAGGA_BGP_RFAPI_BACKEND_H

#if ENABLE_BGP_VNC

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_nexthop.h"

extern void rfapi_init (void);
extern void vnc_zebra_init (struct thread_master *master);
extern void vnc_zebra_destroy (void);

extern void rfapi_delete (struct bgp *);

struct rfapi *bgp_rfapi_new (struct bgp *bgp);
void bgp_rfapi_destroy (struct bgp *bgp, struct rfapi *h);

struct rfapi_import_table *rfapiImportTableRefAdd (struct bgp *bgp,
                                                   struct ecommunity
                                                   *rt_import_list);

void
rfapiImportTableRefDelByIt (struct bgp *bgp,
                            struct rfapi_import_table *it_target);


extern void
rfapiProcessUpdate (struct peer *peer,
                    void *rfd,
                    struct prefix *p,
                    struct prefix_rd *prd,
                    struct attr *attr,
                    afi_t afi,
                    safi_t safi,
                    u_char type, u_char sub_type, uint32_t * label);


extern void
rfapiProcessWithdraw (struct peer *peer,
                      void *rfd,
                      struct prefix *p,
                      struct prefix_rd *prd,
                      struct attr *attr,
                      afi_t afi, safi_t safi, u_char type, int kill);

extern void rfapiProcessPeerDown (struct peer *peer);

extern void
vnc_zebra_announce (struct prefix *p,
                    struct bgp_info *new_select, struct bgp *bgp);

extern void
vnc_zebra_withdraw (struct prefix *p, struct bgp_info *old_select);


extern void
rfapi_vty_out_vncinfo (struct vty *vty,
                       struct prefix *p, struct bgp_info *bi, safi_t safi);


extern void vnc_direct_bgp_vpn_enable (struct bgp *bgp, afi_t afi);

extern void vnc_direct_bgp_vpn_disable (struct bgp *bgp, afi_t afi);

extern void vnc_direct_bgp_rh_vpn_enable (struct bgp *bgp, afi_t afi);

extern void vnc_direct_bgp_rh_vpn_disable (struct bgp *bgp, afi_t afi);

#endif /* ENABLE_BGP_VNC */

#endif /* _QUAGGA_BGP_RFAPI_BACKEND_H */
