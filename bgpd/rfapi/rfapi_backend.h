// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *
 * Copyright 2009-2016, LabN Consulting, L.L.C.
 *
 */

#ifndef _QUAGGA_BGP_RFAPI_BACKEND_H
#define _QUAGGA_BGP_RFAPI_BACKEND_H

#ifdef ENABLE_BGP_VNC

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_nexthop.h"

extern void rfapi_init(void);
extern void vnc_zebra_init(struct event_loop *master);
extern void vnc_zebra_destroy(void);

extern void rfapi_delete(struct bgp *);

struct rfapi *bgp_rfapi_new(struct bgp *bgp);
void bgp_rfapi_destroy(struct bgp *bgp, struct rfapi *h);

extern void rfapiProcessUpdate(struct peer *peer, void *rfd,
			       const struct prefix *p, struct prefix_rd *prd,
			       struct attr *attr, afi_t afi, safi_t safi,
			       uint8_t type, uint8_t sub_type, uint32_t *label);


extern void rfapiProcessWithdraw(struct peer *peer, void *rfd,
				 const struct prefix *p, struct prefix_rd *prd,
				 struct attr *attr, afi_t afi, safi_t safi,
				 uint8_t type, int kill);

extern void rfapiProcessPeerDown(struct peer *peer);

extern void vnc_zebra_announce(struct prefix *p,
			       struct bgp_path_info *new_select,
			       struct bgp *bgp);

extern void vnc_zebra_withdraw(struct prefix *p,
			       struct bgp_path_info *old_select);


extern void rfapi_vty_out_vncinfo(struct vty *vty, const struct prefix *p,
				  struct bgp_path_info *bpi, safi_t safi);


extern void vnc_direct_bgp_vpn_enable(struct bgp *bgp, afi_t afi);

extern void vnc_direct_bgp_vpn_disable(struct bgp *bgp, afi_t afi);

extern void vnc_direct_bgp_rh_vpn_enable(struct bgp *bgp, afi_t afi);

extern void vnc_direct_bgp_rh_vpn_disable(struct bgp *bgp, afi_t afi);

#endif /* ENABLE_BGP_VNC */

#endif /* _QUAGGA_BGP_RFAPI_BACKEND_H */
