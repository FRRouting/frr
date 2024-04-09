// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Nexthop tracking
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */

#ifndef _BGP_NHT_H
#define _BGP_NHT_H

/**
 * bgp_nexthop_update() - process a nexthop update message from Zebra.
 */
extern void bgp_nexthop_update(struct vrf *vrf, struct prefix *match,
			       struct zapi_route *nhr);

/**
 * bgp_find_or_add_nexthop() - lookup the nexthop cache table for the bnc
 *  object. If not found, create a new object and register with ZEBRA for
 *  nexthop notification.
 * ARGUMENTS:
 *   bgp_route - BGP instance of route
 *   bgp_nexthop - BGP instance of nexthop
 *   a - afi: AFI_IP or AF_IP6
 *   safi - safi: to check which table nhs are being imported to
 *   p - path for which the nexthop object is being looked up
 *   peer - The BGP peer associated with this NHT
 *   connected - True if NH MUST be a connected route
 */
extern int bgp_find_or_add_nexthop(struct bgp *bgp_route,
				   struct bgp *bgp_nexthop, afi_t a,
				   safi_t safi, struct bgp_path_info *p,
				   struct peer *peer, int connected,
				   const struct prefix *orig_prefix);

/**
 * bgp_unlink_nexthop() - Unlink the nexthop object from the path structure.
 * ARGUMENTS:
 *   p - path structure.
 */
extern void bgp_unlink_nexthop(struct bgp_path_info *p);
void bgp_unlink_nexthop_by_peer(struct peer *peer);
void bgp_replace_nexthop_by_peer(struct peer *from, struct peer *to);
/**
 * bgp_delete_connected_nexthop() - Reset the 'peer' pointer for a connected
 * nexthop entry. If no paths reference the nexthop, it will be unregistered
 * and freed.
 * ARGUMENTS:
 *   afi - afi: AFI_IP or AF_IP6
 *   peer - Ptr to peer
 */
extern void bgp_delete_connected_nexthop(afi_t afi, struct peer *peer);

/*
 * Cleanup nexthop registration and status information for BGP nexthops
 * pertaining to this VRF. This is invoked upon VRF deletion.
 */
extern void bgp_cleanup_nexthops(struct bgp *bgp);

/*
 * Add or remove the tracking of the bgp_path_info that
 * uses this nexthop
 */
extern void path_nh_map(struct bgp_path_info *path,
			struct bgp_nexthop_cache *bnc, bool make);
/*
 * When we actually have the connection to
 * the zebra daemon, we need to reregister
 * any nexthops we may have sitting around
 */
extern void bgp_nht_register_nexthops(struct bgp *bgp);

/*
 * When we have the the PEER_FLAG_CAPABILITY_ENHE flag
 * set on a peer *after* it has been brought up we need
 * to notice and setup the interface based RA,
 * this code can walk the registered nexthops and
 * register the important ones with zebra for RA.
 */
extern void bgp_nht_reg_enhe_cap_intfs(struct peer *peer);
extern void bgp_nht_dereg_enhe_cap_intfs(struct peer *peer);
extern void evaluate_paths(struct bgp_nexthop_cache *bnc);

extern void bgp_nht_ifp_up(struct interface *ifp);
extern void bgp_nht_ifp_down(struct interface *ifp);

extern void bgp_nht_interface_events(struct peer *peer);
#endif /* _BGP_NHT_H */
