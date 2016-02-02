/* BGP Nexthop tracking
 * Copyright (C) 2013 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _BGP_NHT_H
#define _BGP_NHT_H

extern void bgp_nht_register_all (vrf_id_t);

/**
 * bgp_parse_nexthop_update() - parse a nexthop update message from Zebra.
 */
extern void bgp_parse_nexthop_update(int command, vrf_id_t vrf_id);

/**
 * bgp_find_nexthop() - lookup the nexthop cache table for the bnc object
 * ARGUMENTS:
 *   p - path for which the nexthop object is being looked up
 *   connected - True if NH MUST be a connected route
 */
extern int bgp_find_nexthop(struct bgp_info *p, int connected);

/**
 * bgp_find_or_add_nexthop() - lookup the nexthop cache table for the bnc
 *  object. If not found, create a new object and register with ZEBRA for
 *  nexthop notification.
 * ARGUMENTS:
 *   bgp - BGP instance
 *   a - afi: AFI_IP or AF_IP6
 *   p - path for which the nexthop object is being looked up
 *   peer - The BGP peer associated with this NHT
 *   connected - True if NH MUST be a connected route
 */
extern int bgp_find_or_add_nexthop(struct bgp *bgp, afi_t a,
                       struct bgp_info *p, struct peer *peer, int connected);

/**
 * bgp_unlink_nexthop() - Unlink the nexthop object from the path structure.
 * ARGUMENTS:
 *   p - path structure.
 */
extern void bgp_unlink_nexthop(struct bgp_info *p);

/**
 * bgp_delete_connected_nexthop() - Reset the 'peer' pointer for a connected
 * nexthop entry. If no paths reference the nexthop, it will be unregistered
 * and freed.
 * ARGUMENTS:
 *   afi - afi: AFI_IP or AF_IP6
 *   peer - Ptr to peer
 */
extern void bgp_delete_connected_nexthop (afi_t afi, struct peer *peer);

#endif /* _BGP_NHT_H */
