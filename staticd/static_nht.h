/*
 * Static NHT header.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __STATIC_NHT_H__
#define __STATIC_NHT_H__

#ifdef __cplusplus
extern "C" {
#endif

/*
 * When we get notification that nexthop tracking has an answer for
 * us call this function to find the nexthop we are tracking so it
 * can be installed or removed.
 *
 * sp -> The route we are looking at.  If NULL then look at all
 *       routes.
 * nhp -> The nexthop that is being tracked.
 * nh_num -> number of valid nexthops.
 * afi -> The afi we are working in.
 * vrf_id -> The vrf the nexthop is in.
 */
extern void static_nht_update(struct prefix *sp, struct prefix *nhp,
			      uint32_t nh_num, afi_t afi, safi_t safi,
			      vrf_id_t vrf_id);

/*
 * For the given tracked nexthop, nhp, mark all routes that use
 * this route as in starting state again.
 */
extern void static_nht_reset_start(struct prefix *nhp, afi_t afi, safi_t safi,
				   vrf_id_t nh_vrf_id);

/*
 * For the given prefix, sp, mark it as in a particular state
 */
extern void static_nht_mark_state(struct prefix *sp, safi_t safi,
				  vrf_id_t vrf_id,
				  enum static_install_states state);

/*
 * For the given nexthop, returns the string
 */
extern void static_get_nh_str(struct static_nexthop *nh, char *nexthop,
			      size_t size);

#ifdef __cplusplus
}
#endif

#endif
