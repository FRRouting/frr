// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_route.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(bgp_snmp_update_stats, (struct bgp_dest *, rn), (struct bgp_path_info *, pi),
	(bool, added));

DO_HOOK(bgp_rpki_prefix_status, (struct peer *, peer), (struct attr *, attr),
	(const struct prefix *, prefix));

/* called when a route is updated in the rib */
DO_HOOK(bgp_route_update, (struct bgp *, bgp), (afi_t, afi), (safi_t, safi),
	(struct bgp_dest *, bn), (struct bgp_path_info *, old_route),
	(struct bgp_path_info *, new_route));

/* called before bgp_process() */
DO_HOOK(bgp_process, (struct bgp *, bgp), (afi_t, afi), (safi_t, safi), (struct bgp_dest *, bn),
	(struct peer *, peer), (bool, withdraw));

/* whether a component other than soft-reconfiguration inbound needs the
 * peer's Adj-RIB-In to be maintained (e.g. BMP pre-policy monitoring)
 */
DO_HOOK(bgp_adj_in_needed, (struct peer *, peer), (afi_t, afi), (safi_t, safi));
