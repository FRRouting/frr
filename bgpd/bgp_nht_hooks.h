// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_nht.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* called when a path becomes valid or invalid, because of nexthop tracking */
DO_HOOK(bgp_nht_path_update, (struct bgp *, bgp), (struct bgp_path_info *, pi), (bool, valid));
