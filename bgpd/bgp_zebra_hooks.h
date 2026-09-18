// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_zebra.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

/* hook to indicate vrf status change for SNMP */
DO_HOOK(bgp_vrf_status_changed, (struct bgp *, bgp), (struct interface *, ifp));
