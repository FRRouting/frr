// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgpd.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(bgp_inst_delete, (struct bgp *, bgp));

DO_HOOK(bgp_instance_state, (struct bgp *, bgp));

DO_HOOK(bgp_routerid_update, (struct bgp *, bgp), (bool, withdraw));
