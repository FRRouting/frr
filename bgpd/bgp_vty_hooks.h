// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_vty.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(bgp_inst_config_write, (struct bgp *, bgp), (struct vty *, vty));

DO_HOOK(bgp_snmp_update_last_changed, (struct bgp *, bgp));

DO_HOOK(bgp_snmp_init_stats, (struct bgp *, bgp));

DO_HOOK(bgp_snmp_traps_config_write, (struct vty *, vty));

DO_HOOK(bgp_route_distinguisher_update, (struct bgp *, bgp), (afi_t, afi), (bool, preconfig));

DO_HOOK(bgp_config_end, (struct bgp *, bgp));
