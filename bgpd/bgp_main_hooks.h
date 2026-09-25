// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_main.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(bgp_hook_config_write_vrf, (struct vty *, vty), (struct vrf *, vrf));

DO_HOOK(bgp_hook_vrf_update, (struct vrf *, vrf), (bool, enabled));
