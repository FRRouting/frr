// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_debug.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(bgp_hook_config_write_debug, (struct vty *, vty), (bool, running));
