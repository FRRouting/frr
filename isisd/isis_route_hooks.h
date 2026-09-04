// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for isisd/isis_route.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(isis_route_update_hook, (struct isis_area *, area), (struct prefix *, prefix),
	(struct isis_route_info *, route_info));
