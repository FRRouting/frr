// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/interface.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(zebra_if_extra_info, (struct vty *, vty), (json_object *, json_if),
	(struct interface *, ifp));
