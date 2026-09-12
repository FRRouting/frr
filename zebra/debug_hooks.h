// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/debug.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(zebra_debug_show_debugging, (struct vty *, vty));
