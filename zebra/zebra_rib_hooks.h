// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for zebra/zebra_rib.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(rib_update, (struct route_node *, rn), (const char *, reason));
DO_HOOK(rib_shutdown, (struct route_node *, rn));
