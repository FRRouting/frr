// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ripd/rip_interface.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(rip_ifaddr_add, (struct connected *, ifc));
DO_HOOK(rip_ifaddr_del, (struct connected *, ifc));
