// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ospf6d/ospf6_interface.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ospf6_interface_change, (struct ospf6_interface *, oi), (int, state), (int, old_state));
