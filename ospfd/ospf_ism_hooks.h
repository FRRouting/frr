// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ospfd/ospf_ism.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ospf_ism_change, (struct ospf_interface *, oi), (int, state), (int, oldstate));
