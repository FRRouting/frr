// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ospfd/ospf_nsm.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ospf_nsm_change, (struct ospf_neighbor *, on), (int, state), (int, oldstate));
