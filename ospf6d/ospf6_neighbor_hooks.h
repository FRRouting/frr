// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for ospf6d/ospf6_neighbor.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ospf6_neighbor_change, (struct ospf6_neighbor *, on), (int, state), (int, next_state));
