// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for isisd/isis_tlvs.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(isis_adj_ip_enabled_hook, (struct isis_adjacency *, adj), (int, family), (bool, global));
DO_HOOK(isis_adj_ip_disabled_hook, (struct isis_adjacency *, adj), (int, family), (bool, global));
