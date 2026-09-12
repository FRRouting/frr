// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for isisd/isis_adjacency.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(isis_adj_state_change_hook, (struct isis_adjacency *, adj));
