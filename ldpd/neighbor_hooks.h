// SPDX-License-Identifier: ISC
/* hook definitions for ldpd/neighbor.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(ldp_nbr_state_change, (struct nbr *, nbr), (int, old_state));
