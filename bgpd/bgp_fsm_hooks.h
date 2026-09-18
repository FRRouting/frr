// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_fsm.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(peer_backward_transition, (struct peer *, peer));
DO_HOOK(peer_status_changed, (struct peer *, peer));

DO_HOOK(bgp_rpki_connection_status, (const char *, vrf_name));
