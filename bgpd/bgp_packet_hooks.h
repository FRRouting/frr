// SPDX-License-Identifier: GPL-2.0-or-later
/* hook definitions for bgpd/bgp_packet.c
 *
 * note: file may be included multiple times - intentionally no include guard!
 */

DO_HOOK(bgp_packet_dump, (struct peer *, peer), (uint8_t, type), (bgp_size_t, size),
	(struct stream *, s));
DO_HOOK(bgp_packet_send, (struct peer *, peer), (uint8_t, type), (bgp_size_t, size),
	(struct stream *, s));
