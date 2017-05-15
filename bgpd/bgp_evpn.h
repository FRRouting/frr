/* E-VPN header for packet handling
 * Copyright (C) 2016 6WIND
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_EVPN_H
#define _QUAGGA_BGP_EVPN_H

extern int bgp_nlri_parse_evpn(struct peer *peer, struct attr *attr,
			       struct bgp_nlri *packet, int withdraw);

extern void
bgp_packet_mpattr_route_type_5(struct stream *s,
			       struct prefix *p, struct prefix_rd *prd,
			       u_char * label, struct attr *attr);

extern void
bgp_evpn_cleanup (struct bgp *bgp);
extern void
bgp_evpn_init (struct bgp *bgp);

/* EVPN route types as per RFC7432 and
 * as per draft-ietf-bess-evpn-prefix-advertisement-02
 */
#define EVPN_ETHERNET_AUTO_DISCOVERY 1
#define EVPN_MACIP_ADVERTISEMENT 2
#define EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG 3
#define EVPN_ETHERNET_SEGMENT 4
#define EVPN_IP_PREFIX 5

#endif				/* _QUAGGA_BGP_EVPN_H */
