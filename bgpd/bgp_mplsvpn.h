/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GxNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_BGP_MPLSVPN_H
#define _QUAGGA_BGP_MPLSVPN_H

#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rd.h"

#define MPLS_LABEL_IS_SPECIAL(label) ((label) <= MPLS_LABEL_EXTENSION)
#define MPLS_LABEL_IS_NULL(label)                                              \
	((label) == MPLS_LABEL_IPV4_EXPLICIT_NULL                              \
	 || (label) == MPLS_LABEL_IPV6_EXPLICIT_NULL                           \
	 || (label) == MPLS_LABEL_IMPLICIT_NULL)

#define BGP_VPNVX_HELP_STR                                                     \
	"Address Family\n"                                                     \
	"Address Family\n"

#define V4_HEADER                                                              \
	"   Network          Next Hop            Metric LocPrf Weight Path\n"
#define V4_HEADER_TAG "   Network          Next Hop      In tag/Out tag\n"
#define V4_HEADER_OVERLAY                                                      \
	"   Network          Next Hop      EthTag    Overlay Index   RouterMac\n"

extern void bgp_mplsvpn_init(void);
extern int bgp_nlri_parse_vpn(struct peer *, struct attr *, struct bgp_nlri *);
extern u_int32_t decode_label(mpls_label_t *);
extern void encode_label(mpls_label_t, mpls_label_t *);

extern int argv_find_and_parse_vpnvx(struct cmd_token **argv, int argc,
				     int *index, afi_t *afi);
extern int bgp_show_mpls_vpn(struct vty *vty, afi_t afi, struct prefix_rd *prd,
			     enum bgp_show_type type, void *output_arg,
			     int tags, u_char use_json);

#endif /* _QUAGGA_BGP_MPLSVPN_H */
