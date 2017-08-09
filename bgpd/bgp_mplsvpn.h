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

#ifdef MPLS_LABEL_MAX
#undef MPLS_LABEL_MAX
#endif

typedef enum {
	MPLS_LABEL_IPV4_EXPLICIT_NULL = 0, /* [RFC3032] */
	MPLS_LABEL_ROUTER_ALERT = 1,       /* [RFC3032] */
	MPLS_LABEL_IPV6_EXPLICIT_NULL = 2, /* [RFC3032] */
	MPLS_LABEL_IMPLICIT_NULL = 3,      /* [RFC3032] */
	MPLS_LABEL_UNASSIGNED4 = 4,
	MPLS_LABEL_UNASSIGNED5 = 5,
	MPLS_LABEL_UNASSIGNED6 = 6,
	MPLS_LABEL_ELI = 7, /* Entropy Indicator [RFC6790] */
	MPLS_LABEL_UNASSIGNED8 = 8,
	MPLS_LABEL_UNASSIGNED9 = 9,
	MPLS_LABEL_UNASSIGNED10 = 10,
	MPLS_LABEL_UNASSIGNED11 = 11,
	MPLS_LABEL_GAL = 13,       /* [RFC5586] */
	MPLS_LABEL_OAM_ALERT = 14, /* [RFC3429] */
	MPLS_LABEL_EXTENSION = 15, /* [RFC7274] */
	MPLS_LABEL_MAX = 1048575,
	MPLS_LABEL_ILLEGAL = 0xFFFFFFFF /* for internal use only */
} mpls_special_label_t;

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

/* For Emacs:          */
/* Local Variables:    */
/* indent-tabs-mode: t */
/* c-basic-offset: 8   */
/* End:                */
