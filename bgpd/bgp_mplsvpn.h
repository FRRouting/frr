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
#include "bgpd/bgp_zebra.h"

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
extern uint32_t decode_label(mpls_label_t *);
extern void encode_label(mpls_label_t, mpls_label_t *);

extern int argv_find_and_parse_vpnvx(struct cmd_token **argv, int argc,
				     int *index, afi_t *afi);
extern int bgp_show_mpls_vpn(struct vty *vty, afi_t afi, struct prefix_rd *prd,
			     enum bgp_show_type type, void *output_arg,
			     int tags, uint8_t use_json);

extern void vpn_leak_from_vrf_update(struct bgp *bgp_vpn, struct bgp *bgp_vrf,
				     struct bgp_info *info_vrf);

extern void vpn_leak_from_vrf_withdraw(struct bgp *bgp_vpn, struct bgp *bgp_vrf,
				       struct bgp_info *info_vrf);

extern void vpn_leak_from_vrf_withdraw_all(struct bgp *bgp_vpn,
					   struct bgp *bgp_vrf, afi_t afi);

extern void vpn_leak_from_vrf_update_all(struct bgp *bgp_vpn,
					 struct bgp *bgp_vrf, afi_t afi);

extern void vpn_leak_to_vrf_withdraw_all(struct bgp *bgp_vrf, afi_t afi);

extern void vpn_leak_to_vrf_update_all(struct bgp *bgp_vrf, struct bgp *bgp_vpn,
				       afi_t afi);

extern void vpn_leak_to_vrf_update(struct bgp *bgp_vpn,
				   struct bgp_info *info_vpn);

extern void vpn_leak_to_vrf_withdraw(struct bgp *bgp_vpn,
				     struct bgp_info *info_vpn);

extern void vpn_leak_zebra_vrf_label_update(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_label_withdraw(struct bgp *bgp, afi_t afi);
extern int vpn_leak_label_callback(mpls_label_t label, void *lblid, bool alloc);
extern void vrf_import_from_vrf(struct bgp *to_bgp, struct bgp *from_bgp,
				afi_t afi, safi_t safi);
void vrf_unimport_from_vrf(struct bgp *to_bgp, struct bgp *from_bgp,
			   afi_t afi, safi_t safi);

static inline int vpn_leak_to_vpn_active(struct bgp *bgp_vrf, afi_t afi,
					 const char **pmsg)
{
	if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF
		&& bgp_vrf->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {

		if (pmsg)
			*pmsg = "source bgp instance neither vrf nor default";
		return 0;
	}

	/* Is vrf configured to export to vpn? */
	if (!CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
			BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT)
	    && !CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
			   BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
		if (pmsg)
			*pmsg = "export not set";
		return 0;
	}

	/* Is there an RT list set? */
	if (!bgp_vrf->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN]) {
		if (pmsg)
			*pmsg = "rtlist tovpn not defined";
		return 0;
	}

	/* Is there an RD set? */
	if (!CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
			BGP_VPN_POLICY_TOVPN_RD_SET)) {
		if (pmsg)
			*pmsg = "rd not defined";
		return 0;
	}

	/* Is a route-map specified, but not defined? */
	if (bgp_vrf->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_TOVPN] &&
		!bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_TOVPN]) {
		if (pmsg)
			*pmsg = "route-map tovpn named but not defined";
		return 0;
	}

	/* Is there an "auto" export label that isn't allocated yet? */
	if (CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
		BGP_VPN_POLICY_TOVPN_LABEL_AUTO) &&
		(bgp_vrf->vpn_policy[afi].tovpn_label == MPLS_LABEL_NONE)) {

		if (pmsg)
			*pmsg = "auto label not allocated";
		return 0;
	}

	return 1;
}

static inline int vpn_leak_from_vpn_active(struct bgp *bgp_vrf, afi_t afi,
					   const char **pmsg)
{
	if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF
		&& bgp_vrf->inst_type != BGP_INSTANCE_TYPE_DEFAULT) {

		if (pmsg)
			*pmsg = "destination bgp instance neither vrf nor default";
		return 0;
	}

	/* Is vrf configured to import from vpn? */
	if (!CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
			BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT)
	    && !CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
			   BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
		if (pmsg)
			*pmsg = "import not set";
		return 0;
	}

	/* Is there an RT list set? */
	if (!bgp_vrf->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN]) {
		if (pmsg)
			*pmsg = "rtlist fromvpn not defined";
		return 0;
	}

	/* Is a route-map specified, but not defined? */
	if (bgp_vrf->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN] &&
		!bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN]) {
		if (pmsg)
			*pmsg = "route-map fromvpn named but not defined";
		return 0;
	}
	return 1;
}

static inline void vpn_leak_prechange(vpn_policy_direction_t direction,
				      afi_t afi, struct bgp *bgp_vpn,
				      struct bgp *bgp_vrf)
{
	if ((direction == BGP_VPN_POLICY_DIR_FROMVPN) &&
		vpn_leak_from_vpn_active(bgp_vrf, afi, NULL)) {

		vpn_leak_to_vrf_withdraw_all(bgp_vrf, afi);
	}
	if ((direction == BGP_VPN_POLICY_DIR_TOVPN) &&
		vpn_leak_to_vpn_active(bgp_vrf, afi, NULL)) {

		vpn_leak_from_vrf_withdraw_all(bgp_vpn, bgp_vrf, afi);
	}
}

static inline void vpn_leak_postchange(vpn_policy_direction_t direction,
				       afi_t afi, struct bgp *bgp_vpn,
				       struct bgp *bgp_vrf)
{
	if (direction == BGP_VPN_POLICY_DIR_FROMVPN)
		vpn_leak_to_vrf_update_all(bgp_vrf, bgp_vpn, afi);
	if (direction == BGP_VPN_POLICY_DIR_TOVPN) {

		if (bgp_vrf->vpn_policy[afi].tovpn_label !=
			bgp_vrf->vpn_policy[afi]
			       .tovpn_zebra_vrf_label_last_sent) {
			vpn_leak_zebra_vrf_label_update(bgp_vrf, afi);
		}

		vpn_leak_from_vrf_update_all(bgp_vpn, bgp_vrf, afi);
	}
}

extern void vpn_policy_routemap_event(const char *rmap_name);

extern vrf_id_t get_first_vrf_for_redirect_with_rt(struct ecommunity *eckey);

#endif /* _QUAGGA_BGP_MPLSVPN_H */
