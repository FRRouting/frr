// SPDX-License-Identifier: GPL-2.0-or-later
/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GxNU Zebra.
 */

#ifndef _QUAGGA_BGP_MPLSVPN_H
#define _QUAGGA_BGP_MPLSVPN_H

#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_vty.h"

#define MPLS_LABEL_IS_SPECIAL(label) ((label) <= MPLS_LABEL_EXTENSION)
#define MPLS_LABEL_IS_NULL(label)                                              \
	((label) == MPLS_LABEL_IPV4_EXPLICIT_NULL                              \
	 || (label) == MPLS_LABEL_IPV6_EXPLICIT_NULL                           \
	 || (label) == MPLS_LABEL_IMPLICIT_NULL)

#define BGP_VPNVX_HELP_STR BGP_AF_STR BGP_AF_STR

#define V4_HEADER                                                              \
	"   Network          Next Hop            Metric LocPrf Weight Path\n"
#define V4_HEADER_TAG "   Network          Next Hop      In tag/Out tag\n"
#define V4_HEADER_OVERLAY                                                      \
	"   Network          Next Hop      EthTag    Overlay Index   RouterMac\n"

#define BGP_PREFIX_SID_SRV6_MAX_FUNCTION_LENGTH 20

extern void bgp_mplsvpn_init(void);
extern void bgp_mplsvpn_path_nh_label_unlink(struct bgp_path_info *pi);
extern int bgp_nlri_parse_vpn(struct peer *, struct attr *, struct bgp_nlri *);
extern uint32_t decode_label(mpls_label_t *);
extern void encode_label(mpls_label_t, mpls_label_t *);

extern int argv_find_and_parse_vpnvx(struct cmd_token **argv, int argc,
				     int *index, afi_t *afi);
extern int bgp_show_mpls_vpn(struct vty *vty, afi_t afi, struct prefix_rd *prd,
			     enum bgp_show_type type, void *output_arg,
			     int tags, bool use_json);

extern void vpn_leak_from_vrf_update(struct bgp *to_bgp, struct bgp *from_bgp,
				     struct bgp_path_info *path_vrf);

extern void vpn_leak_from_vrf_withdraw(struct bgp *to_bgp, struct bgp *from_bgp,
				       struct bgp_path_info *path_vrf);

extern void vpn_leak_from_vrf_withdraw_all(struct bgp *to_bgp,
					   struct bgp *from_bgp, afi_t afi);

extern void vpn_leak_from_vrf_update_all(struct bgp *to_bgp,
					 struct bgp *from_bgp, afi_t afi);

extern void vpn_leak_to_vrf_withdraw_all(struct bgp *to_bgp, afi_t afi);

extern void vpn_leak_no_retain(struct bgp *to_bgp, struct bgp *vpn_from,
			       afi_t afi);

extern void vpn_leak_to_vrf_update_all(struct bgp *to_bgp, struct bgp *from_bgp,
				       afi_t afi);

extern bool vpn_leak_to_vrf_no_retain_filter_check(struct bgp *from_bgp,
						   struct attr *attr,
						   afi_t afi);

extern void vpn_leak_to_vrf_update(struct bgp *from_bgp,
				   struct bgp_path_info *path_vpn,
				   struct prefix_rd *prd);

extern void vpn_leak_to_vrf_withdraw(struct bgp_path_info *path_vpn);

extern void vpn_leak_zebra_vrf_label_update(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_label_withdraw(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_sid_update(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_sid_update_per_af(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_sid_update_per_vrf(struct bgp *bgp);
extern void vpn_leak_zebra_vrf_sid_withdraw(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_sid_withdraw_per_af(struct bgp *bgp, afi_t afi);
extern void vpn_leak_zebra_vrf_sid_withdraw_per_vrf(struct bgp *bgp);
extern int vpn_leak_label_callback(mpls_label_t label, void *lblid, bool alloc);
extern void ensure_vrf_tovpn_sid(struct bgp *vpn, struct bgp *vrf, afi_t afi);
extern void delete_vrf_tovpn_sid(struct bgp *vpn, struct bgp *vrf, afi_t afi);
extern void delete_vrf_tovpn_sid_per_af(struct bgp *vpn, struct bgp *vrf,
					afi_t afi);
extern void delete_vrf_tovpn_sid_per_vrf(struct bgp *vpn, struct bgp *vrf);
extern void ensure_vrf_tovpn_sid_per_af(struct bgp *vpn, struct bgp *vrf,
					afi_t afi);
extern void ensure_vrf_tovpn_sid_per_vrf(struct bgp *vpn, struct bgp *vrf);
extern void transpose_sid(struct in6_addr *sid, uint32_t label, uint8_t offset,
			  uint8_t size);
extern void vrf_import_from_vrf(struct bgp *to_bgp, struct bgp *from_bgp,
				afi_t afi, safi_t safi);
void vrf_unimport_from_vrf(struct bgp *to_bgp, struct bgp *from_bgp,
			   afi_t afi, safi_t safi);

static inline bool is_bgp_vrf_mplsvpn(struct bgp *bgp)
{
	afi_t afi;

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF)
		for (afi = 0; afi < AFI_MAX; ++afi) {
			if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
				       BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT)
			    || CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
					  BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT))
				return true;
		}
	return false;
}

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

	if (bgp_vrf->vrf_id == VRF_UNKNOWN) {
		if (pmsg)
			*pmsg = "destination bgp instance vrf is VRF_UNKNOWN";
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

static inline void vpn_leak_prechange(enum vpn_policy_direction direction,
				      afi_t afi, struct bgp *bgp_vpn,
				      struct bgp *bgp_vrf)
{
	/* Detect when default bgp instance is not (yet) defined by config */
	if (!bgp_vpn)
		return;

	if ((direction == BGP_VPN_POLICY_DIR_FROMVPN) &&
		vpn_leak_from_vpn_active(bgp_vrf, afi, NULL)) {

		vpn_leak_to_vrf_withdraw_all(bgp_vrf, afi);
	}
	if ((direction == BGP_VPN_POLICY_DIR_TOVPN) &&
		vpn_leak_to_vpn_active(bgp_vrf, afi, NULL)) {

		vpn_leak_from_vrf_withdraw_all(bgp_vpn, bgp_vrf, afi);
	}
}

static inline void vpn_leak_postchange(enum vpn_policy_direction direction,
				       afi_t afi, struct bgp *bgp_vpn,
				       struct bgp *bgp_vrf)
{
	/* Detect when default bgp instance is not (yet) defined by config */
	if (!bgp_vpn)
		return;

	if (direction == BGP_VPN_POLICY_DIR_FROMVPN) {
		/* trigger a flush to re-sync with ADJ-RIB-in */
		if (!CHECK_FLAG(bgp_vpn->af_flags[afi][SAFI_MPLS_VPN],
				BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
			bgp_clear_soft_in(bgp_vpn, afi, SAFI_MPLS_VPN);
		vpn_leak_to_vrf_update_all(bgp_vrf, bgp_vpn, afi);
	}
	if (direction == BGP_VPN_POLICY_DIR_TOVPN) {

		if (bgp_vrf->vpn_policy[afi].tovpn_label !=
			bgp_vrf->vpn_policy[afi]
			       .tovpn_zebra_vrf_label_last_sent) {
			vpn_leak_zebra_vrf_label_update(bgp_vrf, afi);
		}

		if (bgp_vrf->vpn_policy[afi].tovpn_sid_index == 0 &&
		    !CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
				BGP_VPN_POLICY_TOVPN_SID_AUTO) &&
		    bgp_vrf->tovpn_sid_index == 0 &&
		    !CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_TOVPN_SID_AUTO))
			delete_vrf_tovpn_sid(bgp_vpn, bgp_vrf, afi);

		if (!bgp_vrf->vpn_policy[afi].tovpn_sid && !bgp_vrf->tovpn_sid)
			ensure_vrf_tovpn_sid(bgp_vpn, bgp_vrf, afi);

		if ((!bgp_vrf->vpn_policy[afi].tovpn_sid &&
		     bgp_vrf->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent) ||
		    (!bgp_vrf->tovpn_sid &&
		     bgp_vrf->tovpn_zebra_vrf_sid_last_sent))
			vpn_leak_zebra_vrf_sid_withdraw(bgp_vrf, afi);

		if (bgp_vrf->vpn_policy[afi].tovpn_sid) {
			if (sid_diff(bgp_vrf->vpn_policy[afi].tovpn_sid,
				     bgp_vrf->vpn_policy[afi]
					     .tovpn_zebra_vrf_sid_last_sent)) {
				vpn_leak_zebra_vrf_sid_update(bgp_vrf, afi);
			}
		} else if (bgp_vrf->tovpn_sid) {
			if (sid_diff(bgp_vrf->tovpn_sid,
				     bgp_vrf->tovpn_zebra_vrf_sid_last_sent)) {
				vpn_leak_zebra_vrf_sid_update(bgp_vrf, afi);
			}
		}

		vpn_leak_from_vrf_update_all(bgp_vpn, bgp_vrf, afi);
	}
}

/* Flag if the route is injectable into VPN. This would be either a
 * non-imported route or a non-VPN imported route.
 */
static inline bool is_route_injectable_into_vpn(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent_pi;
	struct bgp_table *table;
	struct bgp_dest *dest;

	if (pi->sub_type != BGP_ROUTE_IMPORTED || !pi->extra ||
	    !pi->extra->vrfleak || !pi->extra->vrfleak->parent)
		return true;

	parent_pi = (struct bgp_path_info *)pi->extra->vrfleak->parent;
	dest = parent_pi->net;
	if (!dest)
		return true;
	table = bgp_dest_table(dest);
	if (table &&
	    (table->afi == AFI_IP || table->afi == AFI_IP6) &&
	    table->safi == SAFI_MPLS_VPN)
		return false;
	return true;
}

/* Flag if the route path's family is VPN. */
static inline bool is_pi_family_vpn(struct bgp_path_info *pi)
{
	return (is_pi_family_matching(pi, AFI_IP, SAFI_MPLS_VPN) ||
		is_pi_family_matching(pi, AFI_IP6, SAFI_MPLS_VPN));
}

extern void vpn_policy_routemap_event(const char *rmap_name);

extern vrf_id_t get_first_vrf_for_redirect_with_rt(struct ecommunity *eckey);

extern void vpn_leak_postchange_all(void);
extern void vpn_handle_router_id_update(struct bgp *bgp, bool withdraw,
					bool is_config);
extern void bgp_vpn_leak_unimport(struct bgp *from_bgp);
extern void bgp_vpn_leak_export(struct bgp *from_bgp);

extern bool bgp_mplsvpn_path_uses_valid_mpls_label(struct bgp_path_info *pi);
extern int
bgp_mplsvpn_nh_label_bind_cmp(const struct bgp_mplsvpn_nh_label_bind_cache *a,
			      const struct bgp_mplsvpn_nh_label_bind_cache *b);
extern void bgp_mplsvpn_path_nh_label_bind_unlink(struct bgp_path_info *pi);
extern void bgp_mplsvpn_nh_label_bind_register_local_label(
	struct bgp *bgp, struct bgp_dest *dest, struct bgp_path_info *pi);
mpls_label_t bgp_mplsvpn_nh_label_bind_get_label(struct bgp_path_info *pi);

/* used to bind a local label to the (label, nexthop) values
 * from an incoming BGP mplsvpn update
 */
struct bgp_mplsvpn_nh_label_bind_cache {

	/* RB-tree entry. */
	struct bgp_mplsvpn_nh_label_bind_cache_item entry;

	/* The nexthop and the vpn label are the key of the list.
	 * Only received BGP MPLSVPN updates may use that structure.
	 * orig_label is the original label received from the BGP Update.
	 */
	struct prefix nexthop;
	mpls_label_t orig_label;

	/* resolved interface for the paths */
	struct nexthop *nh;

	/* number of mplsvpn path */
	unsigned int path_count;

	/* back pointer to bgp instance */
	struct bgp *bgp_vpn;

	/* MPLS label allocated value.
	 * When the next-hop is changed because of 'next-hop-self' or
	 * because it is an eBGP peer, the redistributed orig_label value
	 * is unmodified, unless the 'l3vpn-multi-domain-switching'
	 * is enabled: a new_label value is allocated:
	 * - The new_label value is sent in the advertised BGP update,
	 * instead of the label value.
	 * - An MPLS entry is set to swap <new_label> with <orig_label>.
	 */
	mpls_label_t new_label;

	/* list of path_vrfs using it */
	LIST_HEAD(mplsvpn_nh_label_bind_path_lists, bgp_path_info) paths;

	time_t last_update;

	bool allocation_in_progress;
};

DECLARE_RBTREE_UNIQ(bgp_mplsvpn_nh_label_bind_cache,
		    struct bgp_mplsvpn_nh_label_bind_cache, entry,
		    bgp_mplsvpn_nh_label_bind_cmp);

void bgp_mplsvpn_nh_label_bind_free(
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc);

struct bgp_mplsvpn_nh_label_bind_cache *
bgp_mplsvpn_nh_label_bind_new(struct bgp_mplsvpn_nh_label_bind_cache_head *tree,
			      struct prefix *p, mpls_label_t orig_label);
struct bgp_mplsvpn_nh_label_bind_cache *bgp_mplsvpn_nh_label_bind_find(
	struct bgp_mplsvpn_nh_label_bind_cache_head *tree, struct prefix *p,
	mpls_label_t orig_label);
void bgp_mplsvpn_nexthop_init(void);
extern void sid_unregister(struct bgp *bgp, const struct in6_addr *sid);

#endif /* _QUAGGA_BGP_MPLSVPN_H */
