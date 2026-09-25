// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright 2025 6WIND S.A.
 * Loïc SANG <loic.sang@6wind.com>
 */

#include <zebra.h>

#include "log.h"
#include "vty.h"
#include "zclient.h"

#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgpd.h"

#include "bgpd/bgp_srv6_clippy.c"

DEFINE_MTYPE_STATIC(BGPD, SRV6_LOCATOR_EXTRA, "BGP SRv6 Extra locator");
DEFINE_MTYPE_STATIC(BGPD, SRV6_PER_LOCATOR_CACHE, "BGP SRv6 per locator cache");

extern struct zclient *zclient;

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi)
{
	uint32_t sid_func;
	safi_t safi = SAFI_UNICAST;
	struct srv6_sid_ctx ctx = {};
	bool unicast_sid_auto = false;
	uint32_t unicast_sid_index = 0;
	struct in6_addr unicast_sid = {};
	struct srv6_locator *locator_bgp;
	bool unicast_sid_explicit = false;

	/* no configured */
	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	/* already allocated */
	if (bgp->srv6_unicast[afi].sid)
		return;

	locator_bgp = bgp->srv6_locator;
	/* locator no set */
	if (!locator_bgp)
		return;

	unicast_sid_index = bgp->srv6_unicast[afi].sid_index;
	unicast_sid_auto = CHECK_FLAG(bgp->af_flags[afi][safi],
				      BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	unicast_sid_explicit = bgp->srv6_unicast[afi].sid_explicit;

	if ((unicast_sid_index != 0 && unicast_sid_auto) ||
	    (unicast_sid_index != 0 && unicast_sid_explicit) ||
	    (unicast_sid_auto && unicast_sid_explicit)) {
		zlog_err("%s: more than one mode selected among index-mode, auto-mode and explicit-mode. ignored.",
			 __func__);
		return;
	}

	if (!unicast_sid_auto && !unicast_sid_explicit) {
		if (!srv6_sid_compose(&unicast_sid, locator_bgp, unicast_sid_index)) {
			zlog_err("%s: failed to compose unicast sid %s: afi %s",
				 __func__, bgp->name_pretty, afi2str(afi));
			return;
		}
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_EXPLICIT;
	} else if (unicast_sid_explicit) {
		unicast_sid = *(bgp->srv6_unicast[afi].sid_explicit);
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_EXPLICIT;
	} else if (!unicast_sid_auto) {
		zlog_err("%s: neither index, auto, nor explicit mode is selected.",  __func__);
		return;
	} else
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_DYNAMIC;

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	if (!bgp_zebra_request_srv6_sid(&ctx, &unicast_sid, locator_bgp->name, &sid_func)) {
		zlog_err("%s: failed to request sid for bgp %s: afi %s", __func__,
			 bgp->name_pretty, afi2str(afi));
		return;
	}
	bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent = ctx.alloc_mode;
}

struct interface *get_srv6_endpoint_ifp(char *vrf_name)
{
	struct vrf *vrf;

	if (!vrf_name[0])
		return if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);

	vrf = vrf_lookup_by_name(vrf_name);
	if (!vrf)
		return NULL;

	return if_get_vrf_loopback(vrf->vrf_id);
}

void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install)
{
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *unicast_sid_ls = NULL;

	if (!bgp->srv6_unicast[afi].sid)
		return;

	ctx.block_len = bgp->srv6_unicast[afi].sid_locator->block_bits_length;
	ctx.node_len = bgp->srv6_unicast[afi].sid_locator->node_bits_length;
	ctx.function_len = bgp->srv6_unicast[afi].sid_locator->function_bits_length;
	ctx.argument_len = bgp->srv6_unicast[afi].sid_locator->argument_bits_length;

	if (install) {
		if (CHECK_FLAG(bgp->srv6_unicast[afi].sid_locator->flags,
			       SRV6_LOCATOR_USID | SRV6_LOCATOR_F3216))
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		ctx.table = ifp->vrf->data.l.table_id;
		act = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4 :
			ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		zclient_send_localsid(zclient, ZEBRA_ROUTE_ADD, bgp->srv6_unicast[afi].sid,
				      IPV6_MAX_BITLEN, ifp->ifindex, act, &ctx);
		unicast_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		*unicast_sid_ls = *bgp->srv6_unicast[afi].sid;
		if (bgp->srv6_unicast[afi].zebra_sid_last_sent)
			XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);
		bgp->srv6_unicast[afi].zebra_sid_last_sent = unicast_sid_ls;

	} else if (bgp->srv6_unicast[afi].zebra_sid_last_sent) {
		zclient_send_localsid(zclient, ZEBRA_ROUTE_DELETE,
				      bgp->srv6_unicast[afi].zebra_sid_last_sent, IPV6_MAX_BITLEN,
				      ifp->ifindex, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC, &ctx);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].zebra_sid_last_sent);
		bgp->srv6_unicast[afi].zebra_sid_last_sent = NULL;
	}
}

void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi)
{
	char debug_msg[128];
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};
	struct srv6_policy *srv6_policy;
	int debug = BGP_DEBUG(zebra, ZEBRA);

	if (bgp->vrf_id != VRF_DEFAULT)
		return;

	srv6_policy = &bgp->srv6_unicast[afi];
	if (debug)
		zlog_debug("%s: vrf %s: deleting sid %pI6 for vrf id %d", __func__,
			   bgp->name_pretty, srv6_policy->sid, bgp->vrf_id);

	ifp = get_srv6_endpoint_ifp(srv6_policy->endpoint_vrf);
	if (!ifp) {
		if (srv6_policy->endpoint_vrf[0])
			snprintf(debug_msg, sizeof(debug_msg), "VRF loopback %s",
				 srv6_policy->endpoint_vrf);
		else
			snprintf(debug_msg, sizeof(debug_msg), "%s", DEFAULT_SRV6_IFNAME);
		zlog_warn("%s interface not found, nothing to uninstall", debug_msg);
		return;
	}

	if (srv6_policy->zebra_sid_last_sent)
		bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	ctx.vrf_id = bgp->vrf_id;
	ctx.alloc_mode = srv6_policy->zebra_sid_alloc_mode_last_sent;
	bgp_zebra_release_srv6_sid(&ctx, srv6_policy->sid_locator->name);
}

void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};

	if (!bgp || bgp->vrf_id != VRF_DEFAULT)
		return;

	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	if (bgp->srv6_unicast[afi].sid) {
		ifp = get_srv6_endpoint_ifp(bgp->srv6_unicast[afi].endpoint_vrf);
		if (ifp && bgp->srv6_unicast[afi].zebra_sid_last_sent)
			bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

		ctx.vrf_id = bgp->vrf_id;
		ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
					     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		ctx.alloc_mode = bgp->srv6_unicast[afi].zebra_sid_alloc_mode_last_sent;
		bgp_zebra_release_srv6_sid(&ctx, bgp->srv6_unicast[afi].sid_locator->name);

		sid_unregister(bgp, bgp->srv6_unicast[afi].sid);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid);
	}

	if (bgp->srv6_unicast[afi].sid_explicit)
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[afi].sid_explicit);

	if (bgp->srv6_unicast[afi].rmap_name) {
		XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast[afi].rmap_name);
		route_map_counter_decrement(
			route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name));
	}

	srv6_locator_free(bgp->srv6_unicast[afi].sid_locator);
	bgp->srv6_unicast[afi].sid_locator = NULL;
	UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		   BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
}

void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi)
{
	char debug_msg[128];
	struct interface *ifp;
	struct srv6_policy *srv6_policy;

	srv6_policy = &bgp->srv6_unicast[afi];
	if (!bgp->srv6_unicast[afi].sid)
		return;

	ifp = get_srv6_endpoint_ifp(srv6_policy->endpoint_vrf);
	if (!ifp) {
		if (srv6_policy->endpoint_vrf[0])
			snprintf(debug_msg, sizeof(debug_msg), "VRF loopback %s",
				 srv6_policy->endpoint_vrf);
		else
			snprintf(debug_msg, sizeof(debug_msg), "%s", DEFAULT_SRV6_IFNAME);
		zlog_warn("%s interface not found, can not install SRV6 endpoint behavior",
			  debug_msg);
		return;
	}
	if (!if_is_up(ifp))
		return;

	bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, true);
}

static void bgp_srv6_unicast_ifp_update_afi(struct bgp *bgp, struct interface *ifp,
				       afi_t afi, bool state)
{
	struct srv6_policy *srv6_policy;

	srv6_policy = &bgp->srv6_unicast[afi];
	if((!srv6_policy->endpoint_vrf[0] && ifp->vrf->data.l.table_id == 254 &&
	    strmatch(ifp->name, DEFAULT_SRV6_IFNAME)) ||
	   (if_is_vrf(ifp) && strmatch(ifp->name, srv6_policy->endpoint_vrf)))
		bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, state);
}

void bgp_srv6_unicast_ifp_update(struct interface *ifp, bool state)
{
	struct bgp *bgp = bgp_get_default();

	if (!bgp)
		return;

	if (is_srv6_unicast_enabled(bgp, AFI_IP))
		bgp_srv6_unicast_ifp_update_afi(bgp, ifp, AFI_IP, state);

	if (is_srv6_unicast_enabled(bgp, AFI_IP6))
		bgp_srv6_unicast_ifp_update_afi(bgp, ifp, AFI_IP6, state);
}

void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest)
{
	XFREE(MTYPE_BGP_SRV6_L3SERVICE, dest->srv6_unicast);
	dest->srv6_unicast = NULL;
}

void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct bgp_path_info *bpi)
{
	struct attr attr_tmp;
	const struct prefix *p;
	struct route_map *rmap;
	route_map_result_t ret;
	struct bgp_path_info info;
	struct srv6_locator *locator;

	if (!bpi) {
		if (dest->srv6_unicast)
			bgp_srv6_unicast_unregister_route(dest);

		return;
	}

	if (bpi->attr->srv6_l3service)
		return;

	if (!bgp->srv6_unicast[afi].sid_locator)
		return;

	if (bgp->srv6_unicast[afi].rmap_name) {
		rmap = route_map_lookup_by_name(bgp->srv6_unicast[afi].rmap_name);
		if (rmap) {
			attr_tmp = *bpi->attr;
			info.attr = &attr_tmp;
			info.peer = bgp->peer_self;
			memset(&info, 0, sizeof(info));
			p = bgp_dest_get_prefix(bpi->net);

			ret = route_map_apply(rmap, p, &info);

			if (ret == RMAP_DENYMATCH) {
				if (dest->srv6_unicast)
					bgp_srv6_unicast_unregister_route(dest);

				if (BGP_DEBUG(update, UPDATE_OUT))
					zlog_debug("srv6 unicast prefix %pBD denied", dest);

				return;
			}

			route_map_counter_increment(rmap);
		} else {
			if (dest->srv6_unicast)
				bgp_srv6_unicast_unregister_route(dest);

			zlog_warn("route-map %s was no found, prefix %pBD will be ignored",
				  bgp->srv6_unicast[afi].rmap_name, dest);
			return;
		}
	}

	if (dest->srv6_unicast && sid_same(bgp->srv6_unicast[afi].sid, &dest->srv6_unicast->sid))
		return;

	locator = bgp->srv6_unicast[afi].sid_locator;
	dest->srv6_unicast = XCALLOC(MTYPE_BGP_SRV6_L3SERVICE,
				     sizeof(struct bgp_attr_srv6_l3service));
	dest->srv6_unicast->sid_flags = 0x00;
	dest->srv6_unicast->endpoint_behavior =
		afi == AFI_IP ? (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID | SRV6_LOCATOR_F3216)
					 ? SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID
					 : SRV6_ENDPOINT_BEHAVIOR_END_DT4)
			      : (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID | SRV6_LOCATOR_F3216)
					 ? SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID
					 : SRV6_ENDPOINT_BEHAVIOR_END_DT6);
	dest->srv6_unicast->loc_block_len = locator->block_bits_length;
	dest->srv6_unicast->loc_node_len = locator->node_bits_length;
	dest->srv6_unicast->func_len = locator->function_bits_length;
	dest->srv6_unicast->arg_len = locator->argument_bits_length;
	memcpy(&dest->srv6_unicast->sid, bgp->srv6_unicast[afi].sid,
	       sizeof(struct in6_addr));
}

void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi)
{
	struct peer *peer;
	struct bgp_dest *pdest;
	struct bgp_path_info *bpi;
	safi_t safi = SAFI_UNICAST;
	struct listnode *node, *nnode;

	if (!bgp->srv6_unicast[afi].sid_locator)
		return;

	for (pdest = bgp_table_top(bgp->rib[afi][safi]); pdest; pdest = bgp_route_next(pdest)) {
		for (bpi = bgp_dest_get_bgp_path_info(pdest); bpi; bpi = bpi->next) {
			if (!CHECK_FLAG(bpi->flags, BGP_PATH_SELECTED))
				continue;

			if (bpi->attr->srv6_l3service)
				continue;

			bgp_srv6_unicast_register_route(bgp, afi, pdest, bpi);
			break;
		}
	}

	/* force to resend all routes */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX) ||
		    peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6))
			bgp_announce_route(peer, afi, safi, true);
	}
}

void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi)
{
	struct peer *peer;
	struct bgp_dest *pdest;
	safi_t safi = SAFI_UNICAST;
	struct listnode *node, *nnode;

	for (pdest = bgp_table_top(bgp->rib[afi][safi]); pdest; pdest = bgp_route_next(pdest)) {
		if (!pdest->srv6_unicast)
			continue;

		bgp_srv6_unicast_unregister_route(pdest);
	}

	/* force to resend all routes */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_RELAX) ||
		    peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6))
			bgp_announce_route(peer, afi, safi, true);
	}
}

/**
 * Return the SRv6 locator by name
 *
 * @param name Locator name
 * @return srv6_locator
 */
struct srv6_locator *bgp_srv6_locator_lookup_all_by_name(const char *name)
{
	if (!bm || !bm->srv6_locators)
		return NULL;

	struct srv6_locator lkey;

	memset(&lkey, 0, sizeof(lkey));
	strlcpy(lkey.name, name, sizeof(lkey.name));

	return hash_lookup(bm->srv6_locators, &lkey);
}

void bgp_srv6_path_locator_extra_free(struct bgp_path_info_extra *extra)
{
	XFREE(MTYPE_SRV6_LOCATOR_EXTRA, extra->srv6_locator);
}

void bgp_srv6_path_locator_extra_alloc(struct bgp_path_info_extra *extra, char *locator)
{
	extra->srv6_locator = XSTRDUP(MTYPE_SRV6_LOCATOR_EXTRA, locator);
}

static void bgp_srv6_per_locator_free(struct bgp_srv6_per_locator_cache *bslc)
{
	if (!bslc)
		return;

	assert(bslc->tree);

	bslc = bgp_srv6_per_locator_cache_del(bslc->tree, bslc);
	if (bslc)
		XFREE(MTYPE_SRV6_PER_LOCATOR_CACHE, bslc);
}

/* code derived from ensure_vrf_tovpn_sid(), applied to auto mode only */
static void bgp_srv6_per_locator_cache_delete_tovpn_sid(struct bgp_srv6_per_locator_cache *bslc)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct srv6_sid_ctx ctx = {};

	if (debug)
		zlog_debug("%s: try to remove SID for vrf %s: afi %s locator %s, mode %s", __func__,
			   bslc->bgp->name_pretty, afi2str(bslc->afi), bslc->locator_name,
			   srv6_sid_alloc_mode2str(
				   bslc->sid_policy.tovpn_zebra_sid_alloc_mode_last_sent));

	if (bslc->sid_policy.tovpn_sid) {
		ctx.vrf_id = bslc->bgp->vrf_id;
		ctx.behavior = bslc->afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
						   : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		ctx.alloc_mode = SRV6_SID_ALLOC_MODE_DYNAMIC;
		bgp_zebra_release_srv6_sid(&ctx, bslc->locator_name);
		sid_unregister(bgp_get_default(), bslc->sid_policy.tovpn_sid);
		XFREE(MTYPE_BGP_SRV6_SID, bslc->sid_policy.tovpn_sid);
		XFREE(MTYPE_BGP_SRV6_SID, bslc->sid_policy.tovpn_zebra_sid_last_sent);
	}
	bslc->sid_policy.tovpn_sid = NULL;
	bslc->sid_policy.tovpn_sid_transpose_label = 0;
	bslc->sid_policy.tovpn_zebra_sid_alloc_mode_last_sent = SRV6_SID_ALLOC_MODE_UNSPEC;
	srv6_locator_free(bslc->sid_policy.tovpn_sid_locator);
	bslc->sid_policy.tovpn_sid_locator = NULL;

	if (bslc->bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf sid", __func__,
				   bslc->bgp->name_pretty);
	}
}

struct bgp_srv6_per_locator_cache *
bgp_srv6_per_locator_new(struct bgp_srv6_per_locator_cache_head *tree, const char *locator_name)
{
	struct bgp_srv6_per_locator_cache *bslc;

	bslc = XCALLOC(MTYPE_SRV6_PER_LOCATOR_CACHE, sizeof(struct bgp_srv6_per_locator_cache));
	bslc->tree = tree;
	strncpy(bslc->locator_name, locator_name, sizeof(bslc->locator_name) - 1);
	LIST_INIT(&(bslc->paths));
	bgp_srv6_per_locator_cache_add(tree, bslc);

	return bslc;
}

int bgp_srv6_per_locator_cache_cmp(const struct bgp_srv6_per_locator_cache *a,
				   const struct bgp_srv6_per_locator_cache *b)
{
	return strncmp(a->locator_name, b->locator_name, sizeof(a->locator_name));
}

struct bgp_srv6_per_locator_cache *
bgp_srv6_per_locator_find(struct bgp_srv6_per_locator_cache_head *tree, const char *locator_name)
{
	struct bgp_srv6_per_locator_cache bslc = {};

	assert(tree);

	strncpy(bslc.locator_name, locator_name, sizeof(bslc.locator_name) - 1);

	return bgp_srv6_per_locator_cache_find(tree, &bslc);
}

/* detach locator when bgp path is removed */
static void bgp_srv6_per_locator_unlink_and_free(struct bgp_path_info *pi, bool free_bslc)
{
	struct bgp_srv6_per_locator_cache *bslc;

	bslc = pi->srv6_vpn.bslc;
	if (!bslc)
		return;

	LIST_REMOVE(pi, srv6_vpn.srv6_locator_thread);
	bslc->path_count--;
	pi->srv6_vpn.bslc = NULL;

	if (free_bslc && LIST_EMPTY(&(bslc->paths))) {
		bgp_srv6_per_locator_cache_delete_tovpn_sid(bslc);
		bgp_srv6_per_locator_free(bslc);
	}
}

void bgp_srv6_per_locator_unlink(struct bgp_path_info *pi)
{
	bgp_srv6_per_locator_unlink_and_free(pi, true);
}

/* Reset and free all BGP nexthop cache */
void bgp_srv6_per_locator_cache_reset(struct bgp *bgp, afi_t afi)
{
	struct bgp_srv6_per_locator_cache *bslc;
	struct bgp_srv6_per_locator_cache_head *tree;

	tree = &bgp->srv6_locators_per_routemap[afi];

	while (bgp_srv6_per_locator_cache_count(tree) > 0) {
		bslc = bgp_srv6_per_locator_cache_first(tree);

		while (!LIST_EMPTY(&(bslc->paths)))
			bgp_srv6_per_locator_unlink_and_free(LIST_FIRST(&(bslc->paths)), false);
		bgp_srv6_per_locator_cache_delete_tovpn_sid(bslc);
		bgp_srv6_per_locator_free(bslc);
	}
}

static void show_bgp_srv6_locators_per_routemap_afi(struct vty *vty, afi_t afi, struct bgp *bgp,
						    bool detail, json_object *json_list)
{
	struct bgp_srv6_per_locator_cache_head *tree;
	struct bgp_srv6_per_locator_cache *iter;
	struct srv6_locator *locator;
	safi_t safi;
	char buf[PREFIX2STR_BUFFER];
	struct bgp_dest *dest;
	struct bgp_path_info *path;
	struct bgp *bgp_path;
	struct bgp_table *table;
	json_object *json;
	json_object *json_path_list, *json_path_entry;

	if (json_list == NULL)
		vty_out(vty, "Current BGP SRv6 locator per route-map for %s, VRF %s\n",
			afi2str(afi), bgp->name_pretty);

	tree = &bgp->srv6_locators_per_routemap[afi];
	frr_each (bgp_srv6_per_locator_cache, tree, iter) {
		if (json_list) {
			json = json_object_new_object();

			json_object_string_add(json, "afi", afi2str(afi));
			json_object_string_add(json, "locatorName", iter->locator_name);
			locator = bgp_srv6_locator_lookup_all_by_name(iter->locator_name);
			if (locator)
				json_object_string_addf(json, "locatorPrefix", "%pFX",
							&locator->prefix);
			json_object_int_add(json, "pathCount", iter->path_count);
			json_object_string_add(json, "lastUpdate",
					       time_to_string_json(iter->last_update, buf));
			if (iter->sid_policy.tovpn_sid) {
				json_object_string_addf(json, "sid", "%pI6",
							iter->sid_policy.tovpn_sid);
				json_object_int_add(json, "label",
						    iter->sid_policy.tovpn_sid_transpose_label);
			}
			json_object_array_add(json_list, json);

			if (!detail)
				continue;

			json_path_list = json_object_new_array();

			LIST_FOREACH (path, &(iter->paths), srv6_vpn.srv6_locator_thread) {
				dest = path->net;
				table = bgp_dest_table(dest);
				assert(dest && table);
				afi = family2afi(bgp_dest_get_prefix(dest)->family);
				safi = table->safi;
				bgp_path = table->bgp;
				json_path_entry = json_object_new_object();
				json_object_string_add(json_path_entry, "afi", afi2str(afi));
				json_object_string_add(json_path_entry, "safi", safi2str(safi));
				json_object_string_addf(json_path_entry, "prefix", "%pBD", dest);
				json_object_string_add(json_path_entry, "bgpName",
						       bgp_path->name_pretty);
				json_object_string_addf(json_path_entry, "flags", "%08x",
							path->flags);
				if (dest->pdest)
					json_object_string_addf(json_path_entry,
								"route-distinguisher",
								BGP_RD_AS_FORMAT(bgp->asnotation),
								(struct prefix_rd *)
									bgp_dest_get_prefix(
										dest->pdest));
				json_object_array_add(json_path_list, json_path_entry);
			}
			json_object_object_add(json, "pathList", json_path_list);
			continue;
		}

		vty_out(vty, " %s, #paths %u\n", iter->locator_name, iter->path_count);
		vty_out(vty, "  Last update: %s\n", time_to_string_json(iter->last_update, buf));
		if (iter->sid_policy.tovpn_sid)
			vty_out(vty, "  SID %pI6, label %u\n", iter->sid_policy.tovpn_sid,
				iter->sid_policy.tovpn_sid_transpose_label);
		if (!detail)
			continue;
		vty_out(vty, "  Paths:\n");
		LIST_FOREACH (path, &(iter->paths), srv6_vpn.srv6_locator_thread) {
			dest = path->net;
			table = bgp_dest_table(dest);
			assert(dest && table);
			afi = family2afi(bgp_dest_get_prefix(dest)->family);
			safi = table->safi;
			bgp_path = table->bgp;

			if (dest->pdest) {
				vty_out(vty, "    %d/%d %pBD RD ", afi, safi, dest);

				vty_out(vty, BGP_RD_AS_FORMAT(bgp->asnotation),
					(struct prefix_rd *)bgp_dest_get_prefix(dest->pdest));
				vty_out(vty, " %s flags 0x%x\n", bgp_path->name_pretty,
					path->flags);
			} else
				vty_out(vty, "    %d/%d %pBD %s flags 0x%x\n", afi, safi, dest,
					bgp_path->name_pretty, path->flags);
		}
	}
}

DEFPY(show_bgp_srv6_locator_per_routemap, show_bgp_srv6_locator_per_routemap_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME] locator-routemap [detail] [json]",
      SHOW_STR BGP_STR BGP_INSTANCE_HELP_STR
      "BGP locator from route-map table\n"
      "Show detailed information\n"
      JSON_STR)
{
	int idx = 0;
	char *vrf = NULL;
	struct bgp *bgp;
	bool detail = false;
	int afi;
	struct json_object *json_list = NULL;

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[++idx]->arg;
		bgp = bgp_lookup_by_name(vrf);
	} else
		bgp = bgp_get_default();

	if (!bgp)
		return CMD_SUCCESS;

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	if (use_json(argc, argv))
		json_list = json_object_new_array();

	for (afi = AFI_IP; afi <= AFI_IP6; afi++)
		show_bgp_srv6_locators_per_routemap_afi(vty, afi, bgp, detail, json_list);

	if (json_list)
		vty_json(vty, json_list);

	return CMD_SUCCESS;
}

void bgp_srv6_locator_per_routemap_init(void)
{
	install_element(VIEW_NODE, &show_bgp_srv6_locator_per_routemap_cmd);
}

/* attempt to withdraw exported vpn path - code derived from vpn_leak_from_vrf_withdraw_all() */
void bgp_srv6_vpn_path_withdraw(struct bgp *bgp, const struct prefix *p, afi_t afi,
				struct srv6_locator *locator)
{
	struct bgp_dest *pdest, *bn = NULL;
	struct bgp_table *table;
	struct prefix_ipv6 tmp_prefix;
	struct bgp_path_info *bpi;
	bool process_pdest;

	assert(bgp);
	if (p == NULL)
		return;

	for (pdest = bgp_table_top(bgp_get_default()->rib[afi][SAFI_MPLS_VPN]); pdest;
	     pdest = bgp_route_next(pdest)) {
		/* This is the per-RD table of prefixes */
		table = bgp_dest_get_bgp_table_info(pdest);
		if (table)
			bn = bgp_node_lookup(table, p);
		if (!bn)
			continue;
		bpi = bgp_dest_get_bgp_path_info(bn);
		process_pdest = false;
		for (; bpi; bpi = bpi->next) {
			if (bpi->sub_type != BGP_ROUTE_IMPORTED)
				continue;
			/* Srv6 should match */
			if (!bpi->attr->srv6_l3service)
				continue;
			/* Verify that the received SID belongs to the configured locator */
			tmp_prefix.family = AF_INET6;
			tmp_prefix.prefixlen = IPV6_MAX_BITLEN;
			IPV6_ADDR_COPY(&tmp_prefix.prefix, &bpi->attr->srv6_l3service->sid);

			if (!prefix_match((struct prefix *)&locator->prefix,
					  (struct prefix *)&tmp_prefix))
				continue;
			vpn_leak_to_vrf_withdraw(bpi);
			bgp_aggregate_decrement(bgp_get_default(), bgp_dest_get_prefix(bn), bpi,
						afi, SAFI_MPLS_VPN);
			bgp_path_info_mark_for_delete(bn, bpi);
			process_pdest = true;
			/* no need to handle mpls function */
		}
		if (process_pdest)
			bgp_process(bgp, bn, afi, SAFI_MPLS_VPN);
	}
}

/* code derived from ensure_vrf_tovpn_sid(), applied to auto mode only */
void bgp_srv6_per_locator_cache_ensure_tovpn_sid(struct bgp_srv6_per_locator_cache *bslc)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct in6_addr tovpn_sid = {};
	struct srv6_sid_ctx ctx = {};
	uint32_t sid_func;
	struct srv6_locator *hash_locator;

	if (!bslc)
		return;

	/* auto mode is always configured.
	 * XXX when allocation mode are extended, more controls will be added here
	 */
	if (bslc->sid_policy.tovpn_sid)
		return;
	if (bslc->bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf SRv6 SID",
				   __func__, bslc->bgp->name_pretty);
		return;
	}
	hash_locator = hash_lookup(bm->srv6_locators, bslc->locator_name);
	if (!bslc->sid_policy.tovpn_sid_locator && hash_locator) {
		bslc->sid_policy.tovpn_sid_locator = srv6_locator_alloc(bslc->locator_name);
		srv6_locator_copy(bslc->sid_policy.tovpn_sid_locator, hash_locator);
	}
	if (!bslc->sid_policy.tovpn_sid_locator)
		return;
	ctx.vrf_id = bslc->bgp->vrf_id;
	ctx.behavior = bslc->afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
					   : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	ctx.alloc_mode = SRV6_SID_ALLOC_MODE_DYNAMIC;
	if (!bgp_zebra_request_srv6_sid(&ctx, &tovpn_sid, bslc->sid_policy.tovpn_sid_locator->name,
					&sid_func)) {
		zlog_err("%s: failed to request sid for vrf %s: afi %s locator %s", __func__,
			 bslc->bgp->name_pretty, afi2str(bslc->afi),
			 bslc->sid_policy.tovpn_sid_locator->name);
		return;
	}
	if (debug)
		zlog_debug("%s: allocating new SID for vrf %s: afi %s, locator %s", __func__,
			   bslc->bgp->name_pretty, afi2str(bslc->afi),
			   bslc->sid_policy.tovpn_sid_locator->name);
}

void bgp_srv6_per_locator_cache_vrf_sid_update(struct bgp_srv6_per_locator_cache *bslc)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *tovpn_sid;
	struct in6_addr *tovpn_sid_ls = NULL;
	struct vrf *vrf;
	struct interface *ifp;
	struct bgp *bgp;
	afi_t afi;

	if (!bslc)
		return;

	tovpn_sid = bslc->sid_policy.tovpn_sid;
	if (!bslc->sid_policy.tovpn_sid)
		return;
	if (sid_same(bslc->sid_policy.tovpn_sid, bslc->sid_policy.tovpn_zebra_sid_last_sent))
		return;
	bgp = bslc->bgp;
	afi = bslc->afi;
	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: afi %s: vrf_id not set, can't set zebra vrf label",
				   __func__, bgp->name_pretty, afi2str(afi));
		return;
	}

	if (debug)
		zlog_debug("%s: vrf %s: afi %s: setting sid %pI6 for vrf id %d", __func__,
			   bgp->name_pretty, afi2str(afi), tovpn_sid, bgp->vrf_id);

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (!vrf)
		return;

	ifp = if_get_vrf_loopback(bgp->vrf_id);
	if (!ifp)
		return;

	if (bslc->sid_policy.tovpn_sid_locator) {
		ctx.block_len = bslc->sid_policy.tovpn_sid_locator->block_bits_length;
		ctx.node_len = bslc->sid_policy.tovpn_sid_locator->node_bits_length;
		ctx.function_len = bslc->sid_policy.tovpn_sid_locator->function_bits_length;
		ctx.argument_len = bslc->sid_policy.tovpn_sid_locator->argument_bits_length;
		if (CHECK_FLAG(bslc->sid_policy.tovpn_sid_locator->flags,
			       SRV6_LOCATOR_USID | SRV6_LOCATOR_F3216))
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
	}
	ctx.table = vrf->data.l.table_id;
	act = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4 : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	zclient_send_localsid(zclient, ZEBRA_ROUTE_ADD, tovpn_sid, IPV6_MAX_BITLEN, ifp->ifindex,
			      act, &ctx);

	tovpn_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
	*tovpn_sid_ls = *tovpn_sid;
	if (bslc->sid_policy.tovpn_zebra_sid_last_sent)
		XFREE(MTYPE_BGP_SRV6_SID, bslc->sid_policy.tovpn_zebra_sid_last_sent);
	bslc->sid_policy.tovpn_zebra_sid_last_sent = tovpn_sid_ls;
}

void bgp_srv6_route_map_update(struct bgp *bgp, afi_t afi, const char *rmap_name)
{
	if (!is_srv6_unicast_enabled(bgp, afi))
		return;

	if (!bgp->srv6_unicast[afi].rmap_name)
		return;

	if (!strmatch(bgp->srv6_unicast[afi].rmap_name, rmap_name))
		return;

	bgp_srv6_unicast_announce(bgp, afi);
}

void bgp_srv6_unicast_sids_unset(struct bgp *bgp, afi_t afi)
{
	/* withdraw srv6 unicast and refresh srv6 unicast sid locator */
	if (afi != AFI_IP6 && is_srv6_unicast_enabled(bgp, AFI_IP)) {
		bgp_srv6_unicast_withdraw(bgp, AFI_IP);
		bgp_srv6_unicast_sid_withdraw(bgp, AFI_IP);
		/* locator deleted after this call, free the sid */
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[AFI_IP].sid);
		srv6_locator_free(bgp->srv6_unicast[AFI_IP].sid_locator);
		bgp->srv6_unicast[AFI_IP].sid_locator = NULL;
	}
	if (afi != AFI_IP && is_srv6_unicast_enabled(bgp, AFI_IP6)) {
		bgp_srv6_unicast_withdraw(bgp, AFI_IP6);
		bgp_srv6_unicast_sid_withdraw(bgp, AFI_IP6);
		/* locator deleted after this call, free the sid */
		XFREE(MTYPE_BGP_SRV6_SID, bgp->srv6_unicast[AFI_IP6].sid);
		srv6_locator_free(bgp->srv6_unicast[AFI_IP6].sid_locator);
		bgp->srv6_unicast[AFI_IP6].sid_locator = NULL;
	}
}
