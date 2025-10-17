// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#include <zebra.h>

#include "log.h"
#include "zclient.h"

#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgpd.h"

extern struct zclient *bgp_zclient;

int bgp_srv6_configure(struct vty *vty, struct bgp *bgp, afi_t afi, bool sid_auto,
			   uint32_t sid_idx, bool sid_explicit,
			   struct in6_addr sid_value, const char *rmap_str, bool no)
{

	safi_t safi = SAFI_UNICAST;
	uint32_t configured_flags;
	struct srv6_policy *srv6_policy;
	struct in6_addr *unicast_sid_explicit = NULL;

	if (no) {
		if (!is_srv6_unicast_afi_enabled(bgp, afi))
			return CMD_SUCCESS;

		srv6_policy = get_srv6_policy(bgp, afi);
		if (srv6_policy->rmap_name) {
			XFREE(MTYPE_ROUTE_MAP_NAME, srv6_policy->rmap_name);
			srv6_policy->rmap_name = NULL;
		}
		if (srv6_policy->sid_explicit) {
			XFREE(MTYPE_BGP_SRV6_SID, srv6_policy->sid_explicit);
			srv6_policy->sid_explicit = NULL;
		}

		srv6_policy->sid_index = 0;
		if (afi == AFI_UNSPEC)
			UNSET_FLAG(bgp->vrf_flags, BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
		else
			UNSET_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_SRV6_UNICAST_SID_AUTO);

		bgp_srv6_unicast_sid_withdraw(bgp, afi);

		return CMD_SUCCESS;
	}

	srv6_policy = get_srv6_policy(bgp, afi);
	if (afi == AFI_UNSPEC)
		configured_flags = bgp->vrf_flags;
	else
		configured_flags = bgp->af_flags[afi][safi];

	/* configured */
	if ((sid_auto && CHECK_FLAG(configured_flags, BGP_CONFIG_SRV6_UNICAST_SID_AUTO)) ||
	    (sid_idx != 0 && srv6_policy->sid_index != 0) ||
	    (sid_explicit && srv6_policy->sid_explicit)) {
		/* no rmap change */
		if (!rmap_str || (srv6_policy->rmap_name &&
				  !strcmp(rmap_str, srv6_policy->rmap_name)))
			return CMD_SUCCESS;

		/* apply route-map change */
		bgp_srv6_unicast_announce(bgp, afi);

		return CMD_SUCCESS;
	}

	/*
	 * mode change between sid_idx and sid_auto isn't supported.
	 * user must negate sid vpn export when they want to change the mode
	 */
	if ((sid_auto || sid_explicit) && srv6_policy->sid_index != 0) {
		vty_out(vty, "it's already configured as idx-mode.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if ((sid_auto || sid_idx != 0) && srv6_policy->sid_explicit) {
		vty_out(vty, "it's already configured as explicit-mode.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if ((sid_idx != 0 || sid_explicit) &&
	    CHECK_FLAG(configured_flags, BGP_CONFIG_SRV6_UNICAST_SID_AUTO)) {
		vty_out(vty, "it's already configured as auto-mode.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rmap_str)
		srv6_policy->rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_str);

	if (sid_auto) {
		if (afi == AFI_UNSPEC)
			SET_FLAG(bgp->vrf_flags, BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
		else
			SET_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	} else if (sid_idx) {
		srv6_policy->sid_index = sid_idx;
	} else if (sid_explicit) {
		unicast_sid_explicit = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		IPV6_ADDR_COPY(unicast_sid_explicit, &sid_value);
		srv6_policy->sid_explicit = unicast_sid_explicit;
	}

	/* request srv6 sid */
	bgp_srv6_unicast_ensure_afi_sid(bgp, afi);

	return CMD_SUCCESS;
}

struct srv6_policy *get_srv6_policy(struct bgp *bgp, afi_t afi)
{
	if (afi == AFI_UNSPEC)
		return &bgp->srv6_unicast_vrf;
	else
		return &bgp->srv6_unicast[afi];
}

static int bgp_srv6_get_seg6_action(afi_t afi)
{
	if (afi == AFI_IP)
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT4;
	else if (afi == AFI_IP6)
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	else
		return ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
}

void bgp_srv6_unicast_ensure_afi_sid(struct bgp *bgp, afi_t afi)
{
	uint32_t sid_func;
	safi_t safi = SAFI_UNICAST;
	struct srv6_sid_ctx ctx = {};
	bool unicast_sid_auto = false;
	uint32_t unicast_sid_index = 0;
	struct srv6_policy *srv6_policy;
	struct in6_addr unicast_sid = {};
	struct srv6_locator *locator_bgp;
	bool unicast_sid_explicit = false;

	/* no configured */
	if (!is_srv6_unicast_enabled(bgp))
		return;

	srv6_policy = get_srv6_policy(bgp, afi);
	/* already allocated */
	if (srv6_policy->sid)
		return;

	locator_bgp = bgp->srv6_locator;
	/* locator no set */
	if (!locator_bgp)
		return;

	unicast_sid_index = srv6_policy->sid_index;
	if (afi == AFI_UNSPEC)
		unicast_sid_auto = CHECK_FLAG(bgp->vrf_flags, BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	else
		unicast_sid_auto = CHECK_FLAG(bgp->af_flags[afi][safi],
					      BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	unicast_sid_explicit = srv6_policy->sid_explicit;

	if ((unicast_sid_index != 0 && unicast_sid_auto) ||
	    (unicast_sid_index != 0 && unicast_sid_explicit) ||
	    (unicast_sid_auto && unicast_sid_explicit)) {
		zlog_err("%s: more than one mode selected among index-mode, auto-mode and explicit-mode. ignored.",
			 __func__);
		return;
	}

	/* skip when sid value isn't set for explicit-mode */
	if (unicast_sid_explicit && !srv6_policy->sid_explicit) {
		zlog_err("%s: explicit-mode selected without sid value.", __func__);
		return;
	}
	if (!unicast_sid_auto && !unicast_sid_explicit) {
		if (!srv6_sid_compose(&unicast_sid, locator_bgp, unicast_sid_index)) {
			zlog_err("%s: failed to compose unicast sid %s: afi %s",
				 __func__, bgp->name_pretty, afi2str(afi));
			return;
		}
	} else if (unicast_sid_explicit) {
		unicast_sid = *(srv6_policy->sid_explicit);
	}

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = bgp_srv6_get_seg6_action(afi);
	if (!bgp_zebra_request_srv6_sid(&ctx, &unicast_sid, locator_bgp->name, &sid_func)) {
		zlog_err("%s: failed to request sid for bgp %s: afi %s", __func__,
			 bgp->name_pretty, afi2str(afi));
	}
}

void bgp_srv6_unicast_sid_endpoint(struct bgp *bgp, afi_t afi,
				   struct interface *ifp, bool install)
{
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	int debug = BGP_DEBUG(zebra, ZEBRA);
	struct in6_addr *unicast_sid_ls = NULL;
	struct srv6_policy *srv6_policy = get_srv6_policy(bgp, afi);

	if (!srv6_policy->sid)
		return;

	if (debug)
		zlog_debug("%s: vrf %s: %s endpoint action for %pI6", __func__, bgp->name_pretty,
			   install ? "install" : "uinstall", srv6_policy->sid);

	ctx.block_len = srv6_policy->sid_locator->block_bits_length;
	ctx.node_len = srv6_policy->sid_locator->node_bits_length;
	ctx.function_len = srv6_policy->sid_locator->function_bits_length;
	ctx.argument_len = srv6_policy->sid_locator->argument_bits_length;

	if (install) {
		if (CHECK_FLAG(srv6_policy->sid_locator->flags, SRV6_LOCATOR_USID))
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
		ctx.table = ifp->vrf->data.l.table_id;
		act = bgp_srv6_get_seg6_action(afi);
		zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_ADD, srv6_policy->sid,
				      IPV6_MAX_BITLEN, ifp->ifindex, act, &ctx);
		unicast_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		*unicast_sid_ls = *srv6_policy->sid;
		if (srv6_policy->zebra_sid_last_sent)
			XFREE(MTYPE_BGP_SRV6_SID, srv6_policy->zebra_sid_last_sent);
		srv6_policy->zebra_sid_last_sent = unicast_sid_ls;

	} else {
		zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_DELETE,
				      srv6_policy->zebra_sid_last_sent, IPV6_MAX_BITLEN,
				      ifp->ifindex, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC, &ctx);
		XFREE(MTYPE_BGP_SRV6_SID, srv6_policy->zebra_sid_last_sent);
		srv6_policy->zebra_sid_last_sent = NULL;
	}
}

void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};
	struct srv6_policy *srv6_policy;
	int debug = BGP_DEBUG(zebra, ZEBRA);

	if (bgp->vrf_id != VRF_DEFAULT)
		return;

	srv6_policy = get_srv6_policy(bgp, afi);
	if (debug)
		zlog_debug("%s: vrf %s: deleting sid %pI6 for vrf id %d", __func__,
			   bgp->name_pretty, srv6_policy->sid, bgp->vrf_id);

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s interface not found, nothing to uninstall",
			  DEFAULT_SRV6_IFNAME);
		return;
	}

	if (srv6_policy->zebra_sid_last_sent)
		bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

	ctx.behavior = bgp_srv6_get_seg6_action(afi);
	ctx.vrf_id = bgp->vrf_id;
	bgp_zebra_release_srv6_sid(&ctx, srv6_policy->sid_locator->name);
}

void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};
	struct srv6_policy *srv6_policy;

	if (!bgp || bgp->vrf_id != VRF_DEFAULT)
		return;

	if (!is_srv6_unicast_enabled(bgp))
		return;

	srv6_policy = get_srv6_policy(bgp, afi);

	if (srv6_policy->sid) {
		ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
		if (ifp && srv6_policy->zebra_sid_last_sent)
			bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, false);

		ctx.vrf_id = bgp->vrf_id;
		ctx.behavior = bgp_srv6_get_seg6_action(afi);
		bgp_zebra_release_srv6_sid(&ctx, srv6_policy->sid_locator->name);

		sid_unregister(bgp, srv6_policy->sid);
		XFREE(MTYPE_BGP_SRV6_SID, srv6_policy->sid);
	}

	if (srv6_policy->sid_explicit)
		XFREE(MTYPE_BGP_SRV6_SID, srv6_policy->sid_explicit);

	if (srv6_policy->rmap_name)
		XFREE(MTYPE_ROUTE_MAP_NAME, srv6_policy->rmap_name);

	srv6_locator_free(srv6_policy->sid_locator);
	srv6_policy->sid_locator = NULL;
	if (afi == AFI_UNSPEC)
		UNSET_FLAG(bgp->vrf_flags, BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	else
		UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
}

void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_policy *srv6_policy = get_srv6_policy(bgp, afi);

	if (!srv6_policy->sid)
		return;

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s interface not found, can not install SRV6 endpoint behavior",
			  DEFAULT_SRV6_IFNAME);
		return;
	}
	if (!if_is_up(ifp))
		return;

	bgp_srv6_unicast_sid_endpoint(bgp, afi, ifp, true);
}

void bgp_srv6_unicast_unregister_route(struct bgp_dest *dest)
{
	XFREE(MTYPE_BGP_SRV6_L3SERVICE, dest->srv6_unicast);
	dest->srv6_unicast = NULL;
}

void bgp_srv6_unicast_register_route(struct bgp *bgp, afi_t afi, struct bgp_dest *dest,
				     struct srv6_policy *srv6_policy, struct bgp_path_info *bpi)
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

	if (!srv6_policy)
		srv6_policy = is_srv6_unicast_afi_enabled(bgp, afi) ?
			get_srv6_policy(bgp, afi) : &bgp->srv6_unicast_vrf;

	if (!srv6_policy->sid_locator)
		return;

	if (srv6_policy->rmap_name) {
		rmap = route_map_lookup_by_name(srv6_policy->rmap_name);
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
		} else {
			zlog_warn("route-map %s was no found, ignored",
				  srv6_policy->rmap_name);
		}
	}

	if (dest->srv6_unicast && sid_same(srv6_policy->sid, &dest->srv6_unicast->sid))
		return;

	locator = srv6_policy->sid_locator;
	dest->srv6_unicast = XCALLOC(MTYPE_BGP_SRV6_L3SERVICE,
				     sizeof(struct bgp_attr_srv6_l3service));
	dest->srv6_unicast->sid_flags = 0x00;
	dest->srv6_unicast->endpoint_behavior =
			afi == AFI_IP ? (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
						 ? SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID
						 : SRV6_ENDPOINT_BEHAVIOR_END_DT4)
				      : (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
						 ? SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID
						 : SRV6_ENDPOINT_BEHAVIOR_END_DT6);
	dest->srv6_unicast->loc_block_len = locator->block_bits_length;
	dest->srv6_unicast->loc_node_len = locator->node_bits_length;
	dest->srv6_unicast->func_len = locator->function_bits_length;
	dest->srv6_unicast->arg_len = locator->argument_bits_length;
	memcpy(&dest->srv6_unicast->sid, srv6_policy->sid, sizeof(struct in6_addr));
}

static void _bgp_srv6_unicast_announce(struct bgp *bgp, struct srv6_policy *srv6_policy,
				       afi_t afi)
{
	struct peer *peer;
	struct bgp_dest *pdest;
	struct bgp_path_info *bpi;
	safi_t safi = SAFI_UNICAST;
	struct listnode *node, *nnode;

	if (!srv6_policy->sid_locator)
		return;

	for (pdest = bgp_table_top(bgp->rib[afi][safi]); pdest; pdest = bgp_route_next(pdest)) {
		for (bpi = bgp_dest_get_bgp_path_info(pdest); bpi; bpi = bpi->next) {
			if (!CHECK_FLAG(bpi->flags, BGP_PATH_SELECTED))
				continue;

			if (bpi->attr->srv6_l3service)
				continue;

			bgp_srv6_unicast_register_route(bgp, afi, pdest, srv6_policy, bpi);
			break;
		}
	}

	/* force to resend all routes */
	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (peergroup_af_flag_check(peer, afi, safi,
					    PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_STRICT) ||
		    peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6))
			bgp_announce_route(peer, afi, safi, true);
	}
}

void bgp_srv6_unicast_announce(struct bgp *bgp, afi_t afi)
{
	struct srv6_policy *srv6_policy = get_srv6_policy(bgp, afi);

	if (afi == AFI_UNSPEC) {
		_bgp_srv6_unicast_announce(bgp, srv6_policy, AFI_IP);
		_bgp_srv6_unicast_announce(bgp, srv6_policy, AFI_IP6);
	} else {
		_bgp_srv6_unicast_announce(bgp, srv6_policy, afi);
	}
}

static void _bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi)
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
					    PEER_FLAG_CONFIG_ENCAPSULATION_SRV6_STRICT) ||
		    peergroup_af_flag_check(peer, afi, safi, PEER_FLAG_CONFIG_ENCAPSULATION_SRV6))
			bgp_announce_route(peer, afi, safi, true);
	}
}

void bgp_srv6_unicast_withdraw(struct bgp *bgp, afi_t afi)
{
	if (afi == AFI_UNSPEC) {
		_bgp_srv6_unicast_withdraw(bgp, AFI_IP);
		_bgp_srv6_unicast_withdraw(bgp, AFI_IP6);
	} else {
		_bgp_srv6_unicast_withdraw(bgp, afi);
	}
}
