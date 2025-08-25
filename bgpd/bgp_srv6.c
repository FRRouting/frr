// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SRv6 definitions
 * Copyright (C) 2025 6WIND
 * Loïc SANG <loic.sang@6wind.com>
 */

#include <zebra.h>

#include "log.h"
#include "zclient.h"

#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_srv6.h"
#include "bgpd/bgpd.h"

extern struct zclient *bgp_zclient;

bool is_srv6_unicast_enabled(struct bgp *bgp, afi_t afi)
{
	if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST], BGP_CONFIG_SRV6_UNICAST_SID_AUTO)
	    || bgp->unicast_sid_explicit[afi] || bgp->unicast_sid_index[afi])
		return true;

	return false;
}

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
	if (bgp->unicast_sid[afi])
		return;

	locator_bgp = bgp->srv6_locator;
	/* locator no set */
	if (!locator_bgp)
		return;

	unicast_sid_index = bgp->unicast_sid_index[afi];
	unicast_sid_auto = CHECK_FLAG(bgp->af_flags[afi][safi],
				      BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
	unicast_sid_explicit = bgp->unicast_sid_explicit[afi];

	if ((unicast_sid_index != 0 && unicast_sid_auto) ||
	    (unicast_sid_index != 0 && unicast_sid_explicit) ||
	    (unicast_sid_auto && unicast_sid_explicit)) {
		zlog_err("%s: more than one mode selected among index-mode, auto-mode and explicit-mode. ignored.",
			 __func__);
		return;
	}

	/* skip when sid value isn't set for explicit-mode */
	if (unicast_sid_explicit && !bgp->unicast_sid_explicit[afi]) {
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
		unicast_sid = *(bgp->unicast_sid_explicit[afi]);
	}

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	if (!bgp_zebra_request_srv6_sid(&ctx, &unicast_sid, locator_bgp->name, &sid_func)) {
		zlog_err("%s: failed to request sid for bgp %s: afi %s", __func__,
			 bgp->name_pretty, afi2str(afi));
	}
}

void bgp_srv6_unicast_sid_withdraw(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	struct srv6_sid_ctx ctx = {};
	struct seg6local_context seg6localctx = {};

	if (bgp->vrf_id != VRF_DEFAULT)
		return;

	if (!bgp->unicast_zebra_vrf_sid_last_sent[afi])
		return;

	zlog_debug("%s: vrf %s: deleteing sid %pI6 for vrf id %d", __func__, bgp->name_pretty,
		   bgp->unicast_sid[afi], bgp->vrf_id);

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("%s interface not found, nothing to uninstall",
			  DEFAULT_SRV6_IFNAME);
		return;
	}

	seg6localctx.block_len = bgp->unicast_sid_locator[afi]->block_bits_length;
	seg6localctx.node_len = bgp->unicast_sid_locator[afi]->node_bits_length;
	seg6localctx.function_len = bgp->unicast_sid_locator[afi]->function_bits_length;
	seg6localctx.argument_len = bgp->unicast_sid_locator[afi]->argument_bits_length;
	zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_DELETE,
			      bgp->unicast_zebra_vrf_sid_last_sent[afi], IPV6_MAX_BITLEN,
			      ifp->ifindex, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC, &seg6localctx);
	XFREE(MTYPE_BGP_SRV6_SID, bgp->unicast_zebra_vrf_sid_last_sent[afi]);
	bgp->unicast_zebra_vrf_sid_last_sent[afi] = NULL;

	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	ctx.vrf_id = bgp->vrf_id;
	bgp_zebra_release_srv6_sid(&ctx, bgp->unicast_sid_locator[afi]->name);
}

void bgp_srv6_unicast_delete(struct bgp *bgp, afi_t afi)
{
	struct srv6_sid_ctx ctx = {};

	if (!bgp || bgp->vrf_id != VRF_DEFAULT)
		return;

	if (!is_srv6_unicast_enabled(bgp, AFI_IP))
		return;

	if (bgp->unicast_sid[afi]) {
		ctx.vrf_id = bgp->vrf_id;
		ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
					     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		bgp_zebra_release_srv6_sid(&ctx, bgp->unicast_sid_locator[afi]->name);

		sid_unregister(bgp, bgp->unicast_sid[afi]);
		XFREE(MTYPE_BGP_SRV6_SID, bgp->unicast_sid[afi]);
	}

	if (bgp->unicast_sid_explicit[afi])
		XFREE(MTYPE_BGP_SRV6_SID, bgp->unicast_sid_explicit[afi]);

	if (bgp->srv6_unicast_rmap_name[afi])
		XFREE(MTYPE_ROUTE_MAP_NAME, bgp->srv6_unicast_rmap_name[afi]);

	if (bgp->unicast_zebra_vrf_sid_last_sent[afi])
		XFREE(MTYPE_BGP_SRV6_SID, bgp->unicast_zebra_vrf_sid_last_sent[afi]);

	srv6_locator_free(bgp->unicast_sid_locator[afi]);
	bgp->unicast_sid_locator[afi] = NULL;
	UNSET_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
		   BGP_CONFIG_SRV6_UNICAST_SID_AUTO);
}

void bgp_srv6_unicast_sid_update(struct bgp *bgp, afi_t afi)
{
	struct vrf *vrf;
	struct interface *ifp;
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *unicast_sid = NULL;
	struct in6_addr *unicast_sid_ls = NULL;

	unicast_sid = bgp->unicast_sid[afi];
	if (!unicast_sid)
		return;

	ifp = if_lookup_by_name(DEFAULT_SRV6_IFNAME, VRF_DEFAULT);
	if (!ifp) {
		zlog_warn("Failed to install SRv6 SID %pI6: %s interface not found",
			  unicast_sid, DEFAULT_SRV6_IFNAME);
		return;
	}

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (!vrf)
		return;

	if (bgp->unicast_sid_locator[afi]) {
		ctx.block_len = bgp->unicast_sid_locator[afi]->block_bits_length;
		ctx.node_len = bgp->unicast_sid_locator[afi]->node_bits_length;
		ctx.function_len = bgp->unicast_sid_locator[afi]->function_bits_length;
		ctx.argument_len = bgp->unicast_sid_locator[afi]->argument_bits_length;
		if (CHECK_FLAG(bgp->unicast_sid_locator[afi]->flags, SRV6_LOCATOR_USID))
			SET_SRV6_FLV_OP(ctx.flv.flv_ops, ZEBRA_SEG6_LOCAL_FLV_OP_NEXT_CSID);
	}
	ctx.table = vrf->data.l.table_id;
	act = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4 : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	zclient_send_localsid(bgp_zclient, ZEBRA_ROUTE_ADD, unicast_sid, IPV6_MAX_BITLEN,
			      ifp->ifindex, act, &ctx);

	unicast_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
	*unicast_sid_ls = *unicast_sid;
	if (bgp->unicast_zebra_vrf_sid_last_sent[afi])
		XFREE(MTYPE_BGP_SRV6_SID, bgp->unicast_zebra_vrf_sid_last_sent[afi]);
	bgp->unicast_zebra_vrf_sid_last_sent[afi] = unicast_sid_ls;
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

	if (!bgp->unicast_sid_locator[afi])
		return;

	if (bgp->srv6_unicast_rmap_name[afi]) {
		rmap = route_map_lookup_by_name(bgp->srv6_unicast_rmap_name[afi]);
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
				zlog_debug("srv6 unicast prefix %pBD denied", dest);
				return;
			}
		} else {
			zlog_warn("route-map %s was no found, ignored",
				  bgp->srv6_unicast_rmap_name[afi]);
		}
	}

	if (dest->srv6_unicast && sid_same(bgp->unicast_sid[afi], &dest->srv6_unicast->sid))
		return;

	locator = bgp->unicast_sid_locator[afi];
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
	memcpy(&dest->srv6_unicast->sid, bgp->unicast_sid[afi],
	       sizeof(struct in6_addr));
}
