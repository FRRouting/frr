// SPDX-License-Identifier: GPL-2.0-or-later
/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "queue.h"
#include "filter.h"
#include "mpls.h"
#include "json.h"
#include "zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_vpn.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_memory.h"
#include "bgpd/bgp_aspath.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

DEFINE_MTYPE_STATIC(BGPD, MPLSVPN_NH_LABEL_BIND_CACHE,
		    "BGP MPLSVPN nexthop label bind cache");

/*
 * Definitions and external declarations.
 */
extern struct zclient *zclient;

extern int argv_find_and_parse_vpnvx(struct cmd_token **argv, int argc,
				     int *index, afi_t *afi)
{
	int ret = 0;
	if (argv_find(argv, argc, "vpnv4", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP;
	} else if (argv_find(argv, argc, "vpnv6", index)) {
		ret = 1;
		if (afi)
			*afi = AFI_IP6;
	}
	return ret;
}

uint32_t decode_label(mpls_label_t *label_pnt)
{
	uint32_t l;
	uint8_t *pnt = (uint8_t *)label_pnt;

	l = ((uint32_t)*pnt++ << 12);
	l |= (uint32_t)*pnt++ << 4;
	l |= (uint32_t)((*pnt & 0xf0) >> 4);
	return l;
}

void encode_label(mpls_label_t label, mpls_label_t *label_pnt)
{
	uint8_t *pnt = (uint8_t *)label_pnt;
	if (pnt == NULL)
		return;
	if (label == BGP_PREVENT_VRF_2_VRF_LEAK) {
		*label_pnt = label;
		return;
	}
	*pnt++ = (label >> 12) & 0xff;
	*pnt++ = (label >> 4) & 0xff;
	*pnt++ = ((label << 4) + 1) & 0xff; /* S=1 */
}

int bgp_nlri_parse_vpn(struct peer *peer, struct attr *attr,
		       struct bgp_nlri *packet)
{
	struct prefix p;
	uint8_t psize = 0;
	uint8_t prefixlen;
	uint16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	struct prefix_rd prd = {0};
	mpls_label_t label = {0};
	afi_t afi;
	safi_t safi;
	bool addpath_capable;
	uint32_t addpath_id;
	int ret = 0;

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	struct stream *data = stream_new(packet->length);
	stream_put(data, packet->nlri, packet->length);
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

#define VPN_PREFIXLEN_MIN_BYTES (3 + 8) /* label + RD */
	while (STREAM_READABLE(data) > 0) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		if (addpath_capable) {
			STREAM_GET(&addpath_id, data, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
		}

		if (STREAM_READABLE(data) < 1) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (truncated NLRI of size %u; no prefix length)",
				peer->host, packet->length);
			ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			goto done;
		}

		/* Fetch prefix length. */
		STREAM_GETC(data, prefixlen);
		p.family = afi2family(packet->afi);
		psize = PSIZE(prefixlen);

		if (prefixlen < VPN_PREFIXLEN_MIN_BYTES * 8) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (prefix length %d less than VPN min length)",
				peer->host, prefixlen);
			ret = BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
			goto done;
		}

		/* sanity check against packet data */
		if (STREAM_READABLE(data) < psize) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (prefix length %d exceeds packet size %u)",
				peer->host, prefixlen, packet->length);
			ret = BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			goto done;
		}

		/* sanity check against storage for the IP address portion */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > (ssize_t)sizeof(p.u)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (psize %d exceeds storage size %zu)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				sizeof(p.u));
			ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			goto done;
		}

		/* Sanity check against max bitlen of the address family */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > prefix_blen(&p)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (psize %d exceeds family (%u) max byte len %u)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				p.family, prefix_blen(&p));
			ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			goto done;
		}

		/* Copy label to prefix. */
		if (STREAM_READABLE(data) < BGP_LABEL_BYTES) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (truncated NLRI of size %u; no label)",
				peer->host, packet->length);
			ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			goto done;
		}

		STREAM_GET(&label, data, BGP_LABEL_BYTES);
		bgp_set_valid_label(&label);

		/* Copy routing distinguisher to rd. */
		if (STREAM_READABLE(data) < 8) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (truncated NLRI of size %u; no RD)",
				peer->host, packet->length);
			ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
			goto done;
		}
		STREAM_GET(&prd.val, data, 8);

		/* Decode RD type. */
		type = decode_rd_type(prd.val);

		switch (type) {
		case RD_TYPE_AS:
			decode_rd_as(&prd.val[2], &rd_as);
			break;

		case RD_TYPE_AS4:
			decode_rd_as4(&prd.val[2], &rd_as);
			break;

		case RD_TYPE_IP:
			decode_rd_ip(&prd.val[2], &rd_ip);
			break;

#ifdef ENABLE_BGP_VNC
		case RD_TYPE_VNC_ETH:
			break;
#endif

		default:
			flog_err(EC_BGP_UPDATE_RCV, "Unknown RD type %d", type);
			break; /* just report */
		}

		/* exclude label & RD */
		p.prefixlen = prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8;
		STREAM_GET(p.u.val, data, psize - VPN_PREFIXLEN_MIN_BYTES);

		if (attr) {
			bgp_update(peer, &p, addpath_id, attr, packet->afi,
				   SAFI_MPLS_VPN, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, &prd, &label, 1, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, addpath_id, packet->afi,
				     SAFI_MPLS_VPN, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, &prd, &label, 1);
		}
	}
	/* Packet length consistency check. */
	if (STREAM_READABLE(data) != 0) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / VPN (%zu data remaining after parsing)",
			peer->host, STREAM_READABLE(data));
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
	}

	goto done;

stream_failure:
	flog_err(
		EC_BGP_UPDATE_RCV,
		"%s [Error] Update packet error / VPN (NLRI of size %u - length error)",
		peer->host, packet->length);
	ret = BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

done:
	stream_free(data);
	return ret;

#undef VPN_PREFIXLEN_MIN_BYTES
}

/*
 * This function informs zebra of the label this vrf sets on routes
 * leaked to VPN. Zebra should install this label in the kernel with
 * an action of "pop label and then use this vrf's IP FIB to route the PDU."
 *
 * Sending this vrf-label association is qualified by a) whether vrf->vpn
 * exporting is active ("export vpn" is enabled, vpn-policy RD and RT list
 * are set), b) whether vpn-policy label is set and c) the vrf loopback
 * interface is up.
 *
 * If any of these conditions do not hold, then we send MPLS_LABEL_NONE
 * for this vrf, which zebra interprets to mean "delete this vrf-label
 * association."
 */
void vpn_leak_zebra_vrf_label_update(struct bgp *bgp, afi_t afi)
{
	struct interface *ifp;
	mpls_label_t label = MPLS_LABEL_NONE;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug) {
			zlog_debug(
				"%s: vrf %s: afi %s: vrf_id not set, can't set zebra vrf label",
				__func__, bgp->name_pretty, afi2str(afi));
		}
		return;
	}

	if (vpn_leak_to_vpn_active(bgp, afi, NULL, false)) {
		ifp = if_get_vrf_loopback(bgp->vrf_id);
		if (ifp && if_is_up(ifp))
			label = bgp->vpn_policy[afi].tovpn_label;
	}

	if (debug) {
		zlog_debug("%s: vrf %s: afi %s: setting label %d for vrf id %d",
			   __func__, bgp->name_pretty, afi2str(afi), label,
			   bgp->vrf_id);
	}

	if (label == BGP_PREVENT_VRF_2_VRF_LEAK)
		label = MPLS_LABEL_NONE;
	zclient_send_vrf_label(zclient, bgp->vrf_id, afi, label, ZEBRA_LSP_BGP);
	bgp->vpn_policy[afi].tovpn_zebra_vrf_label_last_sent = label;
}

/*
 * If zebra tells us vrf has become unconfigured, tell zebra not to
 * use this label to forward to the vrf anymore
 */
void vpn_leak_zebra_vrf_label_withdraw(struct bgp *bgp, afi_t afi)
{
	mpls_label_t label = MPLS_LABEL_NONE;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug) {
			zlog_debug(
				"%s: vrf_id not set, can't delete zebra vrf label",
				__func__);
		}
		return;
	}

	if (debug) {
		zlog_debug("%s: deleting label for vrf %s (id=%d)", __func__,
			   bgp->name_pretty, bgp->vrf_id);
	}

	zclient_send_vrf_label(zclient, bgp->vrf_id, afi, label, ZEBRA_LSP_BGP);
	bgp->vpn_policy[afi].tovpn_zebra_vrf_label_last_sent = label;
}

/*
 * This function informs zebra of the srv6-function this vrf sets on routes
 * leaked to VPN. Zebra should install this srv6-function in the kernel with
 * an action of "End.DT4/6's IP FIB to route the PDU."
 */
void vpn_leak_zebra_vrf_sid_update_per_af(struct bgp *bgp, afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *tovpn_sid = NULL;
	struct in6_addr *tovpn_sid_ls = NULL;
	struct vrf *vrf;

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: afi %s: vrf_id not set, can't set zebra vrf label",
				   __func__, bgp->name_pretty, afi2str(afi));
		return;
	}

	tovpn_sid = bgp->vpn_policy[afi].tovpn_sid;
	if (!tovpn_sid) {
		if (debug)
			zlog_debug("%s: vrf %s: afi %s: sid not set", __func__,
				   bgp->name_pretty, afi2str(afi));
		return;
	}

	if (debug)
		zlog_debug("%s: vrf %s: afi %s: setting sid %pI6 for vrf id %d",
			   __func__, bgp->name_pretty, afi2str(afi), tovpn_sid,
			   bgp->vrf_id);

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (!vrf)
		return;

	if (bgp->vpn_policy[afi].tovpn_sid_locator) {
		ctx.block_len =
			bgp->vpn_policy[afi].tovpn_sid_locator->block_bits_length;
		ctx.node_len =
			bgp->vpn_policy[afi].tovpn_sid_locator->node_bits_length;
		ctx.function_len =
			bgp->vpn_policy[afi]
				.tovpn_sid_locator->function_bits_length;
		ctx.argument_len =
			bgp->vpn_policy[afi]
				.tovpn_sid_locator->argument_bits_length;
	}
	ctx.table = vrf->data.l.table_id;
	act = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
		: ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	zclient_send_localsid(zclient, tovpn_sid, bgp->vrf_id, act, &ctx);

	tovpn_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
	*tovpn_sid_ls = *tovpn_sid;
	if (bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent)
		XFREE(MTYPE_BGP_SRV6_SID,
		      bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent);
	bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent = tovpn_sid_ls;
}

/*
 * This function informs zebra of the srv6-function this vrf sets on routes
 * leaked to VPN. Zebra should install this srv6-function in the kernel with
 * an action of "End.DT46's IP FIB to route the PDU."
 */
void vpn_leak_zebra_vrf_sid_update_per_vrf(struct bgp *bgp)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	enum seg6local_action_t act;
	struct seg6local_context ctx = {};
	struct in6_addr *tovpn_sid = NULL;
	struct in6_addr *tovpn_sid_ls = NULL;
	struct vrf *vrf;

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug(
				"%s: vrf %s: vrf_id not set, can't set zebra vrf label",
				__func__, bgp->name_pretty);
		return;
	}

	tovpn_sid = bgp->tovpn_sid;
	if (!tovpn_sid) {
		if (debug)
			zlog_debug("%s: vrf %s: sid not set", __func__,
				   bgp->name_pretty);
		return;
	}

	if (debug)
		zlog_debug("%s: vrf %s: setting sid %pI6 for vrf id %d",
			   __func__, bgp->name_pretty, tovpn_sid, bgp->vrf_id);

	vrf = vrf_lookup_by_id(bgp->vrf_id);
	if (!vrf)
		return;

	if (bgp->tovpn_sid_locator) {
		ctx.block_len = bgp->tovpn_sid_locator->block_bits_length;
		ctx.node_len = bgp->tovpn_sid_locator->node_bits_length;
		ctx.function_len = bgp->tovpn_sid_locator->function_bits_length;
		ctx.argument_len = bgp->tovpn_sid_locator->argument_bits_length;
	}
	ctx.table = vrf->data.l.table_id;
	act = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
	zclient_send_localsid(zclient, tovpn_sid, bgp->vrf_id, act, &ctx);

	tovpn_sid_ls = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
	*tovpn_sid_ls = *tovpn_sid;
	if (bgp->tovpn_zebra_vrf_sid_last_sent)
		XFREE(MTYPE_BGP_SRV6_SID, bgp->tovpn_zebra_vrf_sid_last_sent);
	bgp->tovpn_zebra_vrf_sid_last_sent = tovpn_sid_ls;
}

/*
 * This function informs zebra of the srv6-function this vrf sets on routes
 * leaked to VPN. Zebra should install this srv6-function in the kernel with
 * an action of "End.DT4/6/46's IP FIB to route the PDU."
 */
void vpn_leak_zebra_vrf_sid_update(struct bgp *bgp, afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (bgp->vpn_policy[afi].tovpn_sid)
		return vpn_leak_zebra_vrf_sid_update_per_af(bgp, afi);

	if (bgp->tovpn_sid)
		return vpn_leak_zebra_vrf_sid_update_per_vrf(bgp);

	if (debug)
		zlog_debug("%s: vrf %s: afi %s: sid not set", __func__,
			   bgp->name_pretty, afi2str(afi));
}

/*
 * If zebra tells us vrf has become unconfigured, tell zebra not to
 * use this srv6-function to forward to the vrf anymore
 */
void vpn_leak_zebra_vrf_sid_withdraw_per_af(struct bgp *bgp, afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	struct srv6_sid_ctx ctx = {};
	struct seg6local_context seg6localctx = {};

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: afi %s: vrf_id not set, can't set zebra vrf label",
				   __func__, bgp->name_pretty, afi2str(afi));
		return;
	}

	if (debug)
		zlog_debug("%s: deleting sid for vrf %s afi (id=%d)", __func__,
			   bgp->name_pretty, bgp->vrf_id);

	if (bgp->vpn_policy[afi].tovpn_sid_locator) {
		seg6localctx.block_len =
			bgp->vpn_policy[afi].tovpn_sid_locator->block_bits_length;
		seg6localctx.node_len =
			bgp->vpn_policy[afi].tovpn_sid_locator->node_bits_length;
		seg6localctx.function_len =
			bgp->vpn_policy[afi]
				.tovpn_sid_locator->function_bits_length;
		seg6localctx.argument_len =
			bgp->vpn_policy[afi]
				.tovpn_sid_locator->argument_bits_length;
	}
	zclient_send_localsid(zclient,
			      bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent,
			      bgp->vrf_id, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC,
			      &seg6localctx);
	XFREE(MTYPE_BGP_SRV6_SID,
	      bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent);
	bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent = NULL;

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	bgp_zebra_release_srv6_sid(&ctx);
}

/*
 * If zebra tells us vrf has become unconfigured, tell zebra not to
 * use this srv6-function to forward to the vrf anymore
 */
void vpn_leak_zebra_vrf_sid_withdraw_per_vrf(struct bgp *bgp)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	struct srv6_sid_ctx ctx = {};
	struct seg6local_context seg6localctx = {};

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug(
				"%s: vrf %s: vrf_id not set, can't set zebra vrf label",
				__func__, bgp->name_pretty);
		return;
	}

	if (debug)
		zlog_debug("%s: deleting sid for vrf %s (id=%d)", __func__,
			   bgp->name_pretty, bgp->vrf_id);

	if (bgp->tovpn_sid_locator) {
		seg6localctx.block_len =
			bgp->tovpn_sid_locator->block_bits_length;
		seg6localctx.node_len = bgp->tovpn_sid_locator->node_bits_length;
		seg6localctx.function_len =
			bgp->tovpn_sid_locator->function_bits_length;
		seg6localctx.argument_len =
			bgp->tovpn_sid_locator->argument_bits_length;
	}
	zclient_send_localsid(zclient, bgp->tovpn_zebra_vrf_sid_last_sent,
			      bgp->vrf_id, ZEBRA_SEG6_LOCAL_ACTION_UNSPEC,
			      &seg6localctx);
	XFREE(MTYPE_BGP_SRV6_SID, bgp->tovpn_zebra_vrf_sid_last_sent);
	bgp->tovpn_zebra_vrf_sid_last_sent = NULL;

	ctx.vrf_id = bgp->vrf_id;
	ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
	bgp_zebra_release_srv6_sid(&ctx);
}

/*
 * If zebra tells us vrf has become unconfigured, tell zebra not to
 * use this srv6-function to forward to the vrf anymore
 */
void vpn_leak_zebra_vrf_sid_withdraw(struct bgp *bgp, afi_t afi)
{
	if (bgp->vpn_policy[afi].tovpn_zebra_vrf_sid_last_sent)
		vpn_leak_zebra_vrf_sid_withdraw_per_af(bgp, afi);

	if (bgp->tovpn_zebra_vrf_sid_last_sent)
		vpn_leak_zebra_vrf_sid_withdraw_per_vrf(bgp);
}

int vpn_leak_label_callback(
	mpls_label_t label,
	void *labelid,
	bool allocated)
{
	struct vpn_policy *vp = (struct vpn_policy *)labelid;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (debug)
		zlog_debug("%s: label=%u, allocated=%d",
			__func__, label, allocated);

	if (!allocated) {
		/*
		 * previously-allocated label is now invalid
		 */
		if (CHECK_FLAG(vp->flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO) &&
			(vp->tovpn_label != MPLS_LABEL_NONE)) {

			vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN,
				vp->afi, bgp_get_default(), vp->bgp);
			vp->tovpn_label = MPLS_LABEL_NONE;
			vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN,
				vp->afi, bgp_get_default(), vp->bgp);
		}
		return 0;
	}

	/*
	 * New label allocation
	 */
	if (!CHECK_FLAG(vp->flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {

		/*
		 * not currently configured for auto label, reject allocation
		 */
		return -1;
	}

	if (vp->tovpn_label != MPLS_LABEL_NONE) {
		if (label == vp->tovpn_label) {
			/* already have same label, accept but do nothing */
			return 0;
		}
		/* Shouldn't happen: different label allocation */
		flog_err(EC_BGP_LABEL,
			 "%s: %s had label %u but got new assignment %u",
			 __func__, vp->bgp->name_pretty, vp->tovpn_label,
			 label);
		/* use new one */
	}

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN,
		vp->afi, bgp_get_default(), vp->bgp);
	vp->tovpn_label = label;
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN,
		vp->afi, bgp_get_default(), vp->bgp);

	return 0;
}

void sid_register(struct bgp *bgp, const struct in6_addr *sid,
		  const char *locator_name)
{
	struct bgp_srv6_function *func;
	func = XCALLOC(MTYPE_BGP_SRV6_FUNCTION,
		       sizeof(struct bgp_srv6_function));
	func->sid = *sid;
	snprintf(func->locator_name, sizeof(func->locator_name),
		 "%s", locator_name);
	listnode_add(bgp->srv6_functions, func);
}

void srv6_function_free(struct bgp_srv6_function *func)
{
	XFREE(MTYPE_BGP_SRV6_FUNCTION, func);
}

void sid_unregister(struct bgp *bgp, const struct in6_addr *sid)
{
	struct listnode *node, *nnode;
	struct bgp_srv6_function *func;

	for (ALL_LIST_ELEMENTS(bgp->srv6_functions, node, nnode, func))
		if (sid_same(&func->sid, sid)) {
			listnode_delete(bgp->srv6_functions, func);
			srv6_function_free(func);
		}
}

static bool sid_exist(struct bgp *bgp, const struct in6_addr *sid)
{
	struct listnode *node;
	struct bgp_srv6_function *func;

	for (ALL_LIST_ELEMENTS_RO(bgp->srv6_functions, node, func))
		if (sid_same(&func->sid, sid))
			return true;
	return false;
}

/**
 * Return the SRv6 SID value obtained by composing the LOCATOR and FUNCTION.
 *
 * @param sid_value SRv6 SID value returned
 * @param locator Parent locator of the SRv6 SID
 * @param sid_func Function part of the SID
 * @return True if success, False otherwise
 */
static bool srv6_sid_compose(struct in6_addr *sid_value,
			     struct srv6_locator *locator, uint32_t sid_func)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	int label = 0;
	uint8_t offset = 0;
	uint8_t func_len = 0, shift_len = 0;
	uint32_t sid_func_max = 0;

	if (!locator || !sid_value)
		return false;

	if (locator->function_bits_length >
	    BGP_PREFIX_SID_SRV6_MAX_FUNCTION_LENGTH) {
		if (debug)
			zlog_debug("%s: invalid SRv6 Locator (%pFX): Function Length must be less or equal to %d",
				   __func__, &locator->prefix,
				   BGP_PREFIX_SID_SRV6_MAX_FUNCTION_LENGTH);
		return false;
	}

	/* Max value that can be encoded in the Function part of the SID */
	sid_func_max = (1 << locator->function_bits_length) - 1;

	if (sid_func > sid_func_max) {
		if (debug)
			zlog_debug("%s: invalid SRv6 Locator (%pFX): Function Length is too short to support specified function (%u)",
				   __func__, &locator->prefix, sid_func);
		return false;
	}

	/**
	 * Let's build the SID value.
	 * sid_value = LOC:FUNC::
	 */

	/* First, we put the locator (LOC) in the most significant bits of sid_value */
	*sid_value = locator->prefix.prefix;

	/*
	 * Then, we compute the offset at which we have to place the function (FUNC).
	 * FUNC will be placed immediately after LOC, i.e. at block_bits_length + node_bits_length
	 */
	offset = locator->block_bits_length + locator->node_bits_length;

	/*
	 * The FUNC part of the SID is advertised in the label field of SRv6 Service TLV.
	 * (see SID Transposition Scheme, RFC 9252 section #4).
	 * Therefore, we need to encode the FUNC in the most significant bits of the
	 * 20-bit label.
	 */
	func_len = locator->function_bits_length;
	shift_len = BGP_PREFIX_SID_SRV6_MAX_FUNCTION_LENGTH - func_len;

	label = sid_func << shift_len;
	if (label < MPLS_LABEL_UNRESERVED_MIN) {
		if (debug)
			zlog_debug("%s: skipped to allocate SRv6 SID (%pFX): Label (%u) is too small to use",
				   __func__, &locator->prefix, label);
		return false;
	}

	if (sid_exist(bgp_get_default(), sid_value)) {
		zlog_warn("%s: skipped to allocate SRv6 SID (%pFX): SID %pI6 already in use",
			  __func__, &locator->prefix, sid_value);
		return false;
	}

	/* Finally, we put the FUNC in sid_value at the computed offset */
	transpose_sid(sid_value, label, offset, func_len);

	return true;
}

void ensure_vrf_tovpn_sid_per_af(struct bgp *bgp_vpn, struct bgp *bgp_vrf,
				 afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct in6_addr tovpn_sid = {};
	uint32_t tovpn_sid_index = 0;
	bool tovpn_sid_auto = false;
	struct srv6_sid_ctx ctx = {};
	uint32_t sid_func;

	if (debug)
		zlog_debug("%s: try to allocate new SID for vrf %s: afi %s",
			   __func__, bgp_vrf->name_pretty, afi2str(afi));

	/* skip when tovpn sid is already allocated on vrf instance */
	if (bgp_vrf->vpn_policy[afi].tovpn_sid)
		return;

	/*
	 * skip when bgp vpn instance ins't allocated
	 * or srv6 locator isn't allocated
	 */
	if (!bgp_vpn || !bgp_vpn->srv6_locator)
		return;

	if (bgp_vrf->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf SRv6 SID",
				   __func__, bgp_vrf->name_pretty);
		return;
	}

	tovpn_sid_index = bgp_vrf->vpn_policy[afi].tovpn_sid_index;
	tovpn_sid_auto = CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
				    BGP_VPN_POLICY_TOVPN_SID_AUTO);

	/* skip when VPN isn't configured on vrf-instance */
	if (tovpn_sid_index == 0 && !tovpn_sid_auto)
		return;

	/* check invalid case both configured index and auto */
	if (tovpn_sid_index != 0 && tovpn_sid_auto) {
		zlog_err("%s: index-mode and auto-mode both selected. ignored.",
			 __func__);
		return;
	}

	if (!tovpn_sid_auto) {
		if (!srv6_sid_compose(&tovpn_sid, bgp_vpn->srv6_locator,
				      tovpn_sid_index)) {
			zlog_err("%s: failed to compose sid for vrf %s: afi %s",
				 __func__, bgp_vrf->name_pretty, afi2str(afi));
			return;
		}
	}

	ctx.vrf_id = bgp_vrf->vrf_id;
	ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
				     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
	if (!bgp_zebra_request_srv6_sid(&ctx, &tovpn_sid,
					bgp_vpn->srv6_locator_name, &sid_func)) {
		zlog_err("%s: failed to request sid for vrf %s: afi %s",
			 __func__, bgp_vrf->name_pretty, afi2str(afi));
		return;
	}
}

void ensure_vrf_tovpn_sid_per_vrf(struct bgp *bgp_vpn, struct bgp *bgp_vrf)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct in6_addr tovpn_sid = {};
	uint32_t tovpn_sid_index = 0;
	bool tovpn_sid_auto = false;
	struct srv6_sid_ctx ctx = {};
	uint32_t sid_func;

	if (debug)
		zlog_debug("%s: try to allocate new SID for vrf %s", __func__,
			   bgp_vrf->name_pretty);

	/* skip when tovpn sid is already allocated on vrf instance */
	if (bgp_vrf->tovpn_sid)
		return;

	/*
	 * skip when bgp vpn instance ins't allocated
	 * or srv6 locator isn't allocated
	 */
	if (!bgp_vpn || !bgp_vpn->srv6_locator)
		return;

	if (bgp_vrf->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf SRv6 SID",
				   __func__, bgp_vrf->name_pretty);
		return;
	}

	tovpn_sid_index = bgp_vrf->tovpn_sid_index;
	tovpn_sid_auto = CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);

	/* skip when VPN isn't configured on vrf-instance */
	if (tovpn_sid_index == 0 && !tovpn_sid_auto)
		return;

	/* check invalid case both configured index and auto */
	if (tovpn_sid_index != 0 && tovpn_sid_auto) {
		zlog_err("%s: index-mode and auto-mode both selected. ignored.",
			 __func__);
		return;
	}

	if (!tovpn_sid_auto) {
		if (!srv6_sid_compose(&tovpn_sid, bgp_vpn->srv6_locator,
				      bgp_vrf->tovpn_sid_index)) {
			zlog_err("%s: failed to compose new sid for vrf %s",
				 __func__, bgp_vrf->name_pretty);
			return;
		}
	}

	ctx.vrf_id = bgp_vrf->vrf_id;
	ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
	if (!bgp_zebra_request_srv6_sid(&ctx, &tovpn_sid,
					bgp_vpn->srv6_locator_name, &sid_func)) {
		zlog_err("%s: failed to request new sid for vrf %s", __func__,
			 bgp_vrf->name_pretty);
		return;
	}
}

void ensure_vrf_tovpn_sid(struct bgp *bgp_vpn, struct bgp *bgp_vrf, afi_t afi)
{
	/* per-af sid */
	if (bgp_vrf->vpn_policy[afi].tovpn_sid_index != 0 ||
	    CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_SID_AUTO))
		return ensure_vrf_tovpn_sid_per_af(bgp_vpn, bgp_vrf, afi);

	/* per-vrf sid */
	if (bgp_vrf->tovpn_sid_index != 0 ||
	    CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VRF_TOVPN_SID_AUTO))
		return ensure_vrf_tovpn_sid_per_vrf(bgp_vpn, bgp_vrf);
}

void delete_vrf_tovpn_sid_per_af(struct bgp *bgp_vpn, struct bgp *bgp_vrf,
				 afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	uint32_t tovpn_sid_index = 0;
	bool tovpn_sid_auto = false;
	struct srv6_sid_ctx ctx = {};

	if (debug)
		zlog_debug("%s: try to remove SID for vrf %s: afi %s", __func__,
			   bgp_vrf->name_pretty, afi2str(afi));

	tovpn_sid_index = bgp_vrf->vpn_policy[afi].tovpn_sid_index;
	tovpn_sid_auto = CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
				    BGP_VPN_POLICY_TOVPN_SID_AUTO);

	/* skip when VPN is configured on vrf-instance */
	if (tovpn_sid_index != 0 || tovpn_sid_auto)
		return;

	if (bgp_vrf->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf label",
				   __func__, bgp_vrf->name_pretty);
		return;
	}

	srv6_locator_free(bgp_vrf->vpn_policy[afi].tovpn_sid_locator);
	bgp_vrf->vpn_policy[afi].tovpn_sid_locator = NULL;

	if (bgp_vrf->vpn_policy[afi].tovpn_sid) {
		ctx.vrf_id = bgp_vrf->vrf_id;
		ctx.behavior = afi == AFI_IP ? ZEBRA_SEG6_LOCAL_ACTION_END_DT4
					     : ZEBRA_SEG6_LOCAL_ACTION_END_DT6;
		bgp_zebra_release_srv6_sid(&ctx);

		sid_unregister(bgp_vpn, bgp_vrf->vpn_policy[afi].tovpn_sid);
		XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->vpn_policy[afi].tovpn_sid);
	}
	bgp_vrf->vpn_policy[afi].tovpn_sid_transpose_label = 0;
}

void delete_vrf_tovpn_sid_per_vrf(struct bgp *bgp_vpn, struct bgp *bgp_vrf)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	uint32_t tovpn_sid_index = 0;
	bool tovpn_sid_auto = false;
	struct srv6_sid_ctx ctx = {};

	if (debug)
		zlog_debug("%s: try to remove SID for vrf %s", __func__,
			   bgp_vrf->name_pretty);

	tovpn_sid_index = bgp_vrf->tovpn_sid_index;
	tovpn_sid_auto =
		CHECK_FLAG(bgp_vrf->vrf_flags, BGP_VPN_POLICY_TOVPN_SID_AUTO);

	/* skip when VPN is configured on vrf-instance */
	if (tovpn_sid_index != 0 || tovpn_sid_auto)
		return;

	if (bgp_vrf->vrf_id == VRF_UNKNOWN) {
		if (debug)
			zlog_debug("%s: vrf %s: vrf_id not set, can't set zebra vrf label",
				   __func__, bgp_vrf->name_pretty);
		return;
	}

	srv6_locator_free(bgp_vrf->tovpn_sid_locator);
	bgp_vrf->tovpn_sid_locator = NULL;

	if (bgp_vrf->tovpn_sid) {
		ctx.vrf_id = bgp_vrf->vrf_id;
		ctx.behavior = ZEBRA_SEG6_LOCAL_ACTION_END_DT46;
		bgp_zebra_release_srv6_sid(&ctx);

		sid_unregister(bgp_vpn, bgp_vrf->tovpn_sid);
		XFREE(MTYPE_BGP_SRV6_SID, bgp_vrf->tovpn_sid);
	}
	bgp_vrf->tovpn_sid_transpose_label = 0;
}

void delete_vrf_tovpn_sid(struct bgp *bgp_vpn, struct bgp *bgp_vrf, afi_t afi)
{
	delete_vrf_tovpn_sid_per_af(bgp_vpn, bgp_vrf, afi);
	delete_vrf_tovpn_sid_per_vrf(bgp_vpn, bgp_vrf);
}

/*
 * This function embeds upper `len` bits of `label` in `sid`,
 * starting at offset `offset` as seen from the MSB of `sid`.
 *
 * e.g. Given that `label` is 0x12345 and `len` is 16,
 * then `label` will be embedded in `sid` as follows:
 *
 *                 <----   len  ----->
 *         label:  0001 0002 0003 0004 0005
 *         sid:    .... 0001 0002 0003 0004
 *                      <----   len  ----->
 *                    ^
 *                    |
 *                 offset from MSB
 *
 * e.g. Given that `label` is 0x12345 and `len` is 8,
 * `label` will be embedded in `sid` as follows:
 *
 *                 <- len ->
 *         label:  0001 0002 0003 0004 0005
 *         sid:    .... 0001 0002 0000 0000
 *                      <- len ->
 *                    ^
 *                    |
 *                 offset from MSB
 */
void transpose_sid(struct in6_addr *sid, uint32_t label, uint8_t offset,
		   uint8_t len)
{
	for (uint8_t idx = 0; idx < len; idx++) {
		uint8_t tidx = offset + idx;
		sid->s6_addr[tidx / 8] &= ~(0x1 << (7 - tidx % 8));
		if (label >> (19 - idx) & 0x1)
			sid->s6_addr[tidx / 8] |= 0x1 << (7 - tidx % 8);
	}
}

static bool leak_update_nexthop_valid(struct bgp *to_bgp, struct bgp_dest *bn,
				      struct attr *new_attr, afi_t afi,
				      safi_t safi,
				      struct bgp_path_info *source_bpi,
				      struct bgp_path_info *bpi,
				      struct bgp *bgp_orig,
				      const struct prefix *p, int debug)
{
	struct bgp_path_info *bpi_ultimate;
	struct bgp *bgp_nexthop;
	struct bgp_table *table;
	bool nh_valid;

	bpi_ultimate = bgp_get_imported_bpi_ultimate(source_bpi);
	table = bgp_dest_table(bpi_ultimate->net);

	if (bpi->extra && bpi->extra->vrfleak && bpi->extra->vrfleak->bgp_orig)
		bgp_nexthop = bpi->extra->vrfleak->bgp_orig;
	else
		bgp_nexthop = bgp_orig;

	/*
	 * No nexthop tracking for redistributed routes, for
	 * EVPN-imported routes that get leaked, or for routes
	 * leaked between VRFs with accept-own community.
	 */
	if (bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE ||
	    is_pi_family_evpn(bpi_ultimate) ||
	    CHECK_FLAG(bpi_ultimate->flags, BGP_PATH_ACCEPT_OWN))
		nh_valid = true;
	else if (bpi_ultimate->type == ZEBRA_ROUTE_BGP &&
		 bpi_ultimate->sub_type == BGP_ROUTE_STATIC && table &&
		 (table->safi == SAFI_UNICAST ||
		  table->safi == SAFI_LABELED_UNICAST)) {
		/* the route is defined with the "network <prefix>" command */

		if (CHECK_FLAG(bgp_nexthop->flags, BGP_FLAG_IMPORT_CHECK))
			nh_valid = bgp_find_or_add_nexthop(to_bgp, bgp_nexthop,
							   afi, SAFI_UNICAST,
							   bpi_ultimate, NULL,
							   0, p);
		else
			/* if "no bgp network import-check" is set,
			 * then mark the nexthop as valid.
			 */
			nh_valid = true;
	} else
		/*
		 * TBD do we need to do anything about the
		 * 'connected' parameter?
		 */
		nh_valid = bgp_find_or_add_nexthop(to_bgp, bgp_nexthop, afi,
						   safi, bpi, NULL, 0, p);

	/*
	 * If you are using SRv6 VPN instead of MPLS, it need to check
	 * the SID allocation. If the sid is not allocated, the rib
	 * will be invalid.
	 */
	if (to_bgp->srv6_enabled &&
	    (!new_attr->srv6_l3vpn && !new_attr->srv6_vpn)) {
		nh_valid = false;
	}

	if (debug)
		zlog_debug("%s: %pFX nexthop is %svalid (in %s)", __func__, p,
			   (nh_valid ? "" : "not "), bgp_nexthop->name_pretty);

	return nh_valid;
}

/*
 * returns pointer to new bgp_path_info upon success
 */
static struct bgp_path_info *
leak_update(struct bgp *to_bgp, struct bgp_dest *bn,
	    struct attr *new_attr, /* already interned */
	    afi_t afi, safi_t safi, struct bgp_path_info *source_bpi,
	    mpls_label_t *label, uint8_t num_labels, struct bgp *bgp_orig,
	    struct prefix *nexthop_orig, int nexthop_self_flag, int debug)
{
	const struct prefix *p = bgp_dest_get_prefix(bn);
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;
	struct bgp_path_info_extra *extra;
	struct bgp_path_info *parent = source_bpi;
	struct bgp_labels bgp_labels = {};
	bool labelssame;
	uint8_t i;

	if (debug)
		zlog_debug(
			"%s: entry: leak-to=%s, p=%pBD, type=%d, sub_type=%d",
			__func__, to_bgp->name_pretty, bn, source_bpi->type,
			source_bpi->sub_type);

	/*
	 * Routes that are redistributed into BGP from zebra do not get
	 * nexthop tracking, unless MPLS allocation per nexthop is
	 * performed. In the default case nexthop tracking does not apply,
	 * if those routes are subsequently imported to other RIBs within
	 * BGP, the leaked routes do not carry the original
	 * BGP_ROUTE_REDISTRIBUTE sub_type. Therefore, in order to determine
	 * if the route we are currently leaking should have nexthop
	 * tracking, we must find the ultimate parent so we can check its
	 * sub_type.
	 *
	 * As of now, source_bpi may at most be a second-generation route
	 * (only one hop back to ultimate parent for vrf-vpn-vrf scheme).
	 * Using a loop here supports more complex intra-bgp import-export
	 * schemes that could be implemented in the future.
	 *
	 */

	/*
	 * match parent
	 */
	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->vrfleak &&
		    bpi->extra->vrfleak->parent == parent)
			break;
	}

	bgp_labels.num_labels = num_labels;
	for (i = 0; i < num_labels; i++) {
		bgp_labels.label[i] = label[i];
		bgp_set_valid_label(&bgp_labels.label[i]);
	}

	if (bpi) {
		labelssame = bgp_path_info_labels_same(bpi, bgp_labels.label,
						       bgp_labels.num_labels);

		if (CHECK_FLAG(source_bpi->flags, BGP_PATH_REMOVED)
		    && CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {
			if (debug) {
				zlog_debug(
					"%s: ->%s(s_flags: 0x%x b_flags: 0x%x): %pFX: Found route, being removed, not leaking",
					__func__, to_bgp->name_pretty,
					source_bpi->flags, bpi->flags, p);
			}
			return NULL;
		}

		if (attrhash_cmp(bpi->attr, new_attr) && labelssame
		    && !CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {

			bgp_attr_unintern(&new_attr);
			if (debug)
				zlog_debug(
					"%s: ->%s: %pBD: Found route, no change",
					__func__, to_bgp->name_pretty, bn);
			return NULL;
		}

		/* If the RT was changed via extended communities as an
		 * import/export list, we should withdraw implicitly the old
		 * path from VRFs.
		 * For instance, RT list was modified using route-maps:
		 * route-map test permit 10
		 *   set extcommunity rt none
		 */
		if (CHECK_FLAG(bpi->attr->flag,
			       ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES)) &&
		    CHECK_FLAG(new_attr->flag,
			       ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES))) {
			if (!ecommunity_cmp(
				    bgp_attr_get_ecommunity(bpi->attr),
				    bgp_attr_get_ecommunity(new_attr))) {
				vpn_leak_to_vrf_withdraw(bpi);
				bgp_aggregate_decrement(to_bgp, p, bpi, afi,
							safi);
				bgp_path_info_delete(bn, bpi);
			}
		}

		/* attr is changed */
		bgp_path_info_set_flag(bn, bpi, BGP_PATH_ATTR_CHANGED);

		/* Rewrite BGP route information. */
		if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(bn, bpi);
		else
			bgp_aggregate_decrement(to_bgp, p, bpi, afi, safi);
		bgp_attr_unintern(&bpi->attr);
		bpi->attr = new_attr;
		bpi->uptime = monotime(NULL);

		/*
		 * update labels
		 */
		if (!labelssame) {
			bgp_path_info_extra_get(bpi);
			bgp_labels_unintern(&bpi->extra->labels);
			bpi->extra->labels = bgp_labels_intern(&bgp_labels);
		}

		if (nexthop_self_flag)
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_ANNC_NH_SELF);

		if (CHECK_FLAG(source_bpi->flags, BGP_PATH_ACCEPT_OWN))
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_ACCEPT_OWN);

		if (leak_update_nexthop_valid(to_bgp, bn, new_attr, afi, safi,
					      source_bpi, bpi, bgp_orig, p,
					      debug))
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_VALID);
		else
			bgp_path_info_unset_flag(bn, bpi, BGP_PATH_VALID);

		/* Process change. */
		bgp_aggregate_increment(to_bgp, p, bpi, afi, safi);
		bgp_process(to_bgp, bn, bpi, afi, safi);

		if (debug)
			zlog_debug("%s: ->%s: %pBD Found route, changed attr",
				   __func__, to_bgp->name_pretty, bn);

		bgp_dest_unlock_node(bn);

		return bpi;
	}

	if (CHECK_FLAG(source_bpi->flags, BGP_PATH_REMOVED)) {
		if (debug) {
			zlog_debug(
				"%s: ->%s(s_flags: 0x%x): %pFX: New route, being removed, not leaking",
				__func__, to_bgp->name_pretty,
				source_bpi->flags, p);
		}
		return NULL;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_IMPORTED, 0,
			to_bgp->peer_self, new_attr, bn);

	bgp_path_info_extra_get(new);
	if (!new->extra->vrfleak)
		new->extra->vrfleak =
			XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
				sizeof(struct bgp_path_info_extra_vrfleak));

	if (source_bpi->peer) {
		extra = bgp_path_info_extra_get(new);
		extra->vrfleak->peer_orig = peer_lock(source_bpi->peer);
	}

	if (nexthop_self_flag)
		bgp_path_info_set_flag(bn, new, BGP_PATH_ANNC_NH_SELF);

	if (CHECK_FLAG(source_bpi->flags, BGP_PATH_ACCEPT_OWN))
		bgp_path_info_set_flag(bn, new, BGP_PATH_ACCEPT_OWN);

	if (bgp_labels.num_labels)
		new->extra->labels = bgp_labels_intern(&bgp_labels);

	new->extra->vrfleak->parent = bgp_path_info_lock(parent);
	bgp_dest_lock_node(
		(struct bgp_dest *)parent->net);

	new->extra->vrfleak->bgp_orig = bgp_lock(bgp_orig);

	if (nexthop_orig)
		new->extra->vrfleak->nexthop_orig = *nexthop_orig;

	if (leak_update_nexthop_valid(to_bgp, bn, new_attr, afi, safi,
				      source_bpi, new, bgp_orig, p, debug))
		bgp_path_info_set_flag(bn, new, BGP_PATH_VALID);
	else
		bgp_path_info_unset_flag(bn, new, BGP_PATH_VALID);

	bgp_aggregate_increment(to_bgp, p, new, afi, safi);
	bgp_path_info_add(bn, new);

	bgp_process(to_bgp, bn, new, afi, safi);

	if (debug)
		zlog_debug("%s: ->%s: %pBD: Added new route", __func__,
			   to_bgp->name_pretty, bn);

	bgp_dest_unlock_node(bn);

	return new;
}

void bgp_mplsvpn_path_nh_label_unlink(struct bgp_path_info *pi)
{
	struct bgp_label_per_nexthop_cache *blnc;

	if (!pi)
		return;

	if (!CHECK_FLAG(pi->flags, BGP_PATH_MPLSVPN_LABEL_NH))
		return;

	blnc = pi->mplsvpn.blnc.label_nexthop_cache;

	if (!blnc)
		return;

	LIST_REMOVE(pi, mplsvpn.blnc.label_nh_thread);
	pi->mplsvpn.blnc.label_nexthop_cache->path_count--;
	pi->mplsvpn.blnc.label_nexthop_cache = NULL;
	UNSET_FLAG(pi->flags, BGP_PATH_MPLSVPN_LABEL_NH);

	if (LIST_EMPTY(&(blnc->paths)))
		bgp_label_per_nexthop_free(blnc);
}

/* Called upon reception of a ZAPI Message from zebra, about
 * a new available label.
 */
static int bgp_mplsvpn_get_label_per_nexthop_cb(mpls_label_t label,
						void *context, bool allocated)
{
	struct bgp_label_per_nexthop_cache *blnc = context;
	mpls_label_t old_label;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);
	struct bgp_path_info *pi;
	struct bgp_table *table;

	old_label = blnc->label;

	if (debug)
		zlog_debug("%s: label=%u, allocated=%d, nexthop=%pFX", __func__,
			   label, allocated, &blnc->nexthop);
	if (allocated)
		/* update the entry with the new label */
		blnc->label = label;
	else
		/*
		 * previously-allocated label is now invalid
		 * eg: zebra deallocated the labels and notifies it
		 */
		blnc->label = MPLS_INVALID_LABEL;

	if (old_label == blnc->label)
		return 0; /* no change */

	/* update paths */
	if (blnc->label != MPLS_INVALID_LABEL)
		bgp_zebra_send_nexthop_label(ZEBRA_MPLS_LABELS_ADD, blnc->label,
					     blnc->nh->ifindex,
					     blnc->nh->vrf_id, ZEBRA_LSP_BGP,
					     &blnc->nexthop, 0, NULL);

	LIST_FOREACH (pi, &(blnc->paths), mplsvpn.blnc.label_nh_thread) {
		if (!pi->net)
			continue;
		table = bgp_dest_table(pi->net);
		if (!table)
			continue;
		vpn_leak_from_vrf_update(blnc->to_bgp, table->bgp, pi);
	}

	return 0;
}

/* Get a per label nexthop value:
 *  - Find and return a per label nexthop from the cache
 *  - else allocate a new per label nexthop cache entry and request a
 *    label to zebra. Return MPLS_INVALID_LABEL
 */
static mpls_label_t
_vpn_leak_from_vrf_get_per_nexthop_label(struct bgp_path_info *pi,
					 struct bgp *to_bgp,
					 struct bgp *from_bgp, afi_t afi)
{
	struct bgp_nexthop_cache *bnc = pi->nexthop;
	struct bgp_label_per_nexthop_cache *blnc;
	struct bgp_label_per_nexthop_cache_head *tree;
	struct prefix *nh_pfx = NULL;
	struct prefix nh_gate = {0};

	/* extract the nexthop from the BNC nexthop cache */
	switch (bnc->nexthop->type) {
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
		/* the nexthop is recursive */
		nh_gate.family = AF_INET;
		nh_gate.prefixlen = IPV4_MAX_BITLEN;
		IPV4_ADDR_COPY(&nh_gate.u.prefix4, &bnc->nexthop->gate.ipv4);
		nh_pfx = &nh_gate;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		/* the nexthop is recursive */
		nh_gate.family = AF_INET6;
		nh_gate.prefixlen = IPV6_MAX_BITLEN;
		IPV6_ADDR_COPY(&nh_gate.u.prefix6, &bnc->nexthop->gate.ipv6);
		nh_pfx = &nh_gate;
		break;
	case NEXTHOP_TYPE_IFINDEX:
		/* the nexthop is direcly connected */
		nh_pfx = &bnc->prefix;
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		assert(!"Blackhole nexthop. Already checked by the caller.");
	}

	/* find or allocate a nexthop label cache entry */
	tree = &from_bgp->mpls_labels_per_nexthop[family2afi(nh_pfx->family)];
	blnc = bgp_label_per_nexthop_find(tree, nh_pfx);
	if (!blnc) {
		blnc = bgp_label_per_nexthop_new(tree, nh_pfx);
		blnc->to_bgp = to_bgp;
		/* request a label to zebra for this nexthop
		 * the response from zebra will trigger the callback
		 */
		bgp_lp_get(LP_TYPE_NEXTHOP, blnc,
			   bgp_mplsvpn_get_label_per_nexthop_cb);
	}

	if (pi->mplsvpn.blnc.label_nexthop_cache == blnc)
		/* no change */
		return blnc->label;

	/* Unlink from any existing nexthop cache. Free the entry if unused.
	 */
	bgp_mplsvpn_path_nh_label_unlink(pi);

	/* updates NHT pi list reference */
	LIST_INSERT_HEAD(&(blnc->paths), pi, mplsvpn.blnc.label_nh_thread);
	pi->mplsvpn.blnc.label_nexthop_cache = blnc;
	pi->mplsvpn.blnc.label_nexthop_cache->path_count++;
	SET_FLAG(pi->flags, BGP_PATH_MPLSVPN_LABEL_NH);
	blnc->last_update = monotime(NULL);

	/* then add or update the selected nexthop */
	if (!blnc->nh)
		blnc->nh = nexthop_dup(bnc->nexthop, NULL);
	else if (!nexthop_same(bnc->nexthop, blnc->nh)) {
		nexthop_free(blnc->nh);
		blnc->nh = nexthop_dup(bnc->nexthop, NULL);
		if (blnc->label != MPLS_INVALID_LABEL) {
			bgp_zebra_send_nexthop_label(
				ZEBRA_MPLS_LABELS_REPLACE, blnc->label,
				bnc->nexthop->ifindex, bnc->nexthop->vrf_id,
				ZEBRA_LSP_BGP, &blnc->nexthop, 0, NULL);
		}
	}

	return blnc->label;
}

static mpls_label_t bgp_mplsvpn_get_vpn_label(struct vpn_policy *bgp_policy)
{
	if (bgp_policy->tovpn_label == MPLS_LABEL_NONE &&
	    CHECK_FLAG(bgp_policy->flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO)) {
		bgp_lp_get(LP_TYPE_VRF, bgp_policy, vpn_leak_label_callback);
		return MPLS_INVALID_LABEL;
	}
	return bgp_policy->tovpn_label;
}

/* Filter out all the cases where a per nexthop label is not possible:
 * - return an invalid label when the nexthop is invalid
 * - return the per VRF label when the per nexthop label is not supported
 * Otherwise, find or request a per label nexthop.
 */
static mpls_label_t
vpn_leak_from_vrf_get_per_nexthop_label(afi_t afi, struct bgp_path_info *pi,
					struct bgp *from_bgp,
					struct bgp *to_bgp)
{
	struct bgp_path_info *bpi_ultimate = bgp_get_imported_bpi_ultimate(pi);
	struct bgp *bgp_nexthop = NULL;
	bool nh_valid;
	afi_t nh_afi;
	bool is_bgp_static_route;

	is_bgp_static_route = bpi_ultimate->sub_type == BGP_ROUTE_STATIC &&
			      bpi_ultimate->type == ZEBRA_ROUTE_BGP;

	if (is_bgp_static_route == false && afi == AFI_IP &&
	    CHECK_FLAG(pi->attr->flag, ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP)) &&
	    (pi->attr->nexthop.s_addr == INADDR_ANY ||
	     !ipv4_unicast_valid(&pi->attr->nexthop))) {
		/* IPv4 nexthop in standard BGP encoding format.
		 * Format of address is not valid (not any, not unicast).
		 * Fallback to the per VRF label.
		 */
		bgp_mplsvpn_path_nh_label_unlink(pi);
		return bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);
	}

	if (is_bgp_static_route == false && afi == AFI_IP &&
	    pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4 &&
	    (pi->attr->mp_nexthop_global_in.s_addr == INADDR_ANY ||
	     !ipv4_unicast_valid(&pi->attr->mp_nexthop_global_in))) {
		/* IPv4 nexthop is in MP-BGP encoding format.
		 * Format of address is not valid (not any, not unicast).
		 * Fallback to the per VRF label.
		 */
		bgp_mplsvpn_path_nh_label_unlink(pi);
		return bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);
	}

	if (is_bgp_static_route == false && afi == AFI_IP6 &&
	    (pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL ||
	     pi->attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL) &&
	    (IN6_IS_ADDR_UNSPECIFIED(&pi->attr->mp_nexthop_global) ||
	     IN6_IS_ADDR_LOOPBACK(&pi->attr->mp_nexthop_global) ||
	     IN6_IS_ADDR_MULTICAST(&pi->attr->mp_nexthop_global))) {
		/* IPv6 nexthop is in MP-BGP encoding format.
		 * Format of address is not valid
		 * Fallback to the per VRF label.
		 */
		bgp_mplsvpn_path_nh_label_unlink(pi);
		return bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);
	}

	/* Check the next-hop reachability.
	 * Get the bgp instance where the bgp_path_info originates.
	 */
	if (pi->extra && pi->extra->vrfleak && pi->extra->vrfleak->bgp_orig)
		bgp_nexthop = pi->extra->vrfleak->bgp_orig;
	else
		bgp_nexthop = from_bgp;

	nh_afi = BGP_ATTR_NH_AFI(afi, pi->attr);
	nh_valid = bgp_find_or_add_nexthop(from_bgp, bgp_nexthop, nh_afi,
					   SAFI_UNICAST, pi, NULL, 0, NULL);

	if (!nh_valid && is_bgp_static_route &&
	    !CHECK_FLAG(from_bgp->flags, BGP_FLAG_IMPORT_CHECK)) {
		/* "network" prefixes not routable, but since 'no bgp network
		 * import-check' is configured, they are always valid in the BGP
		 * table. Fallback to the per-vrf label
		 */
		bgp_mplsvpn_path_nh_label_unlink(pi);
		return bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);
	}

	if (!nh_valid || !pi->nexthop || pi->nexthop->nexthop_num == 0 ||
	    !pi->nexthop->nexthop) {
		/* invalid next-hop:
		 * do not send the per-vrf label
		 * otherwise, when the next-hop becomes valid,
		 * we will have 2 BGP updates:
		 * - one with the per-vrf label
		 * - the second with the per-nexthop label
		 */
		bgp_mplsvpn_path_nh_label_unlink(pi);
		return MPLS_INVALID_LABEL;
	}

	if (pi->nexthop->nexthop_num > 1 ||
	    pi->nexthop->nexthop->type == NEXTHOP_TYPE_BLACKHOLE) {
		/* Blackhole or ECMP routes
		 * is not compatible with per-nexthop label.
		 * Fallback to per-vrf label.
		 */
		bgp_mplsvpn_path_nh_label_unlink(pi);
		return bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);
	}

	if (is_bgp_static_route && pi->nexthop->nexthop->type == NEXTHOP_TYPE_IFINDEX) {
		/* "network" imported prefixes from vrf
		 * fallback to per-vrf label.
		 */

		bgp_mplsvpn_path_nh_label_unlink(pi);
		return bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);
	}

	return _vpn_leak_from_vrf_get_per_nexthop_label(pi, to_bgp, from_bgp,
							afi);
}

/* cf vnc_import_bgp_add_route_mode_nvegroup() and add_vnc_route() */
void vpn_leak_from_vrf_update(struct bgp *to_bgp,	     /* to */
			      struct bgp *from_bgp,	   /* from */
			      struct bgp_path_info *path_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	const struct prefix *p = bgp_dest_get_prefix(path_vrf->net);
	afi_t afi = family2afi(p->family);
	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	safi_t safi = SAFI_MPLS_VPN;
	mpls_label_t label_val = { 0 };
	mpls_label_t label = { 0 };
	struct bgp_dest *bn;
	const char *debugmsg;
	int nexthop_self_flag = 0;
	struct ecommunity *old_ecom;
	struct ecommunity *new_ecom = NULL;
	struct ecommunity *rtlist_ecom;

	if (debug)
		zlog_debug("%s: from vrf %s", __func__, from_bgp->name_pretty);

	if (debug && bgp_attr_get_ecommunity(path_vrf->attr)) {
		char *s = ecommunity_ecom2str(
			bgp_attr_get_ecommunity(path_vrf->attr),
			ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: %s path_vrf->type=%d, EC{%s}", __func__,
			   from_bgp->name, path_vrf->type, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	if (!to_bgp)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* Is this route exportable into the VPN table? */
	if (!is_route_injectable_into_vpn(path_vrf))
		return;

	if (!vpn_leak_to_vpn_active(from_bgp, afi, &debugmsg, false)) {
		if (debug)
			zlog_debug("%s: %s skipping: %s", __func__,
				   from_bgp->name, debugmsg);
		return;
	}

	/* shallow copy */
	static_attr = *path_vrf->attr;

	if (debug && bgp_attr_get_ecommunity(&static_attr)) {
		char *s = ecommunity_ecom2str(
			bgp_attr_get_ecommunity(&static_attr),
			ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: post route map static_attr.ecommunity{%s}",
			   __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	/*
	 * Add the vpn-policy rt-list
	 */

	/* Export with the 'from' instance's export RTs. */
	/* If doing VRF-to-VRF leaking, strip existing RTs first. */
	old_ecom = bgp_attr_get_ecommunity(&static_attr);
	rtlist_ecom = from_bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_TOVPN];
	if (old_ecom) {
		new_ecom = ecommunity_dup(old_ecom);
		if (CHECK_FLAG(from_bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_VRF_EXPORT))
			ecommunity_strip_rts(new_ecom);
		if (rtlist_ecom)
			new_ecom = ecommunity_merge(new_ecom, rtlist_ecom);
		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else if (rtlist_ecom) {
		new_ecom = ecommunity_dup(rtlist_ecom);
	} else {
		new_ecom = NULL;
	}

	bgp_attr_set_ecommunity(&static_attr, new_ecom);

	/*
	 * route map handling
	 */
	if (from_bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_TOVPN]) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = to_bgp->peer_self;
		info.attr = &static_attr;
		ret = route_map_apply(from_bgp->vpn_policy[afi]
					      .rmap[BGP_VPN_POLICY_DIR_TOVPN],
				      p, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug("%s: vrf %s route map \"%s\" says DENY, returning",
					   __func__, from_bgp->name_pretty,
					   from_bgp->vpn_policy[afi]
						   .rmap[BGP_VPN_POLICY_DIR_TOVPN]
						   ->name);
			return;
		}
	}

	new_ecom = bgp_attr_get_ecommunity(&static_attr);
	if (!ecommunity_has_route_target(new_ecom)) {
		ecommunity_free(&new_ecom);
		if (debug)
			zlog_debug("%s: %s skipping: waiting for a valid export rt list.",
				   __func__, from_bgp->name_pretty);
		return;
	}

	if (debug && bgp_attr_get_ecommunity(&static_attr)) {
		char *s = ecommunity_ecom2str(
			bgp_attr_get_ecommunity(&static_attr),
			ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: post merge static_attr.ecommunity{%s}",
			   __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	community_strip_accept_own(&static_attr);

	/* Nexthop */
	/* if policy nexthop not set, use 0 */
	if (CHECK_FLAG(from_bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_NEXTHOP_SET)) {
		struct prefix *nexthop =
			&from_bgp->vpn_policy[afi].tovpn_nexthop;

		switch (nexthop->family) {
		case AF_INET:
			/* prevent mp_nexthop_global_in <- self in bgp_route.c
			 */
			static_attr.nexthop.s_addr = nexthop->u.prefix4.s_addr;

			static_attr.mp_nexthop_global_in = nexthop->u.prefix4;
			static_attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;
			break;

		case AF_INET6:
			static_attr.mp_nexthop_global = nexthop->u.prefix6;
			static_attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV6_GLOBAL;
			break;

		default:
			assert(0);
		}
	} else {
		if (!CHECK_FLAG(from_bgp->af_flags[afi][SAFI_UNICAST],
				BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			if (afi == AFI_IP &&
			    !BGP_ATTR_NEXTHOP_AFI_IP6(path_vrf->attr)) {
				/*
				 * For ipv4, copy to multiprotocol
				 * nexthop field
				 */
				static_attr.mp_nexthop_global_in =
					static_attr.nexthop;
				static_attr.mp_nexthop_len =
					BGP_ATTR_NHLEN_IPV4;
				/*
				 * XXX Leave static_attr.nexthop
				 * intact for NHT
				 */
				static_attr.flag &=
					~ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			}
		} else {
			/* Update based on next-hop family to account for
			 * RFC 5549 (BGP unnumbered) scenario. Note that
			 * specific action is only needed for the case of
			 * IPv4 nexthops as the attr has been copied
			 * otherwise.
			 */
			if (afi == AFI_IP
			    && !BGP_ATTR_NEXTHOP_AFI_IP6(path_vrf->attr)) {
				static_attr.mp_nexthop_global_in.s_addr =
					static_attr.nexthop.s_addr;
				static_attr.mp_nexthop_len =
					BGP_ATTR_NHLEN_IPV4;
				static_attr.flag |=
					ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			}
		}
		nexthop_self_flag = 1;
	}

	if (CHECK_FLAG(from_bgp->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP))
		/* per nexthop label mode */
		label_val = vpn_leak_from_vrf_get_per_nexthop_label(
			afi, path_vrf, from_bgp, to_bgp);
	else
		label_val =
			bgp_mplsvpn_get_vpn_label(&from_bgp->vpn_policy[afi]);

	if (label_val == MPLS_INVALID_LABEL) {
		/* no valid label for the moment
		 * when the 'bgp_mplsvpn_get_label_per_nexthop_cb' callback gets
		 * a valid label value, it will call the current function again.
		 */
		if (debug)
			zlog_debug(
				"%s: %s skipping: waiting for a valid per-label nexthop.",
				__func__, from_bgp->name_pretty);
		bgp_attr_flush(&static_attr);
		return;
	}
	if (label_val == MPLS_LABEL_NONE)
		encode_label(MPLS_LABEL_IMPLICIT_NULL, &label);
	else
		encode_label(label_val, &label);

	/* Set originator ID to "me" */
	SET_FLAG(static_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));
	static_attr.originator_id = to_bgp->router_id;

	/* Set SID for SRv6 VPN */
	if (from_bgp->vpn_policy[afi].tovpn_sid_locator) {
		struct srv6_locator *locator =
			from_bgp->vpn_policy[afi].tovpn_sid_locator;

		encode_label(
			from_bgp->vpn_policy[afi].tovpn_sid_transpose_label,
			&label);
		static_attr.srv6_l3vpn = XCALLOC(MTYPE_BGP_SRV6_L3VPN,
				sizeof(struct bgp_attr_srv6_l3vpn));
		static_attr.srv6_l3vpn->sid_flags = 0x00;
		static_attr.srv6_l3vpn->endpoint_behavior =
			afi == AFI_IP
				? (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
					   ? SRV6_ENDPOINT_BEHAVIOR_END_DT4_USID
					   : SRV6_ENDPOINT_BEHAVIOR_END_DT4)
				: (CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
					   ? SRV6_ENDPOINT_BEHAVIOR_END_DT6_USID
					   : SRV6_ENDPOINT_BEHAVIOR_END_DT6);
		static_attr.srv6_l3vpn->loc_block_len =
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->block_bits_length;
		static_attr.srv6_l3vpn->loc_node_len =
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->node_bits_length;
		static_attr.srv6_l3vpn->func_len =
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->function_bits_length;
		static_attr.srv6_l3vpn->arg_len =
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->argument_bits_length;
		static_attr.srv6_l3vpn->transposition_len =
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->function_bits_length;
		static_attr.srv6_l3vpn->transposition_offset =
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->block_bits_length +
			from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->node_bits_length;
		;
		memcpy(&static_attr.srv6_l3vpn->sid,
		       &from_bgp->vpn_policy[afi]
				.tovpn_sid_locator->prefix.prefix,
		       sizeof(struct in6_addr));
	} else if (from_bgp->tovpn_sid_locator) {
		struct srv6_locator *locator = from_bgp->tovpn_sid_locator;

		encode_label(from_bgp->tovpn_sid_transpose_label, &label);
		static_attr.srv6_l3vpn =
			XCALLOC(MTYPE_BGP_SRV6_L3VPN,
				sizeof(struct bgp_attr_srv6_l3vpn));
		static_attr.srv6_l3vpn->sid_flags = 0x00;
		static_attr.srv6_l3vpn->endpoint_behavior =
			CHECK_FLAG(locator->flags, SRV6_LOCATOR_USID)
				? SRV6_ENDPOINT_BEHAVIOR_END_DT46_USID
				: SRV6_ENDPOINT_BEHAVIOR_END_DT46;
		static_attr.srv6_l3vpn->loc_block_len =
			from_bgp->tovpn_sid_locator->block_bits_length;
		static_attr.srv6_l3vpn->loc_node_len =
			from_bgp->tovpn_sid_locator->node_bits_length;
		static_attr.srv6_l3vpn->func_len =
			from_bgp->tovpn_sid_locator->function_bits_length;
		static_attr.srv6_l3vpn->arg_len =
			from_bgp->tovpn_sid_locator->argument_bits_length;
		static_attr.srv6_l3vpn->transposition_len =
			from_bgp->tovpn_sid_locator->function_bits_length;
		static_attr.srv6_l3vpn->transposition_offset =
			from_bgp->tovpn_sid_locator->block_bits_length +
			from_bgp->tovpn_sid_locator->node_bits_length;
		memcpy(&static_attr.srv6_l3vpn->sid,
		       &from_bgp->tovpn_sid_locator->prefix.prefix,
		       sizeof(struct in6_addr));
	}


	new_attr = bgp_attr_intern(
		&static_attr);	/* hashed refcounted everything */
	bgp_attr_flush(&static_attr); /* free locally-allocated parts */

	if (debug && bgp_attr_get_ecommunity(new_attr)) {
		char *s = ecommunity_ecom2str(bgp_attr_get_ecommunity(new_attr),
					      ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: new_attr->ecommunity{%s}", __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	/* Now new_attr is an allocated interned attr */

	bn = bgp_afi_node_get(to_bgp->rib[afi][safi], afi, safi, p,
			      &(from_bgp->vpn_policy[afi].tovpn_rd));

	struct bgp_path_info *new_info;

	new_info =
		leak_update(to_bgp, bn, new_attr, afi, safi, path_vrf, &label,
			    1, from_bgp, NULL, nexthop_self_flag, debug);

	/*
	 * Routes actually installed in the vpn RIB must also be
	 * offered to all vrfs (because now they originate from
	 * the vpn RIB).
	 *
	 * Acceptance into other vrfs depends on rt-lists.
	 * Originating vrf will not accept the looped back route
	 * because of loop checking.
	 */
	if (new_info)
		vpn_leak_to_vrf_update(from_bgp, new_info, NULL);
	else
		bgp_dest_unlock_node(bn);
}

void vpn_leak_from_vrf_withdraw(struct bgp *to_bgp,		/* to */
				struct bgp *from_bgp,		/* from */
				struct bgp_path_info *path_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	const struct prefix *p = bgp_dest_get_prefix(path_vrf->net);
	afi_t afi = family2afi(p->family);
	safi_t safi = SAFI_MPLS_VPN;
	struct bgp_path_info *bpi;
	struct bgp_dest *bn;
	const char *debugmsg;

	if (debug) {
		zlog_debug(
			"%s: entry: leak-from=%s, p=%pBD, type=%d, sub_type=%d",
			__func__, from_bgp->name_pretty, path_vrf->net,
			path_vrf->type, path_vrf->sub_type);
	}

	if (!to_bgp)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* Is this route exportable into the VPN table? */
	if (!is_route_injectable_into_vpn(path_vrf))
		return;

	if (!vpn_leak_to_vpn_active(from_bgp, afi, &debugmsg, true)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	bn = bgp_safi_node_lookup(to_bgp->rib[afi][safi], safi, p,
				  &(from_bgp->vpn_policy[afi].tovpn_rd));

	if (!bn)
		return;
	if (debug)
		zlog_debug("%s: withdrawing (path_vrf=%p)", __func__, path_vrf);

	/*
	 * vrf -> vpn
	 * match original bpi imported from
	 */
	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->vrfleak &&
		    bpi->extra->vrfleak->parent == path_vrf) {
			break;
		}
	}

	if (bpi) {
		/* withdraw from looped vrfs as well */
		vpn_leak_to_vrf_withdraw(bpi);

		bgp_aggregate_decrement(to_bgp, p, bpi, afi, safi);
		bgp_path_info_delete(bn, bpi);
		bgp_process(to_bgp, bn, bpi, afi, safi);
	}
	bgp_dest_unlock_node(bn);
}

void vpn_leak_from_vrf_withdraw_all(struct bgp *to_bgp, struct bgp *from_bgp,
				    afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct bgp_dest *pdest;
	safi_t safi = SAFI_MPLS_VPN;

	/*
	 * Walk vpn table, delete bpi with bgp_orig == from_bgp
	 */
	for (pdest = bgp_table_top(to_bgp->rib[afi][safi]); pdest;
	     pdest = bgp_route_next(pdest)) {

		struct bgp_table *table;
		struct bgp_dest *bn;
		struct bgp_path_info *bpi, *next;

		/* This is the per-RD table of prefixes */
		table = bgp_dest_get_bgp_table_info(pdest);

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {
			bpi = bgp_dest_get_bgp_path_info(bn);
			if (debug && bpi) {
				zlog_debug("%s: looking at prefix %pBD",
					   __func__, bn);
			}

			for (; (bpi != NULL) && (next = bpi->next, 1);
			     bpi = next) {
				if (debug)
					zlog_debug("%s: type %d, sub_type %d",
						   __func__, bpi->type,
						   bpi->sub_type);
				if (bpi->sub_type != BGP_ROUTE_IMPORTED)
					continue;
				if (!bpi->extra || !bpi->extra->vrfleak)
					continue;
				if ((struct bgp *)bpi->extra->vrfleak->bgp_orig ==
				    from_bgp) {
					/* delete route */
					if (debug)
						zlog_debug("%s: deleting it",
							   __func__);
					/* withdraw from leak-to vrfs as well */
					vpn_leak_to_vrf_withdraw(bpi);
					bgp_aggregate_decrement(
						to_bgp, bgp_dest_get_prefix(bn),
						bpi, afi, safi);
					bgp_path_info_delete(bn, bpi);
					bgp_process(to_bgp, bn, bpi, afi, safi);
					bgp_mplsvpn_path_nh_label_unlink(
						bpi->extra->vrfleak->parent);
				}
			}
		}
	}
}

void vpn_leak_from_vrf_update_all(struct bgp *to_bgp, struct bgp *from_bgp,
				  afi_t afi)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);

	if (debug)
		zlog_debug("%s: entry, afi=%d, vrf=%s", __func__, afi,
			   from_bgp->name_pretty);

	for (bn = bgp_table_top(from_bgp->rib[afi][SAFI_UNICAST]); bn;
	     bn = bgp_route_next(bn)) {

		if (debug)
			zlog_debug("%s: node=%p", __func__, bn);

		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (debug)
				zlog_debug(
					"%s: calling vpn_leak_from_vrf_update",
					__func__);
			vpn_leak_from_vrf_update(to_bgp, from_bgp, bpi);
		}
	}
}

static struct bgp *bgp_lookup_by_rd(struct bgp_path_info *bpi,
				    struct prefix_rd *rd, afi_t afi)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (!rd)
		return NULL;

	/* If ACCEPT_OWN is not enabled for this path - return. */
	if (!CHECK_FLAG(bpi->flags, BGP_PATH_ACCEPT_OWN))
		return NULL;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		if (!CHECK_FLAG(bgp->vpn_policy[afi].flags,
				BGP_VPN_POLICY_TOVPN_RD_SET))
			continue;

		/* Check if we have source VRF by RD value */
		if (memcmp(&bgp->vpn_policy[afi].tovpn_rd.val, rd->val,
			   ECOMMUNITY_SIZE) == 0)
			return bgp;
	}

	return NULL;
}

static void vpn_leak_to_vrf_update_onevrf(struct bgp *to_bgp,   /* to */
					  struct bgp *from_bgp, /* from */
					  struct bgp_path_info *path_vpn,
					  struct prefix_rd *prd)
{
	const struct prefix *p = bgp_dest_get_prefix(path_vpn->net);
	afi_t afi = family2afi(p->family);

	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	struct bgp_dest *bn;
	safi_t safi = SAFI_UNICAST;
	const char *debugmsg;
	struct prefix nexthop_orig;
	mpls_label_t *label_pnt = NULL;
	uint8_t num_labels = 0;
	int nexthop_self_flag = 1;
	struct bgp_path_info *bpi_ultimate = NULL;
	struct bgp_path_info *bpi;
	int origin_local = 0;
	struct bgp *src_vrf;
	struct interface *ifp = NULL;
	char rd_buf[RD_ADDRSTRLEN];
	struct aspath *new_aspath;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (!vpn_leak_from_vpn_active(to_bgp, afi, &debugmsg)) {
		if (debug)
			zlog_debug(
				"%s: from vpn (%s) to vrf (%s), skipping: %s",
				__func__, from_bgp->name_pretty,
				to_bgp->name_pretty, debugmsg);
		return;
	}

	/*
	 * For VRF-2-VRF route-leaking,
	 * the source will be the originating VRF.
	 *
	 * If ACCEPT_OWN mechanism is enabled, then we SHOULD(?)
	 * get the source VRF (BGP) by looking at the RD.
	 */
	struct bgp *src_bgp = bgp_lookup_by_rd(path_vpn, prd, afi);

	if (path_vpn->extra && path_vpn->extra->vrfleak &&
	    path_vpn->extra->vrfleak->bgp_orig)
		src_vrf = path_vpn->extra->vrfleak->bgp_orig;
	else if (src_bgp)
		src_vrf = src_bgp;
	else
		src_vrf = from_bgp;

	/* Check for intersection of route targets */
	if (!ecommunity_include(
		    to_bgp->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
		    bgp_attr_get_ecommunity(path_vpn->attr))) {
		if (debug)
			zlog_debug(
				"from vpn (%s) to vrf (%s), skipping after no intersection of route targets",
				from_bgp->name_pretty, to_bgp->name_pretty);
		return;
	}

	rd_buf[0] = '\0';
	if (debug && prd)
		prefix_rd2str(prd, rd_buf, sizeof(rd_buf), to_bgp->asnotation);

	/* A route MUST NOT ever be accepted back into its source VRF, even if
	 * it carries one or more RTs that match that VRF.
	 */
	if (CHECK_FLAG(path_vpn->flags, BGP_PATH_ACCEPT_OWN) && prd &&
	    memcmp(&prd->val, &to_bgp->vpn_policy[afi].tovpn_rd.val,
		   ECOMMUNITY_SIZE) == 0) {
		if (debug)
			zlog_debug(
				"%s: skipping import, match RD (%s) of src VRF (%s) and the prefix (%pFX)",
				__func__, rd_buf, to_bgp->name_pretty, p);
		return;
	}

	bn = bgp_afi_node_get(to_bgp->rib[afi][safi], afi, safi, p, NULL);

	/* Check if leaked route has our asn. If so, don't import it. */
	if (aspath_loop_check(path_vpn->attr->aspath, to_bgp->as)) {
		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (bpi->extra && bpi->extra->vrfleak &&
			    (struct bgp_path_info *)bpi->extra->vrfleak->parent ==
				    path_vpn) {
				break;
			}
		}

		if (bpi) {
			if (debug)
				zlog_debug("%s: blocking import of %p, as-path match",
					   __func__, bpi);
			bgp_aggregate_decrement(to_bgp, p, bpi, afi, safi);
			bgp_path_info_delete(bn, bpi);
			bgp_process(to_bgp, bn, bpi, afi, safi);
		}
		bgp_dest_unlock_node(bn);

		return;
	}

	if (debug)
		zlog_debug("%s: updating RD %s, %pFX to %s", __func__, rd_buf,
			   p, to_bgp->name_pretty);

	/* shallow copy */
	static_attr = *path_vpn->attr;

	struct ecommunity *old_ecom;
	struct ecommunity *new_ecom;

	/* If doing VRF-to-VRF leaking, strip RTs. */
	old_ecom = bgp_attr_get_ecommunity(&static_attr);
	if (old_ecom && CHECK_FLAG(to_bgp->af_flags[afi][safi],
				   BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
		new_ecom = ecommunity_dup(old_ecom);
		ecommunity_strip_rts(new_ecom);
		bgp_attr_set_ecommunity(&static_attr, new_ecom);

		if (new_ecom->size == 0) {
			ecommunity_free(&new_ecom);
			bgp_attr_set_ecommunity(&static_attr, NULL);
		}

		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	}

	community_strip_accept_own(&static_attr);

	bn = bgp_afi_node_get(to_bgp->rib[afi][safi], afi, safi, p, NULL);

	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->vrfleak &&
		    bpi->extra->vrfleak->parent == path_vpn)
			break;
	}

	if (bpi && leak_update_nexthop_valid(to_bgp, bn, &static_attr, afi, safi,
					     path_vpn, bpi, src_vrf, p, debug))
		SET_FLAG(static_attr.nh_flags, BGP_ATTR_NH_VALID);
	else
		UNSET_FLAG(static_attr.nh_flags, BGP_ATTR_NH_VALID);

	/*
	 * Nexthop: stash and clear
	 *
	 * Nexthop is valid in context of VPN core, but not in destination vrf.
	 * Stash it for later label resolution by vrf ingress path and then
	 * overwrite with 0, i.e., "me", for the sake of vrf advertisement.
	 */
	uint8_t nhfamily = NEXTHOP_FAMILY(path_vpn->attr->mp_nexthop_len);

	memset(&nexthop_orig, 0, sizeof(nexthop_orig));
	nexthop_orig.family = nhfamily;

	/* If the path has accept-own community and the source VRF
	 * is valid, reset next-hop to self, to allow importing own
	 * routes between different VRFs on the same node.
	 */

	if (src_bgp)
		subgroup_announce_reset_nhop(nhfamily, &static_attr);

	bpi_ultimate = bgp_get_imported_bpi_ultimate(path_vpn);

	/* The nh ifindex may not be defined (when the route is
	 * imported from the network statement => BGP_ROUTE_STATIC)
	 * or to the real interface.
	 * Rewrite the nh ifindex to VRF's interface.
	 * Let the kernel to decide with double lookup the real next-hop
	 * interface when installing the route.
	 */
	if (src_vrf->vrf_id != VRF_DEFAULT &&
	    (src_bgp || bpi_ultimate->sub_type == BGP_ROUTE_STATIC ||
	     bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE)) {
		ifp = if_get_vrf_loopback(src_vrf->vrf_id);
		if (ifp)
			static_attr.nh_ifindex = ifp->ifindex;
	}

	switch (nhfamily) {
	case AF_INET:
		/* save */
		nexthop_orig.u.prefix4 = path_vpn->attr->mp_nexthop_global_in;
		nexthop_orig.prefixlen = IPV4_MAX_BITLEN;

		if (CHECK_FLAG(to_bgp->af_flags[afi][safi],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			static_attr.nexthop.s_addr =
				nexthop_orig.u.prefix4.s_addr;

			static_attr.mp_nexthop_global_in =
				path_vpn->attr->mp_nexthop_global_in;
			static_attr.mp_nexthop_len =
				path_vpn->attr->mp_nexthop_len;
		}
		static_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
		break;
	case AF_INET6:
		/* save */
		nexthop_orig.u.prefix6 = path_vpn->attr->mp_nexthop_global;
		nexthop_orig.prefixlen = IPV6_MAX_BITLEN;

		if (CHECK_FLAG(to_bgp->af_flags[afi][safi],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			static_attr.mp_nexthop_global = nexthop_orig.u.prefix6;
		}
		break;
	}

	if (!ifp && static_attr.nh_ifindex)
		ifp = if_lookup_by_index(static_attr.nh_ifindex,
					 src_vrf->vrf_id);

	if (ifp && if_is_operative(ifp))
		SET_FLAG(static_attr.nh_flags, BGP_ATTR_NH_IF_OPERSTATE);
	else
		UNSET_FLAG(static_attr.nh_flags, BGP_ATTR_NH_IF_OPERSTATE);

	/*
	 * route map handling
	 */
	if (to_bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN]) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = to_bgp->peer_self;
		info.attr = &static_attr;
		info.extra = path_vpn->extra; /* Used for source-vrf filter */
		ret = route_map_apply(to_bgp->vpn_policy[afi]
					      .rmap[BGP_VPN_POLICY_DIR_FROMVPN],
				      p, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s vpn-policy route map \"%s\" says DENY, returning",
					__func__, to_bgp->name_pretty,
					to_bgp->vpn_policy[afi]
						.rmap[BGP_VPN_POLICY_DIR_FROMVPN]
						->name);
			return;
		}
		/*
		 * if route-map changed nexthop, don't nexthop-self on output
		 */
		if (!CHECK_FLAG(static_attr.rmap_change_flags,
						BATTR_RMAP_NEXTHOP_UNCHANGED))
			nexthop_self_flag = 0;
	}

	/*
	 * if the asn values are different, copy the asn of the source vrf
	 * into the entry before importing. This helps with as-path loop
	 * detection
	 */
	if (path_vpn->extra && path_vpn->extra->vrfleak &&
	    path_vpn->extra->vrfleak->bgp_orig &&
	    (to_bgp->as != path_vpn->extra->vrfleak->bgp_orig->as)) {
		new_aspath = aspath_dup(static_attr.aspath);
		new_aspath =
			aspath_add_seq(new_aspath,
				       path_vpn->extra->vrfleak->bgp_orig->as);
		static_attr.aspath = new_aspath;
	}

	new_attr = bgp_attr_intern(&static_attr);
	bgp_attr_flush(&static_attr);

	/*
	 * ensure labels are copied
	 *
	 * However, there is a special case: if the route originated in
	 * another local VRF (as opposed to arriving via VPN), then the
	 * nexthop is reached by hairpinning through this router (me)
	 * using IP forwarding only (no LSP). Therefore, the route
	 * imported to the VRF should not have labels attached. Note
	 * that nexthop tracking is also involved: eliminating the
	 * labels for these routes enables the non-labeled nexthops
	 * from the originating VRF to be considered valid for this route.
	 */
	if (!CHECK_FLAG(to_bgp->af_flags[afi][safi],
			BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
		/*
		 * if original route was unicast,
		 * then it did not arrive over vpn
		 */
		if (bpi_ultimate->net) {
			struct bgp_table *table;

			table = bgp_dest_table(bpi_ultimate->net);
			if (table && (table->safi == SAFI_UNICAST))
				origin_local = 1;
		}

		num_labels = origin_local ? 0
					  : BGP_PATH_INFO_NUM_LABELS(path_vpn);
		label_pnt = num_labels ? path_vpn->extra->labels->label : NULL;
	}

	if (debug)
		zlog_debug("%s: pfx %pBD: num_labels %d", __func__,
			   path_vpn->net, num_labels);

	if (!leak_update(to_bgp, bn, new_attr, afi, safi, path_vpn, label_pnt,
			 num_labels, src_vrf, &nexthop_orig, nexthop_self_flag,
			 debug))
		bgp_dest_unlock_node(bn);
}

bool vpn_leak_to_vrf_no_retain_filter_check(struct bgp *from_bgp,
					    struct attr *attr, afi_t afi)
{
	struct ecommunity *ecom_route_target = bgp_attr_get_ecommunity(attr);
	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);
	struct listnode *node;
	const char *debugmsg;
	struct bgp *to_bgp;

	/* Loop over BGP instances */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, to_bgp)) {
		if (!vpn_leak_from_vpn_active(to_bgp, afi, &debugmsg)) {
			if (debug)
				zlog_debug(
					"%s: from vpn (%s) to vrf (%s) afi %s, skipping: %s",
					__func__, from_bgp->name_pretty,
					to_bgp->name_pretty, afi2str(afi),
					debugmsg);
			continue;
		}

		/* Check for intersection of route targets */
		if (!ecommunity_include(
			    to_bgp->vpn_policy[afi]
				    .rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
			    ecom_route_target)) {
			if (debug)
				zlog_debug(
					"%s: from vpn (%s) to vrf (%s) afi %s %s, skipping after no intersection of route targets",
					__func__, from_bgp->name_pretty,
					to_bgp->name_pretty, afi2str(afi),
					ecommunity_str(ecom_route_target));
			continue;
		}
		return false;
	}

	if (debug)
		zlog_debug(
			"%s: from vpn (%s) afi %s %s, no import - must be filtered",
			__func__, from_bgp->name_pretty, afi2str(afi),
			ecommunity_str(ecom_route_target));

	return true;
}

void vpn_leak_to_vrf_update(struct bgp *from_bgp,
			    struct bgp_path_info *path_vpn,
			    struct prefix_rd *prd)
{
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: start (path_vpn=%p)", __func__, path_vpn);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		if (!path_vpn->extra || !path_vpn->extra->vrfleak ||
		    path_vpn->extra->vrfleak->bgp_orig != bgp) { /* no loop */
			vpn_leak_to_vrf_update_onevrf(bgp, from_bgp, path_vpn,
						      prd);
		}
	}
}

void vpn_leak_to_vrf_withdraw(struct bgp_path_info *path_vpn)
{
	const struct prefix *p;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp;
	struct listnode *mnode, *mnnode;
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;
	const char *debugmsg;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: entry: p=%pBD, type=%d, sub_type=%d", __func__,
			   path_vpn->net, path_vpn->type, path_vpn->sub_type);

	if (debug)
		zlog_debug("%s: start (path_vpn=%p)", __func__, path_vpn);

	if (!path_vpn->net) {
#ifdef ENABLE_BGP_VNC
		/* BGP_ROUTE_RFP routes do not have path_vpn->net set (yet) */
		if (path_vpn->type == ZEBRA_ROUTE_BGP
		    && path_vpn->sub_type == BGP_ROUTE_RFP) {

			return;
		}
#endif
		if (debug)
			zlog_debug(
				"%s: path_vpn->net unexpectedly NULL, no prefix, bailing",
				__func__);
		return;
	}

	p = bgp_dest_get_prefix(path_vpn->net);
	afi = family2afi(p->family);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		if (!vpn_leak_from_vpn_active(bgp, afi, &debugmsg)) {
			if (debug)
				zlog_debug("%s: from %s, skipping: %s",
					   __func__, bgp->name_pretty,
					   debugmsg);
			continue;
		}

		/* Check for intersection of route targets */
		if (!ecommunity_include(
			    bgp->vpn_policy[afi]
				    .rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
			    bgp_attr_get_ecommunity(path_vpn->attr))) {

			continue;
		}

		if (debug)
			zlog_debug("%s: withdrawing from vrf %s", __func__,
				   bgp->name_pretty);

		bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, NULL);

		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (bpi->extra && bpi->extra->vrfleak &&
			    (struct bgp_path_info *)bpi->extra->vrfleak->parent ==
				    path_vpn) {
				break;
			}
		}

		if (bpi) {
			if (debug)
				zlog_debug("%s: deleting bpi %p", __func__,
					   bpi);
			bgp_aggregate_decrement(bgp, p, bpi, afi, safi);
			bgp_path_info_delete(bn, bpi);
			bgp_process(bgp, bn, bpi, afi, safi);
		}
		bgp_dest_unlock_node(bn);
	}
}

void vpn_leak_to_vrf_withdraw_all(struct bgp *to_bgp, afi_t afi)
{
	struct bgp_dest *bn;
	struct bgp_path_info *bpi, *next;
	safi_t safi = SAFI_UNICAST;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: entry", __func__);
	/*
	 * Walk vrf table, delete bpi with bgp_orig in a different vrf
	 */
	for (bn = bgp_table_top(to_bgp->rib[afi][safi]); bn;
	     bn = bgp_route_next(bn)) {
		for (bpi = bgp_dest_get_bgp_path_info(bn);
		     (bpi != NULL) && (next = bpi->next, 1); bpi = next) {
			if (bpi->extra && bpi->extra->vrfleak &&
			    bpi->extra->vrfleak->bgp_orig != to_bgp &&
			    bpi->extra->vrfleak->parent &&
			    is_pi_family_vpn(bpi->extra->vrfleak->parent)) {
				/* delete route */
				bgp_aggregate_decrement(to_bgp,
							bgp_dest_get_prefix(bn),
							bpi, afi, safi);
				bgp_path_info_delete(bn, bpi);
				bgp_process(to_bgp, bn, bpi, afi, safi);
			}
		}
	}
}

void vpn_leak_no_retain(struct bgp *to_bgp, struct bgp *vpn_from, afi_t afi)
{
	struct bgp_dest *pdest;
	safi_t safi = SAFI_MPLS_VPN;

	assert(vpn_from);

	/*
	 * Walk vpn table
	 */
	for (pdest = bgp_table_top(vpn_from->rib[afi][safi]); pdest;
	     pdest = bgp_route_next(pdest)) {
		struct bgp_table *table;
		struct bgp_dest *bn;
		struct bgp_path_info *bpi;

		/* This is the per-RD table of prefixes */
		table = bgp_dest_get_bgp_table_info(pdest);

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {
			struct bgp_path_info *next;

			for (bpi = bgp_dest_get_bgp_path_info(bn);
			     (bpi != NULL) && (next = bpi->next, 1);
			     bpi = next) {
				if (bpi->extra && bpi->extra->vrfleak &&
				    bpi->extra->vrfleak->bgp_orig == to_bgp)
					continue;

				if (bpi->sub_type != BGP_ROUTE_NORMAL)
					continue;

				if (!vpn_leak_to_vrf_no_retain_filter_check(
					    vpn_from, bpi->attr, afi))
					/* do not filter */
					continue;

				bgp_unlink_nexthop(bpi);
				bgp_rib_remove(bn, bpi, bpi->peer, afi, safi);
			}
		}
	}
}

void vpn_leak_to_vrf_update_all(struct bgp *to_bgp, struct bgp *vpn_from,
				afi_t afi)
{
	struct bgp_dest *pdest;
	safi_t safi = SAFI_MPLS_VPN;

	assert(vpn_from);

	/*
	 * Walk vpn table
	 */
	for (pdest = bgp_table_top(vpn_from->rib[afi][safi]); pdest;
	     pdest = bgp_route_next(pdest)) {
		struct bgp_table *table;
		struct bgp_dest *bn;
		struct bgp_path_info *bpi;

		/* This is the per-RD table of prefixes */
		table = bgp_dest_get_bgp_table_info(pdest);

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {

			for (bpi = bgp_dest_get_bgp_path_info(bn); bpi;
			     bpi = bpi->next) {
				if (bpi->extra && bpi->extra->vrfleak &&
				    bpi->extra->vrfleak->bgp_orig == to_bgp)
					continue;

				vpn_leak_to_vrf_update_onevrf(to_bgp, vpn_from,
							      bpi, NULL);
			}
		}
	}
}

/*
 * This function is called for definition/deletion/change to a route-map
 */
static void vpn_policy_routemap_update(struct bgp *bgp, const char *rmap_name)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_RMAP_EVENT);
	afi_t afi;
	struct route_map *rmap;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
	    && bgp->inst_type != BGP_INSTANCE_TYPE_VRF) {

		return;
	}

	rmap = route_map_lookup_by_name(rmap_name); /* NULL if deleted */

	for (afi = 0; afi < AFI_MAX; ++afi) {

		if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_TOVPN]
			&& !strcmp(rmap_name,
			       bgp->vpn_policy[afi]
				       .rmap_name[BGP_VPN_POLICY_DIR_TOVPN])) {

			if (debug)
				zlog_debug(
					"%s: rmap \"%s\" matches vrf-policy tovpn for as %d afi %s",
					__func__, rmap_name, bgp->as,
					afi2str(afi));

			vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi,
					   bgp_get_default(), bgp);
			if (debug)
				zlog_debug("%s: after vpn_leak_prechange",
					   __func__);

			/* in case of definition/deletion */
			bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_TOVPN] =
				rmap;

			vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
					    bgp_get_default(), bgp);

			if (debug)
				zlog_debug("%s: after vpn_leak_postchange",
					   __func__);
		}

		if (bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]
			&& !strcmp(rmap_name,
				bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_FROMVPN]))  {

			if (debug) {
				zlog_debug("%s: rmap \"%s\" matches vrf-policy fromvpn for as %d afi %s",
					__func__, rmap_name, bgp->as,
					afi2str(afi));
			}

			vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, afi,
					   bgp_get_default(), bgp);

			/* in case of definition/deletion */
			bgp->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN] =
					rmap;

			vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, afi,
					    bgp_get_default(), bgp);
		}
	}
}

/* This API is used during router-id change, reflect VPNs
 * auto RD and RT values and readvertise routes to VPN table.
 */
void vpn_handle_router_id_update(struct bgp *bgp, bool withdraw,
				 bool is_config)
{
	afi_t afi;
	int debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF)
		     | BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));
	char *vname;
	const char *export_name;
	char buf[RD_ADDRSTRLEN];
	struct bgp *bgp_import;
	struct listnode *node;
	struct ecommunity *ecom;
	enum vpn_policy_direction idir, edir;

	/*
	 * Router-id change that is not explicitly configured
	 * (a change from zebra, frr restart for example)
	 * should not replace a configured vpn RD/RT.
	 */
	if (!is_config) {
		if (debug)
			zlog_debug("%s: skipping non explicit router-id change",
				   __func__);
		return;
	}

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
	    && bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	export_name = bgp->name ? bgp->name : VRF_DEFAULT_NAME;
	idir = BGP_VPN_POLICY_DIR_FROMVPN;
	edir = BGP_VPN_POLICY_DIR_TOVPN;

	for (afi = 0; afi < AFI_MAX; ++afi) {
		if (!vpn_leak_to_vpn_active(bgp, afi, NULL, false))
			continue;

		if (withdraw) {
			vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN,
					   afi, bgp_get_default(), bgp);
			if (debug)
				zlog_debug("%s: %s after to_vpn vpn_leak_prechange",
					   __func__, export_name);

			/* Remove import RT from VRFs */
			ecom = bgp->vpn_policy[afi].rtlist[edir];
			for (ALL_LIST_ELEMENTS_RO(bgp->vpn_policy[afi].
						  export_vrf, node, vname)) {
				if (strcmp(vname, VRF_DEFAULT_NAME) == 0)
					bgp_import = bgp_get_default();
				else
					bgp_import = bgp_lookup_by_name(vname);
				if (!bgp_import)
					continue;

				ecommunity_del_val(
					bgp_import->vpn_policy[afi]
						.rtlist[idir],
					(struct ecommunity_val *)ecom->val);
			}
		} else {
			/* New router-id derive auto RD and RT and export
			 * to VPN
			 */
			form_auto_rd(bgp->router_id, bgp->vrf_rd_id,
				     &bgp->vrf_prd_auto);
			bgp->vpn_policy[afi].tovpn_rd = bgp->vrf_prd_auto;
			prefix_rd2str(&bgp->vpn_policy[afi].tovpn_rd, buf,
				      sizeof(buf), bgp->asnotation);

			/* free up pre-existing memory if any and allocate
			 *  the ecommunity attribute with new RD/RT
			 */
			if (bgp->vpn_policy[afi].rtlist[edir])
				ecommunity_free(
					&bgp->vpn_policy[afi].rtlist[edir]);
			bgp->vpn_policy[afi].rtlist[edir] = ecommunity_str2com(
				buf, ECOMMUNITY_ROUTE_TARGET, 0);

			/* Update import_vrf rt_list */
			ecom = bgp->vpn_policy[afi].rtlist[edir];
			for (ALL_LIST_ELEMENTS_RO(bgp->vpn_policy[afi].
						  export_vrf, node, vname)) {
				if (strcmp(vname, VRF_DEFAULT_NAME) == 0)
					bgp_import = bgp_get_default();
				else
					bgp_import = bgp_lookup_by_name(vname);
				if (!bgp_import)
					continue;
				if (bgp_import->vpn_policy[afi].rtlist[idir])
					bgp_import->vpn_policy[afi].rtlist[idir]
						= ecommunity_merge(
						bgp_import->vpn_policy[afi]
						.rtlist[idir], ecom);
				else
					bgp_import->vpn_policy[afi].rtlist[idir]
						= ecommunity_dup(ecom);
			}

			/* Update routes to VPN */
			vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN,
					    afi, bgp_get_default(),
					    bgp);
			if (debug)
				zlog_debug("%s: %s after to_vpn vpn_leak_postchange",
					   __func__, export_name);
		}
	}
}

void vpn_policy_routemap_event(const char *rmap_name)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_RMAP_EVENT);
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;

	if (debug)
		zlog_debug("%s: entry", __func__);

	if (bm->bgp == NULL) /* may be called during cleanup */
		return;

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp))
		vpn_policy_routemap_update(bgp, rmap_name);
}

void vrf_import_from_vrf(struct bgp *to_bgp, struct bgp *from_bgp,
			 afi_t afi, safi_t safi)
{
	const char *export_name;
	enum vpn_policy_direction idir, edir;
	char *vname, *tmp_name;
	char buf[RD_ADDRSTRLEN];
	struct ecommunity *ecom;
	bool first_export = false;
	int debug;
	struct listnode *node;
	bool is_inst_match = false;

	export_name = to_bgp->name ? to_bgp->name : VRF_DEFAULT_NAME;
	idir = BGP_VPN_POLICY_DIR_FROMVPN;
	edir = BGP_VPN_POLICY_DIR_TOVPN;

	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		     BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	/*
	 * Cross-ref both VRFs. Also, note if this is the first time
	 * any VRF is importing from "import_vrf".
	 */
	vname = (from_bgp->name ? XSTRDUP(MTYPE_TMP, from_bgp->name)
			       : XSTRDUP(MTYPE_TMP, VRF_DEFAULT_NAME));

	/* Check the import_vrf list of destination vrf for the source vrf name,
	 * insert otherwise.
	 */
	for (ALL_LIST_ELEMENTS_RO(to_bgp->vpn_policy[afi].import_vrf,
				  node, tmp_name)) {
		if (strcmp(vname, tmp_name) == 0) {
			is_inst_match = true;
			break;
		}
	}
	if (!is_inst_match)
		listnode_add(to_bgp->vpn_policy[afi].import_vrf,
				     vname);
	else
		XFREE(MTYPE_TMP, vname);

	/* Check if the source vrf already exports to any vrf,
	 * first time export requires to setup auto derived RD/RT values.
	 * Add the destination vrf name to export vrf list if it is
	 * not present.
	 */
	is_inst_match = false;
	vname = XSTRDUP(MTYPE_TMP, export_name);
	if (!listcount(from_bgp->vpn_policy[afi].export_vrf)) {
		first_export = true;
	} else {
		for (ALL_LIST_ELEMENTS_RO(from_bgp->vpn_policy[afi].export_vrf,
					  node, tmp_name)) {
			if (strcmp(vname, tmp_name) == 0) {
				is_inst_match = true;
				break;
			}
		}
	}
	if (!is_inst_match)
		listnode_add(from_bgp->vpn_policy[afi].export_vrf,
			     vname);
	else
		XFREE(MTYPE_TMP, vname);

	/* Update import RT for current VRF using export RT of the VRF we're
	 * importing from. First though, make sure "import_vrf" has that
	 * set.
	 */
	if (first_export) {
		form_auto_rd(from_bgp->router_id, from_bgp->vrf_rd_id,
			     &from_bgp->vrf_prd_auto);
		from_bgp->vpn_policy[afi].tovpn_rd = from_bgp->vrf_prd_auto;
		SET_FLAG(from_bgp->vpn_policy[afi].flags,
			 BGP_VPN_POLICY_TOVPN_RD_SET);
		prefix_rd2str(&from_bgp->vpn_policy[afi].tovpn_rd, buf,
			      sizeof(buf), from_bgp->asnotation);
		from_bgp->vpn_policy[afi].rtlist[edir] =
			ecommunity_str2com(buf, ECOMMUNITY_ROUTE_TARGET, 0);
		SET_FLAG(from_bgp->af_flags[afi][safi],
			 BGP_CONFIG_VRF_TO_VRF_EXPORT);
		from_bgp->vpn_policy[afi].tovpn_label =
			BGP_PREVENT_VRF_2_VRF_LEAK;
	}
	ecom = from_bgp->vpn_policy[afi].rtlist[edir];
	if (to_bgp->vpn_policy[afi].rtlist[idir])
		to_bgp->vpn_policy[afi].rtlist[idir] =
			ecommunity_merge(to_bgp->vpn_policy[afi]
					 .rtlist[idir], ecom);
	else
		to_bgp->vpn_policy[afi].rtlist[idir] = ecommunity_dup(ecom);
	SET_FLAG(to_bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT);

	if (debug) {
		const char *from_name;
		char *ecom1, *ecom2;

		from_name = from_bgp->name ? from_bgp->name :
			VRF_DEFAULT_NAME;

		ecom1 = ecommunity_ecom2str(
			to_bgp->vpn_policy[afi].rtlist[idir],
			ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		ecom2 = ecommunity_ecom2str(
			to_bgp->vpn_policy[afi].rtlist[edir],
			ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug(
			"%s from %s to %s first_export %u import-rt %s export-rt %s",
			__func__, from_name, export_name, first_export, ecom1,
			ecom2);

		ecommunity_strfree(&ecom1);
		ecommunity_strfree(&ecom2);
	}

	/* Does "import_vrf" first need to export its routes or that
	 * is already done and we just need to import those routes
	 * from the global table?
	 */
	if (first_export)
		vpn_leak_postchange(edir, afi, bgp_get_default(), from_bgp);
	else
		vpn_leak_postchange(idir, afi, bgp_get_default(), to_bgp);
}

void vrf_unimport_from_vrf(struct bgp *to_bgp, struct bgp *from_bgp,
			   afi_t afi, safi_t safi)
{
	const char *export_name, *tmp_name;
	enum vpn_policy_direction idir, edir;
	char *vname;
	struct ecommunity *ecom = NULL;
	struct listnode *node;
	int debug;

	export_name = to_bgp->name ? to_bgp->name : VRF_DEFAULT_NAME;
	tmp_name = from_bgp->name ? from_bgp->name : VRF_DEFAULT_NAME;
	idir = BGP_VPN_POLICY_DIR_FROMVPN;
	edir = BGP_VPN_POLICY_DIR_TOVPN;

	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		     BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	/* Were we importing from "import_vrf"? */
	for (ALL_LIST_ELEMENTS_RO(to_bgp->vpn_policy[afi].import_vrf, node,
				  vname)) {
		if (strcmp(vname, tmp_name) == 0)
			break;
	}

	/*
	 * We do not check in the cli if the passed in bgp
	 * instance is actually imported into us before
	 * we call this function.  As such if we do not
	 * find this in the import_vrf list than
	 * we just need to return safely.
	 */
	if (!vname)
		return;

	if (debug)
		zlog_debug("%s from %s to %s", __func__, tmp_name, export_name);

	/* Remove "import_vrf" from our import list. */
	listnode_delete(to_bgp->vpn_policy[afi].import_vrf, vname);
	XFREE(MTYPE_TMP, vname);

	/* Remove routes imported from "import_vrf". */
	/* TODO: In the current logic, we have to first remove all
	 * imported routes and then (if needed) import back routes
	 */
	vpn_leak_prechange(idir, afi, bgp_get_default(), to_bgp);

	if (to_bgp->vpn_policy[afi].import_vrf->count == 0) {
		if (!to_bgp->vpn_policy[afi].rmap[idir])
			UNSET_FLAG(to_bgp->af_flags[afi][safi],
				   BGP_CONFIG_VRF_TO_VRF_IMPORT);
		if (to_bgp->vpn_policy[afi].rtlist[idir])
			ecommunity_free(&to_bgp->vpn_policy[afi].rtlist[idir]);
	} else {
		ecom = from_bgp->vpn_policy[afi].rtlist[edir];
		if (ecom)
			ecommunity_del_val(to_bgp->vpn_policy[afi].rtlist[idir],
				   (struct ecommunity_val *)ecom->val);
		vpn_leak_postchange(idir, afi, bgp_get_default(), to_bgp);
	}

	/*
	 * What?
	 * So SA is assuming that since the ALL_LIST_ELEMENTS_RO
	 * below is checking for NULL that export_vrf can be
	 * NULL, consequently it is complaining( like a cabbage )
	 * that we could dereference and crash in the listcount(..)
	 * check below.
	 * So make it happy, under protest, with liberty and justice
	 * for all.
	 */
	assert(from_bgp->vpn_policy[afi].export_vrf);

	/* Remove us from "import_vrf's" export list. If no other VRF
	 * is importing from "import_vrf", cleanup appropriately.
	 */
	for (ALL_LIST_ELEMENTS_RO(from_bgp->vpn_policy[afi].export_vrf,
				  node, vname)) {
		if (strcmp(vname, export_name) == 0)
			break;
	}

	/*
	 * If we have gotten to this point then the vname must
	 * exist.  If not, we are in a world of trouble and
	 * have slag sitting around.
	 *
	 * import_vrf and export_vrf must match in having
	 * the in/out names as appropriate.
	 * export_vrf list could have been cleaned up
	 * as part of no router bgp source instnace.
	 */
	if (!vname)
		return;

	listnode_delete(from_bgp->vpn_policy[afi].export_vrf, vname);
	XFREE(MTYPE_TMP, vname);

	if (!listcount(from_bgp->vpn_policy[afi].export_vrf)) {
		vpn_leak_prechange(edir, afi, bgp_get_default(), from_bgp);
		ecommunity_free(&from_bgp->vpn_policy[afi].rtlist[edir]);
		UNSET_FLAG(from_bgp->af_flags[afi][safi],
			   BGP_CONFIG_VRF_TO_VRF_EXPORT);
		memset(&from_bgp->vpn_policy[afi].tovpn_rd, 0,
		       sizeof(struct prefix_rd));
		UNSET_FLAG(from_bgp->vpn_policy[afi].flags,
			   BGP_VPN_POLICY_TOVPN_RD_SET);
		from_bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;

	}
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (vpnv4_network,
       vpnv4_network_cmd,
       "network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575)",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n")
{
	int idx_ipv4_prefixlen = 1;
	int idx_ext_community = 3;
	int idx_label = 5;

	return bgp_static_set(vty, false, argv[idx_ipv4_prefixlen]->arg,
			      argv[idx_ext_community]->arg,
			      argv[idx_label]->arg, AFI_IP, SAFI_MPLS_VPN, NULL,
			      0, 0, 0, NULL, NULL, NULL, NULL);
}

DEFUN (vpnv4_network_route_map,
       vpnv4_network_route_map_cmd,
       "network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575) route-map RMAP_NAME",
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n"
       "route map\n"
       "route map name\n")
{
	int idx_ipv4_prefixlen = 1;
	int idx_ext_community = 3;
	int idx_label = 5;
	int idx_rmap = 7;

	return bgp_static_set(vty, false, argv[idx_ipv4_prefixlen]->arg,
			      argv[idx_ext_community]->arg, argv[idx_label]->arg,
			      AFI_IP, SAFI_MPLS_VPN, argv[idx_rmap]->arg, 0, 0,
			      0, NULL, NULL, NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv4_network,
       no_vpnv4_network_cmd,
       "no network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575)",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv4 prefix\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n")
{
	int idx_ipv4_prefixlen = 2;
	int idx_ext_community = 4;
	int idx_label = 6;

	return bgp_static_set(vty, true, argv[idx_ipv4_prefixlen]->arg,
			      argv[idx_ext_community]->arg,
			      argv[idx_label]->arg, AFI_IP, SAFI_MPLS_VPN, NULL,
			      0, 0, 0, NULL, NULL, NULL, NULL);
}

DEFUN (vpnv6_network,
       vpnv6_network_cmd,
       "network X:X::X:X/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575) [route-map RMAP_NAME]",
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n"
       "route map\n"
       "route map name\n")
{
	int idx_ipv6_prefix = 1;
	int idx_ext_community = 3;
	int idx_label = 5;
	int idx_rmap = 7;

	if (argc == 8)
		return bgp_static_set(vty, false, argv[idx_ipv6_prefix]->arg,
				      argv[idx_ext_community]->arg,
				      argv[idx_label]->arg, AFI_IP6,
				      SAFI_MPLS_VPN, argv[idx_rmap]->arg, 0, 0,
				      0, NULL, NULL, NULL, NULL);
	else
		return bgp_static_set(vty, false, argv[idx_ipv6_prefix]->arg,
				      argv[idx_ext_community]->arg,
				      argv[idx_label]->arg, AFI_IP6,
				      SAFI_MPLS_VPN, NULL, 0, 0, 0, NULL, NULL,
				      NULL, NULL);
}

/* For testing purpose, static route of MPLS-VPN. */
DEFUN (no_vpnv6_network,
       no_vpnv6_network_cmd,
       "no network X:X::X:X/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575)",
       NO_STR
       "Specify a network to announce via BGP\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Specify Route Distinguisher\n"
       "VPN Route Distinguisher\n"
       "VPN NLRI label (tag)\n"
       "VPN NLRI label (tag)\n"
       "Label value\n")
{
	int idx_ipv6_prefix = 2;
	int idx_ext_community = 4;
	int idx_label = 6;

	return bgp_static_set(vty, true, argv[idx_ipv6_prefix]->arg,
			      argv[idx_ext_community]->arg,
			      argv[idx_label]->arg, AFI_IP6, SAFI_MPLS_VPN,
			      NULL, 0, 0, 0, NULL, NULL, NULL, NULL);
}

int bgp_show_mpls_vpn(struct vty *vty, afi_t afi, struct prefix_rd *prd,
		      enum bgp_show_type type, void *output_arg, int tags,
		      bool use_json)
{
	struct bgp *bgp;
	struct bgp_table *table;
	uint16_t show_flags = 0;

	if (use_json)
		SET_FLAG(show_flags, BGP_SHOW_OPT_JSON);

	bgp = bgp_get_default();
	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}
	table = bgp->rib[afi][SAFI_MPLS_VPN];
	return bgp_show_table_rd(vty, bgp, afi, SAFI_MPLS_VPN, table, prd, type,
				 output_arg, show_flags);
}

DEFUN (show_bgp_ip_vpn_all_rd,
       show_bgp_ip_vpn_all_rd_cmd,
       "show bgp "BGP_AFI_CMD_STR" vpn all [rd <ASN:NN_OR_IP-ADDRESS:NN|all>] [json]",
       SHOW_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display VPN NLRI specific information\n"
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "All VPN Route Distinguishers\n"
       JSON_STR)
{
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		/* Constrain search if user supplies RD && RD != "all" */
		if (argv_find(argv, argc, "rd", &idx)
		    && strcmp(argv[idx + 1]->arg, "all")) {
			ret = str2prefix_rd(argv[idx + 1]->arg, &prd);
			if (!ret) {
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
				return CMD_WARNING;
			}
			return bgp_show_mpls_vpn(vty, afi, &prd,
						 bgp_show_type_normal, NULL, 0,
						 use_json(argc, argv));
		} else {
			return bgp_show_mpls_vpn(vty, afi, NULL,
						 bgp_show_type_normal, NULL, 0,
						 use_json(argc, argv));
		}
	}
	return CMD_SUCCESS;
}

ALIAS(show_bgp_ip_vpn_all_rd,
      show_bgp_ip_vpn_rd_cmd,
       "show bgp "BGP_AFI_CMD_STR" vpn rd <ASN:NN_OR_IP-ADDRESS:NN|all> [json]",
       SHOW_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "All VPN Route Distinguishers\n"
       JSON_STR)

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN (show_ip_bgp_vpn_rd,
       show_ip_bgp_vpn_rd_cmd,
       "show ip bgp "BGP_AFI_CMD_STR" vpn rd <ASN:NN_OR_IP-ADDRESS:NN|all>",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_AFI_HELP_STR
       BGP_AF_MODIFIER_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "All VPN Route Distinguishers\n")
{
	int idx_ext_community = argc - 1;
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (!strcmp(argv[idx_ext_community]->arg, "all"))
			return bgp_show_mpls_vpn(vty, afi, NULL,
						 bgp_show_type_normal, NULL, 0,
						 0);
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
		return bgp_show_mpls_vpn(vty, afi, &prd, bgp_show_type_normal,
					 NULL, 0, 0);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all,
       show_ip_bgp_vpn_all_cmd,
       "show [ip] bgp <vpnv4|vpnv6>",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR)
{
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi))
		return bgp_show_mpls_vpn(vty, afi, NULL, bgp_show_type_normal,
					 NULL, 0, 0);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all_tags,
       show_ip_bgp_vpn_all_tags_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all tags",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4/VPNV6 NLRIs\n"
       "Display BGP tags for prefixes\n")
{
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi))
		return bgp_show_mpls_vpn(vty, afi, NULL, bgp_show_type_normal,
					 NULL, 1, 0);
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_rd_tags,
       show_ip_bgp_vpn_rd_tags_cmd,
       "show [ip] bgp <vpnv4|vpnv6> rd <ASN:NN_OR_IP-ADDRESS:NN|all> tags",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "All VPN Route Distinguishers\n"
       "Display BGP tags for prefixes\n")
{
	int idx_ext_community = 5;
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (!strcmp(argv[idx_ext_community]->arg, "all"))
			return bgp_show_mpls_vpn(vty, afi, NULL,
						 bgp_show_type_normal, NULL, 1,
						 0);
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			vty_out(vty, "%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}
		return bgp_show_mpls_vpn(vty, afi, &prd, bgp_show_type_normal,
					 NULL, 1, 0);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all_neighbor_routes,
       show_ip_bgp_vpn_all_neighbor_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all neighbors A.B.C.D routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4/VPNv6 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n"
       JSON_STR)
{
	int idx_ipv4 = 6;
	union sockunion su;
	struct peer *peer;
	int ret;
	bool uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ipv4]->arg);
			return CMD_WARNING;
		}

		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}

		return bgp_show_mpls_vpn(vty, afi, NULL, bgp_show_type_neighbor,
					 &su, 0, uj);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_rd_neighbor_routes,
       show_ip_bgp_vpn_rd_neighbor_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> rd <ASN:NN_OR_IP-ADDRESS:NN|all> neighbors A.B.C.D routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "All VPN Route Distinguishers\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display routes learned from neighbor\n"
       JSON_STR)
{
	int idx_ext_community = 5;
	int idx_ipv4 = 7;
	int ret;
	union sockunion su;
	struct peer *peer;
	struct prefix_rd prd;
	bool prefix_rd_all = false;
	bool uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		if (!strcmp(argv[idx_ext_community]->arg, "all"))
			prefix_rd_all = true;
		else {
			ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
			if (!ret) {
				if (uj) {
					json_object *json_no = NULL;
					json_no = json_object_new_object();
					json_object_string_add(
						json_no, "warning",
						"Malformed Route Distinguisher");
					vty_out(vty, "%s\n",
						json_object_to_json_string(
							json_no));
					json_object_free(json_no);
				} else
					vty_out(vty,
						"%% Malformed Route Distinguisher\n");
				return CMD_WARNING;
			}
		}

		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ext_community]->arg);
			return CMD_WARNING;
		}

		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}

		if (prefix_rd_all)
			return bgp_show_mpls_vpn(vty, afi, NULL,
						 bgp_show_type_neighbor, &su, 0,
						 uj);
		else
			return bgp_show_mpls_vpn(vty, afi, &prd,
						 bgp_show_type_neighbor, &su, 0,
						 uj);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_all_neighbor_advertised_routes,
       show_ip_bgp_vpn_all_neighbor_advertised_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> all neighbors A.B.C.D advertised-routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information about all VPNv4/VPNv6 NLRIs\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n"
       JSON_STR)
{
	int idx_ipv4 = 6;
	int ret;
	struct peer *peer;
	union sockunion su;
	bool uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ipv4]->arg);
			return CMD_WARNING;
		}
		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}
		return show_adj_route_vpn(vty, peer, NULL, AFI_IP,
					  SAFI_MPLS_VPN, uj);
	}
	return CMD_SUCCESS;
}

DEFUN (show_ip_bgp_vpn_rd_neighbor_advertised_routes,
       show_ip_bgp_vpn_rd_neighbor_advertised_routes_cmd,
       "show [ip] bgp <vpnv4|vpnv6> rd <ASN:NN_OR_IP-ADDRESS:NN|all> neighbors A.B.C.D advertised-routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "All VPN Route Distinguishers\n"
       "Detailed information on TCP and BGP neighbor connections\n"
       "Neighbor to display information about\n"
       "Display the routes advertised to a BGP neighbor\n"
       JSON_STR)
{
	int idx_ext_community = 5;
	int idx_ipv4 = 7;
	int ret;
	struct peer *peer;
	struct prefix_rd prd;
	union sockunion su;
	bool uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
		ret = str2sockunion(argv[idx_ipv4]->arg, &su);
		if (ret < 0) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(json_no, "warning",
						       "Malformed address");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty, "Malformed address: %s\n",
					argv[idx_ext_community]->arg);
			return CMD_WARNING;
		}
		peer = peer_lookup(NULL, &su);
		if (!peer || !peer->afc[afi][SAFI_MPLS_VPN]) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"No such neighbor or address family");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% No such neighbor or address family\n");
			return CMD_WARNING;
		}

		if (!strcmp(argv[idx_ext_community]->arg, "all"))
			return show_adj_route_vpn(vty, peer, NULL, AFI_IP,
						  SAFI_MPLS_VPN, uj);
		ret = str2prefix_rd(argv[idx_ext_community]->arg, &prd);
		if (!ret) {
			if (uj) {
				json_object *json_no = NULL;
				json_no = json_object_new_object();
				json_object_string_add(
					json_no, "warning",
					"Malformed Route Distinguisher");
				vty_out(vty, "%s\n",
					json_object_to_json_string(json_no));
				json_object_free(json_no);
			} else
				vty_out(vty,
					"%% Malformed Route Distinguisher\n");
			return CMD_WARNING;
		}

		return show_adj_route_vpn(vty, peer, &prd, AFI_IP,
					  SAFI_MPLS_VPN, uj);
	}
	return CMD_SUCCESS;
}
#endif /* KEEP_OLD_VPN_COMMANDS */

void bgp_mplsvpn_init(void)
{
	install_element(BGP_VPNV4_NODE, &vpnv4_network_cmd);
	install_element(BGP_VPNV4_NODE, &vpnv4_network_route_map_cmd);
	install_element(BGP_VPNV4_NODE, &no_vpnv4_network_cmd);

	install_element(BGP_VPNV6_NODE, &vpnv6_network_cmd);
	install_element(BGP_VPNV6_NODE, &no_vpnv6_network_cmd);

	install_element(VIEW_NODE, &show_bgp_ip_vpn_all_rd_cmd);
	install_element(VIEW_NODE, &show_bgp_ip_vpn_rd_cmd);
#ifdef KEEP_OLD_VPN_COMMANDS
	install_element(VIEW_NODE, &show_ip_bgp_vpn_rd_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_tags_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_rd_tags_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_all_neighbor_routes_cmd);
	install_element(VIEW_NODE, &show_ip_bgp_vpn_rd_neighbor_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_vpn_all_neighbor_advertised_routes_cmd);
	install_element(VIEW_NODE,
			&show_ip_bgp_vpn_rd_neighbor_advertised_routes_cmd);
#endif /* KEEP_OLD_VPN_COMMANDS */
}

vrf_id_t get_first_vrf_for_redirect_with_rt(struct ecommunity *eckey)
{
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;
	afi_t afi = AFI_IP;

	if (eckey->unit_size == IPV6_ECOMMUNITY_SIZE)
		afi = AFI_IP6;

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		struct ecommunity *ec;

		if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		ec = bgp->vpn_policy[afi].import_redirect_rtlist;

		if (ec && eckey->unit_size != ec->unit_size)
			continue;

		if (ecommunity_include(ec, eckey))
			return bgp->vrf_id;
	}
	return VRF_UNKNOWN;
}

/*
 * The purpose of this function is to process leaks that were deferred
 * from earlier per-vrf configuration due to not-yet-existing default
 * vrf, in other words, configuration such as:
 *
 *     router bgp MMM vrf FOO
 *       address-family ipv4 unicast
 *         rd vpn export 1:1
 *       exit-address-family
 *
 *     router bgp NNN
 *       ...
 *
 * This function gets called when the default instance ("router bgp NNN")
 * is created.
 */
void vpn_leak_postchange_all(void)
{
	struct listnode *next;
	struct bgp *bgp;
	struct bgp *bgp_default = bgp_get_default();

	assert(bgp_default);

	/* First, do any exporting from VRFs to the single VPN RIB */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, bgp)) {

		if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		vpn_leak_postchange(
			BGP_VPN_POLICY_DIR_TOVPN,
			AFI_IP,
			bgp_default,
			bgp);

		vpn_leak_postchange(
			BGP_VPN_POLICY_DIR_TOVPN,
			AFI_IP6,
			bgp_default,
			bgp);
	}

	/* Now, do any importing to VRFs from the single VPN RIB */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, bgp)) {

		if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		if (CHECK_FLAG(bgp->vrf_flags, BGP_VRF_AUTO))
			continue;

		vpn_leak_postchange(
			BGP_VPN_POLICY_DIR_FROMVPN,
			AFI_IP,
			bgp_default,
			bgp);

		vpn_leak_postchange(
			BGP_VPN_POLICY_DIR_FROMVPN,
			AFI_IP6,
			bgp_default,
			bgp);
	}
}

/* When a bgp vrf instance is unconfigured, remove its routes
 * from the VPN table and this vrf could be importing routes from other
 * bgp vrf instnaces, unimport them.
 * VRF X and VRF Y are exporting routes to each other.
 * When VRF X is deleted, unimport its routes from all target vrfs,
 * also VRF Y should unimport its routes from VRF X table.
 * This will ensure VPN table is cleaned up appropriately.
 */
void bgp_vpn_leak_unimport(struct bgp *from_bgp)
{
	struct bgp *bgp_default = bgp_get_default();
	struct bgp *to_bgp;
	const char *tmp_name;
	char *vname;
	struct listnode *node, *next;
	safi_t safi = SAFI_UNICAST;
	afi_t afi;
	bool is_vrf_leak_bind;
	int debug;

	if (from_bgp->inst_type != BGP_INSTANCE_TYPE_VRF &&
	    from_bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)
		return;

	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		     BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	tmp_name = from_bgp->name ? from_bgp->name : VRF_DEFAULT_NAME;

	for (afi = 0; afi < AFI_MAX; ++afi) {
		/* vrf leak is for IPv4 and IPv6 Unicast only */
		if (afi != AFI_IP && afi != AFI_IP6)
			continue;

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, to_bgp)) {
			if (from_bgp == to_bgp)
				continue;

			/* Unimport and remove source vrf from the
			 * other vrfs import list.
			 */
			struct vpn_policy *to_vpolicy;

			is_vrf_leak_bind = false;
			to_vpolicy = &(to_bgp->vpn_policy[afi]);
			for (ALL_LIST_ELEMENTS_RO(to_vpolicy->import_vrf, node,
						  vname)) {
				if (strcmp(vname, tmp_name) == 0) {
					is_vrf_leak_bind = true;
					break;
				}
			}
			/* skip this bgp instance as there is no leak to this
			 * vrf instance.
			 */
			if (!is_vrf_leak_bind)
				continue;

			if (debug)
				zlog_debug("%s: unimport routes from %s to_bgp %s afi %s import vrfs count %u",
					   __func__, from_bgp->name_pretty,
					   to_bgp->name_pretty, afi2str(afi),
					   to_vpolicy->import_vrf->count);

			vrf_unimport_from_vrf(to_bgp, from_bgp, afi, safi);

			/* readd vrf name as unimport removes import vrf name
			 * from the destination vrf's import list where the
			 * `import vrf` configuration still exist.
			 */
			vname = XSTRDUP(MTYPE_TMP, tmp_name);
			listnode_add(to_bgp->vpn_policy[afi].import_vrf,
				     vname);
			SET_FLAG(to_bgp->af_flags[afi][safi],
				 BGP_CONFIG_VRF_TO_VRF_IMPORT);

			/* If to_bgp exports its routes to the bgp vrf
			 * which is being deleted, un-import the
			 * to_bgp routes from VPN.
			 */
			for (ALL_LIST_ELEMENTS_RO(to_bgp->vpn_policy[afi]
						  .export_vrf, node,
						  vname)) {
				if (strcmp(vname, tmp_name) == 0) {
					vrf_unimport_from_vrf(from_bgp, to_bgp,
						      afi, safi);
					break;
				}
			}
		}

		if (bgp_default &&
		    !CHECK_FLAG(bgp_default->af_flags[afi][SAFI_MPLS_VPN],
				BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL)) {
			/* 'from_bgp' instance will be deleted
			 * so force to unset importation to update VPN labels
			 */
			UNSET_FLAG(from_bgp->af_flags[afi][SAFI_UNICAST],
				   BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT);
			vpn_leak_no_retain(from_bgp, bgp_default, afi);
		}
	}
	return;
}

/* When a router bgp is configured, there could be a bgp vrf
 * instance importing routes from this newly configured
 * bgp vrf instance. Export routes from configured
 * bgp vrf to VPN.
 * VRF Y has import from bgp vrf x,
 * when a bgp vrf x instance is created, export its routes
 * to VRF Y instance.
 */
void bgp_vpn_leak_export(struct bgp *from_bgp)
{
	afi_t afi;
	const char *export_name;
	char *vname;
	struct listnode *node, *next;
	struct ecommunity *ecom;
	enum vpn_policy_direction idir, edir;
	safi_t safi = SAFI_UNICAST;
	struct bgp *to_bgp;
	int debug;

	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		     BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	idir = BGP_VPN_POLICY_DIR_FROMVPN;
	edir = BGP_VPN_POLICY_DIR_TOVPN;

	export_name = from_bgp->name ? from_bgp->name : VRF_DEFAULT_NAME;

	for (afi = 0; afi < AFI_MAX; ++afi) {
		/* vrf leak is for IPv4 and IPv6 Unicast only */
		if (afi != AFI_IP && afi != AFI_IP6)
			continue;

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, next, to_bgp)) {
			if (from_bgp == to_bgp)
				continue;

			/* bgp instance has import list, check to see if newly
			 * configured bgp instance is the list.
			 */
			struct vpn_policy *to_vpolicy;

			to_vpolicy = &(to_bgp->vpn_policy[afi]);
			for (ALL_LIST_ELEMENTS_RO(to_vpolicy->import_vrf,
						  node, vname)) {
				if (strcmp(vname, export_name) != 0)
					continue;

				if (debug)
					zlog_debug("%s: found from_bgp %s in to_bgp %s import list, import routes.",
					   __func__,
					   export_name, to_bgp->name_pretty);

				ecom = from_bgp->vpn_policy[afi].rtlist[edir];
				/* remove import rt, it will be readded
				 * as part of import from vrf.
				 */
				if (ecom)
					ecommunity_del_val(
						to_vpolicy->rtlist[idir],
						(struct ecommunity_val *)
							ecom->val);
				vrf_import_from_vrf(to_bgp, from_bgp,
						    afi, safi);
				break;

			}
		}
	}
}

/* The nexthops values are compared to
 * find in the tree the appropriate cache entry
 */
int bgp_mplsvpn_nh_label_bind_cmp(
	const struct bgp_mplsvpn_nh_label_bind_cache *a,
	const struct bgp_mplsvpn_nh_label_bind_cache *b)
{
	if (prefix_cmp(&a->nexthop, &b->nexthop))
		return 1;
	if (a->orig_label > b->orig_label)
		return 1;
	if (a->orig_label < b->orig_label)
		return -1;
	return 0;
}

static void bgp_mplsvpn_nh_label_bind_send_nexthop_label(
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc, int cmd)
{
	struct prefix pfx_nh, *p = NULL;
	uint8_t num_labels = 0, lsp_num_labels;
	mpls_label_t label[MPLS_MAX_LABELS];
	struct nexthop *nh;
	ifindex_t ifindex = IFINDEX_INTERNAL;
	vrf_id_t vrf_id = VRF_DEFAULT;
	uint32_t i;

	if (bmnc->nh == NULL)
		return;
	nh = bmnc->nh;
	switch (nh->type) {
	case NEXTHOP_TYPE_IFINDEX:
		p = &bmnc->nexthop;
		label[num_labels] = bmnc->orig_label;
		num_labels += 1;
		ifindex = nh->ifindex;
		vrf_id = nh->vrf_id;
		break;
	case NEXTHOP_TYPE_IPV4:
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
		if (nh->type == NEXTHOP_TYPE_IPV4 ||
		    nh->type == NEXTHOP_TYPE_IPV4_IFINDEX) {
			pfx_nh.family = AF_INET;
			pfx_nh.prefixlen = IPV4_MAX_BITLEN;
			IPV4_ADDR_COPY(&pfx_nh.u.prefix4, &nh->gate.ipv4);
		} else {
			pfx_nh.family = AF_INET6;
			pfx_nh.prefixlen = IPV6_MAX_BITLEN;
			IPV6_ADDR_COPY(&pfx_nh.u.prefix6, &nh->gate.ipv6);
		}
		p = &pfx_nh;
		if (nh->nh_label) {
			if (nh->nh_label->num_labels + 1 > MPLS_MAX_LABELS) {
				/* label stack overflow. no label switching will be performed
				 */
				flog_err(EC_BGP_LABEL,
					 "%s [Error] BGP label %u->%u to %pFX, forged label stack too big: %u. Abort LSP installation",
					 bmnc->bgp_vpn->name_pretty,
					 bmnc->new_label, bmnc->orig_label,
					 &bmnc->nexthop,
					 nh->nh_label->num_labels + 1);
				return;
			}
			lsp_num_labels = nh->nh_label->num_labels;
			for (i = 0; i < lsp_num_labels; i++)
				label[num_labels + i] = nh->nh_label->label[i];
			num_labels = lsp_num_labels;
		}
		label[num_labels] = bmnc->orig_label;
		num_labels += 1;
		if (nh->type == NEXTHOP_TYPE_IPV4_IFINDEX ||
		    nh->type == NEXTHOP_TYPE_IPV6_IFINDEX) {
			ifindex = nh->ifindex;
			vrf_id = nh->vrf_id;
		}
		break;
	case NEXTHOP_TYPE_BLACKHOLE:
		return;
	}
	bgp_zebra_send_nexthop_label(cmd, bmnc->new_label, ifindex, vrf_id,
				     ZEBRA_LSP_BGP, p, num_labels, &label[0]);
}

void bgp_mplsvpn_nh_label_bind_free(
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc)
{
	if (bmnc->allocation_in_progress) {
		bmnc->allocation_in_progress = false;
		bgp_mplsvpn_nh_label_bind_cache_del(
			&bmnc->bgp_vpn->mplsvpn_nh_label_bind, bmnc);
		return;
	}
	if (bmnc->new_label != MPLS_INVALID_LABEL) {
		bgp_mplsvpn_nh_label_bind_send_nexthop_label(
			bmnc, ZEBRA_MPLS_LABELS_DELETE);
		bgp_lp_release(LP_TYPE_BGP_L3VPN_BIND, bmnc, bmnc->new_label);
	}
	bgp_mplsvpn_nh_label_bind_cache_del(
		&bmnc->bgp_vpn->mplsvpn_nh_label_bind, bmnc);

	if (bmnc->nh)
		nexthop_free(bmnc->nh);

	XFREE(MTYPE_MPLSVPN_NH_LABEL_BIND_CACHE, bmnc);
}

struct bgp_mplsvpn_nh_label_bind_cache *
bgp_mplsvpn_nh_label_bind_new(struct bgp_mplsvpn_nh_label_bind_cache_head *tree,
			      struct prefix *p, mpls_label_t orig_label)
{
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc;

	bmnc = XCALLOC(MTYPE_MPLSVPN_NH_LABEL_BIND_CACHE,
		       sizeof(struct bgp_mplsvpn_nh_label_bind_cache));
	bmnc->new_label = MPLS_INVALID_LABEL;
	prefix_copy(&bmnc->nexthop, p);
	bmnc->orig_label = orig_label;

	LIST_INIT(&(bmnc->paths));
	bgp_mplsvpn_nh_label_bind_cache_add(tree, bmnc);

	return bmnc;
}

struct bgp_mplsvpn_nh_label_bind_cache *bgp_mplsvpn_nh_label_bind_find(
	struct bgp_mplsvpn_nh_label_bind_cache_head *tree, struct prefix *p,
	mpls_label_t orig_label)
{
	struct bgp_mplsvpn_nh_label_bind_cache bmnc = {0};

	if (!tree)
		return NULL;
	prefix_copy(&bmnc.nexthop, p);
	bmnc.orig_label = orig_label;

	return bgp_mplsvpn_nh_label_bind_cache_find(tree, &bmnc);
}

/* Called to check if the incoming l3vpn path entry
 * has mpls label information
 */
bool bgp_mplsvpn_path_uses_valid_mpls_label(struct bgp_path_info *pi)
{
	if (pi->attr && pi->attr->srv6_l3vpn)
		/* srv6 sid */
		return false;

	if (pi->attr &&
	    CHECK_FLAG(pi->attr->flag, ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID)) &&
	    pi->attr->label_index != BGP_INVALID_LABEL_INDEX)
		/* prefix_sid attribute */
		return false;

	if (!bgp_path_info_has_valid_label(pi))
		/* invalid MPLS label */
		return false;
	return true;
}

mpls_label_t bgp_mplsvpn_nh_label_bind_get_label(struct bgp_path_info *pi)
{
	mpls_label_t label;
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc;

	bmnc = pi->mplsvpn.bmnc.nh_label_bind_cache;
	if (!bmnc || bmnc->new_label == MPLS_INVALID_LABEL)
		/* allocation in progress
		 * or path not eligible for local label
		 */
		return MPLS_INVALID_LABEL;

	label = mpls_lse_encode(bmnc->new_label, 0, 0, 1);
	bgp_set_valid_label(&label);

	return label;
}

/* Called upon reception of a ZAPI Message from zebra, about
 * a new available label.
 */
static int bgp_mplsvpn_nh_label_bind_get_local_label_cb(mpls_label_t label,
							void *context,
							bool allocated)
{
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc = context;
	struct bgp_table *table;
	struct bgp_path_info *pi;

	if (BGP_DEBUG(labelpool, LABELPOOL))
		zlog_debug("%s: label=%u, allocated=%d, nexthop=%pFX, label %u",
			   __func__, label, allocated, &bmnc->nexthop,
			   bmnc->orig_label);
	if (allocated)
		/* update the entry with the new label */
		bmnc->new_label = label;
	else
		/*
		 * previously-allocated label is now invalid
		 * eg: zebra deallocated the labels and notifies it
		 */
		bmnc->new_label = MPLS_INVALID_LABEL;

	if (!bmnc->allocation_in_progress) {
		bgp_mplsvpn_nh_label_bind_free(bmnc);
		return 0;
	}
	bmnc->allocation_in_progress = false;

	if (bmnc->new_label != MPLS_INVALID_LABEL)
		/*
		 * Create the LSP : <local_label -> bmnc->orig_label,
		 * via bmnc->prefix, interface bnc->nexthop->ifindex
		 */
		bgp_mplsvpn_nh_label_bind_send_nexthop_label(
			bmnc, ZEBRA_MPLS_LABELS_ADD);

	LIST_FOREACH (pi, &(bmnc->paths), mplsvpn.bmnc.nh_label_bind_thread) {
		/* we can advertise it */
		if (!pi->net)
			continue;
		table = bgp_dest_table(pi->net);
		if (!table)
			continue;
		SET_FLAG(pi->net->flags, BGP_NODE_LABEL_CHANGED);
		bgp_process(table->bgp, pi->net, pi, table->afi, table->safi);
	}

	return 0;
}

void bgp_mplsvpn_path_nh_label_bind_unlink(struct bgp_path_info *pi)
{
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc;

	if (!pi)
		return;

	if (!CHECK_FLAG(pi->flags, BGP_PATH_MPLSVPN_NH_LABEL_BIND))
		return;

	bmnc = pi->mplsvpn.bmnc.nh_label_bind_cache;

	if (!bmnc)
		return;

	LIST_REMOVE(pi, mplsvpn.bmnc.nh_label_bind_thread);
	pi->mplsvpn.bmnc.nh_label_bind_cache->path_count--;
	pi->mplsvpn.bmnc.nh_label_bind_cache = NULL;
	SET_FLAG(pi->flags, BGP_PATH_MPLSVPN_NH_LABEL_BIND);

	if (LIST_EMPTY(&(bmnc->paths)))
		bgp_mplsvpn_nh_label_bind_free(bmnc);
}

void bgp_mplsvpn_nh_label_bind_register_local_label(struct bgp *bgp,
						    struct bgp_dest *dest,
						    struct bgp_path_info *pi)
{
	struct bgp_mplsvpn_nh_label_bind_cache *bmnc;
	struct bgp_mplsvpn_nh_label_bind_cache_head *tree;
	mpls_label_t label;

	label = BGP_PATH_INFO_NUM_LABELS(pi)
			? decode_label(&pi->extra->labels->label[0])
			: MPLS_INVALID_LABEL;

	tree = &bgp->mplsvpn_nh_label_bind;
	bmnc = bgp_mplsvpn_nh_label_bind_find(tree, &pi->nexthop->prefix, label);
	if (!bmnc) {
		bmnc = bgp_mplsvpn_nh_label_bind_new(tree, &pi->nexthop->prefix,
						     label);
		bmnc->bgp_vpn = bgp;
		bmnc->allocation_in_progress = true;
		bgp_lp_get(LP_TYPE_BGP_L3VPN_BIND, bmnc,
			   bgp_mplsvpn_nh_label_bind_get_local_label_cb);
	}

	if (pi->mplsvpn.bmnc.nh_label_bind_cache == bmnc)
		/* no change */
		return;

	bgp_mplsvpn_path_nh_label_bind_unlink(pi);

	/* updates NHT pi list reference */
	LIST_INSERT_HEAD(&(bmnc->paths), pi, mplsvpn.bmnc.nh_label_bind_thread);
	pi->mplsvpn.bmnc.nh_label_bind_cache = bmnc;
	pi->mplsvpn.bmnc.nh_label_bind_cache->path_count++;
	SET_FLAG(pi->flags, BGP_PATH_MPLSVPN_NH_LABEL_BIND);
	bmnc->last_update = monotime(NULL);

	/* Add or update the selected nexthop */
	if (!bmnc->nh)
		bmnc->nh = nexthop_dup(pi->nexthop->nexthop, NULL);
	else if (!nexthop_same(pi->nexthop->nexthop, bmnc->nh)) {
		nexthop_free(bmnc->nh);
		bmnc->nh = nexthop_dup(pi->nexthop->nexthop, NULL);
		if (bmnc->new_label != MPLS_INVALID_LABEL)
			bgp_mplsvpn_nh_label_bind_send_nexthop_label(
				bmnc, ZEBRA_MPLS_LABELS_REPLACE);
	}
}

static void show_bgp_mplsvpn_nh_label_bind_internal(struct vty *vty,
						    struct bgp *bgp,
						    bool detail)
{
	struct bgp_mplsvpn_nh_label_bind_cache_head *tree;
	struct bgp_mplsvpn_nh_label_bind_cache *iter;
	afi_t afi;
	safi_t safi;
	struct bgp_dest *dest;
	struct bgp_path_info *path;
	struct bgp *bgp_path;
	struct bgp_table *table;
	time_t tbuf;
	char buf[32];

	vty_out(vty, "Current BGP mpls-vpn nexthop label bind cache, %s\n",
		bgp->name_pretty);

	tree = &bgp->mplsvpn_nh_label_bind;
	frr_each (bgp_mplsvpn_nh_label_bind_cache, tree, iter) {
		if (iter->nexthop.family == AF_INET)
			vty_out(vty, " %pI4", &iter->nexthop.u.prefix4);
		else
			vty_out(vty, " %pI6", &iter->nexthop.u.prefix6);
		vty_out(vty, ", label %u, local label %u #paths %u\n",
			iter->orig_label, iter->new_label, iter->path_count);
		if (iter->nh)
			vty_out(vty, "  interface %s\n",
				ifindex2ifname(iter->nh->ifindex,
					       iter->nh->vrf_id));
		tbuf = time(NULL) - (monotime(NULL) - iter->last_update);
		vty_out(vty, "  Last update: %s", ctime_r(&tbuf, buf));
		if (!detail)
			continue;
		vty_out(vty, "  Paths:\n");
		LIST_FOREACH (path, &(iter->paths),
			      mplsvpn.bmnc.nh_label_bind_thread) {
			dest = path->net;
			table = bgp_dest_table(dest);
			assert(dest && table);
			afi = family2afi(bgp_dest_get_prefix(dest)->family);
			safi = table->safi;
			bgp_path = table->bgp;

			vty_out(vty, "    %d/%d %pBD %s flags 0x%x\n", afi,
				safi, dest, bgp_path->name_pretty, path->flags);
		}
	}
}


DEFUN(show_bgp_mplsvpn_nh_label_bind, show_bgp_mplsvpn_nh_label_bind_cmd,
      "show bgp [<view|vrf> VIEWVRFNAME] mplsvpn-nh-label-bind [detail]",
      SHOW_STR BGP_STR BGP_INSTANCE_HELP_STR
      "BGP mplsvpn nexthop label binding entries\n"
      "Show detailed information\n")
{
	int idx = 0;
	char *vrf = NULL;
	struct bgp *bgp;
	bool detail = false;

	if (argv_find(argv, argc, "vrf", &idx)) {
		vrf = argv[++idx]->arg;
		bgp = bgp_lookup_by_name(vrf);
	} else
		bgp = bgp_get_default();

	if (!bgp)
		return CMD_SUCCESS;

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	show_bgp_mplsvpn_nh_label_bind_internal(vty, bgp, detail);
	return CMD_SUCCESS;
}

void bgp_mplsvpn_nexthop_init(void)
{
	install_element(VIEW_NODE, &show_bgp_mplsvpn_nh_label_bind_cmd);
}
