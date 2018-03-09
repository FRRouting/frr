/* MPLS-VPN
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of GNU Zebra.
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

#include <zebra.h>

#include "command.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "queue.h"
#include "filter.h"
#include "mpls.h"
#include "lib/json.h"
#include "lib/zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_vpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"

#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

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

u_int32_t decode_label(mpls_label_t *label_pnt)
{
	u_int32_t l;
	u_char *pnt = (u_char *)label_pnt;

	l = ((u_int32_t)*pnt++ << 12);
	l |= (u_int32_t)*pnt++ << 4;
	l |= (u_int32_t)((*pnt & 0xf0) >> 4);
	return l;
}

void encode_label(mpls_label_t label, mpls_label_t *label_pnt)
{
	u_char *pnt = (u_char *)label_pnt;
	if (pnt == NULL)
		return;
	*pnt++ = (label >> 12) & 0xff;
	*pnt++ = (label >> 4) & 0xff;
	*pnt++ = ((label << 4) + 1) & 0xff; /* S=1 */
}

int bgp_nlri_parse_vpn(struct peer *peer, struct attr *attr,
		       struct bgp_nlri *packet)
{
	u_char *pnt;
	u_char *lim;
	struct prefix p;
	int psize = 0;
	int prefixlen;
	u_int16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	struct prefix_rd prd;
	mpls_label_t label = {0};
	afi_t afi;
	safi_t safi;
	int addpath_encoded;
	u_int32_t addpath_id;

	/* Check peer status. */
	if (peer->status != Established)
		return 0;

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_encoded =
		(CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV)
		 && CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ADDPATH_AF_TX_RCV));

#define VPN_PREFIXLEN_MIN_BYTES (3 + 8) /* label + RD */
	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));

		if (addpath_encoded) {

			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return -1;

			addpath_id = ntohl(*((uint32_t *)pnt));
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length. */
		prefixlen = *pnt++;
		p.family = afi2family(packet->afi);
		psize = PSIZE(prefixlen);

		if (prefixlen < VPN_PREFIXLEN_MIN_BYTES * 8) {
			zlog_err(
				"%s [Error] Update packet error / VPN (prefix length %d less than VPN min length)",
				peer->host, prefixlen);
			return -1;
		}

		/* sanity check against packet data */
		if ((pnt + psize) > lim) {
			zlog_err(
				"%s [Error] Update packet error / VPN (prefix length %d exceeds packet size %u)",
				peer->host, prefixlen, (uint)(lim - pnt));
			return -1;
		}

		/* sanity check against storage for the IP address portion */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > (ssize_t)sizeof(p.u)) {
			zlog_err(
				"%s [Error] Update packet error / VPN (psize %d exceeds storage size %zu)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				sizeof(p.u));
			return -1;
		}

		/* Sanity check against max bitlen of the address family */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > prefix_blen(&p)) {
			zlog_err(
				"%s [Error] Update packet error / VPN (psize %d exceeds family (%u) max byte len %u)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				p.family, prefix_blen(&p));
			return -1;
		}

		/* Copy label to prefix. */
		memcpy(&label, pnt, BGP_LABEL_BYTES);
		bgp_set_valid_label(&label);

		/* Copy routing distinguisher to rd. */
		memcpy(&prd.val, pnt + BGP_LABEL_BYTES, 8);

		/* Decode RD type. */
		type = decode_rd_type(pnt + BGP_LABEL_BYTES);

		switch (type) {
		case RD_TYPE_AS:
			decode_rd_as(pnt + 5, &rd_as);
			break;

		case RD_TYPE_AS4:
			decode_rd_as4(pnt + 5, &rd_as);
			break;

		case RD_TYPE_IP:
			decode_rd_ip(pnt + 5, &rd_ip);
			break;

#if ENABLE_BGP_VNC
		case RD_TYPE_VNC_ETH:
			break;
#endif

		default:
			zlog_err("Unknown RD type %d", type);
			break; /* just report */
		}

		p.prefixlen =
			prefixlen
			- VPN_PREFIXLEN_MIN_BYTES * 8; /* exclude label & RD */
		memcpy(&p.u.prefix, pnt + VPN_PREFIXLEN_MIN_BYTES,
		       psize - VPN_PREFIXLEN_MIN_BYTES);

		if (attr) {
			bgp_update(peer, &p, addpath_id, attr, packet->afi,
				   SAFI_MPLS_VPN, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, &prd, &label, 1, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, addpath_id, attr, packet->afi,
				     SAFI_MPLS_VPN, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, &prd, &label, 1, NULL);
		}
	}
	/* Packet length consistency check. */
	if (pnt != lim) {
		zlog_err(
			"%s [Error] Update packet error / VPN (%zu data remaining after parsing)",
			peer->host, lim - pnt);
		return -1;
	}

	return 0;
#undef VPN_PREFIXLEN_MIN_BYTES
}

/*
 * This function informs zebra of the label this vrf sets on routes
 * leaked to VPN. Zebra should install this label in the kernel with
 * an action of "pop label and then use this vrf's IP FIB to route the PDU."
 *
 * Sending this vrf-label association is qualified by a) whether vrf->vpn
 * exporting is active ("export vpn" is enabled, vpn-policy RD and RT list
 * are set) and b) whether vpn-policy label is set.
 *
 * If any of these conditions do not hold, then we send MPLS_LABEL_NONE
 * for this vrf, which zebra interprets to mean "delete this vrf-label
 * association."
 */
void vpn_leak_zebra_vrf_label_update(struct bgp *bgp, afi_t afi)
{
	mpls_label_t label = MPLS_LABEL_NONE;
	const char *name = "default";
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (debug && (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT)) {
		name = bgp->name;
	}

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug) {
			zlog_debug(
				"%s: vrf %s: afi %s: vrf_id not set, "
				"can't set zebra vrf label",
				__func__, name, afi2str(afi));
		}
		return;
	}

	if (vpn_leak_to_vpn_active(bgp, afi, NULL)) {
		label = bgp->vpn_policy[afi].tovpn_label;
	}

	if (debug) {
		zlog_debug("%s: vrf %s: afi %s: setting label %d for vrf id %d",
			   __func__, name, afi2str(afi), label, bgp->vrf_id);
	}

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
			   (bgp->name ? bgp->name : "default"), bgp->vrf_id);
	}

	zclient_send_vrf_label(zclient, bgp->vrf_id, afi, label, ZEBRA_LSP_BGP);
	bgp->vpn_policy[afi].tovpn_zebra_vrf_label_last_sent = label;
}

static int ecom_intersect(struct ecommunity *e1, struct ecommunity *e2)
{
	int i;
	int j;

	if (!e1 || !e2)
		return 0;

	for (i = 0; i < e1->size; ++i) {
		for (j = 0; j < e2->size; ++j) {
			if (!memcmp(e1->val + (i * ECOMMUNITY_SIZE),
				    e2->val + (j * ECOMMUNITY_SIZE),
				    ECOMMUNITY_SIZE)) {

				return 1;
			}
		}
	}
	return 0;
}

/*
 * returns pointer to new bgp_info upon success
 */
static struct bgp_info *
leak_update(struct bgp *bgp, /* destination bgp instance */
	    struct bgp_node *bn, struct attr *new_attr, /* already interned */
	    afi_t afi, safi_t safi, struct bgp_info *source_bi, u_char type,
	    u_char sub_type, mpls_label_t *label, int num_labels, void *parent,
	    struct bgp *bgp_orig, struct prefix *nexthop_orig, int debug)
{
	struct prefix *p = &bn->p;
	struct bgp_info *bi;
	struct bgp_info *new;
	char buf_prefix[PREFIX_STRLEN];
	const char *pDestInstanceName = "default";

	if (debug) {
		prefix2str(&bn->p, buf_prefix, sizeof(buf_prefix));
		if (bgp->name)
			pDestInstanceName = bgp->name;
	}

	/*
	 * match parent
	 */
	for (bi = bn->info; bi; bi = bi->next) {
		if (bi->extra && bi->extra->parent == parent)
			break;
	}

	if (bi) {
		if (attrhash_cmp(bi->attr, new_attr)
		    && !CHECK_FLAG(bi->flags, BGP_INFO_REMOVED)) {

			bgp_attr_unintern(&new_attr);
			if (debug)
				zlog_debug(
					"%s: ->%s: %s: Found route, no change",
					__func__, pDestInstanceName,
					buf_prefix);
			return NULL;
		}

		/* attr is changed */
		bgp_info_set_flag(bn, bi, BGP_INFO_ATTR_CHANGED);

		/* Rewrite BGP route information. */
		if (CHECK_FLAG(bi->flags, BGP_INFO_REMOVED))
			bgp_info_restore(bn, bi);
		else
			bgp_aggregate_decrement(bgp, p, bi, afi, safi);
		bgp_attr_unintern(&bi->attr);
		bi->attr = new_attr;
		bi->uptime = bgp_clock();

		/* Process change. */
		bgp_aggregate_increment(bgp, p, bi, afi, safi);
		bgp_process(bgp, bn, afi, safi);
		bgp_unlock_node(bn);

		if (debug)
			zlog_debug("%s: ->%s: %s Found route, changed attr",
				   __func__, pDestInstanceName, buf_prefix);

		return NULL;
	}

	new = info_make(type, sub_type, 0, bgp->peer_self, new_attr, bn);
	SET_FLAG(new->flags, BGP_INFO_VALID);

	bgp_info_extra_get(new);
	if (label) {
		int i;

		for (i = 0; i < num_labels; ++i) {
			new->extra->label[i] = label[i];
			if (!bgp_is_valid_label(&label[i])) {
				if (debug) {
					zlog_debug(
						"%s: %s: marking label %d valid",
						__func__, buf_prefix, i);
				}
				bgp_set_valid_label(&new->extra->label[i]);
			}
		}
		new->extra->num_labels = num_labels;
	}
	new->extra->parent = parent;

	if (bgp_orig)
		new->extra->bgp_orig = bgp_orig;
	if (nexthop_orig)
		new->extra->nexthop_orig = *nexthop_orig;

	bgp_aggregate_increment(bgp, p, new, afi, safi);
	bgp_info_add(bn, new);

	bgp_unlock_node(bn);
	bgp_process(bgp, bn, afi, safi);

	if (debug)
		zlog_debug("%s: ->%s: %s: Added new route", __func__,
			   pDestInstanceName, buf_prefix);

	return new;
}

/* cf vnc_import_bgp_add_route_mode_nvegroup() and add_vnc_route() */
void vpn_leak_from_vrf_update(struct bgp *bgp_vpn,       /* to */
			      struct bgp *bgp_vrf,       /* from */
			      struct bgp_info *info_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct prefix *p = &info_vrf->net->p;
	afi_t afi = family2afi(p->family);
	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	safi_t safi = SAFI_MPLS_VPN;
	mpls_label_t label_val;
	mpls_label_t label;
	struct bgp_node *bn;
	const char *debugmsg;

	if (debug) {
		const char *s = "";

		if (info_vrf->attr && info_vrf->attr->ecommunity) {
			s = ecommunity_ecom2str(info_vrf->attr->ecommunity,
						ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		}

		zlog_debug("%s: info_vrf->type=%d, EC{%s}", __func__,
			   info_vrf->type, s);
	}

	if (!bgp_vpn)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* loop check */
	if (info_vrf->extra && info_vrf->extra->bgp_orig == bgp_vpn)
		return;


	if (!vpn_leak_to_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	bgp_attr_dup(&static_attr, info_vrf->attr); /* shallow copy */

	/*
	 * route map handling
	 */
	if (bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_TOVPN]) {
		struct bgp_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = bgp_vpn->peer_self;
		info.attr = &static_attr;
		ret = route_map_apply(
			bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_TOVPN],
			p, RMAP_BGP, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s route map \"%s\" says DENY, returning",
					__func__, bgp_vrf->name,
					bgp_vrf->vpn_policy[afi]
						.rmap[BGP_VPN_POLICY_DIR_TOVPN]
						->name);
			return;
		}
	}

	if (debug) {
		const char *s = "";

		if (static_attr.ecommunity) {
			s = ecommunity_ecom2str(static_attr.ecommunity,
						ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		}
		zlog_debug("%s: post route map static_attr.ecommunity{%s}",
			   __func__, s);
	}

	/*
	 * Add the vpn-policy rt-list
	 */
	struct ecommunity *old_ecom;
	struct ecommunity *new_ecom;

	old_ecom = static_attr.ecommunity;
	if (old_ecom) {
		new_ecom = ecommunity_merge(
			ecommunity_dup(old_ecom),
			bgp_vrf->vpn_policy[afi]
				.rtlist[BGP_VPN_POLICY_DIR_TOVPN]);
		if (!old_ecom->refcnt)
			ecommunity_free(&old_ecom);
	} else {
		new_ecom = ecommunity_dup(
			bgp_vrf->vpn_policy[afi]
				.rtlist[BGP_VPN_POLICY_DIR_TOVPN]);
	}
	static_attr.ecommunity = new_ecom;
	SET_FLAG(static_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_EXT_COMMUNITIES));

	if (debug) {
		const char *s = "";

		if (static_attr.ecommunity) {
			s = ecommunity_ecom2str(static_attr.ecommunity,
						ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		}
		zlog_debug("%s: post merge static_attr.ecommunity{%s}",
			   __func__, s);
	}

	/* Nexthop */
	/* if policy nexthop not set, use 0 */
	if (CHECK_FLAG(bgp_vrf->vpn_policy[afi].flags,
		       BGP_VPN_POLICY_TOVPN_NEXTHOP_SET)) {

		struct prefix *nexthop =
			&bgp_vrf->vpn_policy[afi].tovpn_nexthop;
		switch (nexthop->family) {
		case AF_INET:
			/* prevent mp_nexthop_global_in <- self in bgp_route.c
			 */
			static_attr.nexthop.s_addr = nexthop->u.prefix4.s_addr;

			static_attr.mp_nexthop_global_in = nexthop->u.prefix4;
			static_attr.mp_nexthop_len = 4;
			break;

		case AF_INET6:
			static_attr.mp_nexthop_global = nexthop->u.prefix6;
			static_attr.mp_nexthop_len = 16;
			break;

		default:
			assert(0);
		}
	} else {
		switch (afi) {
		case AFI_IP:
		default:
			/* Clear ipv4 */
			static_attr.mp_nexthop_global_in.s_addr = 0;
			static_attr.mp_nexthop_len = 4;
			static_attr.nexthop.s_addr = 0; /* self */
			static_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);
			break;

		case AFI_IP6:
			/* Clear ipv6 */
			memset(&static_attr.mp_nexthop_global, 0,
			       sizeof(static_attr.mp_nexthop_global));
			static_attr.mp_nexthop_len = 16; /* bytes */
			break;
		}
	}

	label_val = bgp_vrf->vpn_policy[afi].tovpn_label;
	if (label_val == MPLS_LABEL_NONE) {
		/* TBD get from label manager */
		label = MPLS_LABEL_IMPLICIT_NULL;
	} else {
		encode_label(label_val, &label);
	}

	/* Set originator ID to "me" */
	SET_FLAG(static_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));
	static_attr.originator_id = bgp_vpn->router_id;


	new_attr = bgp_attr_intern(
		&static_attr);	/* hashed refcounted everything */
	bgp_attr_flush(&static_attr); /* free locally-allocated parts */

	if (debug) {
		const char *s = "";

		if (new_attr->ecommunity) {
			s = ecommunity_ecom2str(new_attr->ecommunity,
						ECOMMUNITY_FORMAT_ROUTE_MAP, 0);
		}
		zlog_debug("%s: new_attr->ecommunity{%s}", __func__, s);
	}

	/* Now new_attr is an allocated interned attr */

	bn = bgp_afi_node_get(bgp_vpn->rib[afi][safi], afi, safi, p,
			      &(bgp_vrf->vpn_policy[afi].tovpn_rd));

	struct bgp_info *new_info;

	new_info = leak_update(bgp_vpn, bn, new_attr, afi, safi, info_vrf,
			       ZEBRA_ROUTE_BGP, BGP_ROUTE_IMPORTED, &label, 1,
			       info_vrf, bgp_vrf, NULL, debug);

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
		vpn_leak_to_vrf_update(bgp_vrf, new_info);
}

void vpn_leak_from_vrf_withdraw(struct bgp *bgp_vpn,       /* to */
				struct bgp *bgp_vrf,       /* from */
				struct bgp_info *info_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct prefix *p = &info_vrf->net->p;
	afi_t afi = family2afi(p->family);
	safi_t safi = SAFI_MPLS_VPN;
	struct bgp_info *bi;
	struct bgp_node *bn;
	const char *debugmsg;

	if (info_vrf->type != ZEBRA_ROUTE_BGP) {
		if (debug)
			zlog_debug("%s: wrong type %d", __func__,
				   info_vrf->type);
		return;
	}
	if (info_vrf->sub_type != BGP_ROUTE_NORMAL
	    && info_vrf->sub_type != BGP_ROUTE_STATIC) {

		if (debug)
			zlog_debug("%s: wrong sub_type %d", __func__,
				   info_vrf->sub_type);
		return;
	}
	if (!bgp_vpn)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	if (!vpn_leak_to_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	if (debug)
		zlog_debug("%s: withdrawing (info_vrf=%p)", __func__, info_vrf);

	bn = bgp_afi_node_get(bgp_vpn->rib[afi][safi], afi, safi, p,
			      &(bgp_vrf->vpn_policy[afi].tovpn_rd));

	/*
	 * vrf -> vpn
	 * match original bi imported from
	 */
	for (bi = (bn ? bn->info : NULL); bi; bi = bi->next) {
		if (bi->extra && bi->extra->parent == info_vrf) {
			break;
		}
	}

	if (bi) {
		/* withdraw from looped vrfs as well */
		vpn_leak_to_vrf_withdraw(bgp_vpn, bi);

		bgp_aggregate_decrement(bgp_vpn, p, bi, afi, safi);
		bgp_info_delete(bn, bi);
		bgp_process(bgp_vpn, bn, afi, safi);
	}
	bgp_unlock_node(bn);
}

void vpn_leak_from_vrf_withdraw_all(struct bgp *bgp_vpn, /* to */
				    struct bgp *bgp_vrf, /* from */
				    afi_t afi)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct bgp_node *prn;
	safi_t safi = SAFI_MPLS_VPN;

	/*
	 * Walk vpn table, delete bi with parent == bgp_vrf
	 * Walk vpn table, delete bi with bgp_orig == bgp_vrf
	 */
	for (prn = bgp_table_top(bgp_vpn->rib[afi][safi]); prn;
	     prn = bgp_route_next(prn)) {

		struct bgp_table *table;
		struct bgp_node *bn;
		struct bgp_info *bi;

		/* This is the per-RD table of prefixes */
		table = prn->info;

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {

			char buf[PREFIX2STR_BUFFER];

			if (debug && bn->info) {
				zlog_debug(
					"%s: looking at prefix %s", __func__,
					prefix2str(&bn->p, buf, sizeof(buf)));
			}

			for (bi = bn->info; bi; bi = bi->next) {
				if (debug)
					zlog_debug("%s: type %d, sub_type %d",
						   __func__, bi->type,
						   bi->sub_type);
				if (bi->sub_type != BGP_ROUTE_IMPORTED)
					continue;
				if (!bi->extra)
					continue;
				if ((struct bgp *)bi->extra->bgp_orig
				    == bgp_vrf) {
					/* delete route */
					if (debug)
						zlog_debug("%s: deleting it\n",
							   __func__);
					bgp_aggregate_decrement(bgp_vpn, &bn->p,
								bi, afi, safi);
					bgp_info_delete(bn, bi);
					bgp_process(bgp_vpn, bn, afi, safi);
				}
			}
		}
	}
}

void vpn_leak_from_vrf_update_all(struct bgp *bgp_vpn, /* to */
				  struct bgp *bgp_vrf, /* from */
				  afi_t afi)
{
	struct bgp_node *bn;
	struct bgp_info *bi;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);

	if (debug)
		zlog_debug("%s: entry, afi=%d, vrf=%s", __func__, afi,
			   bgp_vrf->name);

	for (bn = bgp_table_top(bgp_vrf->rib[afi][SAFI_UNICAST]); bn;
	     bn = bgp_route_next(bn)) {

		if (debug)
			zlog_debug("%s: node=%p", __func__, bn);

		for (bi = bn->info; bi; bi = bi->next) {
			if (debug)
				zlog_debug(
					"%s: calling vpn_leak_from_vrf_update",
					__func__);
			vpn_leak_from_vrf_update(bgp_vpn, bgp_vrf, bi);
		}
	}
}

static void vpn_leak_to_vrf_update_onevrf(struct bgp *bgp_vrf,       /* to */
					  struct bgp *bgp_vpn,       /* from */
					  struct bgp_info *info_vpn) /* route */
{
	struct prefix *p = &info_vpn->net->p;
	afi_t afi = family2afi(p->family);

	struct bgp_redist *red;
	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	struct bgp_node *bn;
	safi_t safi = SAFI_UNICAST;
	const char *debugmsg;
	struct prefix nexthop_orig;
	mpls_label_t *pLabels = NULL;
	int num_labels = 0;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (!vpn_leak_from_vpn_active(bgp_vrf, afi, &debugmsg, &red)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	/* Check for intersection of route targets */
	if (!ecom_intersect(
		    bgp_vrf->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
		    info_vpn->attr->ecommunity)) {

		return;
	}

	if (debug)
		zlog_debug("%s: updating to vrf %s", __func__, bgp_vrf->name);

	bgp_attr_dup(&static_attr, info_vpn->attr); /* shallow copy */

	/*
	 * Nexthop: stash and clear
	 *
	 * Nexthop is valid in context of VPN core, but not in destination vrf.
	 * Stash it for later label resolution by vrf ingress path and then
	 * overwrite with 0, i.e., "me", for the sake of vrf advertisement.
	 */
	uint8_t nhfamily = NEXTHOP_FAMILY(info_vpn->attr->mp_nexthop_len);

	memset(&nexthop_orig, 0, sizeof(nexthop_orig));
	nexthop_orig.family = nhfamily;

	switch (nhfamily) {

	case AF_INET:
		/* save */
		nexthop_orig.u.prefix4 = info_vpn->attr->mp_nexthop_global_in;
		nexthop_orig.prefixlen = 32;

		static_attr.nexthop.s_addr = 0; /* self */
		static_attr.flag |= ATTR_FLAG_BIT(BGP_ATTR_NEXT_HOP);

		break;

	case AF_INET6:
		/* save */
		nexthop_orig.u.prefix6 = info_vpn->attr->mp_nexthop_global;
		nexthop_orig.prefixlen = 128;

		memset(&static_attr.mp_nexthop_global, 0,
		       sizeof(static_attr.mp_nexthop_global)); /* clear */
		static_attr.mp_nexthop_len = 16;	       /* bytes */
		break;
	}


	/*
	 * route map handling
	 * For now, we apply two route maps: the "redist" route map and the
	 * vpn-policy route map. Once we finalize CLI syntax, one of these
	 * route maps will probably go away.
	 */
	if (red->rmap.map) {
		struct bgp_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = bgp_vrf->peer_self;
		info.attr = &static_attr;
		ret = route_map_apply(red->rmap.map, p, RMAP_BGP, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s redist route map \"%s\" says DENY, skipping",
					__func__, bgp_vrf->name,
					red->rmap.name);
			return;
		}
	}
	if (bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN]) {
		struct bgp_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = bgp_vrf->peer_self;
		info.attr = &static_attr;
		ret = route_map_apply(bgp_vrf->vpn_policy[afi]
					      .rmap[BGP_VPN_POLICY_DIR_FROMVPN],
				      p, RMAP_BGP, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s vpn-policy route map \"%s\" says DENY, returning",
					__func__, bgp_vrf->name,
					bgp_vrf->vpn_policy[afi]
						.rmap[BGP_VPN_POLICY_DIR_FROMVPN]
						->name);
			return;
		}
	}

	new_attr = bgp_attr_intern(&static_attr);
	bgp_attr_flush(&static_attr);

	bn = bgp_afi_node_get(bgp_vrf->rib[afi][safi], afi, safi, p, NULL);

	/*
	 * ensure labels are copied
	 */
	if (info_vpn->extra && info_vpn->extra->num_labels) {
		num_labels = info_vpn->extra->num_labels;
		if (num_labels > BGP_MAX_LABELS)
			num_labels = BGP_MAX_LABELS;
		pLabels = info_vpn->extra->label;
	}
	if (debug) {
		char buf_prefix[PREFIX_STRLEN];
		prefix2str(p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: pfx %s: num_labels %d", __func__, buf_prefix,
			   num_labels);
	}

	leak_update(bgp_vrf, bn, new_attr, afi, safi, info_vpn, ZEBRA_ROUTE_BGP,
		    BGP_ROUTE_IMPORTED, pLabels, num_labels,
		    info_vpn, /* parent */
		    bgp_vpn, &nexthop_orig, debug);
}

void vpn_leak_to_vrf_update(struct bgp *bgp_vpn,       /* from */
			    struct bgp_info *info_vpn) /* route */
{
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: start (info_vpn=%p)", __func__, info_vpn);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {

		if (!info_vpn->extra
		    || info_vpn->extra->bgp_orig != bgp) { /* no loop */
			vpn_leak_to_vrf_update_onevrf(bgp, bgp_vpn, info_vpn);
		}
	}
}

void vpn_leak_to_vrf_withdraw(struct bgp *bgp_vpn,       /* from */
			      struct bgp_info *info_vpn) /* route */
{
	struct prefix *p = &info_vpn->net->p;
	afi_t afi = family2afi(p->family);
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp;
	struct listnode *mnode, *mnnode;
	struct bgp_redist *red;
	struct bgp_node *bn;
	struct bgp_info *bi;
	const char *debugmsg;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: start (info_vpn=%p)", __func__, info_vpn);


	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		if (!vpn_leak_from_vpn_active(bgp, afi, &debugmsg, &red)) {
			if (debug)
				zlog_debug("%s: skipping: %s", __func__,
					   debugmsg);
			continue;
		}

		/* Check for intersection of route targets */
		if (!ecom_intersect(bgp->vpn_policy[afi]
					    .rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
				    info_vpn->attr->ecommunity)) {

			continue;
		}

		if (debug)
			zlog_debug("%s: withdrawing from vrf %s", __func__,
				   bgp->name);

		bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, NULL);
		for (bi = (bn ? bn->info : NULL); bi; bi = bi->next) {
			if (bi->extra
			    && (struct bgp_info *)bi->extra->parent
				       == info_vpn) {
				break;
			}
		}

		if (bi) {
			if (debug)
				zlog_debug("%s: deleting bi %p", __func__, bi);
			bgp_aggregate_decrement(bgp, p, bi, afi, safi);
			bgp_info_delete(bn, bi);
			bgp_process(bgp, bn, afi, safi);
		}
		bgp_unlock_node(bn);
	}
}

void vpn_leak_to_vrf_withdraw_all(struct bgp *bgp_vrf, /* to */
				  afi_t afi)
{
	struct bgp_node *bn;
	struct bgp_info *bi;
	safi_t safi = SAFI_UNICAST;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);
	struct bgp *bgp_vpn = bgp_get_default();

	if (debug)
		zlog_debug("%s: entry", __func__);
	/*
	 * Walk vrf table, delete bi with bgp_orig == bgp_vpn
	 */
	for (bn = bgp_table_top(bgp_vrf->rib[afi][safi]); bn;
	     bn = bgp_route_next(bn)) {

		for (bi = bn->info; bi; bi = bi->next) {
			if (bi->extra && bi->extra->bgp_orig == bgp_vpn) {

				/* delete route */
				bgp_aggregate_decrement(bgp_vrf, &bn->p, bi,
							afi, safi);
				bgp_info_delete(bn, bi);
				bgp_process(bgp_vrf, bn, afi, safi);
			}
		}
	}
}

void vpn_leak_to_vrf_update_all(struct bgp *bgp_vrf, /* to */
				struct bgp *bgp_vpn, /* from */
				afi_t afi)
{
	struct prefix_rd prd;
	struct bgp_node *prn;
	safi_t safi = SAFI_MPLS_VPN;

	/*
	 * Walk vpn table
	 */
	for (prn = bgp_table_top(bgp_vpn->rib[afi][safi]); prn;
	     prn = bgp_route_next(prn)) {

		struct bgp_table *table;
		struct bgp_node *bn;
		struct bgp_info *bi;

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;
		memcpy(prd.val, prn->p.u.val, 8);

		/* This is the per-RD table of prefixes */
		table = prn->info;

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {

			for (bi = bn->info; bi; bi = bi->next) {

				if (bi->extra && bi->extra->bgp_orig == bgp_vrf)
					continue;

				vpn_leak_to_vrf_update_onevrf(bgp_vrf, bgp_vpn,
							      bi);
			}
		}
	}
}

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

		if (vpn_leak_to_vpn_active(bgp, afi, NULL)
		    && bgp->vpn_policy[afi].rmap_name[BGP_VPN_POLICY_DIR_TOVPN]
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

			if (!rmap)
				bgp->vpn_policy[afi]
					.rmap[BGP_VPN_POLICY_DIR_TOVPN] = NULL;

			vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi,
					    bgp_get_default(), bgp);
			if (debug)
				zlog_debug("%s: after vpn_leak_postchange",
					   __func__);
		}

		/*
		 * vpn -> vrf leaking currently can have two route-maps:
		 * 1. the vpn-policy tovpn route-map
		 * 2. the (per-afi) redistribute vpn route-map
		 */
		char *mapname_vpn_policy =
			bgp->vpn_policy[afi]
				.rmap_name[BGP_VPN_POLICY_DIR_FROMVPN];
		struct bgp_redist *red = NULL;

		if (vpn_leak_from_vpn_active(bgp, afi, NULL, &red)
		    && ((mapname_vpn_policy
			 && !strcmp(rmap_name, mapname_vpn_policy))
			|| (red && red->rmap.name
			    && !strcmp(red->rmap.name, rmap_name)))) {

			if (debug)
				zlog_debug(
					"%s: rmap \"%s\" matches vrf-policy fromvpn"
					" for as %d afi %s",
					__func__, rmap_name, bgp->as,
					afi2str(afi));

			vpn_leak_prechange(BGP_VPN_POLICY_DIR_FROMVPN, afi,
					   bgp_get_default(), bgp);

			if (!rmap)
				bgp->vpn_policy[afi]
					.rmap[BGP_VPN_POLICY_DIR_FROMVPN] =
					NULL;

			vpn_leak_postchange(BGP_VPN_POLICY_DIR_FROMVPN, afi,
					    bgp_get_default(), bgp);
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
	return bgp_static_set_safi(
		AFI_IP, SAFI_MPLS_VPN, vty, argv[idx_ipv4_prefixlen]->arg,
		argv[idx_ext_community]->arg, argv[idx_label]->arg, NULL, 0,
		NULL, NULL, NULL, NULL);
}

DEFUN (vpnv4_network_route_map,
       vpnv4_network_route_map_cmd,
       "network A.B.C.D/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575) route-map WORD",
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
	int idx_word_2 = 7;
	return bgp_static_set_safi(
		AFI_IP, SAFI_MPLS_VPN, vty, argv[idx_ipv4_prefixlen]->arg,
		argv[idx_ext_community]->arg, argv[idx_label]->arg,
		argv[idx_word_2]->arg, 0, NULL, NULL, NULL, NULL);
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
	return bgp_static_unset_safi(AFI_IP, SAFI_MPLS_VPN, vty,
				     argv[idx_ipv4_prefixlen]->arg,
				     argv[idx_ext_community]->arg,
				     argv[idx_label]->arg, 0, NULL, NULL, NULL);
}

DEFUN (vpnv6_network,
       vpnv6_network_cmd,
       "network X:X::X:X/M rd ASN:NN_OR_IP-ADDRESS:NN <tag|label> (0-1048575) [route-map WORD]",
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
	int idx_word_2 = 7;
	if (argc == 8)
		return bgp_static_set_safi(
			AFI_IP6, SAFI_MPLS_VPN, vty, argv[idx_ipv6_prefix]->arg,
			argv[idx_ext_community]->arg, argv[idx_label]->arg,
			argv[idx_word_2]->arg, 0, NULL, NULL, NULL, NULL);
	else
		return bgp_static_set_safi(
			AFI_IP6, SAFI_MPLS_VPN, vty, argv[idx_ipv6_prefix]->arg,
			argv[idx_ext_community]->arg, argv[idx_label]->arg,
			NULL, 0, NULL, NULL, NULL, NULL);
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
	return bgp_static_unset_safi(AFI_IP6, SAFI_MPLS_VPN, vty,
				     argv[idx_ipv6_prefix]->arg,
				     argv[idx_ext_community]->arg,
				     argv[idx_label]->arg, 0, NULL, NULL, NULL);
}

int bgp_show_mpls_vpn(struct vty *vty, afi_t afi, struct prefix_rd *prd,
		      enum bgp_show_type type, void *output_arg, int tags,
		      u_char use_json)
{
	struct bgp *bgp;
	struct bgp_table *table;

	bgp = bgp_get_default();
	if (bgp == NULL) {
		if (!use_json)
			vty_out(vty, "No BGP process is configured\n");
		else
			vty_out(vty, "{}\n");
		return CMD_WARNING;
	}
	table = bgp->rib[afi][SAFI_MPLS_VPN];
	return bgp_show_table_rd(vty, bgp, SAFI_MPLS_VPN, table, prd, type,
				 output_arg, use_json);
}

DEFUN (show_bgp_ip_vpn_all_rd,
       show_bgp_ip_vpn_all_rd_cmd,
       "show bgp "BGP_AFI_CMD_STR" vpn all [rd ASN:NN_OR_IP-ADDRESS:NN] [json]",
       SHOW_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display VPN NLRI specific information\n"
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       JSON_STR)
{
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_afi(argv, argc, &idx, &afi)) {
		if (argv_find(argv, argc, "rd", &idx)) {
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
       "show bgp "BGP_AFI_CMD_STR" vpn rd ASN:NN_OR_IP-ADDRESS:NN [json]",
       SHOW_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display VPN NLRI specific information\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       JSON_STR)

#ifdef KEEP_OLD_VPN_COMMANDS
DEFUN (show_ip_bgp_vpn_rd,
       show_ip_bgp_vpn_rd_cmd,
       "show ip bgp "BGP_AFI_CMD_STR" vpn rd ASN:NN_OR_IP-ADDRESS:NN",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_AFI_HELP_STR
       "Address Family modifier\n"
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n")
{
	int idx_ext_community = argc - 1;
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
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
       "show [ip] bgp <vpnv4|vpnv6> rd ASN:NN_OR_IP-ADDRESS:NN tags",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
       "Display BGP tags for prefixes\n")
{
	int idx_ext_community = 5;
	int ret;
	struct prefix_rd prd;
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
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
	u_char uj = use_json(argc, argv);
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
       "show [ip] bgp <vpnv4|vpnv6> rd ASN:NN_OR_IP-ADDRESS:NN neighbors A.B.C.D routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
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
	u_char uj = use_json(argc, argv);
	afi_t afi;
	int idx = 0;

	if (argv_find_and_parse_vpnvx(argv, argc, &idx, &afi)) {
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

		return bgp_show_mpls_vpn(vty, afi, &prd, bgp_show_type_neighbor,
					 &su, 0, uj);
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
	u_char uj = use_json(argc, argv);
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
       "show [ip] bgp <vpnv4|vpnv6> rd ASN:NN_OR_IP-ADDRESS:NN neighbors A.B.C.D advertised-routes [json]",
       SHOW_STR
       IP_STR
       BGP_STR
       BGP_VPNVX_HELP_STR
       "Display information for a route distinguisher\n"
       "VPN Route Distinguisher\n"
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
	u_char uj = use_json(argc, argv);
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
