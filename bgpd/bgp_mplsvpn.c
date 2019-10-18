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
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_nexthop.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_evpn.h"

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
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize = 0;
	int prefixlen;
	uint16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	struct prefix_rd prd = {0};
	mpls_label_t label = {0};
	afi_t afi;
	safi_t safi;
	int addpath_encoded;
	uint32_t addpath_id;

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
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			addpath_id = ntohl(*((uint32_t *)pnt));
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length. */
		prefixlen = *pnt++;
		p.family = afi2family(packet->afi);
		psize = PSIZE(prefixlen);

		if (prefixlen < VPN_PREFIXLEN_MIN_BYTES * 8) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (prefix length %d less than VPN min length)",
				peer->host, prefixlen);
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;
		}

		/* sanity check against packet data */
		if ((pnt + psize) > lim) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (prefix length %d exceeds packet size %u)",
				peer->host, prefixlen, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* sanity check against storage for the IP address portion */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > (ssize_t)sizeof(p.u)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (psize %d exceeds storage size %zu)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				sizeof(p.u));
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
		}

		/* Sanity check against max bitlen of the address family */
		if ((psize - VPN_PREFIXLEN_MIN_BYTES) > prefix_blen(&p)) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / VPN (psize %d exceeds family (%u) max byte len %u)",
				peer->host,
				prefixlen - VPN_PREFIXLEN_MIN_BYTES * 8,
				p.family, prefix_blen(&p));
			return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
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
			flog_err(EC_BGP_UPDATE_RCV, "Unknown RD type %d", type);
			break; /* just report */
		}

		p.prefixlen =
			prefixlen
			- VPN_PREFIXLEN_MIN_BYTES * 8; /* exclude label & RD */
		memcpy(p.u.val, pnt + VPN_PREFIXLEN_MIN_BYTES,
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
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / VPN (%zu data remaining after parsing)",
			peer->host, lim - pnt);
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
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
	int debug = BGP_DEBUG(vpn, VPN_LEAK_LABEL);

	if (bgp->vrf_id == VRF_UNKNOWN) {
		if (debug) {
			zlog_debug(
				"%s: vrf %s: afi %s: vrf_id not set, "
				"can't set zebra vrf label",
				__func__, bgp->name_pretty, afi2str(afi));
		}
		return;
	}

	if (vpn_leak_to_vpn_active(bgp, afi, NULL)) {
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

static bool labels_same(struct bgp_path_info *bpi, mpls_label_t *label,
			uint32_t n)
{
	uint32_t i;

	if (!bpi->extra) {
		if (!n)
			return true;
		else
			return false;
	}

	if (n != bpi->extra->num_labels)
		return false;

	for (i = 0; i < n; ++i) {
		if (label[i] != bpi->extra->label[i])
			return false;
	}
	return true;
}

/*
 * make encoded route labels match specified encoded label set
 */
static void setlabels(struct bgp_path_info *bpi,
		      mpls_label_t *label, /* array of labels */
		      uint32_t num_labels)
{
	if (num_labels)
		assert(label);
	assert(num_labels <= BGP_MAX_LABELS);

	if (!num_labels) {
		if (bpi->extra)
			bpi->extra->num_labels = 0;
		return;
	}

	struct bgp_path_info_extra *extra = bgp_path_info_extra_get(bpi);
	uint32_t i;

	for (i = 0; i < num_labels; ++i) {
		extra->label[i] = label[i];
		if (!bgp_is_valid_label(&label[i])) {
			bgp_set_valid_label(&extra->label[i]);
		}
	}
	extra->num_labels = num_labels;
}

/*
 * returns pointer to new bgp_path_info upon success
 */
static struct bgp_path_info *
leak_update(struct bgp *bgp, /* destination bgp instance */
	    struct bgp_node *bn, struct attr *new_attr, /* already interned */
	    afi_t afi, safi_t safi, struct bgp_path_info *source_bpi,
	    mpls_label_t *label, uint32_t num_labels, void *parent,
	    struct bgp *bgp_orig, struct prefix *nexthop_orig,
	    int nexthop_self_flag, int debug)
{
	struct prefix *p = &bn->p;
	struct bgp_path_info *bpi;
	struct bgp_path_info *bpi_ultimate;
	struct bgp_path_info *new;
	char buf_prefix[PREFIX_STRLEN];

	if (debug) {
		prefix2str(&bn->p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: entry: leak-to=%s, p=%s, type=%d, sub_type=%d",
			   __func__, bgp->name_pretty, buf_prefix,
			   source_bpi->type, source_bpi->sub_type);
	}

	/*
	 * Routes that are redistributed into BGP from zebra do not get
	 * nexthop tracking. However, if those routes are subsequently
	 * imported to other RIBs within BGP, the leaked routes do not
	 * carry the original BGP_ROUTE_REDISTRIBUTE sub_type. Therefore,
	 * in order to determine if the route we are currently leaking
	 * should have nexthop tracking, we must find the ultimate
	 * parent so we can check its sub_type.
	 *
	 * As of now, source_bpi may at most be a second-generation route
	 * (only one hop back to ultimate parent for vrf-vpn-vrf scheme).
	 * Using a loop here supports more complex intra-bgp import-export
	 * schemes that could be implemented in the future.
	 *
	 */
	for (bpi_ultimate = source_bpi;
	     bpi_ultimate->extra && bpi_ultimate->extra->parent;
	     bpi_ultimate = bpi_ultimate->extra->parent)
		;

	/*
	 * match parent
	 */
	for (bpi = bgp_node_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->parent == parent)
			break;
	}

	if (bpi) {
		bool labelssame = labels_same(bpi, label, num_labels);

		if (attrhash_cmp(bpi->attr, new_attr) && labelssame
		    && !CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {

			bgp_attr_unintern(&new_attr);
			if (debug)
				zlog_debug(
					"%s: ->%s: %s: Found route, no change",
					__func__, bgp->name_pretty,
					buf_prefix);
			return NULL;
		}

		/* attr is changed */
		bgp_path_info_set_flag(bn, bpi, BGP_PATH_ATTR_CHANGED);

		/* Rewrite BGP route information. */
		if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(bn, bpi);
		else
			bgp_aggregate_decrement(bgp, p, bpi, afi, safi);
		bgp_attr_unintern(&bpi->attr);
		bpi->attr = new_attr;
		bpi->uptime = bgp_clock();

		/*
		 * rewrite labels
		 */
		if (!labelssame)
			setlabels(bpi, label, num_labels);

		if (nexthop_self_flag)
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_ANNC_NH_SELF);

		struct bgp *bgp_nexthop = bgp;
		int nh_valid;

		if (bpi->extra && bpi->extra->bgp_orig)
			bgp_nexthop = bpi->extra->bgp_orig;

		/*
		 * No nexthop tracking for redistributed routes or for
		 * EVPN-imported routes that get leaked.
		 */
		if (bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE ||
		    is_pi_family_evpn(bpi_ultimate))
			nh_valid = 1;
		else
			/*
			 * TBD do we need to do anything about the
			 * 'connected' parameter?
			 */
			nh_valid = bgp_find_or_add_nexthop(bgp, bgp_nexthop,
							   afi, bpi, NULL, 0);

		if (debug)
			zlog_debug("%s: nexthop is %svalid (in vrf %s)",
				__func__, (nh_valid ? "" : "not "),
				bgp_nexthop->name_pretty);

		if (nh_valid)
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_VALID);

		/* Process change. */
		bgp_aggregate_increment(bgp, p, bpi, afi, safi);
		bgp_process(bgp, bn, afi, safi);
		bgp_unlock_node(bn);

		if (debug)
			zlog_debug("%s: ->%s: %s Found route, changed attr",
				   __func__, bgp->name_pretty, buf_prefix);

		return bpi;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_IMPORTED, 0,
		bgp->peer_self, new_attr, bn);

	if (nexthop_self_flag)
		bgp_path_info_set_flag(bn, new, BGP_PATH_ANNC_NH_SELF);

	bgp_path_info_extra_get(new);

	if (num_labels)
		setlabels(new, label, num_labels);

	new->extra->parent = bgp_path_info_lock(parent);
	bgp_lock_node((struct bgp_node *)((struct bgp_path_info *)parent)->net);
	if (bgp_orig)
		new->extra->bgp_orig = bgp_lock(bgp_orig);
	if (nexthop_orig)
		new->extra->nexthop_orig = *nexthop_orig;

	/*
	 * nexthop tracking for unicast routes
	 */
	struct bgp *bgp_nexthop = bgp;
	int nh_valid;

	if (new->extra->bgp_orig)
		bgp_nexthop = new->extra->bgp_orig;

	/*
	 * No nexthop tracking for redistributed routes because
	 * their originating protocols will do the tracking and
	 * withdraw those routes if the nexthops become unreachable
	 * This also holds good for EVPN-imported routes that get
	 * leaked.
	 */
	if (bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE ||
	    is_pi_family_evpn(bpi_ultimate))
		nh_valid = 1;
	else
		/*
		 * TBD do we need to do anything about the
		 * 'connected' parameter?
		 */
		nh_valid = bgp_find_or_add_nexthop(bgp, bgp_nexthop,
						afi, new, NULL, 0);

	if (debug)
		zlog_debug("%s: nexthop is %svalid (in vrf %s)",
			__func__, (nh_valid ? "" : "not "),
			bgp_nexthop->name_pretty);
	if (nh_valid)
		bgp_path_info_set_flag(bn, new, BGP_PATH_VALID);

	bgp_aggregate_increment(bgp, p, new, afi, safi);
	bgp_path_info_add(bn, new);

	bgp_unlock_node(bn);
	bgp_process(bgp, bn, afi, safi);

	if (debug)
		zlog_debug("%s: ->%s: %s: Added new route", __func__,
			   bgp->name_pretty, buf_prefix);

	return new;
}

/* cf vnc_import_bgp_add_route_mode_nvegroup() and add_vnc_route() */
void vpn_leak_from_vrf_update(struct bgp *bgp_vpn,	    /* to */
			      struct bgp *bgp_vrf,	    /* from */
			      struct bgp_path_info *path_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct prefix *p = &path_vrf->net->p;
	afi_t afi = family2afi(p->family);
	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	safi_t safi = SAFI_MPLS_VPN;
	mpls_label_t label_val;
	mpls_label_t label;
	struct bgp_node *bn;
	const char *debugmsg;
	int nexthop_self_flag = 0;

	if (debug)
		zlog_debug("%s: from vrf %s", __func__, bgp_vrf->name_pretty);

	if (debug && path_vrf->attr->ecommunity) {
		char *s = ecommunity_ecom2str(path_vrf->attr->ecommunity,
					      ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: %s path_vrf->type=%d, EC{%s}", __func__,
			   bgp_vrf->name, path_vrf->type, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	if (!bgp_vpn)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* Is this route exportable into the VPN table? */
	if (!is_route_injectable_into_vpn(path_vrf))
		return;

	if (!vpn_leak_to_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: %s skipping: %s", __func__,
				   bgp_vrf->name, debugmsg);
		return;
	}

	bgp_attr_dup(&static_attr, path_vrf->attr); /* shallow copy */

	/*
	 * route map handling
	 */
	if (bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_TOVPN]) {
		struct bgp_path_info info;
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
					__func__, bgp_vrf->name_pretty,
					bgp_vrf->vpn_policy[afi]
						.rmap[BGP_VPN_POLICY_DIR_TOVPN]
						->name);
			return;
		}
	}

	if (debug && static_attr.ecommunity) {
		char *s = ecommunity_ecom2str(static_attr.ecommunity,
					      ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: post route map static_attr.ecommunity{%s}",
			   __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
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

	if (debug && static_attr.ecommunity) {
		char *s = ecommunity_ecom2str(static_attr.ecommunity,
					      ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: post merge static_attr.ecommunity{%s}",
			   __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
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
		if (!CHECK_FLAG(bgp_vrf->af_flags[afi][SAFI_UNICAST],
				BGP_CONFIG_VRF_TO_VRF_EXPORT)) {
			if (afi == AFI_IP) {
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

	label_val = bgp_vrf->vpn_policy[afi].tovpn_label;
	if (label_val == MPLS_LABEL_NONE) {
		encode_label(MPLS_LABEL_IMPLICIT_NULL, &label);
	} else {
		encode_label(label_val, &label);
	}

	/* Set originator ID to "me" */
	SET_FLAG(static_attr.flag, ATTR_FLAG_BIT(BGP_ATTR_ORIGINATOR_ID));
	static_attr.originator_id = bgp_vpn->router_id;


	new_attr = bgp_attr_intern(
		&static_attr);	/* hashed refcounted everything */
	bgp_attr_flush(&static_attr); /* free locally-allocated parts */

	if (debug && new_attr->ecommunity) {
		char *s = ecommunity_ecom2str(new_attr->ecommunity,
					      ECOMMUNITY_FORMAT_ROUTE_MAP, 0);

		zlog_debug("%s: new_attr->ecommunity{%s}", __func__, s);
		XFREE(MTYPE_ECOMMUNITY_STR, s);
	}

	/* Now new_attr is an allocated interned attr */

	bn = bgp_afi_node_get(bgp_vpn->rib[afi][safi], afi, safi, p,
			      &(bgp_vrf->vpn_policy[afi].tovpn_rd));

	struct bgp_path_info *new_info;

	new_info = leak_update(bgp_vpn, bn, new_attr, afi, safi, path_vrf,
			       &label, 1, path_vrf, bgp_vrf, NULL,
			       nexthop_self_flag, debug);

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

void vpn_leak_from_vrf_withdraw(struct bgp *bgp_vpn,		/* to */
				struct bgp *bgp_vrf,		/* from */
				struct bgp_path_info *path_vrf) /* route */
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	struct prefix *p = &path_vrf->net->p;
	afi_t afi = family2afi(p->family);
	safi_t safi = SAFI_MPLS_VPN;
	struct bgp_path_info *bpi;
	struct bgp_node *bn;
	const char *debugmsg;
	char buf_prefix[PREFIX_STRLEN];

	if (debug) {
		prefix2str(p, buf_prefix, sizeof(buf_prefix));
		zlog_debug(
			"%s: entry: leak-from=%s, p=%s, type=%d, sub_type=%d",
			__func__, bgp_vrf->name_pretty, buf_prefix,
			path_vrf->type, path_vrf->sub_type);
	}

	if (!bgp_vpn)
		return;

	if (!afi) {
		if (debug)
			zlog_debug("%s: can't get afi of prefix", __func__);
		return;
	}

	/* Is this route exportable into the VPN table? */
	if (!is_route_injectable_into_vpn(path_vrf))
		return;

	if (!vpn_leak_to_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	if (debug)
		zlog_debug("%s: withdrawing (path_vrf=%p)", __func__, path_vrf);

	bn = bgp_afi_node_get(bgp_vpn->rib[afi][safi], afi, safi, p,
			      &(bgp_vrf->vpn_policy[afi].tovpn_rd));

	if (!bn)
		return;
	/*
	 * vrf -> vpn
	 * match original bpi imported from
	 */
	for (bpi = bgp_node_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->parent == path_vrf) {
			break;
		}
	}

	if (bpi) {
		/* withdraw from looped vrfs as well */
		vpn_leak_to_vrf_withdraw(bgp_vpn, bpi);

		bgp_aggregate_decrement(bgp_vpn, p, bpi, afi, safi);
		bgp_path_info_delete(bn, bpi);
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
	 * Walk vpn table, delete bpi with bgp_orig == bgp_vrf
	 */
	for (prn = bgp_table_top(bgp_vpn->rib[afi][safi]); prn;
	     prn = bgp_route_next(prn)) {

		struct bgp_table *table;
		struct bgp_node *bn;
		struct bgp_path_info *bpi;

		/* This is the per-RD table of prefixes */
		table = bgp_node_get_bgp_table_info(prn);

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {

			char buf[PREFIX2STR_BUFFER];

			bpi = bgp_node_get_bgp_path_info(bn);
			if (debug && bpi) {
				zlog_debug(
					"%s: looking at prefix %s", __func__,
					prefix2str(&bn->p, buf, sizeof(buf)));
			}

			for (; bpi; bpi = bpi->next) {
				if (debug)
					zlog_debug("%s: type %d, sub_type %d",
						   __func__, bpi->type,
						   bpi->sub_type);
				if (bpi->sub_type != BGP_ROUTE_IMPORTED)
					continue;
				if (!bpi->extra)
					continue;
				if ((struct bgp *)bpi->extra->bgp_orig
				    == bgp_vrf) {
					/* delete route */
					if (debug)
						zlog_debug("%s: deleting it",
							   __func__);
					bgp_aggregate_decrement(bgp_vpn, &bn->p,
								bpi, afi, safi);
					bgp_path_info_delete(bn, bpi);
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
	struct bgp_path_info *bpi;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);

	if (debug)
		zlog_debug("%s: entry, afi=%d, vrf=%s", __func__, afi,
			   bgp_vrf->name_pretty);

	for (bn = bgp_table_top(bgp_vrf->rib[afi][SAFI_UNICAST]); bn;
	     bn = bgp_route_next(bn)) {

		if (debug)
			zlog_debug("%s: node=%p", __func__, bn);

		for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (debug)
				zlog_debug(
					"%s: calling vpn_leak_from_vrf_update",
					__func__);
			vpn_leak_from_vrf_update(bgp_vpn, bgp_vrf, bpi);
		}
	}
}

static void
vpn_leak_to_vrf_update_onevrf(struct bgp *bgp_vrf,	    /* to */
			      struct bgp *bgp_vpn,	    /* from */
			      struct bgp_path_info *path_vpn) /* route */
{
	struct prefix *p = &path_vpn->net->p;
	afi_t afi = family2afi(p->family);

	struct attr static_attr = {0};
	struct attr *new_attr = NULL;
	struct bgp_node *bn;
	safi_t safi = SAFI_UNICAST;
	const char *debugmsg;
	struct prefix nexthop_orig;
	mpls_label_t *pLabels = NULL;
	uint32_t num_labels = 0;
	int nexthop_self_flag = 1;
	struct bgp_path_info *bpi_ultimate = NULL;
	int origin_local = 0;
	struct bgp *src_vrf;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (!vpn_leak_from_vpn_active(bgp_vrf, afi, &debugmsg)) {
		if (debug)
			zlog_debug("%s: skipping: %s", __func__, debugmsg);
		return;
	}

	/* Check for intersection of route targets */
	if (!ecom_intersect(
		    bgp_vrf->vpn_policy[afi].rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
		    path_vpn->attr->ecommunity)) {

		return;
	}

	if (debug) {
		char buf_prefix[PREFIX_STRLEN];

		prefix2str(p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: updating %s to vrf %s", __func__,
				buf_prefix, bgp_vrf->name_pretty);
	}

	bgp_attr_dup(&static_attr, path_vpn->attr); /* shallow copy */

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

	switch (nhfamily) {
	case AF_INET:
		/* save */
		nexthop_orig.u.prefix4 = path_vpn->attr->mp_nexthop_global_in;
		nexthop_orig.prefixlen = 32;

		if (CHECK_FLAG(bgp_vrf->af_flags[afi][safi],
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
		nexthop_orig.prefixlen = 128;

		if (CHECK_FLAG(bgp_vrf->af_flags[afi][safi],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
			static_attr.mp_nexthop_global = nexthop_orig.u.prefix6;
		}
		break;
	}

	/*
	 * route map handling
	 */
	if (bgp_vrf->vpn_policy[afi].rmap[BGP_VPN_POLICY_DIR_FROMVPN]) {
		struct bgp_path_info info;
		route_map_result_t ret;

		memset(&info, 0, sizeof(info));
		info.peer = bgp_vrf->peer_self;
		info.attr = &static_attr;
		info.extra = path_vpn->extra; /* Used for source-vrf filter */
		ret = route_map_apply(bgp_vrf->vpn_policy[afi]
					      .rmap[BGP_VPN_POLICY_DIR_FROMVPN],
				      p, RMAP_BGP, &info);
		if (RMAP_DENYMATCH == ret) {
			bgp_attr_flush(&static_attr); /* free any added parts */
			if (debug)
				zlog_debug(
					"%s: vrf %s vpn-policy route map \"%s\" says DENY, returning",
					__func__, bgp_vrf->name_pretty,
					bgp_vrf->vpn_policy[afi]
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

	new_attr = bgp_attr_intern(&static_attr);
	bgp_attr_flush(&static_attr);

	bn = bgp_afi_node_get(bgp_vrf->rib[afi][safi], afi, safi, p, NULL);

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
	if (!CHECK_FLAG(bgp_vrf->af_flags[afi][safi],
			BGP_CONFIG_VRF_TO_VRF_IMPORT)) {
		/* work back to original route */
		for (bpi_ultimate = path_vpn;
		     bpi_ultimate->extra && bpi_ultimate->extra->parent;
		     bpi_ultimate = bpi_ultimate->extra->parent)
			;

		/*
		 * if original route was unicast,
		 * then it did not arrive over vpn
		 */
		if (bpi_ultimate->net) {
			struct bgp_table *table;

			table = bgp_node_table(bpi_ultimate->net);
			if (table && (table->safi == SAFI_UNICAST))
				origin_local = 1;
		}

		/* copy labels */
		if (!origin_local && path_vpn->extra
		    && path_vpn->extra->num_labels) {
			num_labels = path_vpn->extra->num_labels;
			if (num_labels > BGP_MAX_LABELS)
				num_labels = BGP_MAX_LABELS;
			pLabels = path_vpn->extra->label;
		}
	}

	if (debug) {
		char buf_prefix[PREFIX_STRLEN];
		prefix2str(p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: pfx %s: num_labels %d", __func__, buf_prefix,
			   num_labels);
	}

	/*
	 * For VRF-2-VRF route-leaking,
	 * the source will be the originating VRF.
	 */
	if (path_vpn->extra && path_vpn->extra->bgp_orig)
		src_vrf = path_vpn->extra->bgp_orig;
	else
		src_vrf = bgp_vpn;

	leak_update(bgp_vrf, bn, new_attr, afi, safi, path_vpn, pLabels,
		    num_labels, path_vpn, /* parent */
		    src_vrf, &nexthop_orig, nexthop_self_flag, debug);
}

void vpn_leak_to_vrf_update(struct bgp *bgp_vpn,	    /* from */
			    struct bgp_path_info *path_vpn) /* route */
{
	struct listnode *mnode, *mnnode;
	struct bgp *bgp;

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: start (path_vpn=%p)", __func__, path_vpn);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {

		if (!path_vpn->extra
		    || path_vpn->extra->bgp_orig != bgp) { /* no loop */
			vpn_leak_to_vrf_update_onevrf(bgp, bgp_vpn, path_vpn);
		}
	}
}

void vpn_leak_to_vrf_withdraw(struct bgp *bgp_vpn,	    /* from */
			      struct bgp_path_info *path_vpn) /* route */
{
	struct prefix *p;
	afi_t afi;
	safi_t safi = SAFI_UNICAST;
	struct bgp *bgp;
	struct listnode *mnode, *mnnode;
	struct bgp_node *bn;
	struct bgp_path_info *bpi;
	const char *debugmsg;
	char buf_prefix[PREFIX_STRLEN];

	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug) {
		prefix2str(&path_vpn->net->p, buf_prefix, sizeof(buf_prefix));
		zlog_debug("%s: entry: p=%s, type=%d, sub_type=%d", __func__,
			   buf_prefix, path_vpn->type, path_vpn->sub_type);
	}

	if (debug)
		zlog_debug("%s: start (path_vpn=%p)", __func__, path_vpn);

	if (!path_vpn->net) {
#if ENABLE_BGP_VNC
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

	p = &path_vpn->net->p;
	afi = family2afi(p->family);

	/* Loop over VRFs */
	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		if (!vpn_leak_from_vpn_active(bgp, afi, &debugmsg)) {
			if (debug)
				zlog_debug("%s: skipping: %s", __func__,
					   debugmsg);
			continue;
		}

		/* Check for intersection of route targets */
		if (!ecom_intersect(bgp->vpn_policy[afi]
					    .rtlist[BGP_VPN_POLICY_DIR_FROMVPN],
				    path_vpn->attr->ecommunity)) {

			continue;
		}

		if (debug)
			zlog_debug("%s: withdrawing from vrf %s", __func__,
				   bgp->name_pretty);

		bn = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, p, NULL);

		for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (bpi->extra
			    && (struct bgp_path_info *)bpi->extra->parent
				       == path_vpn) {
				break;
			}
		}

		if (bpi) {
			if (debug)
				zlog_debug("%s: deleting bpi %p", __func__,
					   bpi);
			bgp_aggregate_decrement(bgp, p, bpi, afi, safi);
			bgp_path_info_delete(bn, bpi);
			bgp_process(bgp, bn, afi, safi);
		}
		bgp_unlock_node(bn);
	}
}

void vpn_leak_to_vrf_withdraw_all(struct bgp *bgp_vrf, /* to */
				  afi_t afi)
{
	struct bgp_node *bn;
	struct bgp_path_info *bpi;
	safi_t safi = SAFI_UNICAST;
	int debug = BGP_DEBUG(vpn, VPN_LEAK_TO_VRF);

	if (debug)
		zlog_debug("%s: entry", __func__);
	/*
	 * Walk vrf table, delete bpi with bgp_orig in a different vrf
	 */
	for (bn = bgp_table_top(bgp_vrf->rib[afi][safi]); bn;
	     bn = bgp_route_next(bn)) {

		for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
		     bpi = bpi->next) {
			if (bpi->extra
			    && bpi->extra->bgp_orig != bgp_vrf
			    && bpi->extra->parent
			    && is_pi_family_vpn(bpi->extra->parent)) {

				/* delete route */
				bgp_aggregate_decrement(bgp_vrf, &bn->p, bpi,
							afi, safi);
				bgp_path_info_delete(bn, bpi);
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

	assert(bgp_vpn);

	/*
	 * Walk vpn table
	 */
	for (prn = bgp_table_top(bgp_vpn->rib[afi][safi]); prn;
	     prn = bgp_route_next(prn)) {

		struct bgp_table *table;
		struct bgp_node *bn;
		struct bgp_path_info *bpi;

		memset(&prd, 0, sizeof(prd));
		prd.family = AF_UNSPEC;
		prd.prefixlen = 64;
		memcpy(prd.val, prn->p.u.val, 8);

		/* This is the per-RD table of prefixes */
		table = bgp_node_get_bgp_table_info(prn);

		if (!table)
			continue;

		for (bn = bgp_table_top(table); bn; bn = bgp_route_next(bn)) {

			for (bpi = bgp_node_get_bgp_path_info(bn); bpi;
			     bpi = bpi->next) {

				if (bpi->extra
				    && bpi->extra->bgp_orig == bgp_vrf)
					continue;

				vpn_leak_to_vrf_update_onevrf(bgp_vrf, bgp_vpn,
							      bpi);
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
	int debug;
	char *vname;
	const char *export_name;
	char buf[RD_ADDRSTRLEN];
	struct bgp *bgp_import;
	struct listnode *node;
	struct ecommunity *ecom;
	vpn_policy_direction_t idir, edir;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_DEFAULT
	    && bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	export_name = bgp->name ? bgp->name : VRF_DEFAULT_NAME;
	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		     BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	idir = BGP_VPN_POLICY_DIR_FROMVPN;
	edir = BGP_VPN_POLICY_DIR_TOVPN;

	for (afi = 0; afi < AFI_MAX; ++afi) {
		if (!vpn_leak_to_vpn_active(bgp, afi, NULL))
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
				bgp_import = bgp_lookup_by_name(vname);
				if (!bgp_import)
					continue;

				ecommunity_del_val(bgp_import->vpn_policy[afi].
						   rtlist[idir],
					(struct ecommunity_val *)ecom->val);

			}
		} else {
			/*
			 * Router-id changes that are not explicit config
			 * changes should not replace configured RD/RT.
			 */
			if (!is_config) {
				if (CHECK_FLAG(bgp->vpn_policy[afi].flags,
					       BGP_VPN_POLICY_TOVPN_RD_SET)) {
					if (debug)
						zlog_debug("%s: auto router-id change skipped",
							   __func__);
					goto postchange;
				}
			}

			/* New router-id derive auto RD and RT and export
			 * to VPN
			 */
			form_auto_rd(bgp->router_id, bgp->vrf_rd_id,
				     &bgp->vrf_prd_auto);
			bgp->vpn_policy[afi].tovpn_rd = bgp->vrf_prd_auto;
			prefix_rd2str(&bgp->vpn_policy[afi].tovpn_rd, buf,
				      sizeof(buf));
			bgp->vpn_policy[afi].rtlist[edir] =
				ecommunity_str2com(buf,
						   ECOMMUNITY_ROUTE_TARGET, 0);

			/* Update import_vrf rt_list */
			ecom = bgp->vpn_policy[afi].rtlist[edir];
			for (ALL_LIST_ELEMENTS_RO(bgp->vpn_policy[afi].
						  export_vrf, node, vname)) {
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

postchange:
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
	vpn_policy_direction_t idir, edir;
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
		prefix_rd2str(&from_bgp->vpn_policy[afi].tovpn_rd,
			      buf, sizeof(buf));
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

		from_name = from_bgp->name ? from_bgp->name :
			VRF_DEFAULT_NAME;
		zlog_debug("%s from %s to %s first_export %u import-rt %s export-rt %s",
			   __func__, from_name, export_name, first_export,
			   to_bgp->vpn_policy[afi].rtlist[idir] ?
			   (ecommunity_ecom2str(to_bgp->vpn_policy[afi].
						rtlist[idir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0)) : " ",
			   to_bgp->vpn_policy[afi].rtlist[edir] ?
			   (ecommunity_ecom2str(to_bgp->vpn_policy[afi].
						rtlist[edir],
					ECOMMUNITY_FORMAT_ROUTE_MAP, 0)) : " ");
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
	vpn_policy_direction_t idir, edir;
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
		      bool use_json)
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
	bool uj = use_json(argc, argv);
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

	for (ALL_LIST_ELEMENTS(bm->bgp, mnode, mnnode, bgp)) {
		struct ecommunity *ec;

		if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		ec = bgp->vpn_policy[AFI_IP].import_redirect_rtlist;

		if (ecom_intersect(ec, eckey))
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
int bgp_vpn_leak_unimport(struct bgp *from_bgp, struct vty *vty)
{
	struct bgp *to_bgp;
	const char *tmp_name;
	char *vname;
	struct listnode *node, *next;
	safi_t safi = SAFI_UNICAST;
	afi_t afi;
	bool is_vrf_leak_bind;
	int debug;

	if (from_bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return 0;

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
	}
	return 0;
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
	vpn_policy_direction_t idir, edir;
	safi_t safi = SAFI_UNICAST;
	struct bgp *to_bgp;
	int debug;

	debug = (BGP_DEBUG(vpn, VPN_LEAK_TO_VRF) |
		     BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF));

	idir = BGP_VPN_POLICY_DIR_FROMVPN;
	edir = BGP_VPN_POLICY_DIR_TOVPN;

	export_name = (from_bgp->name ? XSTRDUP(MTYPE_TMP, from_bgp->name)
			       : XSTRDUP(MTYPE_TMP, VRF_DEFAULT_NAME));

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
