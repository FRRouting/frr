/* BGP carrying label information
 * Copyright (C) 2013 Cumulus Networks, Inc.
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
#include "thread.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"
#include "mpls.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"

extern struct zclient *zclient;

int bgp_parse_fec_update(void)
{
	struct stream *s;
	struct bgp_node *rn;
	struct bgp *bgp;
	struct bgp_table *table;
	struct prefix p;
	uint32_t label;
	afi_t afi;
	safi_t safi;

	s = zclient->ibuf;

	memset(&p, 0, sizeof(struct prefix));
	p.family = stream_getw(s);
	p.prefixlen = stream_getc(s);
	stream_get(p.u.val, s, PSIZE(p.prefixlen));
	label = stream_getl(s);

	/* hack for the bgp instance & SAFI = have to send/receive it */
	afi = family2afi(p.family);
	safi = SAFI_UNICAST;
	bgp = bgp_get_default();
	if (!bgp) {
		zlog_debug("no default bgp instance");
		return -1;
	}

	table = bgp->rib[afi][safi];
	if (!table) {
		zlog_debug("no %u unicast table", p.family);
		return -1;
	}
	rn = bgp_node_lookup(table, &p);
	if (!rn) {
		zlog_debug("no node for the prefix");
		return -1;
	}

	/* treat it as implicit withdraw - the label is invalid */
	if (label == MPLS_INVALID_LABEL)
		bgp_unset_valid_label(&rn->local_label);
	else {
		label_ntop(label, 1, &rn->local_label);
		bgp_set_valid_label(&rn->local_label);
	}
	SET_FLAG(rn->flags, BGP_NODE_LABEL_CHANGED);
	bgp_unlock_node(rn);
	bgp_process(bgp, rn, afi, safi);
	return 1;
}

mpls_label_t bgp_adv_label(struct bgp_node *rn, struct bgp_path_info *pi,
			   struct peer *to, afi_t afi, safi_t safi)
{
	struct peer *from;
	mpls_label_t remote_label;
	int reflect;

	if (!rn || !pi || !to)
		return MPLS_INVALID_LABEL;

	remote_label = pi->extra ? pi->extra->label[0] : MPLS_INVALID_LABEL;
	from = pi->peer;
	reflect =
		((from->sort == BGP_PEER_IBGP) && (to->sort == BGP_PEER_IBGP));

	if (reflect
	    && !CHECK_FLAG(to->af_flags[afi][safi],
			   PEER_FLAG_FORCE_NEXTHOP_SELF))
		return remote_label;

	if (CHECK_FLAG(to->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED))
		return remote_label;

	return rn->local_label;
}

/**
 * This is passed as the callback function to bgp_labelpool.c:bgp_lp_get()
 * by bgp_reg_dereg_for_label() when a label needs to be obtained from
 * label pool.
 * Note that it will reject the allocated label if a label index is found,
 * because the label index supposes predictable labels
 */
int bgp_reg_for_label_callback(mpls_label_t new_label, void *labelid,
			       bool allocated)
{
	struct bgp_path_info *pi;
	struct bgp_node *rn;
	char addr[PREFIX_STRLEN];

	pi = labelid;
	/* Is this path still valid? */
	if (!bgp_path_info_unlock(pi)) {
		if (BGP_DEBUG(labelpool, LABELPOOL))
			zlog_debug(
				"%s: bgp_path_info is no longer valid, ignoring",
				__func__);
		return -1;
	}

	rn = pi->net;
	prefix2str(&rn->p, addr, PREFIX_STRLEN);

	if (BGP_DEBUG(labelpool, LABELPOOL))
		zlog_debug("%s: FEC %s label=%u, allocated=%d", __func__, addr,
			   new_label, allocated);

	if (!allocated) {
		/*
		 * previously-allocated label is now invalid
		 */
		if (pi->attr->label_index == MPLS_INVALID_LABEL_INDEX
		    && pi->attr->label != MPLS_LABEL_NONE
		    && CHECK_FLAG(rn->flags, BGP_NODE_REGISTERED_FOR_LABEL)) {
			bgp_unregister_for_label(rn);
			label_ntop(MPLS_LABEL_IMPLICIT_NULL, 1,
				   &rn->local_label);
			bgp_set_valid_label(&rn->local_label);
		}
		return 0;
	}

	/*
	 * label index is assigned, this should be handled by SR-related code,
	 * so retry FEC registration and then reject label allocation for
	 * it to be released to label pool
	 */
	if (pi->attr->label_index != MPLS_INVALID_LABEL_INDEX) {
		flog_err(
			EC_BGP_LABEL,
			"%s: FEC %s Rejecting allocated label %u as Label Index is %u",
			__func__, addr, new_label, pi->attr->label_index);

		bgp_register_for_label(pi->net, pi);

		return -1;
	}

	if (pi->attr->label != MPLS_INVALID_LABEL) {
		if (new_label == pi->attr->label) {
			/* already have same label, accept but do nothing */
			return 0;
		}
		/* Shouldn't happen: different label allocation */
		flog_err(EC_BGP_LABEL,
			 "%s: %s had label %u but got new assignment %u",
			 __func__, addr, pi->attr->label, new_label);
		/* continue means use new one */
	}

	label_ntop(new_label, 1, &rn->local_label);
	bgp_set_valid_label(&rn->local_label);

	/*
	 * Get back to registering the FEC
	 */
	bgp_register_for_label(pi->net, pi);

	return 0;
}

void bgp_reg_dereg_for_label(struct bgp_node *rn, struct bgp_path_info *pi,
			     bool reg)
{
	bool with_label_index = false;
	struct stream *s;
	struct prefix *p;
	mpls_label_t *local_label;
	int command;
	uint16_t flags = 0;
	size_t flags_pos = 0;
	char addr[PREFIX_STRLEN];

	p = &(rn->p);
	local_label = &(rn->local_label);
	/* this prevents the loop when we're called by
	 * bgp_reg_for_label_callback()
	 */
	bool have_label_to_reg = bgp_is_valid_label(local_label)
			&& label_pton(local_label) != MPLS_LABEL_IMPLICIT_NULL;

	if (reg) {
		assert(pi);
		/*
		 * Determine if we will let zebra should derive label from
		 * label index instead of bgpd requesting from label pool
		 */
		if (CHECK_FLAG(pi->attr->flag,
			    ATTR_FLAG_BIT(BGP_ATTR_PREFIX_SID))
			&& pi->attr->label_index != BGP_INVALID_LABEL_INDEX) {
			with_label_index = true;
		} else {
			/*
			 * If no label index was provided -- assume any label
			 * from label pool will do. This means that label index
			 * always takes precedence over auto-assigned labels.
			 */
			if (!have_label_to_reg) {
				if (BGP_DEBUG(labelpool, LABELPOOL)) {
					prefix2str(p, addr, PREFIX_STRLEN);
					zlog_debug("%s: Requesting label from LP for %s",
						 __func__, addr);
				}
				/* bgp_reg_for_label_callback() will call back
				 * __func__ when it gets a label from the pool.
				 * This means we'll never register FECs without
				 * valid labels.
				 */
				bgp_lp_get(LP_TYPE_BGP_LU, pi,
				    bgp_reg_for_label_callback);
				return;
			}
		}
	}

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return;

	/* If the route node has a local_label assigned or the
	 * path node has an MPLS SR label index allowing zebra to
	 * derive the label, proceed with registration. */
	s = zclient->obuf;
	stream_reset(s);
	command = (reg) ? ZEBRA_FEC_REGISTER : ZEBRA_FEC_UNREGISTER;
	zclient_create_header(s, command, VRF_DEFAULT);
	flags_pos = stream_get_endp(s); /* save position of 'flags' */
	stream_putw(s, flags);		/* initial flags */
	stream_putw(s, PREFIX_FAMILY(p));
	stream_put_prefix(s, p);
	if (reg) {
		if (have_label_to_reg) {
			flags |= ZEBRA_FEC_REGISTER_LABEL;
			stream_putl(s, label_pton(local_label));
		} else if (with_label_index) {
			flags |= ZEBRA_FEC_REGISTER_LABEL_INDEX;
			stream_putl(s, pi->attr->label_index);
		}
		SET_FLAG(rn->flags, BGP_NODE_REGISTERED_FOR_LABEL);
	} else
		UNSET_FLAG(rn->flags, BGP_NODE_REGISTERED_FOR_LABEL);

	/* Set length and flags */
	stream_putw_at(s, 0, stream_get_endp(s));

	/*
	 * We only need to write new flags if this is a register
	 */
	if (reg)
		stream_putw_at(s, flags_pos, flags);

	zclient_send_message(zclient);
}

static int bgp_nlri_get_labels(struct peer *peer, uint8_t *pnt, uint8_t plen,
			       mpls_label_t *label)
{
	uint8_t *data = pnt;
	uint8_t *lim = pnt + plen;
	uint8_t llen = 0;
	uint8_t label_depth = 0;

	for (; data < lim; data += BGP_LABEL_BYTES) {
		memcpy(label, data, BGP_LABEL_BYTES);
		llen += BGP_LABEL_BYTES;

		bgp_set_valid_label(label);
		label_depth += 1;

		if (bgp_is_withdraw_label(label) || label_bos(label))
			break;
	}

	/* If we RX multiple labels we will end up keeping only the last
	 * one. We do not yet support a label stack greater than 1. */
	if (label_depth > 1)
		zlog_info("%s rcvd UPDATE with label stack %d deep", peer->host,
			  label_depth);

	if (!(bgp_is_withdraw_label(label) || label_bos(label)))
		flog_warn(
			EC_BGP_INVALID_LABEL_STACK,
			"%s rcvd UPDATE with invalid label stack - no bottom of stack",
			peer->host);

	return llen;
}

int bgp_nlri_parse_label(struct peer *peer, struct attr *attr,
			 struct bgp_nlri *packet)
{
	uint8_t *pnt;
	uint8_t *lim;
	struct prefix p;
	int psize = 0;
	int prefixlen;
	afi_t afi;
	safi_t safi;
	int addpath_encoded;
	uint32_t addpath_id;
	mpls_label_t label = MPLS_INVALID_LABEL;
	uint8_t llen;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_encoded =
		(CHECK_FLAG(peer->af_cap[afi][safi], PEER_CAP_ADDPATH_AF_RX_ADV)
		 && CHECK_FLAG(peer->af_cap[afi][safi],
			       PEER_CAP_ADDPATH_AF_TX_RCV));

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));

		if (addpath_encoded) {

			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Fetch prefix length. */
		prefixlen = *pnt++;
		p.family = afi2family(packet->afi);
		psize = PSIZE(prefixlen);

		/* sanity check against packet data */
		if ((pnt + psize) > lim) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error / L-U (prefix length %d exceeds packet size %u)",
				peer->host, prefixlen, (uint)(lim - pnt));
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}

		/* Fill in the labels */
		llen = bgp_nlri_get_labels(peer, pnt, psize, &label);
		p.prefixlen = prefixlen - BSIZE(llen);

		/* There needs to be at least one label */
		if (prefixlen < 24) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] Update packet error"
				 " (wrong label length %d)",
				 peer->host, prefixlen);
			bgp_notify_send(peer, BGP_NOTIFY_UPDATE_ERR,
					BGP_NOTIFY_UPDATE_INVAL_NETWORK);
			return BGP_NLRI_PARSE_ERROR_LABEL_LENGTH;
		}

		if ((afi == AFI_IP && p.prefixlen > 32)
		    || (afi == AFI_IP6 && p.prefixlen > 128))
			return BGP_NLRI_PARSE_ERROR_PREFIX_LENGTH;

		/* Fetch prefix from NLRI packet */
		memcpy(&p.u.prefix, pnt + llen, psize - llen);

		/* Check address. */
		if (afi == AFI_IP && safi == SAFI_LABELED_UNICAST) {
			if (IN_CLASSD(ntohl(p.u.prefix4.s_addr))) {
				/* From RFC4271 Section 6.3:
				 *
				 * If a prefix in the NLRI field is semantically
				 * incorrect
				 * (e.g., an unexpected multicast IP address),
				 * an error SHOULD
				 * be logged locally, and the prefix SHOULD be
				 * ignored.
				  */
				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv4 labeled-unicast NLRI is multicast address %s, ignoring",
					peer->host, inet_ntoa(p.u.prefix4));
				continue;
			}
		}

		/* Check address. */
		if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST) {
			if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
				char buf[BUFSIZ];

				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 labeled-unicast NLRI is link-local address %s, ignoring",
					peer->host,
					inet_ntop(AF_INET6, &p.u.prefix6, buf,
						  BUFSIZ));

				continue;
			}

			if (IN6_IS_ADDR_MULTICAST(&p.u.prefix6)) {
				char buf[BUFSIZ];

				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 unicast NLRI is multicast address %s, ignoring",
					peer->host,
					inet_ntop(AF_INET6, &p.u.prefix6, buf,
						  BUFSIZ));

				continue;
			}
		}

		if (attr) {
			bgp_update(peer, &p, addpath_id, attr, packet->afi,
				   SAFI_UNICAST, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, &label, 1, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, addpath_id, attr, packet->afi,
				     SAFI_UNICAST, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, &label, 1, NULL);
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / L-U (%zu data remaining after parsing)",
			peer->host, lim - pnt);
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
	}

	return BGP_NLRI_PARSE_OK;
}
