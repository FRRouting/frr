// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP carrying label information
 * Copyright (C) 2013 Cumulus Networks, Inc.
 */

#include <zebra.h>

#include "command.h"
#include "frrevent.h"
#include "prefix.h"
#include "zclient.h"
#include "stream.h"
#include "network.h"
#include "log.h"
#include "memory.h"
#include "nexthop.h"
#include "mpls.h"
#include "jhash.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_label.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"

extern struct zclient *zclient;


/* MPLS Labels hash routines. */
static struct hash *labels_hash;

static void *bgp_labels_hash_alloc(void *p)
{
	const struct bgp_labels *labels = p;
	struct bgp_labels *new;
	uint8_t i;

	new = XMALLOC(MTYPE_BGP_LABELS, sizeof(struct bgp_labels));

	new->num_labels = labels->num_labels;
	for (i = 0; i < labels->num_labels; i++)
		new->label[i] = labels->label[i];

	return new;
}

static uint32_t bgp_labels_hash_key_make(const void *p)
{
	const struct bgp_labels *labels = p;
	uint32_t key = 0;

	if (labels->num_labels)
		key = jhash(&labels->label,
			    labels->num_labels * sizeof(mpls_label_t), key);

	return key;
}

static bool bgp_labels_hash_cmp(const void *p1, const void *p2)
{
	return bgp_labels_cmp(p1, p2);
}

void bgp_labels_init(void)
{
	labels_hash = hash_create(bgp_labels_hash_key_make, bgp_labels_hash_cmp,
				  "BGP Labels hash");
}

/*
 * special for hash_clean below
 */
static void bgp_labels_free(void *labels)
{
	XFREE(MTYPE_BGP_LABELS, labels);
}

void bgp_labels_finish(void)
{
	hash_clean_and_free(&labels_hash, bgp_labels_free);
}

struct bgp_labels *bgp_labels_intern(struct bgp_labels *labels)
{
	struct bgp_labels *find;

	if (!labels)
		return NULL;

	if (!labels->num_labels)
		/* do not intern void labels structure */
		return NULL;

	find = (struct bgp_labels *)hash_get(labels_hash, labels,
					     bgp_labels_hash_alloc);
	find->refcnt++;

	return find;
}

void bgp_labels_unintern(struct bgp_labels **plabels)
{
	struct bgp_labels *labels = *plabels;
	struct bgp_labels *ret;

	if (!*plabels)
		return;

	/* Decrement labels reference. */
	labels->refcnt--;

	/* If reference becomes zero then free labels object. */
	if (labels->refcnt == 0) {
		ret = hash_release(labels_hash, labels);
		assert(ret != NULL);
		bgp_labels_free(labels);
		*plabels = NULL;
	}
}

bool bgp_labels_cmp(const struct bgp_labels *labels1,
		    const struct bgp_labels *labels2)
{
	uint8_t i;

	if (!labels1 && !labels2)
		return true;

	if (!labels1 && labels2)
		return false;

	if (labels1 && !labels2)
		return false;

	if (labels1->num_labels != labels2->num_labels)
		return false;

	for (i = 0; i < labels1->num_labels; i++) {
		if (labels1->label[i] != labels2->label[i])
			return false;
	}

	return true;
}

int bgp_parse_fec_update(void)
{
	struct stream *s;
	struct bgp_dest *dest;
	struct bgp *bgp;
	struct bgp_table *table;
	struct prefix p;
	uint32_t label;
	afi_t afi;
	safi_t safi;

	s = zclient->ibuf;

	memset(&p, 0, sizeof(p));
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
	dest = bgp_node_lookup(table, &p);
	if (!dest) {
		zlog_debug("no node for the prefix");
		return -1;
	}

	/* treat it as implicit withdraw - the label is invalid */
	if (label == MPLS_INVALID_LABEL)
		bgp_unset_valid_label(&dest->local_label);
	else {
		dest->local_label = mpls_lse_encode(label, 0, 0, 1);
		bgp_set_valid_label(&dest->local_label);
	}
	SET_FLAG(dest->flags, BGP_NODE_LABEL_CHANGED);
	bgp_process(bgp, dest, NULL, afi, safi);
	bgp_dest_unlock_node(dest);
	return 1;
}

mpls_label_t bgp_adv_label(struct bgp_dest *dest, struct bgp_path_info *pi,
			   struct peer *to, afi_t afi, safi_t safi)
{
	struct peer *from;
	mpls_label_t remote_label;
	int reflect;

	if (!dest || !pi || !to)
		return MPLS_INVALID_LABEL;

	remote_label = BGP_PATH_INFO_NUM_LABELS(pi)
			       ? pi->extra->labels->label[0]
			       : MPLS_INVALID_LABEL;
	from = pi->peer;
	reflect =
		((from->sort == BGP_PEER_IBGP) && (to->sort == BGP_PEER_IBGP));

	if (reflect
	    && !CHECK_FLAG(to->af_flags[afi][safi],
			   PEER_FLAG_FORCE_NEXTHOP_SELF))
		return remote_label;

	if (CHECK_FLAG(to->af_flags[afi][safi], PEER_FLAG_NEXTHOP_UNCHANGED))
		return remote_label;

	return dest->local_label;
}

static void bgp_send_fec_register_label_msg(struct bgp_dest *dest, bool reg,
					    uint32_t label_index)
{
	struct stream *s;
	int command;
	const struct prefix *p;
	uint16_t flags = 0;
	size_t flags_pos = 0;
	mpls_label_t *local_label = &(dest->local_label);
	uint32_t ttl = 0;
	uint32_t bos = 0;
	uint32_t exp = 0;
	mpls_label_t label = MPLS_INVALID_LABEL;
	bool have_label_to_reg;

	mpls_lse_decode(*local_label, &label, &ttl, &exp, &bos);

	have_label_to_reg = bgp_is_valid_label(local_label) &&
			    label != MPLS_LABEL_IMPLICIT_NULL;

	p = bgp_dest_get_prefix(dest);

	/* Check socket. */
	if (!zclient || zclient->sock < 0)
		return;

	if (BGP_DEBUG(labelpool, LABELPOOL))
		zlog_debug("%s: FEC %sregister %pBD label_index=%u label=%u",
			   __func__, reg ? "" : "un", dest, label_index, label);
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
		/* label index takes precedence over auto-assigned label. */
		if (label_index != 0) {
			flags |= ZEBRA_FEC_REGISTER_LABEL_INDEX;
			stream_putl(s, label_index);
		} else if (have_label_to_reg) {
			flags |= ZEBRA_FEC_REGISTER_LABEL;
			stream_putl(s, label);
		}
		SET_FLAG(dest->flags, BGP_NODE_REGISTERED_FOR_LABEL);
	} else
		UNSET_FLAG(dest->flags, BGP_NODE_REGISTERED_FOR_LABEL);

	/* Set length and flags */
	stream_putw_at(s, 0, stream_get_endp(s));

	/*
	 * We only need to write new flags if this is a register
	 */
	if (reg)
		stream_putw_at(s, flags_pos, flags);

	zclient_send_message(zclient);
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
	struct bgp_dest *dest;

	dest = labelid;

	/*
	 * if the route had been removed or the request has gone then reject
	 * the allocated label. The requesting code will have done what is
	 * required to allocate the correct label
	 */
	if (!CHECK_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED)) {
		bgp_dest_unlock_node(dest);
		return -1;
	}

	dest = bgp_dest_unlock_node(dest);
	assert(dest);

	if (BGP_DEBUG(labelpool, LABELPOOL))
		zlog_debug("%s: FEC %pBD label=%u, allocated=%d", __func__,
			   dest, new_label, allocated);

	if (!allocated) {
		/*
		 * previously-allocated label is now invalid, set to implicit
		 * null until new label arrives
		 */
		if (CHECK_FLAG(dest->flags, BGP_NODE_REGISTERED_FOR_LABEL)) {
			UNSET_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED);
			dest->local_label = mpls_lse_encode(
				MPLS_LABEL_IMPLICIT_NULL, 0, 0, 1);
			bgp_set_valid_label(&dest->local_label);
		}
	}

	dest->local_label = mpls_lse_encode(new_label, 0, 0, 1);
	bgp_set_valid_label(&dest->local_label);

	/*
	 * Get back to registering the FEC
	 */
	bgp_send_fec_register_label_msg(dest, true, 0);

	return 0;
}

void bgp_reg_dereg_for_label(struct bgp_dest *dest, struct bgp_path_info *pi,
			     bool reg)
{
	bool with_label_index = false;
	const struct prefix *p;
	bool have_label_to_reg;
	uint32_t ttl = 0;
	uint32_t bos = 0;
	uint32_t exp = 0;
	mpls_label_t label = MPLS_INVALID_LABEL;

	mpls_lse_decode(dest->local_label, &label, &ttl, &exp, &bos);

	have_label_to_reg = bgp_is_valid_label(&dest->local_label) &&
			    label != MPLS_LABEL_IMPLICIT_NULL;

	p = bgp_dest_get_prefix(dest);

	if (BGP_DEBUG(labelpool, LABELPOOL))
		zlog_debug("%s: %pFX: %s ", __func__, p,
			   (reg ? "reg" : "dereg"));

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
			UNSET_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED);
		} else {
			/*
			 * If no label has been registered -- assume any label
			 * from label pool will do. This means that label index
			 * always takes precedence over auto-assigned labels.
			 */
			if (!have_label_to_reg) {
				SET_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED);
				if (BGP_DEBUG(labelpool, LABELPOOL))
					zlog_debug(
						"%s: Requesting label from LP for %pFX",
						__func__, p);
				/* bgp_reg_for_label_callback() will deal with
				 * fec registration when it gets a label from
				 * the pool. This means we'll never register
				 * FECs withoutvalid labels.
				 */
				bgp_lp_get(LP_TYPE_BGP_LU, dest,
					   bgp_reg_for_label_callback);
				return;
			}
		}
	} else {
		UNSET_FLAG(dest->flags, BGP_NODE_LABEL_REQUESTED);
		bgp_lp_release(LP_TYPE_BGP_LU, dest, label);
	}

	bgp_send_fec_register_label_msg(
		dest, reg, with_label_index ? pi->attr->label_index : 0);
}

static int bgp_nlri_get_labels(struct peer *peer, uint8_t *pnt, uint8_t plen,
			       mpls_label_t *label)
{
	uint8_t *data = pnt;
	uint8_t *lim = pnt + plen;
	uint8_t llen = 0;
	uint8_t label_depth = 0;

	if (plen < BGP_LABEL_BYTES)
		return 0;

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
		zlog_info("%pBP rcvd UPDATE with label stack %d deep", peer,
			  label_depth);

	if (!(bgp_is_withdraw_label(label) || label_bos(label)))
		flog_warn(
			EC_BGP_INVALID_LABEL_STACK,
			"%pBP rcvd UPDATE with invalid label stack - no bottom of stack",
			peer);

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
	bool addpath_capable;
	uint32_t addpath_id;
	mpls_label_t label = MPLS_INVALID_LABEL;
	uint8_t llen;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		if (addpath_capable) {

			/* When packet overflow occurs return immediately. */
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;

			if (pnt >= lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
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
		if (llen == 0) {
			flog_err(
				EC_BGP_UPDATE_RCV,
				"%s [Error] Update packet error (wrong label length 0)",
				peer->host);
			return BGP_NLRI_PARSE_ERROR_LABEL_LENGTH;
		}
		p.prefixlen = prefixlen - BSIZE(llen);

		/* There needs to be at least one label */
		if (prefixlen < 24) {
			flog_err(EC_BGP_UPDATE_RCV,
				 "%s [Error] Update packet error (wrong label length %d)",
				 peer->host, prefixlen);
			return BGP_NLRI_PARSE_ERROR_LABEL_LENGTH;
		}

		if ((afi == AFI_IP && p.prefixlen > IPV4_MAX_BITLEN)
		    || (afi == AFI_IP6 && p.prefixlen > IPV6_MAX_BITLEN))
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
					"%s: IPv4 labeled-unicast NLRI is multicast address %pI4, ignoring",
					peer->host, &p.u.prefix4);
				continue;
			}
		}

		/* Check address. */
		if (afi == AFI_IP6 && safi == SAFI_LABELED_UNICAST) {
			if (IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 labeled-unicast NLRI is link-local address %pI6, ignoring",
					peer->host, &p.u.prefix6);

				continue;
			}

			if (IN6_IS_ADDR_MULTICAST(&p.u.prefix6)) {
				flog_err(
					EC_BGP_UPDATE_RCV,
					"%s: IPv6 unicast NLRI is multicast address %pI6, ignoring",
					peer->host, &p.u.prefix6);

				continue;
			}
		}

		if (attr) {
			bgp_update(peer, &p, addpath_id, attr, packet->afi,
				   safi, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   NULL, &label, 1, 0, NULL);
		} else {
			bgp_withdraw(peer, &p, addpath_id, packet->afi,
				     SAFI_UNICAST, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, &label, 1, NULL);
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim) {
		flog_err(
			EC_BGP_UPDATE_RCV,
			"%s [Error] Update packet error / L-U (%td data remaining after parsing)",
			peer->host, lim - pnt);
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;
	}

	return BGP_NLRI_PARSE_OK;
}

bool bgp_labels_same(const mpls_label_t *tbl_a, const uint8_t num_labels_a,
		     const mpls_label_t *tbl_b, const uint8_t num_labels_b)
{
	uint32_t i;

	if (num_labels_a != num_labels_b)
		return false;
	if (num_labels_a == 0)
		return true;

	for (i = 0; i < num_labels_a; i++) {
		if (tbl_a[i] != tbl_b[i])
			return false;
	}
	return true;
}
