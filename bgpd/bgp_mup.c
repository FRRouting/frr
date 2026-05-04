// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#include <zebra.h>

#include "prefix.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_mup.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_route.h"

/* On-wire size of one BGP-MUP NLRI: fixed header plus the route body. */
size_t bgp_mup_prefix_size(const struct prefix *p)
{
	const struct prefix_mup *mp = (const struct prefix_mup *)p;

	return BGP_MUP_HDR_BYTES + mp->prefix.length;
}

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
			   const struct prefix_rd *prd, bool addpath_capable,
			   uint32_t addpath_tx_id)
{
	const struct prefix_mup *pm = (const struct prefix_mup *)p;
	const struct mup_prefix *mp = &pm->prefix;
	uint8_t prefix_octets;
	uint8_t addr_octets;
	uint8_t total_len = 0;
	size_t len_pos;

	/* prd is unused: the RD lives inside struct mup_prefix. */
	if (addpath_capable)
		stream_putl(s, addpath_tx_id);

	stream_putc(s, mp->arch_type);
	stream_putw(s, mp->route_type);

	/* Patch the Length octet once the route body length is known. */
	len_pos = stream_get_endp(s);
	stream_putc(s, 0);

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		/* RD + Prefix Length + Prefix. */
		prefix_octets = PSIZE(mp->isd_route.ip_prefix_length);
		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->isd_route.ip_prefix_length);
		stream_put(s, &mp->isd_route.ip.ip.addr, prefix_octets);
		total_len = RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + prefix_octets;
		break;

	case BGP_MUP_DSD_ROUTE:
		/* RD + Address. */
		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		stream_put(s, mp->rd, RD_BYTES);
		stream_put(s, &mp->dsd_route.ip.ip.addr, addr_octets);
		total_len = RD_BYTES + addr_octets;
		break;

	case BGP_MUP_T1ST_ROUTE: {
		/* RD + Prefix Length + Prefix + TEID + QFI + Endpoint Length
		 * + Endpoint + Source Length [+ Source].
		 */
		const struct mup_t1st_3gpp_5g *e = &mp->t1st_route.t1st_3gpp_5g;
		uint8_t ep_octets;
		uint8_t src_octets;

		prefix_octets = PSIZE(mp->t1st_route.ip_prefix_length);
		ep_octets = e->endpoint_address_length / 8;
		src_octets = e->source_address_length / 8;

		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->t1st_route.ip_prefix_length);
		stream_put(s, &mp->t1st_route.ip.ip.addr, prefix_octets);
		stream_putl(s, e->teid);
		stream_putc(s, e->qfi);
		stream_putc(s, e->endpoint_address_length);
		stream_put(s, &e->endpoint_address.ip.addr, ep_octets);
		stream_putc(s, e->source_address_length);
		if (src_octets)
			stream_put(s, &e->source_address.ip.addr, src_octets);

		total_len = RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + prefix_octets +
			    BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES + BGP_MUP_ADDR_LEN_BYTES +
			    ep_octets + BGP_MUP_ADDR_LEN_BYTES + src_octets;
		break;
	}

	case BGP_MUP_T2ST_ROUTE: {
		/* RD + Endpoint Length + Endpoint + TEID (0..4 trailing octets). */
		uint8_t teid_bits;
		uint8_t teid_octets;
		uint32_t teid_be;

		addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
		teid_bits = (mp->t2st_route.endpoint_address_length > addr_octets * 8)
				    ? mp->t2st_route.endpoint_address_length - (addr_octets * 8)
				    : 0;
		/* draft 3.1.4.1: the TEID field is at most 4 octets. */
		if (teid_bits > BGP_MUP_TEID_BYTES * 8)
			teid_bits = BGP_MUP_TEID_BYTES * 8;
		teid_octets = (teid_bits + 7) / 8;
		teid_be = htonl(mp->t2st_route.teid);

		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->t2st_route.endpoint_address_length);
		stream_put(s, &mp->t2st_route.endpoint_address.ip.addr, addr_octets);
		if (teid_octets)
			stream_put(s, &teid_be, teid_octets);

		total_len = RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets + teid_octets;
		break;
	}

	default:
		break;
	}

	stream_putc_at(s, len_pos, total_len);
}

/* Fill in the common prefix_mup fields for a parsed BGP-MUP NLRI. */
static inline void bgp_mup_prefix_init(struct prefix_mup *p, uint16_t route_type, int psize)
{
	p->family = AF_MUP;
	p->prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p->prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p->prefix.route_type = route_type;
	p->prefix.length = psize;
}

static int bgp_mup_process_isd_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				     uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t prefix_len;
	uint8_t prefix_octets;

	if (psize < RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP ISD NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);

	prefix_len = pfx[RD_BYTES];
	if ((afi == AFI_IP && prefix_len > IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && prefix_len > IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP ISD NLRI bad prefix length %u",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return -1;
	}

	prefix_octets = PSIZE(prefix_len);
	if (psize - (RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES) != prefix_octets) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP ISD NLRI prefix length mismatch",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_ISD_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);
	p.prefix.isd_route.ip_prefix_length = prefix_len;
	p.prefix.isd_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.isd_route.ip.ip.addr, pfx + RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES,
	       prefix_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_dsd_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				     uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;

	if ((afi == AFI_IP && psize != RD_BYTES + IPV4_MAX_BYTELEN) ||
	    (afi == AFI_IP6 && psize != RD_BYTES + IPV6_MAX_BYTELEN)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP DSD NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);

	bgp_mup_prefix_init(&p, BGP_MUP_DSD_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);

	if (afi == AFI_IP) {
		addr_octets = IPV4_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V4;
	} else {
		addr_octets = IPV6_MAX_BYTELEN;
		p.prefix.dsd_route.ip.ipa_type = IPADDR_V6;
	}
	memcpy(&p.prefix.dsd_route.ip.ip.addr, pfx + RD_BYTES, addr_octets);

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_t1st_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				      uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	struct mup_t1st_3gpp_5g *ext;
	uint8_t prefix_len;
	uint8_t prefix_octets;
	uint8_t ep_len, src_len;
	uint8_t ep_octets, src_octets;
	int off;

	/* Minimum: RD + Prefix Length + TEID + QFI + Endpoint Length +
	 * Source Length, before any prefix or endpoint address bytes.
	 */
	if (psize < RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES +
			    BGP_MUP_ADDR_LEN_BYTES + BGP_MUP_ADDR_LEN_BYTES) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);
	off = RD_BYTES;

	prefix_len = pfx[off++];
	if ((afi == AFI_IP && prefix_len > IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && prefix_len > IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI bad prefix length %u",
			 peer->bgp->vrf_id, peer->host, prefix_len);
		return -1;
	}
	prefix_octets = PSIZE(prefix_len);

	bgp_mup_prefix_init(&p, BGP_MUP_T1ST_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);
	p.prefix.t1st_route.ip_prefix_length = prefix_len;
	p.prefix.t1st_route.ip.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;

	if (off + prefix_octets + BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES + BGP_MUP_ADDR_LEN_BYTES >
	    psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	memcpy(&p.prefix.t1st_route.ip.ip.addr, pfx + off, prefix_octets);
	off += prefix_octets;

	ext = &p.prefix.t1st_route.t1st_3gpp_5g;
	memcpy(&ext->teid, pfx + off, BGP_MUP_TEID_BYTES);
	ext->teid = ntohl(ext->teid);
	off += BGP_MUP_TEID_BYTES;
	/* draft 3.1.3.1: TEID MUST NOT be 0. */
	if (ext->teid == 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI TEID=0",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	ext->qfi = pfx[off++];
	/* draft 3.1.3.1: Endpoint Length must be a full host address. */
	ep_len = pfx[off++];
	if ((afi == AFI_IP && ep_len != IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && ep_len != IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET,
			 "%u:%s - Rx BGP-MUP T1ST NLRI invalid endpoint length %u for AFI %u",
			 peer->bgp->vrf_id, peer->host, ep_len, afi);
		return -1;
	}
	ext->endpoint_address_length = ep_len;
	ep_octets = ep_len / 8;
	if (off + ep_octets + BGP_MUP_ADDR_LEN_BYTES > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	ext->endpoint_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&ext->endpoint_address.ip.addr, pfx + off, ep_octets);
	off += ep_octets;

	/* Source Length 0 means no Source Address follows. */
	src_len = pfx[off++];
	if (src_len != 0 && ((afi == AFI_IP && src_len != IPV4_MAX_BITLEN) ||
			     (afi == AFI_IP6 && src_len != IPV6_MAX_BITLEN))) {
		flog_err(EC_BGP_MUP_PACKET,
			 "%u:%s - Rx BGP-MUP T1ST NLRI invalid source length %u for AFI %u",
			 peer->bgp->vrf_id, peer->host, src_len, afi);
		return -1;
	}
	ext->source_address_length = src_len;
	if (src_len) {
		src_octets = src_len / 8;
		if (off + src_octets > psize) {
			flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated source",
				 peer->bgp->vrf_id, peer->host);
			return -1;
		}
		ext->source_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
		memcpy(&ext->source_address.ip.addr, pfx + off, src_octets);
	}

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

static int bgp_mup_process_t2st_route(struct peer *peer, afi_t afi, safi_t safi, struct attr *attr,
				      uint8_t *pfx, int psize, uint32_t addpath_id)
{
	struct prefix_rd prd = {};
	struct prefix_mup p = {};
	uint8_t addr_octets;
	uint8_t teid_bits;
	uint8_t teid_octets;
	uint32_t teid_be = 0;
	uint8_t ea_len;

	if (psize < RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + IPV4_MAX_BYTELEN) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI invalid length %d",
			 peer->bgp->vrf_id, peer->host, psize);
		return -1;
	}

	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;
	memcpy(prd.val, pfx, RD_BYTES);

	ea_len = pfx[RD_BYTES];
	if ((afi == AFI_IP && ea_len > IPV4_MAX_BITLEN + BGP_MUP_TEID_BYTES * 8) ||
	    (afi == AFI_IP6 && ea_len > IPV6_MAX_BITLEN + BGP_MUP_TEID_BYTES * 8)) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI bad endpoint length %u",
			 peer->bgp->vrf_id, peer->host, ea_len);
		return -1;
	}

	addr_octets = (afi == AFI_IP) ? IPV4_MAX_BYTELEN : IPV6_MAX_BYTELEN;
	if (RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	teid_bits = (ea_len > addr_octets * 8) ? ea_len - addr_octets * 8 : 0;
	teid_octets = (teid_bits + 7) / 8;
	if (RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets + teid_octets > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI truncated TEID",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_T2ST_ROUTE, psize);
	memcpy(p.prefix.rd, prd.val, RD_BYTES);
	p.prefix.t2st_route.endpoint_address_length = ea_len;
	p.prefix.t2st_route.endpoint_address.ipa_type = (afi == AFI_IP) ? IPADDR_V4 : IPADDR_V6;
	memcpy(&p.prefix.t2st_route.endpoint_address.ip.addr,
	       pfx + RD_BYTES + BGP_MUP_ADDR_LEN_BYTES, addr_octets);
	if (teid_octets) {
		memcpy(&teid_be, pfx + RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets,
		       teid_octets);
		/* Mask the sub-octet padding bits so they do not enter the
		 * route key or pass the TEID=0 check below.
		 */
		p.prefix.t2st_route.teid = ntohl(teid_be) &
					   (0xffffffffU << (BGP_MUP_TEID_BYTES * 8 - teid_bits));
	}
	/* draft 3.1.4.1: a TEID field that is present MUST NOT be 0; an
	 * endpoint-level aggregate carries no TEID field and is valid.
	 */
	if (teid_octets && p.prefix.t2st_route.teid == 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI TEID=0",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	if (attr)
		bgp_update(peer, (struct prefix *)&p, addpath_id, attr, afi, safi, ZEBRA_ROUTE_BGP,
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL);
	else
		bgp_withdraw(peer, (struct prefix *)&p, addpath_id, afi, safi, ZEBRA_ROUTE_BGP,
			     BGP_ROUTE_NORMAL, &prd, NULL, 0);
	return 0;
}

int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	int ret;
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint32_t addpath_id;
	bool addpath_capable;
	int psize = 0;
	uint8_t arch_type;
	uint16_t route_type;

	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;
	addpath_id = 0;

	addpath_capable = bgp_addpath_encode_rx(peer, afi, safi);

	for (; pnt < lim; pnt += psize) {
		if (addpath_capable) {
			if (pnt + BGP_ADDPATH_ID_LEN > lim)
				return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
			memcpy(&addpath_id, pnt, BGP_ADDPATH_ID_LEN);
			addpath_id = ntohl(addpath_id);
			pnt += BGP_ADDPATH_ID_LEN;
		}

		/* Architecture Type + Route Type + Length. */
		if (pnt + BGP_MUP_HDR_BYTES > lim)
			return BGP_NLRI_PARSE_ERROR_MUP_MISSING_TYPE;

		arch_type = pnt[0];
		memcpy(&route_type, pnt + BGP_MUP_ARCH_TYPE_BYTES, BGP_MUP_ROUTE_TYPE_BYTES);
		route_type = ntohs(route_type);
		psize = pnt[BGP_MUP_ARCH_TYPE_BYTES + BGP_MUP_ROUTE_TYPE_BYTES];
		pnt += BGP_MUP_HDR_BYTES;

		if (pnt + psize > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		/* draft 3.1 only defines 3gpp-5g; skip other architectures. */
		if (arch_type != BGP_MUP_ARCH_3GPP_5G)
			continue;

		switch (route_type) {
		case BGP_MUP_ISD_ROUTE:
			ret = bgp_mup_process_isd_route(peer, afi, safi, withdraw ? NULL : attr,
							pnt, psize, addpath_id);
			break;

		case BGP_MUP_DSD_ROUTE:
			ret = bgp_mup_process_dsd_route(peer, afi, safi, withdraw ? NULL : attr,
							pnt, psize, addpath_id);
			break;

		case BGP_MUP_T1ST_ROUTE:
			ret = bgp_mup_process_t1st_route(peer, afi, safi, withdraw ? NULL : attr,
							 pnt, psize, addpath_id);
			break;

		case BGP_MUP_T2ST_ROUTE:
			ret = bgp_mup_process_t2st_route(peer, afi, safi, withdraw ? NULL : attr,
							 pnt, psize, addpath_id);
			break;

		default:
			/* Unknown route type: silently ignore (draft 3.1). */
			ret = BGP_NLRI_PARSE_OK;
			break;
		}

		/* draft 3.1.x: a malformed NLRI is treat-as-withdraw
		 * (RFC 7606) -- skip it and keep parsing the UPDATE.
		 */
		if (ret < 0)
			continue;
	}

	if (pnt != lim)
		return BGP_NLRI_PARSE_ERROR_PACKET_LENGTH;

	return BGP_NLRI_PARSE_OK;
}
