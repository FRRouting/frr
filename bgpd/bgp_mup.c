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

/* Add the decomposed MUP NLRI fields to a json object for show output. */
void bgp_mup_route2json(const struct prefix_mup *pm, struct json_object *json)
{
	const struct mup_prefix *mp = &pm->prefix;
	struct prefix_rd prd = {};
	int family;

	if (!mp || !json)
		return;

	json_object_int_add(json, "archType", mp->arch_type);
	json_object_int_add(json, "routeType", mp->route_type);

	memcpy(prd.val, mp->rd, sizeof(prd.val));
	json_object_string_addf(json, "rd", "%pRDP", &prd);

	switch (mp->route_type) {
	case BGP_MUP_ISD_ROUTE:
		family = IS_IPADDR_V4(&mp->isd_route.ip) ? AF_INET : AF_INET6;
		json_object_string_add(json, "ipFamily", family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "ip", "%pIA", &mp->isd_route.ip);
		json_object_int_add(json, "ipLen", mp->isd_route.ip_prefix_length);
		break;
	case BGP_MUP_DSD_ROUTE:
		family = IS_IPADDR_V4(&mp->dsd_route.ip) ? AF_INET : AF_INET6;
		json_object_string_add(json, "ipFamily", family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "ip", "%pIA", &mp->dsd_route.ip);
		break;
	case BGP_MUP_T1ST_ROUTE:
		family = IS_IPADDR_V4(&mp->t1st_route.ip) ? AF_INET : AF_INET6;
		json_object_string_add(json, "ipFamily", family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "ip", "%pIA", &mp->t1st_route.ip);
		json_object_int_add(json, "ipLen", mp->t1st_route.ip_prefix_length);
		break;
	case BGP_MUP_T2ST_ROUTE:
		family = IS_IPADDR_V4(&mp->t2st_route.endpoint_address) ? AF_INET : AF_INET6;
		json_object_string_add(json, "endpointAddressFamily",
				       family == AF_INET ? "ipv4" : "ipv6");
		json_object_string_addf(json, "endpointAddress", "%pIA",
					&mp->t2st_route.endpoint_address);
		json_object_int_add(json, "teid", mp->t2st_route.teid);
		break;
	}
}

/* Render the non-key NLRI data kept with a T1ST/T2ST route: for T1ST the
 * architecture specific fields followed by TLVs, for T2ST the TLVs alone.
 * TLVs are only decomposed for the route types they apply to (draft 3.1.5);
 * everything else is shown as type plus raw hex value.
 */
void bgp_mup_nlri_data_show(const struct bgp_mup_nlri_data *data, uint16_t route_type,
			    struct vty *vty, struct json_object *json_path)
{
	struct json_object *json_tlvs = NULL;
	int off = 0;

	if (route_type == BGP_MUP_T1ST_ROUTE) {
		char buf[INET6_ADDRSTRLEN];
		uint32_t teid;
		uint8_t qfi, ep_len, src_len;

		if (data->length <
		    BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES + 2 * BGP_MUP_ADDR_LEN_BYTES)
			return;
		memcpy(&teid, data->val, BGP_MUP_TEID_BYTES);
		teid = ntohl(teid);
		off = BGP_MUP_TEID_BYTES;
		qfi = data->val[off++];
		ep_len = data->val[off++];
		if (json_path) {
			json_object_int_add(json_path, "teid", teid);
			json_object_int_add(json_path, "qfi", qfi);
		} else
			vty_out(vty, "      TEID %u, QFI %u\n", teid, qfi);
		if (!(ep_len / 8) || off + ep_len / 8 + BGP_MUP_ADDR_LEN_BYTES > data->length)
			return;
		inet_ntop(ep_len == IPV4_MAX_BITLEN ? AF_INET : AF_INET6, data->val + off, buf,
			  sizeof(buf));
		if (json_path)
			json_object_string_add(json_path, "endpointAddress", buf);
		else
			vty_out(vty, "      Endpoint Address: %s\n", buf);
		off += ep_len / 8;
		src_len = data->val[off++];
		if (src_len / 8) {
			if (off + src_len / 8 > data->length)
				return;
			inet_ntop(src_len == IPV4_MAX_BITLEN ? AF_INET : AF_INET6, data->val + off,
				  buf, sizeof(buf));
			if (json_path)
				json_object_string_add(json_path, "sourceAddress", buf);
			else
				vty_out(vty, "      Source Address: %s\n", buf);
			off += src_len / 8;
		}
	}

	if (off >= data->length)
		return;

	if (json_path)
		json_tlvs = json_object_new_array();
	else
		vty_out(vty, "      MUP TLVs:\n");

	while (off + BGP_MUP_TLV_HDR_BYTES <= data->length) {
		const uint8_t *val = data->val + off + BGP_MUP_TLV_HDR_BYTES;
		uint8_t type = data->val[off];
		uint8_t len = data->val[off + 1];
		struct json_object *json_tlv = NULL;
		bool decoded = false;

		if (off + BGP_MUP_TLV_HDR_BYTES + len > data->length)
			break;

		if (json_path) {
			json_tlv = json_object_new_object();
			json_object_int_add(json_tlv, "type", type);
		}

		if (route_type == BGP_MUP_T2ST_ROUTE) {
			switch (type) {
			case BGP_MUP_TLV_SESSION_PARAMS: {
				uint32_t teid;

				memcpy(&teid, val, BGP_MUP_TEID_BYTES);
				teid = ntohl(teid);
				if (json_tlv) {
					json_object_int_add(json_tlv, "teid", teid);
					json_object_int_add(json_tlv, "qfi",
							    val[BGP_MUP_TEID_BYTES]);
				} else
					vty_out(vty,
						"        Session Parameters: TEID %u, QFI %u\n",
						teid, val[BGP_MUP_TEID_BYTES]);
				decoded = true;
				break;
			}
			case BGP_MUP_TLV_INTERWORK_ENDPOINT:
			case BGP_MUP_TLV_SOURCE_ADDRESS: {
				const char *name = (type == BGP_MUP_TLV_INTERWORK_ENDPOINT)
							   ? "Interwork Endpoint"
							   : "Source Address";
				const char *key = (type == BGP_MUP_TLV_INTERWORK_ENDPOINT)
							  ? "interworkEndpoint"
							  : "sourceAddress";

				if (len == IPV4_MAX_BYTELEN) {
					struct in_addr addr;

					memcpy(&addr, val, sizeof(addr));
					if (json_tlv)
						json_object_string_addf(json_tlv, key, "%pI4",
									&addr);
					else
						vty_out(vty, "        %s: %pI4\n", name, &addr);
					decoded = true;
				} else if (len == IPV6_MAX_BYTELEN) {
					struct in6_addr addr;

					memcpy(&addr, val, sizeof(addr));
					if (json_tlv)
						json_object_string_addf(json_tlv, key, "%pI6",
									&addr);
					else
						vty_out(vty, "        %s: %pI6\n", name, &addr);
					decoded = true;
				}
				break;
			}
			}
		}

		if (!decoded) {
			char hex[2 * UINT8_MAX + 1];
			int i;

			for (i = 0; i < len; i++)
				snprintf(hex + 2 * i, 3, "%02x", val[i]);
			hex[2 * len] = '\0';
			if (json_tlv)
				json_object_string_add(json_tlv, "value", hex);
			else
				vty_out(vty, "        Type %u: %s\n", type, hex);
		}

		if (json_tlv)
			json_object_array_add(json_tlvs, json_tlv);

		off += BGP_MUP_TLV_HDR_BYTES + len;
	}

	if (json_path)
		json_object_object_add(json_path, "mupTlvs", json_tlvs);
}

/* On-wire size of one BGP-MUP NLRI: fixed header plus the route body.
 * T1ST/T2ST length excludes the optional TLVs, so reserve the 1-octet
 * Length field maximum for them.
 */
size_t bgp_mup_prefix_size(const struct prefix *p)
{
	const struct prefix_mup *mp = (const struct prefix_mup *)p;

	if (mp->prefix.route_type == BGP_MUP_T1ST_ROUTE ||
	    mp->prefix.route_type == BGP_MUP_T2ST_ROUTE)
		return BGP_MUP_HDR_BYTES + UINT8_MAX;

	return BGP_MUP_HDR_BYTES + mp->prefix.length;
}

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
			   const struct prefix_rd *prd, const struct attr *attr,
			   bool addpath_capable, uint32_t addpath_tx_id)
{
	const struct prefix_mup *pm = (const struct prefix_mup *)p;
	const struct mup_prefix *mp = &pm->prefix;
	const struct bgp_mup_nlri_data *tlvs;
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

	case BGP_MUP_T1ST_ROUTE:
		/* RD + Prefix Length + Prefix, then the architecture specific
		 * fields and any TLVs carried on the attr, verbatim
		 * (draft 3.1.3.1).
		 */
		prefix_octets = PSIZE(mp->t1st_route.ip_prefix_length);
		stream_put(s, mp->rd, RD_BYTES);
		stream_putc(s, mp->t1st_route.ip_prefix_length);
		stream_put(s, &mp->t1st_route.ip.ip.addr, prefix_octets);
		total_len = RD_BYTES + BGP_MUP_PREFIX_LEN_BYTES + prefix_octets;

		tlvs = attr ? bgp_attr_get_mup_nlri_data(attr) : NULL;
		if (tlvs && total_len + tlvs->length <= UINT8_MAX) {
			stream_put(s, tlvs->val, tlvs->length);
			total_len += tlvs->length;
		} else
			zlog_warn("%s: T1ST %pFX architecture specific fields %s, encoding an incomplete NLRI",
				  __func__, p, tlvs ? "exceed the NLRI Length" : "missing");
		break;

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

		/* Re-encode the received optional TLVs verbatim (draft 3.1.4.1). */
		tlvs = attr ? bgp_attr_get_mup_nlri_data(attr) : NULL;
		if (tlvs) {
			if (total_len + tlvs->length <= UINT8_MAX) {
				stream_put(s, tlvs->val, tlvs->length);
				total_len += tlvs->length;
			} else
				zlog_warn("%s: T2ST %pFX TLVs (%u octets) exceed the NLRI Length, not encoded",
					  __func__, p, tlvs->length);
		}
		break;
	}

	default:
		break;
	}

	stream_putc_at(s, len_pos, total_len);
}

/* Fill in the common prefix_mup fields for a parsed BGP-MUP NLRI.  T1ST
 * and T2ST callers pass the mandatory-part length: TLVs are not route key.
 */
static inline void bgp_mup_prefix_init(struct prefix_mup *p, uint16_t route_type, int psize)
{
	p->family = AF_MUP;
	p->prefixlen = BGP_MUP_ROUTE_PREFIXLEN;
	p->prefix.arch_type = BGP_MUP_ARCH_3GPP_5G;
	p->prefix.route_type = route_type;
	p->prefix.length = psize;
}

/* Validate the optional TLV region of a T1ST/T2ST route body: 0 if valid
 * or empty, -1 if malformed (treat-as-withdraw).  Unknown types only need
 * to be structurally sound; per-type length rules apply only to the route
 * types the TLV is applicable to (draft 3.1.5: Types 1-3 apply to ST2).
 */
int bgp_mup_parse_tlvs(uint16_t route_type, const uint8_t *buf, int len)
{
	uint8_t type, tlv_len;
	int off = 0;

	while (off < len) {
		if (off + BGP_MUP_TLV_HDR_BYTES > len)
			return -1;
		type = buf[off];
		tlv_len = buf[off + 1];
		if (off + BGP_MUP_TLV_HDR_BYTES + tlv_len > len)
			return -1;

		if (route_type == BGP_MUP_T2ST_ROUTE) {
			switch (type) {
			case BGP_MUP_TLV_SESSION_PARAMS:
				if (tlv_len != BGP_MUP_TEID_BYTES + BGP_MUP_QFI_BYTES)
					return -1;
				break;
			case BGP_MUP_TLV_INTERWORK_ENDPOINT:
			case BGP_MUP_TLV_SOURCE_ADDRESS:
				if (tlv_len != IPV4_MAX_BYTELEN && tlv_len != IPV6_MAX_BYTELEN)
					return -1;
				break;
			}
		}

		off += BGP_MUP_TLV_HDR_BYTES + tlv_len;
	}

	return 0;
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
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
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
			   BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
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
	uint32_t teid;
	uint8_t prefix_len;
	uint8_t prefix_octets;
	uint8_t ep_len, src_len;
	uint8_t ep_octets, src_octets;
	int off;
	int arch_off;

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

	/* The architecture specific fields are validated but excluded from
	 * the route key (draft 3.1.3); they ride on the attr instead.
	 */
	arch_off = off;
	memcpy(&teid, pfx + off, BGP_MUP_TEID_BYTES);
	teid = ntohl(teid);
	off += BGP_MUP_TEID_BYTES;
	/* draft 3.1.3.1: TEID MUST NOT be 0. */
	if (teid == 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI TEID=0",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	off++; /* QFI */
	/* draft 3.1.3.1: Endpoint Length must be a full host address. */
	ep_len = pfx[off++];
	if ((afi == AFI_IP && ep_len != IPV4_MAX_BITLEN) ||
	    (afi == AFI_IP6 && ep_len != IPV6_MAX_BITLEN)) {
		flog_err(EC_BGP_MUP_PACKET,
			 "%u:%s - Rx BGP-MUP T1ST NLRI invalid endpoint length %u for AFI %u",
			 peer->bgp->vrf_id, peer->host, ep_len, afi);
		return -1;
	}
	ep_octets = ep_len / 8;
	if (off + ep_octets + BGP_MUP_ADDR_LEN_BYTES > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated endpoint",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
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
	if (src_len) {
		src_octets = src_len / 8;
		if (off + src_octets > psize) {
			flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI truncated source",
				 peer->bgp->vrf_id, peer->host);
			return -1;
		}
		off += src_octets;
	}

	/* Optional TLVs may follow the Source Address (draft 3.1.3.1). */
	if (bgp_mup_parse_tlvs(BGP_MUP_T1ST_ROUTE, pfx + off, psize - off) < 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T1ST NLRI malformed TLVs",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}
	bgp_mup_prefix_init(&p, BGP_MUP_T1ST_ROUTE, arch_off);

	if (attr) {
		struct attr attr_tmp = *attr;
		struct bgp_mup_nlri_data *data;

		/* Carry the architecture specific fields and any TLVs on the
		 * attr so re-advertisement re-encodes them unchanged.
		 */
		data = mup_nlri_data_intern(mup_nlri_data_new(pfx + arch_off, psize - arch_off));
		bgp_attr_set_mup_nlri_data(&attr_tmp, data);
		bgp_update(peer, (struct prefix *)&p, addpath_id, &attr_tmp, afi, safi,
			   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
		mup_nlri_data_unintern(&data);
	} else
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
	int mandatory;

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
	mandatory = RD_BYTES + BGP_MUP_ADDR_LEN_BYTES + addr_octets + teid_octets;
	if (mandatory > psize) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI truncated TEID",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	bgp_mup_prefix_init(&p, BGP_MUP_T2ST_ROUTE, mandatory);
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

	/* Optional TLVs may follow the TEID (draft 3.1.4.1). */
	if (bgp_mup_parse_tlvs(BGP_MUP_T2ST_ROUTE, pfx + mandatory, psize - mandatory) < 0) {
		flog_err(EC_BGP_MUP_PACKET, "%u:%s - Rx BGP-MUP T2ST NLRI malformed TLVs",
			 peer->bgp->vrf_id, peer->host);
		return -1;
	}

	if (attr) {
		struct attr attr_tmp = *attr;
		struct bgp_mup_nlri_data *tlvs = NULL;

		/* Carry the raw TLV bytes on the attr so re-advertisement
		 * re-encodes them unchanged (draft 3.1.4.1).
		 */
		if (psize > mandatory) {
			tlvs = mup_nlri_data_intern(
				mup_nlri_data_new(pfx + mandatory, psize - mandatory));
			bgp_attr_set_mup_nlri_data(&attr_tmp, tlvs);
		}
		bgp_update(peer, (struct prefix *)&p, addpath_id, &attr_tmp, afi, safi,
			   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, &prd, NULL, 0, 0, NULL, NULL);
		if (tlvs)
			mup_nlri_data_unintern(&tlvs);
	} else
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
