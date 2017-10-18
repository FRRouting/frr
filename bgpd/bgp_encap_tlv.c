/*
 * Copyright 2015, LabN Consulting, L.L.C.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "stream.h"

#include "bgpd.h"
#include "bgp_attr.h"

#include "bgp_encap_types.h"
#include "bgp_encap_tlv.h"

/***********************************************************************
 *			SUBTLV ENCODE
 ***********************************************************************/

/* rfc5512 4.1 */
static struct bgp_attr_encap_subtlv *subtlv_encode_encap_l2tpv3_over_ip(
	struct bgp_tea_subtlv_encap_l2tpv3_over_ip *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;
	int total = 4 + st->cookie_length;

	/* sanity check */
	assert(st->cookie_length <= sizeof(st->cookie));
	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION;
	new->length = total;
	p = new->value;

	*p++ = (st->sessionid & 0xff000000) >> 24;
	*p++ = (st->sessionid & 0xff0000) >> 16;
	*p++ = (st->sessionid & 0xff00) >> 8;
	*p++ = (st->sessionid & 0xff);
	memcpy(p, st->cookie, st->cookie_length);
	return new;
}

/* rfc5512 4.1 */
static struct bgp_attr_encap_subtlv *
subtlv_encode_encap_gre(struct bgp_tea_subtlv_encap_gre_key *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;
	int total = 4;

	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION;
	new->length = total;
	p = new->value;

	*p++ = (st->gre_key & 0xff000000) >> 24;
	*p++ = (st->gre_key & 0xff0000) >> 16;
	*p++ = (st->gre_key & 0xff00) >> 8;
	*p++ = (st->gre_key & 0xff);
	return new;
}

static struct bgp_attr_encap_subtlv *
subtlv_encode_encap_pbb(struct bgp_tea_subtlv_encap_pbb *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;
	int total = 1 + 3 + 6 + 2; /* flags + isid + madaddr + vid */

	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION;
	new->length = total;
	p = new->value;

	*p++ = (st->flag_isid ? 0x80 : 0) | (st->flag_vid ? 0x40 : 0) | 0;
	if (st->flag_isid) {
		*p = (st->isid & 0xff0000) >> 16;
		*(p + 1) = (st->isid & 0xff00) >> 8;
		*(p + 2) = (st->isid & 0xff);
	}
	p += 3;
	memcpy(p, st->macaddr, 6);
	p += 6;
	if (st->flag_vid) {
		*p++ = (st->vid & 0xf00) >> 8;
		*p++ = st->vid & 0xff;
	}
	return new;
}

/* rfc5512 4.2 */
static struct bgp_attr_encap_subtlv *
subtlv_encode_proto_type(struct bgp_tea_subtlv_proto_type *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;
	int total = 2;

	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_PROTO_TYPE;
	new->length = total;
	p = new->value;

	*p++ = (st->proto & 0xff00) >> 8;
	*p++ = (st->proto & 0xff);
	return new;
}

/* rfc5512 4.3 */
static struct bgp_attr_encap_subtlv *
subtlv_encode_color(struct bgp_tea_subtlv_color *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;
	int total = 8;

	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_COLOR;
	new->length = total;
	p = new->value;

	*p++ = 0x03; /* transitive*/
	*p++ = 0x0b;
	*p++ = 0; /* reserved */
	*p++ = 0; /* reserved */

	*p++ = (st->color & 0xff000000) >> 24;
	*p++ = (st->color & 0xff0000) >> 16;
	*p++ = (st->color & 0xff00) >> 8;
	*p++ = (st->color & 0xff);

	return new;
}

/* rfc 5566 4. */
static struct bgp_attr_encap_subtlv *
subtlv_encode_ipsec_ta(struct bgp_tea_subtlv_ipsec_ta *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;
	int total = 2 + st->authenticator_length;

	/* sanity check */
	assert(st->authenticator_length <= sizeof(st->value));
	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_IPSEC_TA;
	new->length = total;
	p = new->value;

	*p++ = (st->authenticator_type & 0xff00) >> 8;
	*p++ = st->authenticator_type & 0xff;
	memcpy(p, st->value, st->authenticator_length);
	return new;
}

/* draft-rosen-idr-tunnel-encaps 2.1 */
static struct bgp_attr_encap_subtlv *
subtlv_encode_remote_endpoint(struct bgp_tea_subtlv_remote_endpoint *st)
{
	struct bgp_attr_encap_subtlv *new;
	uint8_t *p;

	int total = (st->family == AF_INET ? 8 : 20);

	assert(total <= 0xff);

	new = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + total);
	assert(new);
	new->type = BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT;
	new->length = total;
	p = new->value;
	if (st->family == AF_INET) {
		memcpy(p, &(st->ip_address.v4.s_addr), 4);
		p += 4;
	} else {
		assert(st->family == AF_INET6);
		memcpy(p, &(st->ip_address.v6.s6_addr), 16);
		p += 16;
	}
	memcpy(p, &(st->as4), 4);
	return new;
}

/***********************************************************************
 *		TUNNEL TYPE-SPECIFIC TLV ENCODE
 ***********************************************************************/

/*
 * requires "extra" and "last" to be defined in caller
 */
#define ENC_SUBTLV(flag, function, field)                                      \
	do {                                                                   \
		struct bgp_attr_encap_subtlv *new;                             \
		if (CHECK_FLAG(bet->valid_subtlvs, (flag))) {                  \
			new = function(&bet->field);                           \
			if (last) {                                            \
				last->next = new;                              \
			} else {                                               \
				attr->encap_subtlvs = new;                     \
			}                                                      \
			last = new;                                            \
		}                                                              \
	} while (0)

void bgp_encap_type_l2tpv3overip_to_tlv(
	struct bgp_encap_type_l2tpv3_over_ip *bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_L2TPV3_OVER_IP;

	assert(CHECK_FLAG(bet->valid_subtlvs, BGP_TEA_SUBTLV_ENCAP));

	ENC_SUBTLV(BGP_TEA_SUBTLV_ENCAP, subtlv_encode_encap_l2tpv3_over_ip,
		   st_encap);
	ENC_SUBTLV(BGP_TEA_SUBTLV_PROTO_TYPE, subtlv_encode_proto_type,
		   st_proto);
	ENC_SUBTLV(BGP_TEA_SUBTLV_COLOR, subtlv_encode_color, st_color);
	ENC_SUBTLV(BGP_TEA_SUBTLV_REMOTE_ENDPOINT,
		   subtlv_encode_remote_endpoint, st_endpoint);
}

void bgp_encap_type_gre_to_tlv(
	struct bgp_encap_type_gre *bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_GRE;

	ENC_SUBTLV(BGP_TEA_SUBTLV_ENCAP, subtlv_encode_encap_gre, st_encap);
	ENC_SUBTLV(BGP_TEA_SUBTLV_PROTO_TYPE, subtlv_encode_proto_type,
		   st_proto);
	ENC_SUBTLV(BGP_TEA_SUBTLV_COLOR, subtlv_encode_color, st_color);
	ENC_SUBTLV(BGP_TEA_SUBTLV_REMOTE_ENDPOINT,
		   subtlv_encode_remote_endpoint, st_endpoint);
}

void bgp_encap_type_ip_in_ip_to_tlv(
	struct bgp_encap_type_ip_in_ip *bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_IP_IN_IP;

	ENC_SUBTLV(BGP_TEA_SUBTLV_PROTO_TYPE, subtlv_encode_proto_type,
		   st_proto);
	ENC_SUBTLV(BGP_TEA_SUBTLV_COLOR, subtlv_encode_color, st_color);
	ENC_SUBTLV(BGP_TEA_SUBTLV_REMOTE_ENDPOINT,
		   subtlv_encode_remote_endpoint, st_endpoint);
}

void bgp_encap_type_transmit_tunnel_endpoint(
	struct bgp_encap_type_transmit_tunnel_endpoint
		*bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_TRANSMIT_TUNNEL_ENDPOINT;

	/* no subtlvs for this type */
}

void bgp_encap_type_ipsec_in_tunnel_mode_to_tlv(
	struct bgp_encap_type_ipsec_in_tunnel_mode *bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_IPSEC_IN_TUNNEL_MODE;

	ENC_SUBTLV(BGP_TEA_SUBTLV_IPSEC_TA, subtlv_encode_ipsec_ta,
		   st_ipsec_ta);
}

void bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode_to_tlv(
	struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode
		*bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype =
		BGP_ENCAP_TYPE_IP_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE;

	ENC_SUBTLV(BGP_TEA_SUBTLV_IPSEC_TA, subtlv_encode_ipsec_ta,
		   st_ipsec_ta);
}

void bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode_to_tlv(
	struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode
		*bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype =
		BGP_ENCAP_TYPE_MPLS_IN_IP_TUNNEL_WITH_IPSEC_TRANSPORT_MODE;

	ENC_SUBTLV(BGP_TEA_SUBTLV_IPSEC_TA, subtlv_encode_ipsec_ta,
		   st_ipsec_ta);
}

void bgp_encap_type_pbb_to_tlv(
	struct bgp_encap_type_pbb *bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *last;

	/* advance to last subtlv */
	for (last = attr->encap_subtlvs; last && last->next; last = last->next)
		;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_PBB;

	assert(CHECK_FLAG(bet->valid_subtlvs, BGP_TEA_SUBTLV_ENCAP));
	ENC_SUBTLV(BGP_TEA_SUBTLV_ENCAP, subtlv_encode_encap_pbb, st_encap);
}

void bgp_encap_type_vxlan_to_tlv(
	struct bgp_encap_type_vxlan *bet, /* input structure */
	struct attr *attr)
{
	struct bgp_attr_encap_subtlv *tlv;
	uint32_t vnid;

	attr->encap_tunneltype = BGP_ENCAP_TYPE_VXLAN;

	if (bet == NULL || !bet->vnid)
		return;
	if (attr->encap_subtlvs)
		XFREE(MTYPE_ENCAP_TLV, attr->encap_subtlvs);
	tlv = XCALLOC(MTYPE_ENCAP_TLV,
		      sizeof(struct bgp_attr_encap_subtlv) + 12);
	tlv->type = 1; /* encapsulation type */
	tlv->length = 12;
	if (bet->vnid) {
		vnid = htonl(bet->vnid | VXLAN_ENCAP_MASK_VNID_VALID);
		memcpy(&tlv->value, &vnid, 4);
	}
	if (bet->mac_address) {
		char *ptr = (char *)&tlv->value + 4;
		memcpy(ptr, bet->mac_address, 6);
	}
	attr->encap_subtlvs = tlv;
	return;
}

void bgp_encap_type_nvgre_to_tlv(
	struct bgp_encap_type_nvgre *bet, /* input structure */
	struct attr *attr)
{
	attr->encap_tunneltype = BGP_ENCAP_TYPE_NVGRE;
}

void bgp_encap_type_mpls_to_tlv(
	struct bgp_encap_type_mpls *bet, /* input structure */
	struct attr *attr)
{
	return; /* no encap attribute for MPLS */
}

void bgp_encap_type_mpls_in_gre_to_tlv(
	struct bgp_encap_type_mpls_in_gre *bet, /* input structure */
	struct attr *attr)
{
	attr->encap_tunneltype = BGP_ENCAP_TYPE_MPLS_IN_GRE;
}

void bgp_encap_type_vxlan_gpe_to_tlv(
	struct bgp_encap_type_vxlan_gpe *bet, /* input structure */
	struct attr *attr)
{

	attr->encap_tunneltype = BGP_ENCAP_TYPE_VXLAN_GPE;
}

void bgp_encap_type_mpls_in_udp_to_tlv(
	struct bgp_encap_type_mpls_in_udp *bet, /* input structure */
	struct attr *attr)
{

	attr->encap_tunneltype = BGP_ENCAP_TYPE_MPLS_IN_UDP;
}


/***********************************************************************
 *			SUBTLV DECODE
 ***********************************************************************/
/* rfc5512 4.1 */
static int subtlv_decode_encap_l2tpv3_over_ip(
	struct bgp_attr_encap_subtlv *subtlv,
	struct bgp_tea_subtlv_encap_l2tpv3_over_ip *st)
{
	if (subtlv->length < 4) {
		zlog_debug("%s, subtlv length %d is less than 4", __func__,
			   subtlv->length);
		return -1;
	}

	ptr_get_be32(subtlv->value, &st->sessionid);
	st->cookie_length = subtlv->length - 4;
	if (st->cookie_length > sizeof(st->cookie)) {
		zlog_debug("%s, subtlv length %d is greater than %d", __func__,
			   st->cookie_length, (int)sizeof(st->cookie));
		return -1;
	}
	memcpy(st->cookie, subtlv->value + 4, st->cookie_length);
	return 0;
}

/* rfc5512 4.1 */
static int subtlv_decode_encap_gre(struct bgp_attr_encap_subtlv *subtlv,
				   struct bgp_tea_subtlv_encap_gre_key *st)
{
	if (subtlv->length != 4) {
		zlog_debug("%s, subtlv length %d does not equal 4", __func__,
			   subtlv->length);
		return -1;
	}
	ptr_get_be32(subtlv->value, &st->gre_key);
	return 0;
}

static int subtlv_decode_encap_pbb(struct bgp_attr_encap_subtlv *subtlv,
				   struct bgp_tea_subtlv_encap_pbb *st)
{
	if (subtlv->length != 1 + 3 + 6 + 2) {
		zlog_debug("%s, subtlv length %d does not equal %d", __func__,
			   subtlv->length, 1 + 3 + 6 + 2);
		return -1;
	}
	if (subtlv->value[0] & 0x80) {
		st->flag_isid = 1;
		st->isid = (subtlv->value[1] << 16) | (subtlv->value[2] << 8)
			   | subtlv->value[3];
	}
	if (subtlv->value[0] & 0x40) {
		st->flag_vid = 1;
		st->vid = ((subtlv->value[10] & 0x0f) << 8) | subtlv->value[11];
	}
	memcpy(st->macaddr, subtlv->value + 4, 6);
	return 0;
}

/* rfc5512 4.2 */
static int subtlv_decode_proto_type(struct bgp_attr_encap_subtlv *subtlv,
				    struct bgp_tea_subtlv_proto_type *st)
{
	if (subtlv->length != 2) {
		zlog_debug("%s, subtlv length %d does not equal 2", __func__,
			   subtlv->length);
		return -1;
	}
	st->proto = (subtlv->value[0] << 8) | subtlv->value[1];
	return 0;
}

/* rfc5512 4.3 */
static int subtlv_decode_color(struct bgp_attr_encap_subtlv *subtlv,
			       struct bgp_tea_subtlv_color *st)
{
	if (subtlv->length != 8) {
		zlog_debug("%s, subtlv length %d does not equal 8", __func__,
			   subtlv->length);
		return -1;
	}
	if ((subtlv->value[0] != 0x03) || (subtlv->value[1] != 0x0b)
	    || (subtlv->value[2] != 0) || (subtlv->value[3] != 0)) {
		zlog_debug("%s, subtlv value 1st 4 bytes are not 0x030b0000",
			   __func__);
		return -1;
	}
	ptr_get_be32(subtlv->value + 4, &st->color);
	return 0;
}

/* rfc 5566 4. */
static int subtlv_decode_ipsec_ta(struct bgp_attr_encap_subtlv *subtlv,
				  struct bgp_tea_subtlv_ipsec_ta *st)
{
	st->authenticator_length = subtlv->length - 2;
	if (st->authenticator_length > sizeof(st->value)) {
		zlog_debug(
			"%s, authenticator length %d exceeds storage maximum %d",
			__func__, st->authenticator_length,
			(int)sizeof(st->value));
		return -1;
	}
	st->authenticator_type = (subtlv->value[0] << 8) | subtlv->value[1];
	memcpy(st->value, subtlv->value + 2, st->authenticator_length);
	return 0;
}

/* draft-rosen-idr-tunnel-encaps 2.1 */
static int
subtlv_decode_remote_endpoint(struct bgp_attr_encap_subtlv *subtlv,
			      struct bgp_tea_subtlv_remote_endpoint *st)
{
	int i;
	if (subtlv->length != 8 && subtlv->length != 20) {
		zlog_debug("%s, subtlv length %d does not equal 8 or 20",
			   __func__, subtlv->length);
		return -1;
	}
	if (subtlv->length == 8) {
		st->family = AF_INET;
		memcpy(&st->ip_address.v4.s_addr, subtlv->value, 4);
	} else {
		st->family = AF_INET6;
		memcpy(&(st->ip_address.v6.s6_addr), subtlv->value, 16);
	}
	i = subtlv->length - 4;
	ptr_get_be32(subtlv->value + i, &st->as4);
	return 0;
}

/***********************************************************************
 *		TUNNEL TYPE-SPECIFIC TLV DECODE
 ***********************************************************************/

int tlv_to_bgp_encap_type_l2tpv3overip(
	struct bgp_attr_encap_subtlv *stlv,	/* subtlv chain */
	struct bgp_encap_type_l2tpv3_over_ip *bet) /* caller-allocated */
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION:
			rc |= subtlv_decode_encap_l2tpv3_over_ip(
				st, &bet->st_encap);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_ENCAP);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_PROTO_TYPE:
			rc |= subtlv_decode_proto_type(st, &bet->st_proto);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_PROTO_TYPE);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_COLOR:
			rc |= subtlv_decode_color(st, &bet->st_color);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_COLOR);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_gre(
	struct bgp_attr_encap_subtlv *stlv, /* subtlv chain */
	struct bgp_encap_type_gre *bet)     /* caller-allocated */
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION:
			rc |= subtlv_decode_encap_gre(st, &bet->st_encap);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_ENCAP);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_PROTO_TYPE:
			rc |= subtlv_decode_proto_type(st, &bet->st_proto);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_PROTO_TYPE);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_COLOR:
			rc |= subtlv_decode_color(st, &bet->st_color);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_COLOR);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_ip_in_ip(
	struct bgp_attr_encap_subtlv *stlv,  /* subtlv chain */
	struct bgp_encap_type_ip_in_ip *bet) /* caller-allocated */
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_PROTO_TYPE:
			rc |= subtlv_decode_proto_type(st, &bet->st_proto);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_PROTO_TYPE);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_COLOR:
			rc |= subtlv_decode_color(st, &bet->st_color);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_COLOR);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_transmit_tunnel_endpoint(
	struct bgp_attr_encap_subtlv *stlv,
	struct bgp_encap_type_transmit_tunnel_endpoint *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_ipsec_in_tunnel_mode(
	struct bgp_attr_encap_subtlv *stlv,		 /* subtlv chain */
	struct bgp_encap_type_ipsec_in_tunnel_mode *bet) /* caller-allocated */
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_IPSEC_TA:
			rc |= subtlv_decode_ipsec_ta(st, &bet->st_ipsec_ta);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_IPSEC_TA);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode(
	struct bgp_attr_encap_subtlv *stlv,
	struct bgp_encap_type_ip_in_ip_tunnel_with_ipsec_transport_mode *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_IPSEC_TA:
			rc |= subtlv_decode_ipsec_ta(st, &bet->st_ipsec_ta);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_IPSEC_TA);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode(
	struct bgp_attr_encap_subtlv *stlv,
	struct bgp_encap_type_mpls_in_ip_tunnel_with_ipsec_transport_mode *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_IPSEC_TA:
			rc |= subtlv_decode_ipsec_ta(st, &bet->st_ipsec_ta);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_IPSEC_TA);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_vxlan(struct bgp_attr_encap_subtlv *stlv,
				struct bgp_encap_type_vxlan *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_nvgre(struct bgp_attr_encap_subtlv *stlv,
				struct bgp_encap_type_nvgre *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_mpls(struct bgp_attr_encap_subtlv *stlv,
			       struct bgp_encap_type_mpls *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_mpls_in_gre(struct bgp_attr_encap_subtlv *stlv,
				      struct bgp_encap_type_mpls_in_gre *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_vxlan_gpe(struct bgp_attr_encap_subtlv *stlv,
				    struct bgp_encap_type_vxlan_gpe *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_mpls_in_udp(struct bgp_attr_encap_subtlv *stlv,
				      struct bgp_encap_type_mpls_in_udp *bet)
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}

int tlv_to_bgp_encap_type_pbb(
	struct bgp_attr_encap_subtlv *stlv, /* subtlv chain */
	struct bgp_encap_type_pbb *bet)     /* caller-allocated */
{
	struct bgp_attr_encap_subtlv *st;
	int rc = 0;

	for (st = stlv; st; st = st->next) {
		switch (st->type) {
		case BGP_ENCAP_SUBTLV_TYPE_ENCAPSULATION:
			rc |= subtlv_decode_encap_pbb(st, &bet->st_encap);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_ENCAP);
			break;

		case BGP_ENCAP_SUBTLV_TYPE_REMOTE_ENDPOINT:
			rc |= subtlv_decode_remote_endpoint(st,
							    &bet->st_endpoint);
			SET_SUBTLV_FLAG(bet, BGP_TEA_SUBTLV_REMOTE_ENDPOINT);
			break;

		default:
			zlog_debug("%s: unexpected subtlv type %d", __func__,
				   st->type);
			rc |= -1;
			break;
		}
	}
	return rc;
}
