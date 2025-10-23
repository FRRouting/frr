// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2025, Donatas Abraitis <donatas@opensourcerouting.org>
 */

#include "bgp_nhc.h"

void bgp_nhc_tlv_add(struct bgp_nhc *nhc, struct bgp_nhc_tlv *tlv)
{
	struct bgp_nhc_tlv *last;

	if (!tlv)
		return;

	for (last = nhc->tlvs; last && last->next; last = last->next)
		;

	if (last)
		last->next = tlv;
	else
		nhc->tlvs = tlv;

	nhc->tlvs_length += tlv->length + BGP_NHC_TLV_MIN_LEN;
}

struct bgp_nhc_tlv *bgp_nhc_tlv_new(uint16_t code, uint16_t length, const void *value)
{
	struct bgp_nhc_tlv *tlv;

	tlv = XCALLOC(MTYPE_BGP_NHC_TLV, sizeof(struct bgp_nhc_tlv) + IPV4_MAX_BYTELEN);
	tlv->code = code;
	tlv->length = length;
	tlv->value = XCALLOC(MTYPE_BGP_NHC_TLV_VAL, length);

	memcpy(tlv->value, value, length);

	return tlv;
}

struct bgp_nhc_tlv *bgp_nhc_tlv_find(struct bgp_nhc *nhc, uint16_t code)
{
	struct bgp_nhc_tlv *tlv = NULL;

	if (!nhc)
		return tlv;

	for (tlv = nhc->tlvs; tlv; tlv = tlv->next) {
		if (tlv->code == code)
			return tlv;
	}

	return NULL;
}

void bgp_nhc_tlv_free(struct bgp_nhc_tlv *tlv)
{
	if (!tlv)
		return;

	if (tlv->value)
		XFREE(MTYPE_BGP_NHC_TLV_VAL, tlv->value);

	XFREE(MTYPE_BGP_NHC_TLV, tlv);
}

void bgp_nhc_tlvs_free(struct bgp_nhc_tlv *tlv)
{
	struct bgp_nhc_tlv *next;

	while (tlv) {
		next = tlv->next;
		bgp_nhc_tlv_free(tlv);
		tlv = next;
	}
}

void bgp_nhc_free(struct bgp_nhc *nhc)
{
	bgp_nhc_tlvs_free(nhc->tlvs);
	XFREE(MTYPE_BGP_NHC, nhc);
}
<<<<<<< HEAD
=======

uint64_t bgp_nhc_nnhn_count(struct bgp_nhc *nhc)
{
	uint64_t count = 0;
	struct bgp_nhc_tlv *tlv;

	for (tlv = nhc->tlvs; tlv; tlv = tlv->next) {
		if (tlv->code == BGP_ATTR_NHC_TLV_NNHN) {
			/* BGP Identifier is always 4-bytes (yet...) */
			count = tlv->length / IPV4_MAX_BYTELEN;
			if (count <= 1)
				return 0;

			/* -1 is to exclude the next-hop BGP ID.
			 * We care only about Next-next hops here.
			 */
			return count - 1;
		}
	}

	return 0;
}
>>>>>>> a6244e56f (bgpd: Put local BGP ID when sending NNHN TLV for NH characteristic)
