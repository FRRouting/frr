// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright 2025, Donatas Abraitis <donatas@opensourcerouting.org>
 */

#ifndef _FRR_BGP_NHC_H
#define _FRR_BGP_NHC_H

#include "zebra.h"
#include <bgpd/bgpd.h>
#include <bgpd/bgp_attr.h>

struct bgp_nhc_tlv {
	struct bgp_nhc_tlv *next;
	uint16_t code;
	uint16_t length;
	uint8_t *value;
};

struct bgp_nhc {
	unsigned long refcnt;
	uint16_t afi;
	uint8_t safi;
	uint8_t nh_length;
	struct in_addr nh_ipv4;
	struct in6_addr nh_ipv6;
	uint16_t tlvs_length;
	struct bgp_nhc_tlv *tlvs;
};

/* 4 => Characteristic Code + Characteristic Length */
#define BGP_NHC_TLV_MIN_LEN sizeof(uint16_t) + sizeof(uint16_t)
/*
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Address Family Identifier   |     SAFI      | Next Hop Len  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~             Network Address of Next Hop (variable)            ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |      Characteristic Code      |      Characteristic Length    |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * ~                Characteristic Value (variable)                ~
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */
#define BGP_NHC_MIN_LEN	     12
#define BGP_NHC_MIN_IPV6_LEN 24

/* TLV values: */
/* draft-wang-idr-next-next-hop-nodes */
#define BGP_ATTR_NHC_TLV_NNHN 2
/* draft-ietf-idr-entropy-label */
#define BGP_ATTR_NHC_TLV_BGPID 3

extern void bgp_nhc_tlv_add(struct bgp_nhc *nhc, struct bgp_nhc_tlv *tlv);
extern struct bgp_nhc_tlv *bgp_nhc_tlv_find(struct bgp_nhc *nhc, uint16_t code);
extern void bgp_nhc_tlv_free(struct bgp_nhc_tlv *tlv);
extern void bgp_nhc_tlvs_free(struct bgp_nhc_tlv *tlv);
extern void bgp_nhc_free(struct bgp_nhc *bnc);
extern struct bgp_nhc_tlv *bgp_nhc_tlv_new(uint16_t code, uint16_t length, const void *value);
extern uint64_t bgp_nhc_nnhn_count(struct bgp_nhc *nhc);

#endif /* _FRR_BGP_NHC_H */
