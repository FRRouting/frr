// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP-MUP NLRI handling for SAFI=MUP (draft-ietf-bess-mup-safi).
 * Copyright (C) 2026 Yuya Kusakabe
 */
#ifndef _FRR_BGP_MUP_H
#define _FRR_BGP_MUP_H

#include "stream.h"

#include "bgpd/bgpd.h"

/* prefix_mup carries the entire MUP route key in struct mup_prefix. */
#define BGP_MUP_ROUTE_PREFIXLEN (sizeof(struct mup_prefix) * 8)

/* On-wire field widths (draft-ietf-bess-mup-safi 3.1). */
#define BGP_MUP_ARCH_TYPE_BYTES	 1
#define BGP_MUP_ROUTE_TYPE_BYTES 2
#define BGP_MUP_LEN_BYTES	 1
#define BGP_MUP_HDR_BYTES  (BGP_MUP_ARCH_TYPE_BYTES + BGP_MUP_ROUTE_TYPE_BYTES + BGP_MUP_LEN_BYTES)
#define BGP_MUP_TEID_BYTES 4
#define BGP_MUP_QFI_BYTES  1
#define BGP_MUP_PREFIX_LEN_BYTES 1
#define BGP_MUP_ADDR_LEN_BYTES	 1

/* Optional TLVs trailing T1ST/T2ST route bodies (draft 3.1.5). */
#define BGP_MUP_TLV_HDR_BYTES	       2 /* Type + Length */
#define BGP_MUP_TLV_SESSION_PARAMS     1 /* 3gpp-5g Session Parameters */
#define BGP_MUP_TLV_INTERWORK_ENDPOINT 2
#define BGP_MUP_TLV_SOURCE_ADDRESS     3

/* Encoded size on the wire of one BGP-MUP NLRI. */
extern size_t bgp_mup_prefix_size(const struct prefix *p);

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
extern void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
				  const struct prefix_rd *prd, const struct attr *attr,
				  bool addpath_capable, uint32_t addpath_tx_id);

/* Parse all BGP-MUP NLRIs in an MP_REACH/MP_UNREACH attribute. */
extern int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      bool withdraw);

/* Validate the optional TLV region of a T1ST/T2ST route body. */
extern int bgp_mup_parse_tlvs(uint16_t route_type, const uint8_t *buf, int len);

/* Add the decomposed MUP NLRI fields to a json object for show output. */
extern void bgp_mup_route2json(const struct prefix_mup *pm, struct json_object *json);

/* Render the optional TLVs kept with a T1ST/T2ST route. */
struct bgp_mup_nlri_data;
extern void bgp_mup_nlri_data_show(const struct bgp_mup_nlri_data *tlvs, uint16_t route_type,
				   struct vty *vty, struct json_object *json_path);

#endif /* _FRR_BGP_MUP_H */
