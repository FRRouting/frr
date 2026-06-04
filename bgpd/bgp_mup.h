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

/* Encoded size on the wire of one BGP-MUP NLRI. */
extern size_t bgp_mup_prefix_size(const struct prefix *p);

/* Encode a BGP-MUP prefix into an MP_REACH/MP_UNREACH NLRI stream. */
extern void bgp_mup_encode_prefix(struct stream *s, afi_t afi, const struct prefix *p,
				  const struct prefix_rd *prd, bool addpath_capable,
				  uint32_t addpath_tx_id);

/* Parse all BGP-MUP NLRIs in an MP_REACH/MP_UNREACH attribute. */
extern int bgp_nlri_parse_mup(struct peer *peer, struct attr *attr, struct bgp_nlri *packet,
			      bool withdraw);

/* Add the decomposed MUP NLRI fields to a json object for show output. */
extern void bgp_mup_route2json(const struct prefix_mup *pm, struct json_object *json);

#endif /* _FRR_BGP_MUP_H */
