// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Link-State TLV Serializer/Deserializer
 * Copyright 2023 6WIND S.A.
 */

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_linkstate_tlv.h"


static uint16_t pnt_decode16(uint8_t **pnt)
{
	uint16_t data;

	*pnt = ptr_get_be16(*pnt, &data);

	return data;
}

int bgp_nlri_parse_linkstate(struct peer *peer, struct attr *attr,
			     struct bgp_nlri *packet, int withdraw)
{
	uint8_t *pnt;
	uint8_t *lim;
	afi_t afi;
	safi_t safi;
	uint16_t length = 0;
	struct prefix p;

	/* Start processing the NLRI - there may be multiple in the MP_REACH */
	pnt = packet->nlri;
	lim = pnt + packet->length;
	afi = packet->afi;
	safi = packet->safi;

	for (; pnt < lim; pnt += length) {
		/* Clear prefix structure. */
		memset(&p, 0, sizeof(p));

		/* All linkstate NLRI begin with NRLI type and length. */
		if (pnt + 4 > lim)
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;

		p.u.prefix_linkstate.nlri_type = pnt_decode16(&pnt);
		length = pnt_decode16(&pnt);
		/* When packet overflow occur return immediately. */
		if (pnt + length > lim) {
			flog_err(
				EC_BGP_LINKSTATE_PACKET,
				"Link-State NLRI length inconsistent (size %u seen)",
				length);
			return BGP_NLRI_PARSE_ERROR_PACKET_OVERFLOW;
		}
		p.family = AF_LINKSTATE;

		p.u.prefix_linkstate.ptr = (uintptr_t)pnt;
		p.prefixlen = length;

		/* Process the route. */
		if (withdraw)
			bgp_withdraw(peer, &p, 0, afi, safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0, NULL);
		else
			bgp_update(peer, &p, 0, attr, afi, safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);
	}
	return BGP_NLRI_PARSE_OK;
}

/*
 * Encode Link-State prefix in Update (MP_REACH)
 */
void bgp_nlri_encode_linkstate(struct stream *s, const struct prefix *p)
{
	/* NLRI type */
	stream_putw(s, p->u.prefix_linkstate.nlri_type);

	/* Size */
	stream_putw(s, p->prefixlen);

	stream_put(s, (const void *)p->u.prefix_linkstate.ptr, p->prefixlen);
}
