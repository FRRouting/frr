// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#include "bgpd/bgp_rtc.h"
#include "lib/stream.h"

int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr, struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = packet->nlri + packet->length;
	int psize = 0;

	/* Iterate over all received prefixes */
	for (; pnt < lim; pnt += psize) {
		struct prefix p = { 0 };

		p.prefixlen = *pnt++;
		if ((p.prefixlen > 0 && p.prefixlen < 32) || p.prefixlen > RTC_MAX_BITLEN) {
			zlog_err("SAFI_RTC parse error. Invalid prefixlen: %u", p.prefixlen);
			return BGP_NLRI_PARSE_ERROR;
		}

		p.family = AF_RTC;
		psize = PSIZE(p.prefixlen);
		if (pnt + psize > lim) {
			zlog_err("SAFI_RTC parse error.");
			return BGP_NLRI_PARSE_ERROR;
		}

		if (p.prefixlen)
			p.u.prefix_rtc.origin_as = ntohl(*(uint32_t *)pnt);

		if (p.prefixlen > 32)
			memcpy(&p.u.prefix_rtc.route_target, pnt + 4, psize - 4);

		apply_mask(&p);

		if (withdraw)
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, NULL, NULL, 0);
		else
			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi, ZEBRA_ROUTE_BGP,
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL, NULL);
	}

	return BGP_NLRI_PARSE_OK;
}

char *bgp_rtc_prefix_display(char *buf, size_t size, uint16_t prefix_len,
			     const struct rtc_info *rtc_info)
{
	char sbuf[PREFIX_STRLEN];
	int type;
	const uint8_t *ptr;
	in_addr_t ipval;
	uint16_t ival;
	uint32_t lval;

	if (prefix_len == 0) {
		strlcpy(buf, "*:*", size);
	} else {
		if (rtc_info->origin_as != 0)
			snprintf(buf, size, "%u:", rtc_info->origin_as);
		else
			snprintf(buf, size, "*:");

		if (prefix_len > 32) {
			/* Format RT type and subtype bytes. Don't love having
			 * this here and in bgpd, but there it is.
			 */
			type = rtc_info->route_target[0];

			snprintf(sbuf, sizeof(sbuf), "%u:%u:", rtc_info->route_target[0],
				 rtc_info->route_target[1]);
			strlcat(buf, sbuf, size);

			ptr = &(rtc_info->route_target[2]);

			/* Format RT data bytes, using well-known types */
			if (type == 0) {
				ptr = ptr_get_be16((uint8_t *)ptr, &ival);
				ptr_get_be32(ptr, &lval);

				snprintf(sbuf, sizeof(sbuf), "%u:%u", ival, lval);
			} else if (type == 1) {
				ptr = ptr_get_be32(ptr, &ipval);
				ptr_get_be16((uint8_t *)ptr, &ival);
				snprintfrr(sbuf, sizeof(sbuf), "%pI4:%u", &ipval, ival);
			} else if (type == 2) {
				ptr = ptr_get_be32(ptr, &lval);
				ptr_get_be16((uint8_t *)ptr, &ival);
				snprintf(sbuf, sizeof(sbuf), "%u:%u", lval, ival);
			} else {
				snprintf(sbuf, sizeof(sbuf), "%02x:%02x:%02x:%02x:%02x:%02x",
					 rtc_info->route_target[2], rtc_info->route_target[3],
					 rtc_info->route_target[4], rtc_info->route_target[5],
					 rtc_info->route_target[6], rtc_info->route_target[7]);
			}

			strlcat(buf, sbuf, size);
		} else {
			strlcpy(sbuf, "*", sizeof(sbuf));
			strlcat(buf, sbuf, size);
		}
	}

	return buf;
}

void bgp_rtc_init(void)
{
	prefix_set_rtc_display_hook(bgp_rtc_prefix_display);
}
