// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RTC - Constrained Route Distribution
 * Constrained Route Distribution - RFC 4684
 * Copyright (C) 2023 Alexander Sohn
 */

#include "bgpd/bgp_rtc.h"

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
				   BGP_ROUTE_NORMAL, NULL, NULL, 0, 0, NULL);
	}

	return BGP_NLRI_PARSE_OK;
}
static void bgp_rtc_add_static(struct bgp *bgp, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], prefix);
	bgp_static = bgp_dest_get_bgp_static_info(dest);

	if (bgp_static) {
		bgp_dest_unlock_node(dest);
		return;
	}

	bgp_static = bgp_static_new();
	bgp_static->label = MPLS_INVALID_LABEL;
	bgp_static->label_index = BGP_INVALID_LABEL_INDEX;

	bgp_dest_set_bgp_static_info(dest, bgp_static);

	bgp_static->valid = 1;
	bgp_static_update(bgp, prefix, bgp_static, AFI_IP, SAFI_RTC);
}

/* Adaption of bgp_static_withdraw */
static void bgp_rtc_remove_static(struct bgp *bgp, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], prefix);

	if (!dest)
		return;

	bgp_static_withdraw(bgp, prefix, AFI_IP, SAFI_RTC, NULL);

	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (bgp_static)
		bgp_static_free(bgp_static);

	bgp_dest_set_bgp_static_info(dest, NULL);
	bgp_dest_unlock_node(dest);
}

int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add)
{
	struct prefix prefix = {};
	char prefix_str[RTC_ADDR_STRLEN];

	if (!strstr(str, ":RT:") && !strstr(str, ":rt:") && !strstr(str, ":rT:") &&
	    !strstr(str, ":Rt:"))
		snprintf(prefix_str, sizeof(prefix_str), "%u:RT:%s", bgp->as, str);
	else
		snprintf(prefix_str, sizeof(prefix_str), "%s", str);

	if (!str2prefix(prefix_str, &prefix)) {
		vty_out(vty, "Unable to decode prefix %s\n", prefix_str);
		return CMD_WARNING_CONFIG_FAILED;
	}

	apply_mask(&prefix);

	if (add)
		bgp_rtc_add_static(bgp, &prefix);
	else
		bgp_rtc_remove_static(bgp, &prefix);

	return CMD_SUCCESS;
}

char *bgp_rtc_prefix_display(char *buf, size_t size, uint16_t prefix_len,
			     const struct rtc_info *rtc_info)
{
	char *cbuf = buf;

	if (prefix_len >= 48 && prefix_len <= 96)
		/* Only prefixes with a length of at least 48 have the
		 * type and subtype field set that can indentify the
		 * Extended Community as a route-target.
		 */
		snprintfrr(buf, size, "%u:%s", rtc_info->origin_as,
			   ecommunity_rt_str(rtc_info->route_target));
	else if (prefix_len > 32 && prefix_len < 48)
		snprintfrr(buf, size, "%u:UNK", rtc_info->origin_as);
	else if (prefix_len == 32)
		snprintfrr(buf, size, "%u:RT:0", rtc_info->origin_as);
	else if (prefix_len == 0)
		snprintfrr(buf, size, "0:RT:0");
	else
		snprintfrr(buf, size, "UNK-RTC");

	return cbuf;
}

void bgp_rtc_init(void)
{
	prefix_set_rtc_display_hook(bgp_rtc_prefix_display);
}
