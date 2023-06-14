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
static void bgp_rtc_add_static(struct bgp *bgp, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_get(bgp->static_routes[AFI_IP][SAFI_RTC], prefix);
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

/* Adaption of bgp_static_update */
void bgp_rtc_add_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	struct bgp_path_info *new;
	struct attr attr;
	struct attr *attr_new;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = RTC_MAX_BITLEN;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, sizeof(prefix.u.prefix_rtc.route_target));
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;


	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, &prefix, NULL);

	bgp_attr_default_set(&attr, bgp, BGP_ORIGIN_IGP);

	attr.nexthop.s_addr = INADDR_ANY;

	bgp_attr_set_med(&attr, 0);

	attr.mp_nexthop_len = BGP_ATTR_NHLEN_IPV4;


	if (bgp_in_graceful_shutdown(bgp))
		bgp_attr_add_gshut_community(&attr);

	attr_new = bgp_attr_intern(&attr);

	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_NORMAL)
			break;

	if (pi) {
		bgp_attr_unintern(&attr_new);
		bgp_dest_unlock_node(dest);
		return;
	}
	/* Make new BGP info. */
	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, 0, bgp->peer_self, attr_new, dest);

	bgp_path_info_set_flag(dest, new, BGP_PATH_VALID);

	/* Aggregate address increment. */
	bgp_aggregate_increment(bgp, &prefix, new, afi, safi);

	/* Register new BGP information. */
	bgp_path_info_add(dest, new);

	/* route_node_get lock */
	bgp_dest_unlock_node(dest);

	/* Process change. */
	bgp_process(bgp, dest, new, afi, safi);

	/* Unintern original. */
	aspath_unintern(&attr.aspath);
}

/* Adaption of bgp_static_withdraw */
static void bgp_rtc_remove_static(struct bgp *bgp, struct prefix *prefix)
{
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;

	dest = bgp_node_get(bgp->static_routes[AFI_IP][SAFI_RTC], prefix);

	if (!dest)
		return;

	bgp_static_withdraw(bgp, prefix, AFI_IP, SAFI_RTC, NULL);

	bgp_static = bgp_dest_get_bgp_static_info(dest);
	if (bgp_static)
		bgp_static_free(bgp_static);

	bgp_dest_set_bgp_static_info(dest, NULL);
	bgp_dest_unlock_node(dest);
}

void bgp_rtc_remove_ecommunity_val_dynamic(struct bgp *bgp, struct ecommunity_val *eval)
{
	struct bgp_dest *dest;
	struct bgp_path_info *pi;
	afi_t afi = AFI_IP;
	safi_t safi = SAFI_RTC;
	struct prefix prefix = { 0 };

	prefix.family = AF_RTC;
	prefix.prefixlen = RTC_MAX_BITLEN;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, sizeof(prefix.u.prefix_rtc.route_target));

	dest = bgp_afi_node_get(bgp->rib[afi][safi], afi, safi, &prefix, NULL);

	/* Check selected route and self inserted route. */
	for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
		if (pi->peer == bgp->peer_self && pi->type == ZEBRA_ROUTE_BGP &&
		    pi->sub_type == BGP_ROUTE_NORMAL)
			break;

	/* Withdraw static BGP route from routing table. */
	if (pi) {
		SET_FLAG(pi->flags, BGP_PATH_UNSORTED);
		bgp_aggregate_decrement(bgp, &prefix, pi, afi, safi);
		bgp_unlink_nexthop(pi);
		bgp_path_info_mark_for_delete(dest, pi);
		bgp_process(bgp, dest, pi, afi, safi);
	}

	/* Unlock bgp_node_lookup. */
	bgp_dest_unlock_node(dest);
}

int bgp_rtc_static_from_str(struct vty *vty, struct bgp *bgp, const char *str, bool add)
{
	struct prefix prefix = {};
	char prefix_str[RTC_ADDR_STRLEN];
	char *cp, *colon, *endptr;
	unsigned long i;
	const char *ptr;
	int count = 0;

	if (strstr(str, "/32")) {
		prefix.family = AF_RTC;
		prefix.prefixlen = 32;
		cp = XSTRDUP(MTYPE_TMP, str);
		colon = strchr(cp, ':');
		*colon = '\0';
		i = strtoul(cp, &endptr, 10);
		if (endptr == cp || *endptr != '\0' || i > UINT32_MAX) {
			XFREE(MTYPE_TMP, cp);
			vty_out(vty, "Unable to decode prefix %s\n", str);
			return CMD_WARNING_CONFIG_FAILED;
		}
		XFREE(MTYPE_TMP, cp);

		prefix.u.prefix_rtc.origin_as = i;
	} else if (strstr(str, "/0"))
		prefix.family = AF_RTC;
	else {
		ptr = str;
		/* Loop through each character in the string */
		while (*ptr != '\0') {
			if (*ptr == ':')
				count++;

			ptr++;
		}

		if (count == 4)
			/* full RTC prefix */
			snprintf(prefix_str, sizeof(prefix_str), "%s", str);
		else if (count == 1) {
			/* only the route-target is provided */
			if (strchr(str, '.'))
				/* assume IPv4 */
				snprintf(prefix_str, sizeof(prefix_str), "%u:1:2:%s", bgp->as, str);
			else {
				cp = XSTRDUP(MTYPE_TMP, str);
				colon = strchr(cp, ':');
				*colon = '\0';
				i = strtoul(cp, &endptr, 10);
				if (endptr == cp || *endptr != '\0' || i > UINT32_MAX) {
					XFREE(MTYPE_TMP, cp);
					vty_out(vty, "Unable to decode prefix %s\n", str);
					return CMD_WARNING_CONFIG_FAILED;
				}
				XFREE(MTYPE_TMP, cp);
				if (i < UINT16_MAX)
					snprintf(prefix_str, sizeof(prefix_str), "%u:0:2:%s",
						 bgp->as, str);
				else
					snprintf(prefix_str, sizeof(prefix_str), "%u:2:2:%s",
						 bgp->as, str);
			}
		} else {
			vty_out(vty, "Unable to decode prefix %s\n", str);
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	if (prefix.family != AF_RTC && !str2prefix(prefix_str, &prefix)) {
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
