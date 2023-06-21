#include "bgpd/bgp_rtc.h"

int bgp_nlri_parse_rtc(struct peer *peer, struct attr *attr,
		       struct bgp_nlri *packet, bool withdraw)
{
	uint8_t *pnt = packet->nlri;
	uint8_t *lim = packet->nlri + packet->length;
	int psize = 0;
	// Iterate over all received prefixes
	for (; pnt < lim; pnt += psize) {
		struct prefix p = {0};
		p.prefixlen = *pnt++;
		if (p.prefixlen > BGP_RTC_MAX_PREFIXLEN || p.prefixlen < 32) {
			zlog_err("SAFI_RTC parse error. Invalid prefixlen: %u",
				 p.prefixlen);
			return BGP_NLRI_PARSE_ERROR;
		}
		p.family = AF_RTC;
		psize = PSIZE(p.prefixlen);
		if (pnt + psize > lim) {
			zlog_err("SAFI_RTC parse error.");
			return BGP_NLRI_PARSE_ERROR;
		}

		// Mask the value according to the prefixlen
		for (int j = p.prefixlen; j < psize * 8; j++) {
			pnt[j / 8] &= ~(1 << (j % 8));
		}

		p.u.prefix_rtc.origin_as = ntohl(*(uint32_t *)pnt);

		memcpy(&p.u.prefix_rtc.route_target, pnt + 4, psize - 4);

		if (withdraw) {
			prefix_bgp_rtc_set(peer->host, &p, PREFIX_PERMIT, 0);
			peer->rtc_plist =
				prefix_list_get(AFI_IP, 0, 1, peer->host);
			bgp_withdraw(peer, &p, 0, packet->afi, packet->safi,
				     ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				     NULL, 0, NULL);
		} else {
			prefix_bgp_rtc_set(peer->host, &p, PREFIX_PERMIT, 1);
			peer->rtc_plist =
				prefix_list_get(AFI_IP, 0, 1, peer->host);
			bgp_update(peer, &p, 0, attr, packet->afi, packet->safi,
				   ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL, NULL,
				   NULL, 0, 0, NULL);
		}
	}
	bgp_announce_route(peer, AFI_L2VPN, SAFI_EVPN, false);
	return BGP_NLRI_PARSE_OK;
}

int bgp_rtc_filter(struct peer *peer, struct attr *attr)
{
	if (peer->rtc_plist == NULL) {
		zlog_info(
			"Filtered update because RTC prefix-list does not exist");
		return true;
	}
	// Build prefix to compare with
	struct prefix cmp;
	cmp.family = AF_RTC;
	cmp.prefixlen = BGP_RTC_MAX_PREFIXLEN;
	cmp.u.prefix_rtc.origin_as = peer->as;

	struct ecommunity *ecom = bgp_attr_get_ecommunity(attr);
	uint8_t *pnt;
	uint8_t sub_type = 0;
	for (uint32_t i = 0; i < ecom->size; i++) {
		/* Retrieve value field */
		pnt = ecom->val + (i * ecom->unit_size);

		sub_type = *++pnt;

		if (sub_type == ECOMMUNITY_ROUTE_TARGET) {
			memcpy(&cmp.u.prefix_rtc.route_target,
			       ecom->val + (i * ecom->unit_size),
			       ECOMMUNITY_SIZE);
			if (prefix_list_apply_ext(peer->rtc_plist, NULL, &cmp,
						  true) == PREFIX_DENY) {
				zlog_info(
					"Filtered update because of RTC prefix-list");
				return true;
			}
		}
	}
	return false;
}

int bgp_rtc_static_from_str(struct bgp *bgp, const char *str, bool add)
{
	struct ecommunity *ecom = NULL;
	int plen = BGP_RTC_MAX_PREFIXLEN;
	char *pnt;
	char *cp;

	/* Find slash inside string. */
	pnt = strchr(str, '/');

	/* String doesn't contain slash. */
	if (pnt == NULL) {
		ecom = ecommunity_str2com(str, ECOMMUNITY_ROUTE_TARGET, 0);
		if (ecom == NULL) {
			zlog_info("str2prefix_rtc: ecommunity_str2com failed");
			return CMD_ERR_NOTHING_TODO;
		}
	} else {
		cp = XMALLOC(MTYPE_TMP, (pnt - str) + 1);
		memcpy(cp, str, pnt - str);
		*(cp + (pnt - str)) = '\0';
		ecom = ecommunity_str2com(cp, ECOMMUNITY_ROUTE_TARGET, 0);

		XFREE(MTYPE_TMP, cp);
		if (ecom == NULL) {
			zlog_info("str2prefix_rtc: ecommunity_str2com failed");
			return CMD_ERR_NOTHING_TODO;
		}

		/* Get prefix length. */
		plen = (uint8_t)atoi(++pnt);
		if (plen > BGP_RTC_MAX_PREFIXLEN) {
			ecommunity_free(&ecom);
			return CMD_ERR_NOTHING_TODO;
		}
	}
	if (add)
		bgp_rtc_add_static(bgp, (struct ecommunity_val *)ecom->val,
				   plen);
	else
		bgp_rtc_remove_static(bgp, (struct ecommunity_val *)ecom->val,
				      plen);

	ecommunity_free(&ecom);
	return CMD_SUCCESS;
}

void bgp_rtc_add_static(struct bgp *bgp, struct ecommunity_val *eval,
			uint32_t prefixlen)
{
	struct prefix prefix = {0};
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;
	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);
	bgp_static = bgp_static_new();
	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], &prefix);

	if (bgp_dest_has_bgp_path_info_data(dest)) {
		zlog_info("Same network configuration exists");
		bgp_dest_unlock_node(dest);
	} else {
		bgp_static = bgp_static_new();
		bgp_static->backdoor = 0;
		bgp_static->valid = 0;
		bgp_static->igpmetric = 0;
		bgp_static->igpnexthop.s_addr = INADDR_ANY;
		bgp_static->label = MPLS_INVALID_LABEL;

		bgp_dest_set_bgp_static_info(dest, bgp_static);

		bgp_static->valid = 1;
		zlog_info("Adding RTC route in auto generated RT");
		bgp_static_update(bgp, &prefix, bgp_static, AFI_IP, SAFI_RTC);
	}
}

void bgp_rtc_remove_static(struct bgp *bgp, struct ecommunity_val *eval,
			   uint32_t prefixlen)
{
	struct prefix prefix = {0};
	struct bgp_dest *dest;
	struct bgp_static *bgp_static;
	prefix.family = AF_RTC;
	prefix.prefixlen = prefixlen;
	prefix.u.prefix_rtc.origin_as = bgp->as;
	memcpy(prefix.u.prefix_rtc.route_target, eval, PSIZE(prefixlen) - 4);
	bgp_static = bgp_static_new();
	dest = bgp_node_get(bgp->route[AFI_IP][SAFI_RTC], &prefix);

	if (dest) {
		bgp_static_withdraw(bgp, &prefix, AFI_IP, SAFI_RTC, NULL);

		bgp_static = bgp_dest_get_bgp_static_info(dest);
		if (bgp_static != NULL)
			bgp_static_free(bgp_static);
		bgp_dest_set_bgp_static_info(dest, NULL);
		bgp_dest_unlock_node(dest);
		bgp_dest_unlock_node(dest);
	} else
		zlog_info("Can't find the route");
}