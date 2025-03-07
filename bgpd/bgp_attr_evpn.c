// SPDX-License-Identifier: GPL-2.0-or-later
/* Ethernet-VPN Attribute handling file
 * Copyright (C) 2016 6WIND
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"
#include "vxlan.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"

bool bgp_route_evpn_same(const struct bgp_route_evpn *e1,
			 const struct bgp_route_evpn *e2)
{
	if (!e1 && e2)
		return false;
	if (!e2 && e1)
		return false;
	if (!e1 && !e2)
		return true;

	return (e1->type == e2->type &&
		!memcmp(&(e1->eth_s_id), &(e2->eth_s_id), sizeof(esi_t)) &&
		!ipaddr_cmp(&(e1->gw_ip), &(e2->gw_ip)));
}

void bgp_add_routermac_ecom(struct attr *attr, struct ethaddr *routermac)
{
	struct ecommunity_val routermac_ecom;
	struct ecommunity *ecomm = bgp_attr_get_ecommunity(attr);

	memset(&routermac_ecom, 0, sizeof(routermac_ecom));
	routermac_ecom.val[0] = ECOMMUNITY_ENCODE_EVPN;
	routermac_ecom.val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
	memcpy(&routermac_ecom.val[2], routermac->octet, ETH_ALEN);
	if (!ecomm) {
		bgp_attr_set_ecommunity(attr, ecommunity_new());
		ecomm = bgp_attr_get_ecommunity(attr);
	}
	ecommunity_add_val(ecomm, &routermac_ecom, false, false);
	ecommunity_str(ecomm);
}

/* converts to an esi
 * returns 1 on success, 0 otherwise
 * format accepted: AA:BB:CC:DD:EE:FF:GG:HH:II:JJ
 * if id is null, check only is done
 */
bool str2esi(const char *str, esi_t *id)
{
	unsigned int a[ESI_BYTES];
	int i;

	if (!str)
		return false;
	if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x", a + 0, a + 1,
		   a + 2, a + 3, a + 4, a + 5, a + 6, a + 7, a + 8, a + 9)
	    != ESI_BYTES) {
		/* error in incoming str length */
		return false;
	}
	/* valid mac address */
	if (!id)
		return true;
	for (i = 0; i < ESI_BYTES; ++i)
		id->val[i] = a[i] & 0xff;
	return true;
}

char *ecom_mac2str(char *ecom_mac)
{
	char *en;

	en = ecom_mac;
	en += 2;

	return prefix_mac2str((struct ethaddr *)en, NULL, 0);
}

/* Fetch router-mac from extended community */
bool bgp_attr_rmac(struct attr *attr, struct ethaddr *rmac)
{
	uint32_t i = 0;
	struct ecommunity *ecom;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return false;

	/* If there is a router mac extended community, set RMAC in attr */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt = NULL;
		uint8_t type = 0;
		uint8_t sub_type = 0;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if (!(type == ECOMMUNITY_ENCODE_EVPN
		      && sub_type == ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC))
			continue;

		memcpy(rmac, pnt, ETH_ALEN);
		return true;
	}
	return false;
}

/*
 * return true if attr contains default gw extended community
 */
void bgp_attr_default_gw(struct attr *attr)
{
	struct ecommunity *ecom;
	uint32_t i;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return;

	/* If there is a default gw extendd community return true otherwise
	 * return 0 */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if ((type == ECOMMUNITY_ENCODE_OPAQUE
		     && sub_type == ECOMMUNITY_EVPN_SUBTYPE_DEF_GW))
			SET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
	}
	UNSET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_DEFAULT_GW);
}

/*
 * Fetch and return the DF preference and algorithm from
 * DF election extended community, if present, else 0.
 */
uint16_t bgp_attr_df_pref_from_ec(struct attr *attr, uint8_t *alg)
{
	struct ecommunity *ecom;
	uint32_t i;
	uint16_t df_pref = 0;

	*alg = EVPN_MH_DF_ALG_SERVICE_CARVING;
	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return 0;

	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (!(type == ECOMMUNITY_ENCODE_EVPN
		      && sub_type == ECOMMUNITY_EVPN_SUBTYPE_DF_ELECTION))
			continue;

		*alg = (*pnt++) & ECOMMUNITY_EVPN_SUBTYPE_DF_ALG_BITS;

		pnt += 3;
		pnt = ptr_get_be16(pnt, &df_pref);
		(void)pnt; /* consume value */
		break;
	}

	return df_pref;
}

/*
 * Fetch and return the sequence number from MAC Mobility extended
 * community, if present, else 0.
 */
uint32_t bgp_attr_mac_mobility_seqnum(struct attr *attr)
{
	struct ecommunity *ecom;
	uint32_t i;
	uint8_t flags = 0;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return 0;

	/* If there is a MAC Mobility extended community, return its
	 * sequence number.
	 * TODO: RFC is silent on handling of multiple MAC mobility extended
	 * communities for the same route. We will bail out upon the first
	 * one.
	 */
	for (i = 0; i < ecom->size; i++) {
		const uint8_t *pnt;
		uint8_t type, sub_type;
		uint32_t seq_num;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (!(type == ECOMMUNITY_ENCODE_EVPN
		      && sub_type == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY))
			continue;
		flags = *pnt++;

		if (CHECK_FLAG(flags,
			       ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY))
			SET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_STICKY);
		else
			UNSET_FLAG(attr->evpn_flags, ATTR_EVPN_FLAG_STICKY);

		pnt++;
		pnt = ptr_get_be32(pnt, &seq_num);
		(void)pnt; /* consume value */
		return seq_num;
	}

	return 0;
}

/*
 * return true if attr contains router flag extended community
 */
void bgp_attr_evpn_na_flag(struct attr *attr, bool *proxy)
{
	struct ecommunity *ecom;
	uint32_t i;
	uint8_t val;

	ecom = bgp_attr_get_ecommunity(attr);
	if (!ecom || !ecom->size)
		return;

	/* If there is a evpn na extendd community set router_flag */
	for (i = 0; i < ecom->size; i++) {
		uint8_t *pnt;
		uint8_t type, sub_type;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if (type == ECOMMUNITY_ENCODE_EVPN &&
		    sub_type == ECOMMUNITY_EVPN_SUBTYPE_ND) {
			val = *pnt++;

			if (CHECK_FLAG(val,
				       ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG))
				SET_FLAG(attr->evpn_flags,
					 ATTR_EVPN_FLAG_ROUTER);

			if (CHECK_FLAG(val, ECOMMUNITY_EVPN_SUBTYPE_PROXY_FLAG))
				*proxy = true;

			break;
		}
	}
}

/* dst prefix must be AF_INET or AF_INET6 prefix, to forge EVPN prefix */
extern int bgp_build_evpn_prefix(int evpn_type, uint32_t eth_tag,
				 struct prefix *dst)
{
	struct evpn_addr *p_evpn_p;
	struct prefix p2;
	struct prefix *src = &p2;

	if (!dst || dst->family == 0)
		return -1;
	/* store initial prefix in src */
	prefix_copy(src, dst);
	memset(dst, 0, sizeof(struct prefix));
	p_evpn_p = &(dst->u.prefix_evpn);
	dst->family = AF_EVPN;
	p_evpn_p->route_type = evpn_type;
	if (evpn_type == BGP_EVPN_IP_PREFIX_ROUTE) {
		p_evpn_p->prefix_addr.eth_tag = eth_tag;
		p_evpn_p->prefix_addr.ip_prefix_length = p2.prefixlen;
		if (src->family == AF_INET) {
			SET_IPADDR_V4(&p_evpn_p->prefix_addr.ip);
			memcpy(&p_evpn_p->prefix_addr.ip.ipaddr_v4,
			       &src->u.prefix4,
			       sizeof(struct in_addr));
			dst->prefixlen = (uint16_t)PREFIX_LEN_ROUTE_TYPE_5_IPV4;
		} else {
			SET_IPADDR_V6(&p_evpn_p->prefix_addr.ip);
			memcpy(&p_evpn_p->prefix_addr.ip.ipaddr_v6,
			       &src->u.prefix6,
			       sizeof(struct in6_addr));
			dst->prefixlen = (uint16_t)PREFIX_LEN_ROUTE_TYPE_5_IPV6;
		}
	} else
		return -1;
	return 0;
}
