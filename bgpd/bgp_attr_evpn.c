/* Ethernet-VPN Attribute handling file
 * Copyright (C) 2016 6WIND
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRRouting is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "prefix.h"
#include "log.h"
#include "memory.h"
#include "stream.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_private.h"

void bgp_add_routermac_ecom(struct attr *attr, struct ethaddr *routermac)
{
	struct ecommunity_val routermac_ecom;

	memset(&routermac_ecom, 0, sizeof(struct ecommunity_val));
	routermac_ecom.val[0] = ECOMMUNITY_ENCODE_EVPN;
	routermac_ecom.val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
	memcpy(&routermac_ecom.val[2], routermac->octet, ETH_ALEN);
	if (!attr->ecommunity)
		attr->ecommunity = ecommunity_new();
	ecommunity_add_val(attr->ecommunity, &routermac_ecom);
	ecommunity_str(attr->ecommunity);
}

/* converts to an esi
 * returns 1 on success, 0 otherwise
 * format accepted: AA:BB:CC:DD:EE:FF:GG:HH:II:JJ
 * if id is null, check only is done
 */
int str2esi(const char *str, struct eth_segment_id *id)
{
	unsigned int a[ESI_LEN];
	int i;

	if (!str)
		return 0;
	if (sscanf(str, "%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x", a + 0, a + 1,
		   a + 2, a + 3, a + 4, a + 5, a + 6, a + 7, a + 8, a + 9)
	    != ESI_LEN) {
		/* error in incoming str length */
		return 0;
	}
	/* valid mac address */
	if (!id)
		return 1;
	for (i = 0; i < ESI_LEN; ++i)
		id->val[i] = a[i] & 0xff;
	return 1;
}

char *esi2str(struct eth_segment_id *id)
{
	char *ptr;
	u_char *val;

	if (!id)
		return NULL;

	val = id->val;
	ptr = (char *)XMALLOC(MTYPE_TMP,
			      (ESI_LEN * 2 + ESI_LEN - 1 + 1) * sizeof(char));

	snprintf(ptr, (ESI_LEN * 2 + ESI_LEN - 1 + 1),
		 "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x", val[0],
		 val[1], val[2], val[3], val[4], val[5], val[6], val[7], val[8],
		 val[9]);

	return ptr;
}

char *ecom_mac2str(char *ecom_mac)
{
	char *en;

	en = ecom_mac;
	en += 2;

	return prefix_mac2str((struct ethaddr *)en, NULL, 0);
}

/* Fetch router-mac from extended community */
void bgp_attr_rmac(struct attr *attr,
		   struct ethaddr *rmac)
{
	int i = 0;
	struct ecommunity *ecom;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return;

	/* If there is a router mac extended community, set RMAC in attr */
	for (i = 0; i < ecom->size; i++) {
		u_char *pnt = NULL;
		u_char type = 0;
		u_char sub_type = 0;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if (!(type == ECOMMUNITY_ENCODE_EVPN &&
		     sub_type == ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC))
			continue;

		memcpy(rmac, pnt, ETH_ALEN);
	}
}

/*
 * return true if attr contains default gw extended community
 */
uint8_t bgp_attr_default_gw(struct attr *attr)
{
	struct ecommunity	*ecom;
	int			i;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return 0;

	/* If there is a default gw extendd community return true otherwise
	 * return 0 */
	for (i = 0; i < ecom->size; i++) {
		u_char		*pnt;
		u_char		type, sub_type;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;

		if ((type == ECOMMUNITY_ENCODE_OPAQUE
		      && sub_type == ECOMMUNITY_EVPN_SUBTYPE_DEF_GW))
			return 1;
	}

	return 0;
}

/*
 * Fetch and return the sequence number from MAC Mobility extended
 * community, if present, else 0.
 */
u_int32_t bgp_attr_mac_mobility_seqnum(struct attr *attr, u_char *sticky)
{
	struct ecommunity *ecom;
	int i;
	u_char flags = 0;

	ecom = attr->ecommunity;
	if (!ecom || !ecom->size)
		return 0;

	/* If there is a MAC Mobility extended community, return its
	 * sequence number.
	 * TODO: RFC is silent on handling of multiple MAC mobility extended
	 * communities for the same route. We will bail out upon the first
	 * one.
	 */
	for (i = 0; i < ecom->size; i++) {
		u_char *pnt;
		u_char type, sub_type;
		u_int32_t seq_num;

		pnt = (ecom->val + (i * ECOMMUNITY_SIZE));
		type = *pnt++;
		sub_type = *pnt++;
		if (!(type == ECOMMUNITY_ENCODE_EVPN
		      && sub_type == ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY))
			continue;
		flags = *pnt++;

		if (flags & ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY)
			*sticky = 1;
		else
			*sticky = 0;

		pnt++;
		pnt = ptr_get_be32(pnt, &seq_num);
		(void)pnt; /* consume value */
		return seq_num;
	}

	return 0;
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
		p_evpn_p->eth_tag = eth_tag;
		p_evpn_p->ip_prefix_length = p2.prefixlen;
		if (src->family == AF_INET) {
			SET_IPADDR_V4(&p_evpn_p->ip);
			memcpy(&p_evpn_p->ip.ipaddr_v4, &src->u.prefix4,
			       sizeof(struct in_addr));
			dst->prefixlen = (u_char)PREFIX_LEN_ROUTE_TYPE_5_IPV4;
		} else {
			SET_IPADDR_V6(&p_evpn_p->ip);
			memcpy(&p_evpn_p->ip.ipaddr_v6, &src->u.prefix6,
			       sizeof(struct in6_addr));
			dst->prefixlen = (u_char)PREFIX_LEN_ROUTE_TYPE_5_IPV6;
		}
	} else
		return -1;
	return 0;
}
