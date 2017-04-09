/* Ethernet-VPN Attribute handling file
   Copyright (C) 2016 6WIND

This file is part of FRRouting.

FRRouting is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 2, or (at your option) any
later version.

FRRouting is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
General Public License for more details.

You should have received a copy of the GNU General Public License
along with FRRouting; see the file COPYING.  If not, write to the Free
Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.  */

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

void bgp_add_routermac_ecom(struct attr *attr, struct ethaddr *routermac)
{
	struct ecommunity_val routermac_ecom;

	if (attr->extra) {
		memset(&routermac_ecom, 0, sizeof(struct ecommunity_val));
		routermac_ecom.val[0] = ECOMMUNITY_ENCODE_EVPN;
		routermac_ecom.val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
		memcpy(&routermac_ecom.val[2], routermac->octet, ETHER_ADDR_LEN);
		if (!attr->extra->ecommunity)
			attr->extra->ecommunity = ecommunity_new();
		ecommunity_add_val(attr->extra->ecommunity, &routermac_ecom);
		ecommunity_str (attr->extra->ecommunity);
	}
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
	if (sscanf (str, "%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x:%2x",
                    a + 0, a + 1, a + 2, a + 3, a + 4, a + 5,
                    a + 6, a + 7, a + 8, a + 9) != ESI_LEN)
	{
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
	ptr = (char *)XMALLOC(MTYPE_TMP, (ESI_LEN * 2 + ESI_LEN - 1 + 1) * sizeof(char));

	snprintf(ptr, (ESI_LEN * 2 + ESI_LEN - 1 + 1),
		 "%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x",
		 val[0], val[1], val[2], val[3], val[4],
		 val[5], val[6], val[7], val[8], val[9]);

	return ptr;
}

char *ecom_mac2str(char *ecom_mac)
{
	char *en;

	en = ecom_mac;
	en += 2;
        return prefix_mac2str((struct ethaddr *)en, NULL, 0);
}

/* dst prefix must be AF_INET or AF_INET6 prefix, to forge EVPN prefix */
extern int
bgp_build_evpn_prefix(int evpn_type, uint32_t eth_tag, struct prefix *dst)
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
	dst->family = AF_ETHERNET;
	p_evpn_p->route_type = evpn_type;
	if (evpn_type == EVPN_IP_PREFIX) {
		p_evpn_p->eth_tag = eth_tag;
		p_evpn_p->ip_prefix_length = p2.prefixlen;
		if (src->family == AF_INET) {
			p_evpn_p->flags = IP_PREFIX_V4;
			memcpy(&p_evpn_p->ip.v4_addr, &src->u.prefix4,
			       sizeof(struct in_addr));
			dst->prefixlen = (u_char) PREFIX_LEN_ROUTE_TYPE_5_IPV4;
		} else {
			p_evpn_p->flags = IP_PREFIX_V6;
			memcpy(&p_evpn_p->ip.v6_addr, &src->u.prefix6,
			       sizeof(struct in6_addr));
			dst->prefixlen = (u_char) PREFIX_LEN_ROUTE_TYPE_5_IPV6;
		}
	} else
		return -1;
	return 0;
}
