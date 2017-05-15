/* Ethernet-VPN Packet and vty Processing File
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

#include "bgpd/bgp_attr_evpn.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_evpn.h"

int
bgp_nlri_parse_evpn(struct peer *peer, struct attr *attr,
		    struct bgp_nlri *packet, int withdraw)
{
	u_char *pnt;
	u_char *lim;
	struct prefix p;
	struct prefix_rd prd;
	struct evpn_addr *p_evpn_p;
	struct bgp_route_evpn evpn;
	uint8_t route_type, route_length;
	u_char *pnt_label;
	u_int32_t addpath_id = 0;

	/* Check peer status. */
	if (peer->status != Established)
		return 0;

	/* Make prefix_rd */
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	p_evpn_p = &p.u.prefix_evpn;
	pnt = packet->nlri;
	lim = pnt + packet->length;
	while (pnt < lim) {
		/* clear evpn structure */
		memset(&evpn, 0, sizeof(evpn));

		/* Clear prefix structure. */
		memset(&p, 0, sizeof(struct prefix));
		memset(&evpn.gw_ip, 0, sizeof(union gw_addr));
		memset(&evpn.eth_s_id, 0, sizeof(struct eth_segment_id));

		/* Fetch Route Type */
		route_type = *pnt++;
		route_length = *pnt++;
		/* simply ignore. goto next route type if any */
		if (route_type != EVPN_IP_PREFIX) {
			if (pnt + route_length > lim) {
				zlog_err
				    ("not enough bytes for New Route Type left in NLRI?");
				return -1;
			}
			pnt += route_length;
			continue;
		}

		/* Fetch RD */
		if (pnt + 8 > lim) {
			zlog_err("not enough bytes for RD left in NLRI?");
			return -1;
		}

		/* Copy routing distinguisher to rd. */
		memcpy(&prd.val, pnt, 8);
		pnt += 8;

		/* Fetch ESI */
		if (pnt + 10 > lim) {
			zlog_err("not enough bytes for ESI left in NLRI?");
			return -1;
		}
		memcpy(&evpn.eth_s_id.val, pnt, 10);
		pnt += 10;

		/* Fetch Ethernet Tag */
		if (pnt + 4 > lim) {
			zlog_err("not enough bytes for Eth Tag left in NLRI?");
			return -1;
		}

		if (route_type == EVPN_IP_PREFIX) {
			p_evpn_p->route_type = route_type;
			memcpy(&(p_evpn_p->eth_tag), pnt, 4);
			p_evpn_p->eth_tag = ntohl(p_evpn_p->eth_tag);
			pnt += 4;

			/* Fetch IP prefix length. */
			p_evpn_p->ip_prefix_length = *pnt++;

			if (p_evpn_p->ip_prefix_length > 128) {
				zlog_err("invalid prefixlen %d in EVPN NLRI?",
					 p.prefixlen);
				return -1;
			}
			/* determine IPv4 or IPv6 prefix */
			if (route_length - 4 - 10 - 8 -
			    3 /* label to be read */  >= 32) {
				SET_IPADDR_V6 (&p_evpn_p->ip);
				memcpy(&(p_evpn_p->ip.ipaddr_v6), pnt, 16);
				pnt += 16;
				memcpy(&evpn.gw_ip.ipv6, pnt, 16);
				pnt += 16;
			} else {
				SET_IPADDR_V4 (&p_evpn_p->ip);
				memcpy(&(p_evpn_p->ip.ipaddr_v4), pnt, 4);
				pnt += 4;
				memcpy(&evpn.gw_ip.ipv4, pnt, 4);
				pnt += 4;
			}
			p.family = AFI_L2VPN;
			if (IS_IPADDR_V4(&p_evpn_p->ip))
				p.prefixlen =
				    (u_char) PREFIX_LEN_ROUTE_TYPE_5_IPV4;
			else
				p.prefixlen = PREFIX_LEN_ROUTE_TYPE_5_IPV6;
			p.family = AF_ETHERNET;
		}

		/* Fetch Label */
		if (pnt + 3 > lim) {
			zlog_err("not enough bytes for Label left in NLRI?");
			return -1;
		}
		pnt_label = pnt;

		pnt += 3;

		if (!withdraw) {
			bgp_update(peer, &p, addpath_id, attr, AFI_L2VPN,
				   SAFI_EVPN, ZEBRA_ROUTE_BGP, BGP_ROUTE_NORMAL,
				   &prd, pnt_label, 0, &evpn);
		} else {
			bgp_withdraw(peer, &p, addpath_id, attr, AFI_L2VPN,
				     SAFI_EVPN, ZEBRA_ROUTE_BGP,
				     BGP_ROUTE_NORMAL, &prd, pnt_label, &evpn);
		}
	}

	/* Packet length consistency check. */
	if (pnt != lim)
		return -1;
	return 0;
}

void
bgp_packet_mpattr_route_type_5(struct stream *s,
			       struct prefix *p, struct prefix_rd *prd,
			       u_char * label, struct attr *attr)
{
	int len;
	char temp[16];
	struct evpn_addr *p_evpn_p;

	memset(&temp, 0, 16);
	if (p->family != AF_ETHERNET)
		return;
	p_evpn_p = &(p->u.prefix_evpn);
        if (IS_IPADDR_V4(&p_evpn_p->ip))
		len = 8;	/* ipv4 */
	else
		len = 32;	/* ipv6 */
	stream_putc(s, EVPN_IP_PREFIX);
	stream_putc(s,
		    8 /* RD */  + 10 /* ESI */  + 4 /* EthTag */  + 1 + len +
		    3 /* label */ );
	stream_put(s, prd->val, 8);
	if (attr && attr->extra)
		stream_put(s, &(attr->extra->evpn_overlay.eth_s_id), 10);
	else
		stream_put(s, &temp, 10);
	stream_putl(s, p_evpn_p->eth_tag);
	stream_putc(s, p_evpn_p->ip_prefix_length);
        if (IS_IPADDR_V4(&p_evpn_p->ip))
		stream_put_ipv4(s, p_evpn_p->ip.ipaddr_v4.s_addr);
	else
		stream_put(s, &p_evpn_p->ip.ipaddr_v6, 16);
	if (attr && attr->extra) {
                if (IS_IPADDR_V4(&p_evpn_p->ip))
			stream_put_ipv4(s,
					attr->extra->evpn_overlay.gw_ip.ipv4.
					s_addr);
		else
			stream_put(s, &(attr->extra->evpn_overlay.gw_ip.ipv6),
				   16);
	} else {
                if (IS_IPADDR_V4(&p_evpn_p->ip))
			stream_put_ipv4(s, 0);
		else
			stream_put(s, &temp, 16);
	}
	if (label)
		stream_put(s, label, 3);
	else
		stream_put3(s, 0);
	return;
}
