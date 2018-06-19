/* BGP RD definitions for BGP-based VPNs (IP/EVPN)
 * -- brought over from bgpd/bgp_mplsvpn.c
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>
#include "command.h"
#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "stream.h"
#include "filter.h"
#include "frrstr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_attr.h"

#if ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

uint16_t decode_rd_type(uint8_t *pnt)
{
	uint16_t v;

	v = ((uint16_t)*pnt++ << 8);
#if ENABLE_BGP_VNC
	/*
	 * VNC L2 stores LHI in lower byte, so omit it
	 */
	if (v != RD_TYPE_VNC_ETH)
		v |= (uint16_t)*pnt;
#else /* duplicate code for clarity */
	v |= (uint16_t)*pnt;
#endif
	return v;
}

void encode_rd_type(uint16_t v, uint8_t *pnt)
{
	*((uint16_t *)pnt) = htons(v);
}

/* type == RD_TYPE_AS */
void decode_rd_as(uint8_t *pnt, struct rd_as *rd_as)
{
	rd_as->as = (uint16_t)*pnt++ << 8;
	rd_as->as |= (uint16_t)*pnt++;
	ptr_get_be32(pnt, &rd_as->val);
}

/* type == RD_TYPE_AS4 */
void decode_rd_as4(uint8_t *pnt, struct rd_as *rd_as)
{
	pnt = ptr_get_be32(pnt, &rd_as->as);
	rd_as->val = ((uint16_t)*pnt++ << 8);
	rd_as->val |= (uint16_t)*pnt;
}

/* type == RD_TYPE_IP */
void decode_rd_ip(uint8_t *pnt, struct rd_ip *rd_ip)
{
	memcpy(&rd_ip->ip, pnt, 4);
	pnt += 4;

	rd_ip->val = ((uint16_t)*pnt++ << 8);
	rd_ip->val |= (uint16_t)*pnt;
}

#if ENABLE_BGP_VNC
/* type == RD_TYPE_VNC_ETH */
void decode_rd_vnc_eth(uint8_t *pnt, struct rd_vnc_eth *rd_vnc_eth)
{
	rd_vnc_eth->type = RD_TYPE_VNC_ETH;
	rd_vnc_eth->local_nve_id = pnt[1];
	memcpy(rd_vnc_eth->macaddr.octet, pnt + 2, ETH_ALEN);
}
#endif

int str2prefix_rd(const char *str, struct prefix_rd *prd)
{
	int ret;  /* ret of called functions */
	int lret; /* local ret, of this func */
	char *p;
	char *p2;
	struct stream *s = NULL;
	char *half = NULL;
	struct in_addr addr;

	s = stream_new(8);

	prd->family = AF_UNSPEC;
	prd->prefixlen = 64;

	lret = 0;
	p = strchr(str, ':');
	if (!p)
		goto out;

	if (!all_digit(p + 1))
		goto out;

	half = XMALLOC(MTYPE_TMP, (p - str) + 1);
	memcpy(half, str, (p - str));
	half[p - str] = '\0';

	p2 = strchr(str, '.');

	if (!p2) {
		unsigned long as_val;

		if (!all_digit(half))
			goto out;

		as_val = atol(half);
		if (as_val > 0xffff) {
			stream_putw(s, RD_TYPE_AS4);
			stream_putl(s, as_val);
			stream_putw(s, atol(p + 1));
		} else {
			stream_putw(s, RD_TYPE_AS);
			stream_putw(s, as_val);
			stream_putl(s, atol(p + 1));
		}
	} else {
		ret = inet_aton(half, &addr);
		if (!ret)
			goto out;

		stream_putw(s, RD_TYPE_IP);
		stream_put_in_addr(s, &addr);
		stream_putw(s, atol(p + 1));
	}
	memcpy(prd->val, s->data, 8);
	lret = 1;

out:
	if (s)
		stream_free(s);
	if (half)
		XFREE(MTYPE_TMP, half);
	return lret;
}

char *prefix_rd2str(struct prefix_rd *prd, char *buf, size_t size)
{
	uint8_t *pnt;
	uint16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;

	assert(size >= RD_ADDRSTRLEN);

	pnt = prd->val;

	type = decode_rd_type(pnt);

	if (type == RD_TYPE_AS) {
		decode_rd_as(pnt + 2, &rd_as);
		snprintf(buf, size, "%u:%d", rd_as.as, rd_as.val);
		return buf;
	} else if (type == RD_TYPE_AS4) {
		decode_rd_as4(pnt + 2, &rd_as);
		snprintf(buf, size, "%u:%d", rd_as.as, rd_as.val);
		return buf;
	} else if (type == RD_TYPE_IP) {
		decode_rd_ip(pnt + 2, &rd_ip);
		snprintf(buf, size, "%s:%d", inet_ntoa(rd_ip.ip), rd_ip.val);
		return buf;
	}
#if ENABLE_BGP_VNC
	else if (type == RD_TYPE_VNC_ETH) {
		snprintf(buf, size, "LHI:%d, %02x:%02x:%02x:%02x:%02x:%02x",
			 *(pnt + 1), /* LHI */
			 *(pnt + 2), /* MAC[0] */
			 *(pnt + 3), *(pnt + 4), *(pnt + 5), *(pnt + 6),
			 *(pnt + 7));

		return buf;
	}
#endif

	snprintf(buf, size, "Unknown Type: %d", type);
	return buf;
}

void form_auto_rd(struct in_addr router_id,
		  uint16_t rd_id,
		  struct prefix_rd *prd)
{
	char buf[100];

	prd->family = AF_UNSPEC;
	prd->prefixlen = 64;
	sprintf(buf, "%s:%hu", inet_ntoa(router_id), rd_id);
	(void)str2prefix_rd(buf, prd);
}
