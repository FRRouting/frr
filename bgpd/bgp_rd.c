// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP RD definitions for BGP-based VPNs (IP/EVPN)
 * -- brought over from bgpd/bgp_mplsvpn.c
 * Copyright (C) 2000 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#include <zebra.h>
#include "command.h"
#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "stream.h"
#include "filter.h"
#include "frrstr.h"

#include "lib/printfrr.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/bgp_attr.h"

#ifdef ENABLE_BGP_VNC
#include "bgpd/rfapi/rfapi_backend.h"
#endif

uint16_t decode_rd_type(const uint8_t *pnt)
{
	uint16_t v;

	v = ((uint16_t)*pnt++ << 8);
#ifdef ENABLE_BGP_VNC
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
void decode_rd_as(const uint8_t *pnt, struct rd_as *rd_as)
{
	rd_as->as = (uint16_t)*pnt++ << 8;
	rd_as->as |= (uint16_t)*pnt++;
	ptr_get_be32(pnt, &rd_as->val);
}

/* type == RD_TYPE_AS4 */
void decode_rd_as4(const uint8_t *pnt, struct rd_as *rd_as)
{
	pnt = ptr_get_be32(pnt, &rd_as->as);
	rd_as->val = ((uint16_t)*pnt++ << 8);
	rd_as->val |= (uint16_t)*pnt;
}

/* type == RD_TYPE_IP */
void decode_rd_ip(const uint8_t *pnt, struct rd_ip *rd_ip)
{
	memcpy(&rd_ip->ip, pnt, 4);
	pnt += 4;

	rd_ip->val = ((uint16_t)*pnt++ << 8);
	rd_ip->val |= (uint16_t)*pnt;
}

#ifdef ENABLE_BGP_VNC
/* type == RD_TYPE_VNC_ETH */
void decode_rd_vnc_eth(const uint8_t *pnt, struct rd_vnc_eth *rd_vnc_eth)
{
	rd_vnc_eth->type = RD_TYPE_VNC_ETH;
	rd_vnc_eth->local_nve_id = pnt[1];
	memcpy(rd_vnc_eth->macaddr.octet, pnt + 2, ETH_ALEN);
}
#endif

int str2prefix_rd(const char *str, struct prefix_rd *prd)
{
	int ret = 0, type = RD_TYPE_UNDEFINED;
	char *p, *p2;
	struct stream *s = NULL;
	char *half = NULL;
	struct in_addr addr;
	as_t as_val;

	prd->family = AF_UNSPEC;
	prd->prefixlen = 64;

	p = strchr(str, ':');
	if (!p)
		goto out;

	/* a second ':' is accepted */
	p2 = strchr(p + 1, ':');
	if (p2) {
		/* type is in first part */
		half = XMALLOC(MTYPE_TMP, (p - str) + 1);
		memcpy(half, str, (p - str));
		half[p - str] = '\0';
		type = atoi(half);
		if (type != RD_TYPE_AS && type != RD_TYPE_IP &&
		    type != RD_TYPE_AS4)
			goto out;
		XFREE(MTYPE_TMP, half);
		half = XMALLOC(MTYPE_TMP, (p2 - p));
		memcpy(half, p + 1, (p2 - p - 1));
		half[p2 - p - 1] = '\0';
		p = p2 + 1;
	} else {
		half = XMALLOC(MTYPE_TMP, (p - str) + 1);
		memcpy(half, str, (p - str));
		half[p - str] = '\0';
	}
	if (!all_digit(p + 1))
		goto out;

	s = stream_new(RD_BYTES);

	/* if it is an AS format or an IP */
	if (asn_str2asn(half, &as_val)) {
		if (as_val > UINT16_MAX) {
			stream_putw(s, RD_TYPE_AS4);
			stream_putl(s, as_val);
			stream_putw(s, atol(p + 1));
			if (type != RD_TYPE_UNDEFINED && type != RD_TYPE_AS4)
				goto out;
		} else {
			stream_putw(s, RD_TYPE_AS);
			stream_putw(s, as_val);
			stream_putl(s, atol(p + 1));
			if (type != RD_TYPE_UNDEFINED && type != RD_TYPE_AS)
				goto out;
		}
	} else if (inet_aton(half, &addr)) {
		stream_putw(s, RD_TYPE_IP);
		stream_put_in_addr(s, &addr);
		stream_putw(s, atol(p + 1));
		if (type != RD_TYPE_UNDEFINED && type != RD_TYPE_IP)
			goto out;
	} else
		goto out;
	memcpy(prd->val, s->data, 8);
	ret = 1;

out:
	if (s)
		stream_free(s);
	XFREE(MTYPE_TMP, half);
	return ret;
}

char *prefix_rd2str(const struct prefix_rd *prd, char *buf, size_t size,
		    enum asnotation_mode asnotation)
{
	const uint8_t *pnt;
	uint16_t type;
	struct rd_as rd_as;
	struct rd_ip rd_ip;
	int len = 0;

	assert(size >= RD_ADDRSTRLEN);

	pnt = prd->val;

	type = decode_rd_type(pnt);

	if (type == RD_TYPE_AS) {
		decode_rd_as(pnt + 2, &rd_as);
		len += snprintfrr(buf + len, size - len, ASN_FORMAT(asnotation),
				  &rd_as.as);
		snprintfrr(buf + len, size - len, ":%u", rd_as.val);
		return buf;
	} else if (type == RD_TYPE_AS4) {
		decode_rd_as4(pnt + 2, &rd_as);
		len += snprintfrr(buf + len, size - len, ASN_FORMAT(asnotation),
				  &rd_as.as);
		snprintfrr(buf + len, size - len, ":%u", rd_as.val);
		return buf;
	} else if (type == RD_TYPE_IP) {
		decode_rd_ip(pnt + 2, &rd_ip);
		snprintfrr(buf, size, "%pI4:%hu", &rd_ip.ip, rd_ip.val);
		return buf;
	}
#ifdef ENABLE_BGP_VNC
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
	snprintfrr(buf, sizeof(buf), "%pI4:%hu", &router_id, rd_id);
	(void)str2prefix_rd(buf, prd);
}

static ssize_t printfrr_prd_asnotation(struct fbuf *buf,
				       struct printfrr_eargs *ea,
				       const void *ptr,
				       enum asnotation_mode asnotation)
{
	char rd_buf[RD_ADDRSTRLEN];

	if (!ptr)
		return bputs(buf, "(null)");

	prefix_rd2str(ptr, rd_buf, sizeof(rd_buf), asnotation);

	return bputs(buf, rd_buf);
}

printfrr_ext_autoreg_p("RDP", printfrr_prd);
static ssize_t printfrr_prd(struct fbuf *buf, struct printfrr_eargs *ea,
			    const void *ptr)
{
	return printfrr_prd_asnotation(buf, ea, ptr, ASNOTATION_PLAIN);
}

printfrr_ext_autoreg_p("RDD", printfrr_prd_dot);
static ssize_t printfrr_prd_dot(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	return printfrr_prd_asnotation(buf, ea, ptr, ASNOTATION_DOT);
}

printfrr_ext_autoreg_p("RDE", printfrr_prd_dotplus);
static ssize_t printfrr_prd_dotplus(struct fbuf *buf, struct printfrr_eargs *ea,
				    const void *ptr)
{
	return printfrr_prd_asnotation(buf, ea, ptr, ASNOTATION_DOTPLUS);
}
