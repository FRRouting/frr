// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP packet crafting.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 */
#include <zebra.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "lib/checksum.h"
#include "lib/ipaddr.h"
#include "lib/memory.h"

#include "vrrp.h"
#include "vrrp_debug.h"
#include "vrrp_packet.h"

DEFINE_MTYPE_STATIC(VRRPD, VRRP_PKT, "VRRP packet");

/* clang-format off */
static const char *const vrrp_packet_names[16] = {
	[0] = "Unknown",
	[VRRP_TYPE_ADVERTISEMENT] = "ADVERTISEMENT",
	[2] = "Unknown",
	[3] = "Unknown",
	[4] = "Unknown",
	[5] = "Unknown",
	[6] = "Unknown",
	[7] = "Unknown",
	[8] = "Unknown",
	[9] = "Unknown",
	[10] = "Unknown",
	[11] = "Unknown",
	[12] = "Unknown",
	[13] = "Unknown",
	[14] = "Unknown",
	[15] = "Unknown",
};
/* clang-format on */

/*
 * Compute the VRRP checksum.
 *
 * Checksum is not set in the packet, just computed.
 *
 * pkt
 *    VRRP packet, fully filled out except for checksum field.
 *
 * pktsize
 *    sizeof(*pkt)
 *
 * src
 *    IP address that pkt will be transmitted from.
 *
 * Returns:
 *    VRRP checksum in network byte order.
 */
static uint16_t vrrp_pkt_checksum(struct vrrp_pkt *pkt, size_t pktsize,
				  struct ipaddr *src, bool ipv4_ph)
{
	uint16_t chksum;
	bool v6 = (src->ipa_type == IPADDR_V6);

	uint16_t chksum_pre = pkt->hdr.chksum;

	pkt->hdr.chksum = 0;

	if (v6) {
		struct ipv6_ph ph = {};

		ph.src = src->ipaddr_v6;
		inet_pton(AF_INET6, VRRP_MCASTV6_GROUP_STR, &ph.dst);
		ph.ulpl = htons(pktsize);
		ph.next_hdr = IPPROTO_VRRP;
		chksum = in_cksum_with_ph6(&ph, pkt, pktsize);
	} else if (!v6 && ((pkt->hdr.vertype >> 4) == 3)) {
		if (ipv4_ph) {
			struct ipv4_ph ph = {};

			ph.src = src->ipaddr_v4;
			inet_pton(AF_INET, VRRP_MCASTV4_GROUP_STR, &ph.dst);
			ph.proto = IPPROTO_VRRP;
			ph.len = htons(pktsize);
			chksum = in_cksum_with_ph4(&ph, pkt, pktsize);
		} else
			chksum = in_cksum(pkt, pktsize);
	} else if (!v6 && ((pkt->hdr.vertype >> 4) == 2)) {
		chksum = in_cksum(pkt, pktsize);
	} else {
		assert(!"Invalid VRRP protocol version");
	}

	pkt->hdr.chksum = chksum_pre;

	return chksum;
}

ssize_t vrrp_pkt_adver_build(struct vrrp_pkt **pkt, struct ipaddr *src,
			     uint8_t version, uint8_t vrid, uint8_t prio,
			     uint16_t max_adver_int, uint8_t numip,
			     struct ipaddr **ips, bool ipv4_ph)
{
	bool v6 = false;
	size_t addrsz = 0;

	assert(version >= 2 && version <= 3);

	if (numip > 0) {
		v6 = IS_IPADDR_V6(ips[0]);
		addrsz = IPADDRSZ(ips[0]);
	}

	assert(!(version == 2 && v6));

	size_t pktsize = VRRP_PKT_SIZE(v6 ? AF_INET6 : AF_INET, version, numip);

	*pkt = XCALLOC(MTYPE_VRRP_PKT, pktsize);

	(*pkt)->hdr.vertype |= version << 4;
	(*pkt)->hdr.vertype |= VRRP_TYPE_ADVERTISEMENT;
	(*pkt)->hdr.vrid = vrid;
	(*pkt)->hdr.priority = prio;
	(*pkt)->hdr.naddr = numip;
	if (version == 3)
		(*pkt)->hdr.v3.adver_int = htons(max_adver_int);
	else if (version == 2) {
		(*pkt)->hdr.v2.auth_type = 0;
		(*pkt)->hdr.v2.adver_int = MAX(max_adver_int / 100, 1);
	}

	uint8_t *aptr = (void *)(*pkt)->addrs;

	for (int i = 0; i < numip; i++) {
		memcpy(aptr, &ips[i]->ip.addr, addrsz);
		aptr += addrsz;
	}

	(*pkt)->hdr.chksum = vrrp_pkt_checksum(*pkt, pktsize, src, ipv4_ph);

	return pktsize;
}

void vrrp_pkt_free(struct vrrp_pkt *pkt)
{
	XFREE(MTYPE_VRRP_PKT, pkt);
}

size_t vrrp_pkt_adver_dump(char *buf, size_t buflen, struct vrrp_pkt *pkt)
{
	if (buflen < 1)
		return 0;

	char tmpbuf[BUFSIZ];
	size_t rs = 0;
	struct vrrp_hdr *hdr = &pkt->hdr;

	buf[0] = 0x00;
	snprintf(tmpbuf, sizeof(tmpbuf), "version %u, ", (hdr->vertype >> 4));
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "type %u (%s), ",
		 (hdr->vertype & 0x0F),
		 vrrp_packet_names[(hdr->vertype & 0x0F)]);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "vrid %u, ", hdr->vrid);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "priority %u, ", hdr->priority);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "#%u addresses, ", hdr->naddr);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "max adver int %u, ",
		 ntohs(hdr->v3.adver_int));
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "checksum %x", ntohs(hdr->chksum));
	rs += strlcat(buf, tmpbuf, buflen);

	return rs;
}

ssize_t vrrp_pkt_parse_datagram(int family, int version, bool ipv4_ph,
				struct msghdr *m, size_t read,
				struct ipaddr *src, struct vrrp_pkt **pkt,
				char *errmsg, size_t errmsg_len)
{
	/* Source (MAC & IP), Dest (MAC & IP) TTL validation done by kernel */
	size_t addrsz = (family == AF_INET) ? sizeof(struct in_addr)
					    : sizeof(struct in6_addr);

	size_t pktsize;
	uint8_t *buf = m->msg_iov->iov_base;

#define VRRP_PKT_VCHECK(cond, _f, ...)                                         \
	do {                                                                   \
		if (!(cond)) {                                                 \
			if (errmsg)                                            \
				snprintf(errmsg, errmsg_len, (_f),             \
					 ##__VA_ARGS__);                       \
			return -1;                                             \
		}                                                              \
	} while (0)

	/* IPvX header check */

	if (family == AF_INET) {
		VRRP_PKT_VCHECK(
			read >= sizeof(struct ip),
			"Datagram not large enough to contain IP header");

		struct ip *ip = (struct ip *)buf;

		/* IP total length check */
		VRRP_PKT_VCHECK(
			ntohs(ip->ip_len) == read,
			"IPv4 packet length field does not match # received bytes; %hu!= %zu",
			ntohs(ip->ip_len), read);

		/* TTL check */
		VRRP_PKT_VCHECK(ip->ip_ttl == 255,
				"IPv4 TTL is %hhu; should be 255",
				ip->ip_ttl);

		*pkt = (struct vrrp_pkt *)(buf + (ip->ip_hl << 2));
		pktsize = read - (ip->ip_hl << 2);

		/* IP empty packet check */
		VRRP_PKT_VCHECK(pktsize > 0, "IPv4 packet has no payload");

		/* Extract source address */
		struct sockaddr_in *sa = m->msg_name;

		src->ipa_type = IPADDR_V4;
		src->ipaddr_v4 = sa->sin_addr;
	} else if (family == AF_INET6) {
		struct cmsghdr *c;

		for (c = CMSG_FIRSTHDR(m); c != NULL; c = CMSG_NXTHDR(m, c)) {
			if (c->cmsg_level == IPPROTO_IPV6
			    && c->cmsg_type == IPV6_HOPLIMIT)
				break;
		}

		VRRP_PKT_VCHECK(!!c, "IPv6 Hop Limit not received");

		uint8_t *hoplimit = CMSG_DATA(c);

		VRRP_PKT_VCHECK(*hoplimit == 255,
				"IPv6 Hop Limit is %hhu; should be 255",
				*hoplimit);

		*pkt = (struct vrrp_pkt *)buf;
		pktsize = read;

		/* Extract source address */
		struct sockaddr_in6 *sa = m->msg_name;

		src->ipa_type = IPADDR_V6;
		memcpy(&src->ipaddr_v6, &sa->sin6_addr,
		       sizeof(struct in6_addr));
	} else {
		assert(!"Unknown address family");
	}

	/* Size check */
	size_t minsize = (family == AF_INET) ? VRRP_MIN_PKT_SIZE_V4
					     : VRRP_MIN_PKT_SIZE_V6;
	size_t maxsize = (family == AF_INET) ? VRRP_MAX_PKT_SIZE_V4
					     : VRRP_MAX_PKT_SIZE_V6;
	VRRP_PKT_VCHECK(pktsize >= minsize,
			"VRRP packet is undersized (%zu < %zu)", pktsize,
			minsize);
	VRRP_PKT_VCHECK(pktsize <= maxsize,
			"VRRP packet is oversized (%zu > %zu)", pktsize,
			maxsize);

	/* Version check */
	uint8_t pktver = (*pkt)->hdr.vertype >> 4;

	VRRP_PKT_VCHECK(pktver == version, "Bad version %u", pktver);

	/* Checksum check */
	uint16_t chksum = vrrp_pkt_checksum(*pkt, pktsize, src, ipv4_ph);

	VRRP_PKT_VCHECK((*pkt)->hdr.chksum == chksum,
			"Bad VRRP checksum %hx; should be %hx",
			(*pkt)->hdr.chksum, chksum);

	/* Type check */
	VRRP_PKT_VCHECK(((*pkt)->hdr.vertype & 0x0F) == 1, "Bad type %u",
			(*pkt)->hdr.vertype & 0x0f);

	/* Exact size check */
	size_t ves = VRRP_PKT_SIZE(family, pktver, (*pkt)->hdr.naddr);

	VRRP_PKT_VCHECK(pktsize == ves, "Packet has incorrect # addresses%s",
			pktver == 2 ? " or missing auth fields" : "");

	/* auth type check */
	if (version == 2)
		VRRP_PKT_VCHECK((*pkt)->hdr.v2.auth_type == 0,
				"Bad authentication type %hhu",
				(*pkt)->hdr.v2.auth_type);

	/* Addresses check */
	char vbuf[INET6_ADDRSTRLEN];
	uint8_t *p = (uint8_t *)(*pkt)->addrs;

	for (uint8_t i = 0; i < (*pkt)->hdr.naddr; i++) {
		VRRP_PKT_VCHECK(inet_ntop(family, p, vbuf, sizeof(vbuf)),
				"Bad IP address, #%hhu", i);
		p += addrsz;
	}

	/* Everything checks out */
	return pktsize;
}
