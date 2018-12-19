/*
 * VRRPD packet crafting
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>

#include "lib/checksum.h"
#include "lib/ipaddr.h"
#include "lib/memory.h"

#include "vrrp_packet.h"

/* clang-format off */
const char *vrrp_packet_names[16] = {
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

ssize_t vrrp_pkt_build(struct vrrp_pkt **pkt, uint8_t vrid, uint8_t prio,
		       uint16_t max_adver_int, uint8_t numip,
		       struct ipaddr **ips)
{
	bool v6 = IS_IPADDR_V6(ips[0]);

	size_t addrsz = v6 ? sizeof(struct in6_addr) : sizeof(struct in_addr);
	size_t pktsize = VRRP_PKT_SIZE(v6 ? AF_INET6 : AF_INET, numip);
	*pkt = XCALLOC(MTYPE_TMP, pktsize);

	(*pkt)->hdr.vertype |= VRRP_VERSION << 4;
	(*pkt)->hdr.vertype |= VRRP_TYPE_ADVERTISEMENT;
	(*pkt)->hdr.vrid = vrid;
	(*pkt)->hdr.priority = prio;
	(*pkt)->hdr.naddr = numip;
	(*pkt)->hdr.v3.adver_int = htons(max_adver_int);

	uint8_t *aptr = (void *)(*pkt)->addrs;

	for (int i = 0; i < numip; i++) {
		memcpy(aptr, &ips[i]->ip.addr, addrsz);
		aptr += addrsz;
	}
	(*pkt)->hdr.chksum = 0;

	/* FIXME: v6 checksum */
	uint16_t chksum = in_cksum(*pkt, pktsize);
	(*pkt)->hdr.chksum = htons(chksum);

	return pktsize;
}

size_t vrrp_pkt_dump(char *buf, size_t buflen, struct vrrp_pkt *pkt)
{
	if (buflen < 1)
		return 0;

	char tmpbuf[BUFSIZ];
	size_t rs = 0;
	struct vrrp_hdr *hdr = &pkt->hdr;

	buf[0] = 0x00;
	snprintf(tmpbuf, sizeof(tmpbuf), "Version: %u\n", (hdr->vertype >> 4));
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "Type: %u (%s)\n",
		 (hdr->vertype & 0x0F),
		 vrrp_packet_names[(hdr->vertype & 0x0F)]);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "VRID: %u\n", hdr->vrid);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "Priority: %u\n", hdr->priority);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "Count IPvX: %u\n", hdr->naddr);
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "Max Adver Int: %u\n",
		 ntohs(hdr->v3.adver_int));
	rs += strlcat(buf, tmpbuf, buflen);
	snprintf(tmpbuf, sizeof(tmpbuf), "Checksum: %x\n", ntohs(hdr->chksum));
	rs += strlcat(buf, tmpbuf, buflen);

	return rs;
}

ssize_t vrrp_parse_datagram(int family, struct msghdr *m, size_t read,
			    struct vrrp_pkt **pkt, char *errmsg,
			    size_t errmsg_len)
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
			"IPv4 packet length field does not match # received bytes; %u != %lu",
			ntohs(ip->ip_len), read);

		/* TTL check */
		VRRP_PKT_VCHECK(ip->ip_ttl == 255, "IPv4 TTL is not 255");

		*pkt = (struct vrrp_pkt *)(buf + (ip->ip_hl << 2));
		pktsize = read - (ip->ip_hl << 2);

		/* IP empty packet check */
		VRRP_PKT_VCHECK(pktsize > 0, "IPv4 packet has no payload");
	} else if (family == AF_INET6) {
		struct cmsghdr *c;
		for (c = CMSG_FIRSTHDR(m); c != NULL; CMSG_NXTHDR(m, c)) {
			if (c->cmsg_level == IPPROTO_IPV6
			    && c->cmsg_type == IPV6_HOPLIMIT)
				break;
		}

		VRRP_PKT_VCHECK(!!c, "IPv6 Hop Limit not received");

		uint8_t *hoplimit = CMSG_DATA(c);
		VRRP_PKT_VCHECK(*hoplimit == 255, "IPv6 Hop Limit is not 255");

		*pkt = (struct vrrp_pkt *)buf;
		pktsize = read;
	} else {
		assert(!"Unknown address family");
	}

	/* Size check */
	size_t minsize = (family == AF_INET) ? VRRP_MIN_PKT_SIZE_V4
					     : VRRP_MIN_PKT_SIZE_V6;
	size_t maxsize = (family == AF_INET) ? VRRP_MAX_PKT_SIZE_V4
					     : VRRP_MAX_PKT_SIZE_V6;
	VRRP_PKT_VCHECK(pktsize >= minsize,
			"VRRP packet is undersized (%lu < %lu)", pktsize,
			VRRP_MIN_PKT_SIZE);
	VRRP_PKT_VCHECK(pktsize <= maxsize,
			"VRRP packet is oversized (%lu > %lu)", pktsize,
			VRRP_MAX_PKT_SIZE);
	/* Version check */
	VRRP_PKT_VCHECK(((*pkt)->hdr.vertype >> 4) != 2, "VRPPv2 unsupported");
	VRRP_PKT_VCHECK(((*pkt)->hdr.vertype >> 4) == 3, "Bad version %u",
			(*pkt)->hdr.vertype >> 4);
	/* Type check */
	VRRP_PKT_VCHECK(((*pkt)->hdr.vertype & 0x0F) == 1, "Bad type %u",
			(*pkt)->hdr.vertype & 0x0f);
	/* Priority check */
	VRRP_PKT_VCHECK((*pkt)->hdr.priority == 255
				|| (*pkt)->hdr.priority == 0,
			"Bad priority %u", (*pkt)->hdr.priority);
	/* # addresses check */
	size_t ves = VRRP_PKT_SIZE(family, (*pkt)->hdr.naddr);
	VRRP_PKT_VCHECK(pktsize == ves, "Packet has incorrect # addresses");
	/* FIXME: checksum check */
	/* ... */

	/* Addresses check */
	char vbuf[INET6_ADDRSTRLEN];
	uint8_t *p = (uint8_t *)(*pkt)->addrs;
	for (uint8_t i = 0; i < (*pkt)->hdr.naddr; i++) {
		VRRP_PKT_VCHECK(inet_ntop(family, p, vbuf, sizeof(vbuf)),
				"Bad IP address, #%u", i);
		p += addrsz;
	}

	/* Everything checks out */
	return pktsize;
}
