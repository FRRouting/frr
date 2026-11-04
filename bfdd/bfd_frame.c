// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BFD raw frame builder.
 *
 * Copyright (C) 2026 Aviz Networks
 */

#include <zebra.h>

#include "lib/checksum.h"

#include "bfd_frame.h"

#define BFD_FRAME_ETHERTYPE_IPV4 0x0800
#define BFD_FRAME_ETHERTYPE_IPV6 0x86DD
#define BFD_FRAME_IPV4_HLEN	 20
#define BFD_FRAME_IPV6_HLEN	 40
#define BFD_FRAME_UDP_HLEN	 8

static inline void put16(uint8_t *p, uint16_t v)
{
	p[0] = v >> 8;
	p[1] = v & 0xff;
}

/* RFC 768: a computed checksum of zero is transmitted as all ones. */
static inline uint16_t udp_cksum_fixup(uint16_t sum)
{
	return sum == 0 ? 0xffff : sum;
}

ssize_t bfd_frame_build(uint8_t *buf, size_t buflen, const struct bfd_frame_params *params,
			const void *payload, size_t plen)
{
	size_t iphlen, udplen, total;
	uint8_t *ip, *udp;
	uint16_t sum;

	switch (params->family) {
	case AF_INET:
		iphlen = BFD_FRAME_IPV4_HLEN;
		break;
	case AF_INET6:
		iphlen = BFD_FRAME_IPV6_HLEN;
		break;
	default:
		return -1;
	}

	/* Check plen alone first: adding the headers to a huge plen wraps. */
	if (plen > UINT16_MAX - iphlen - BFD_FRAME_UDP_HLEN)
		return -1;
	udplen = BFD_FRAME_UDP_HLEN + plen;

	total = BFD_FRAME_ETH_HLEN + iphlen + udplen;
	if (buf == NULL || total > buflen || (plen > 0 && payload == NULL))
		return -1;

	memset(buf, 0, BFD_FRAME_ETH_HLEN + iphlen + BFD_FRAME_UDP_HLEN);

	/* Ethernet header. */
	memcpy(buf, params->dmac, BFD_FRAME_MAC_LEN);
	memcpy(buf + BFD_FRAME_MAC_LEN, params->smac, BFD_FRAME_MAC_LEN);
	put16(buf + 2 * BFD_FRAME_MAC_LEN,
	      params->family == AF_INET ? BFD_FRAME_ETHERTYPE_IPV4 : BFD_FRAME_ETHERTYPE_IPV6);

	ip = buf + BFD_FRAME_ETH_HLEN;
	udp = ip + iphlen;

	/* UDP header and payload; checksum filled in below. */
	put16(udp, params->sport);
	put16(udp + 2, params->dport);
	put16(udp + 4, udplen);
	if (plen > 0)
		memcpy(udp + BFD_FRAME_UDP_HLEN, payload, plen);

	if (params->family == AF_INET) {
		struct ipv4_ph ph = {};

		ip[0] = 0x45; /* version 4, 5 words */
		ip[1] = params->tos;
		put16(ip + 2, iphlen + udplen);
		put16(ip + 4, params->ip_id);
		/* flags / fragment offset left zero */
		ip[8] = params->ttl;
		ip[9] = IPPROTO_UDP;
		memcpy(ip + 12, &params->src.v4, 4);
		memcpy(ip + 16, &params->dst.v4, 4);
		sum = in_cksum(ip, iphlen);
		memcpy(ip + 10, &sum, sizeof(sum));

		ph.src = params->src.v4;
		ph.dst = params->dst.v4;
		ph.proto = IPPROTO_UDP;
		ph.len = htons(udplen);
		sum = udp_cksum_fixup(in_cksum_with_ph4(&ph, udp, udplen));
	} else {
		struct ipv6_ph ph = {};

		/* version 6, traffic class, flow label 0 */
		ip[0] = 0x60 | (params->tos >> 4);
		ip[1] = (params->tos & 0x0f) << 4;
		put16(ip + 4, udplen);
		ip[6] = IPPROTO_UDP;
		ip[7] = params->ttl;
		memcpy(ip + 8, &params->src.v6, 16);
		memcpy(ip + 24, &params->dst.v6, 16);

		ph.src = params->src.v6;
		ph.dst = params->dst.v6;
		ph.ulpl = htonl(udplen);
		ph.next_hdr = IPPROTO_UDP;
		sum = udp_cksum_fixup(in_cksum_with_ph6(&ph, udp, udplen));
	}

	/* in_cksum*() return the checksum already in network byte order. */
	memcpy(udp + 6, &sum, sizeof(sum));

	return total;
}
