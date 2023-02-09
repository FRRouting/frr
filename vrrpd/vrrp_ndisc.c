// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP Neighbor Discovery.
 * Copyright (C) 2019 Cumulus Networks, Inc.
 * Quentin Young
 *
 * Portions:
 *     Copyright (C) 2001-2017 Alexandre Cassen
 */
#include <zebra.h>

#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/icmp6.h>
#include <netinet/in.h>

#include "lib/checksum.h"
#include "lib/if.h"
#include "lib/ipaddr.h"
#include "lib/log.h"

#include "vrrp_debug.h"
#include "vrrp_ndisc.h"

#define VRRP_LOGPFX "[NDISC] "

#define VRRP_NDISC_HOPLIMIT 255
#define VRRP_NDISC_SIZE                                                        \
	ETHER_HDR_LEN + sizeof(struct ip6_hdr)                                 \
		+ sizeof(struct nd_neighbor_advert)                            \
		+ sizeof(struct nd_opt_hdr) + ETH_ALEN

/* static vars */
static int ndisc_fd = -1;

/*
 * Build an unsolicited Neighbour Advertisement.
 *
 * ifp
 *    Interface to send Neighbor Advertisement on
 *
 * ip
 *    IP address to send Neighbor Advertisement for
 *
 * buf
 *    Buffer to fill with IPv6 Neighbor Advertisement message. Includes
 *    Ethernet header.
 *
 * bufsiz
 *    Size of buf.
 *
 * Returns;
 *    -1 if bufsiz is too small
 *     0 otherwise
 */
static int vrrp_ndisc_una_build(struct interface *ifp, struct ipaddr *ip,
				uint8_t *buf, size_t bufsiz)
{
	if (bufsiz < VRRP_NDISC_SIZE)
		return -1;

	memset(buf, 0x00, bufsiz);

	struct ether_header *eth = (struct ether_header *)buf;
	struct ip6_hdr *ip6h = (struct ip6_hdr *)((char *)eth + ETHER_HDR_LEN);
	struct nd_neighbor_advert *ndh =
		(struct nd_neighbor_advert *)((char *)ip6h
					      + sizeof(struct ip6_hdr));
	struct icmp6_hdr *icmp6h = &ndh->nd_na_hdr;
	struct nd_opt_hdr *nd_opt_h =
		(struct nd_opt_hdr *)((char *)ndh
				      + sizeof(struct nd_neighbor_advert));
	char *nd_opt_lladdr = ((char *)nd_opt_h + sizeof(struct nd_opt_hdr));
	char *lladdr = (char *)ifp->hw_addr;

	/*
	 * An IPv6 packet with a multicast destination address DST, consisting
	 * of the sixteen octets DST[1] through DST[16], is transmitted to the
	 * Ethernet multicast address whose first two octets are the value 3333
	 * hexadecimal and whose last four octets are the last four octets of
	 * DST.
	 *    - RFC2464.7
	 *
	 * In this case we are sending to the all nodes multicast address, so
	 * the last four octets are 0x00 0x00 0x00 0x01.
	 */
	memset(eth->ether_dhost, 0, ETH_ALEN);
	eth->ether_dhost[0] = 0x33;
	eth->ether_dhost[1] = 0x33;
	eth->ether_dhost[5] = 1;

	/* Set source Ethernet address to interface link layer address */
	memcpy(eth->ether_shost, lladdr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_IPV6);

	/* IPv6 Header */
	ip6h->ip6_vfc = 6 << 4;
	ip6h->ip6_plen = htons(sizeof(struct nd_neighbor_advert)
			       + sizeof(struct nd_opt_hdr) + ETH_ALEN);
	ip6h->ip6_nxt = IPPROTO_ICMPV6;
	ip6h->ip6_hlim = VRRP_NDISC_HOPLIMIT;
	memcpy(&ip6h->ip6_src, &ip->ipaddr_v6, sizeof(struct in6_addr));
	/* All nodes multicast address */
	ip6h->ip6_dst.s6_addr[0] = 0xFF;
	ip6h->ip6_dst.s6_addr[1] = 0x02;
	ip6h->ip6_dst.s6_addr[15] = 0x01;

	/* ICMPv6 Header */
	ndh->nd_na_type = ND_NEIGHBOR_ADVERT;
	ndh->nd_na_flags_reserved |= ND_NA_FLAG_ROUTER;
	ndh->nd_na_flags_reserved |= ND_NA_FLAG_OVERRIDE;
	memcpy(&ndh->nd_na_target, &ip->ipaddr_v6, sizeof(struct in6_addr));

	/* NDISC Option header */
	nd_opt_h->nd_opt_type = ND_OPT_TARGET_LINKADDR;
	nd_opt_h->nd_opt_len = 1;
	memcpy(nd_opt_lladdr, lladdr, ETH_ALEN);

	/* Compute checksum */
	uint32_t len = sizeof(struct nd_neighbor_advert)
		       + sizeof(struct nd_opt_hdr) + ETH_ALEN;
	struct ipv6_ph ph = {};

	ph.src = ip6h->ip6_src;
	ph.dst = ip6h->ip6_dst;
	ph.ulpl = htonl(len);
	ph.next_hdr = IPPROTO_ICMPV6;

	/* Suppress static analysis warnings about accessing icmp6 oob */
	void *offset = icmp6h;
	icmp6h->icmp6_cksum = in_cksum_with_ph6(&ph, offset, len);

	return 0;
}

int vrrp_ndisc_una_send(struct vrrp_router *r, struct ipaddr *ip)
{
	assert(r->family == AF_INET6);

	int ret = 0;
	struct interface *ifp = r->mvl_ifp;
	uint8_t buf[VRRP_NDISC_SIZE];

	ret = vrrp_ndisc_una_build(ifp, ip, buf, sizeof(buf));

	if (ret == -1)
		return ret;

	struct sockaddr_ll sll;
	ssize_t len;

	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	memcpy(sll.sll_addr, ifp->hw_addr, ETH_ALEN);
	sll.sll_halen = ETH_ALEN;
	sll.sll_ifindex = (int)ifp->ifindex;

	char ipbuf[INET6_ADDRSTRLEN];

	ipaddr2str(ip, ipbuf, sizeof(ipbuf));

	DEBUGD(&vrrp_dbg_ndisc,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Sending unsolicited Neighbor Advertisement on %s for %s",
	       r->vr->vrid, family2str(r->family), ifp->name, ipbuf);

	if (DEBUG_MODE_CHECK(&vrrp_dbg_ndisc, DEBUG_MODE_ALL)
	    && DEBUG_MODE_CHECK(&vrrp_dbg_pkt, DEBUG_MODE_ALL))
		zlog_hexdump(buf, VRRP_NDISC_SIZE);

	len = sendto(ndisc_fd, buf, VRRP_NDISC_SIZE, 0, (struct sockaddr *)&sll,
		     sizeof(sll));

	if (len < 0) {
		zlog_err(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Error sending unsolicited Neighbor Advertisement on %s for %s",
			r->vr->vrid, family2str(r->family), ifp->name, ipbuf);
		ret = -1;
	} else {
		++r->stats.una_tx_cnt;
	}

	return ret;
}

int vrrp_ndisc_una_send_all(struct vrrp_router *r)
{
	assert(r->family == AF_INET6);

	struct listnode *ln;
	struct ipaddr *ip;

	for (ALL_LIST_ELEMENTS_RO(r->addrs, ln, ip))
		vrrp_ndisc_una_send(r, ip);

	return 0;
}

void vrrp_ndisc_init(void)
{
	frr_with_privs(&vrrp_privs) {
		ndisc_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IPV6));
	}

	if (ndisc_fd > 0) {
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX "Initialized Neighbor Discovery socket");
		DEBUGD(&vrrp_dbg_ndisc,
		       VRRP_LOGPFX "Initialized Neighbor Discovery subsystem");
	} else {
		zlog_err(VRRP_LOGPFX
			 "Error initializing Neighbor Discovery socket");
	}
}

void vrrp_ndisc_fini(void)
{
	close(ndisc_fd);
	ndisc_fd = -1;

	DEBUGD(&vrrp_dbg_ndisc,
	       VRRP_LOGPFX "Deinitialized Neighbor Discovery subsystem");
}

bool vrrp_ndisc_is_init(void)
{
	return ndisc_fd > 0;
}
