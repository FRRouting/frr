// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP ARP handling.
 * Copyright (C) 2001-2017 Alexandre Cassen
 * Portions:
 *     Copyright (C) 2018-2019 Cumulus Networks, Inc.
 *     Quentin Young
 */
#include <zebra.h>

#include <linux/if_packet.h>
#include <net/if_arp.h>
#include <netinet/if_ether.h>

#include "lib/if.h"
#include "lib/linklist.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/prefix.h"

#include "vrrp.h"
#include "vrrp_arp.h"
#include "vrrp_debug.h"

#define VRRP_LOGPFX "[ARP] "

/*
 * The size of the garp packet buffer should be the large enough to hold the
 * largest arp packet to be sent + the size of the link layer header for the
 * corresponding protocol. In this case we hardcode for Ethernet.
 */
#define GARP_BUFFER_SIZE                                                       \
	sizeof(struct ether_header) + sizeof(struct arphdr) + 2 * ETH_ALEN     \
		+ 2 * sizeof(struct in_addr)

/* static vars */
static int garp_fd = -1;

/* Send the gratuitous ARP message */
static ssize_t vrrp_send_garp(struct interface *ifp, uint8_t *buf,
			      ssize_t pack_len)
{
	struct sockaddr_ll sll;
	ssize_t len;

	/* Build the dst device */
	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = ETH_P_ARP;
	sll.sll_ifindex = (int)ifp->ifindex;
	sll.sll_halen = ifp->hw_addr_len;
	memset(sll.sll_addr, 0xFF, ETH_ALEN);

	/* Send packet */
	len = sendto(garp_fd, buf, pack_len, 0, (struct sockaddr *)&sll,
		     sizeof(sll));

	return len;
}

/* Build a gratuitous ARP message over a specific interface */
static ssize_t vrrp_build_garp(uint8_t *buf, struct interface *ifp,
			       struct in_addr *v4)
{
	uint8_t *arp_ptr;

	if (ifp->hw_addr_len == 0)
		return -1;

	/* Build Ethernet header */
	struct ether_header *eth = (struct ether_header *)buf;

	memset(eth->ether_dhost, 0xFF, ETH_ALEN);
	memcpy(eth->ether_shost, ifp->hw_addr, ETH_ALEN);
	eth->ether_type = htons(ETHERTYPE_ARP);

	/* Build ARP payload */
	struct arphdr *arph = (struct arphdr *)(buf + ETHER_HDR_LEN);

	arph->ar_hrd = htons(HWTYPE_ETHER);
	arph->ar_pro = htons(ETHERTYPE_IP);
	arph->ar_hln = ifp->hw_addr_len;
	arph->ar_pln = sizeof(struct in_addr);
	arph->ar_op = htons(ARPOP_REQUEST);
	arp_ptr = (uint8_t *)(arph + 1);
	/* Source MAC: us */
	memcpy(arp_ptr, ifp->hw_addr, ifp->hw_addr_len);
	arp_ptr += ifp->hw_addr_len;
	/* Source IP: us */
	memcpy(arp_ptr, v4, sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);
	/* Dest MAC: broadcast */
	memset(arp_ptr, 0xFF, ETH_ALEN);
	arp_ptr += ifp->hw_addr_len;
	/* Dest IP: us */
	memcpy(arp_ptr, v4, sizeof(struct in_addr));
	arp_ptr += sizeof(struct in_addr);

	return arp_ptr - buf;
}

void vrrp_garp_send(struct vrrp_router *r, struct in_addr *v4)
{
	struct interface *ifp = r->mvl_ifp;
	uint8_t garpbuf[GARP_BUFFER_SIZE];
	ssize_t garpbuf_len;
	ssize_t sent_len;
	char astr[INET_ADDRSTRLEN];

	/* If the interface doesn't support ARP, don't try sending */
	if (ifp->flags & IFF_NOARP) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Unable to send gratuitous ARP on %s; has IFF_NOARP",
			r->vr->vrid, family2str(r->family), ifp->name);
		return;
	}

	/* Build garp */
	garpbuf_len = vrrp_build_garp(garpbuf, ifp, v4);

	if (garpbuf_len < 0) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Unable to send gratuitous ARP on %s; MAC address unknown",
			r->vr->vrid, family2str(r->family), ifp->name);
		return;
	};

	/* Send garp */
	inet_ntop(AF_INET, v4, astr, sizeof(astr));

	DEBUGD(&vrrp_dbg_arp,
	       VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
	       "Sending gratuitous ARP on %s for %s",
	       r->vr->vrid, family2str(r->family), ifp->name, astr);
	if (DEBUG_MODE_CHECK(&vrrp_dbg_arp, DEBUG_MODE_ALL))
		zlog_hexdump(garpbuf, garpbuf_len);

	sent_len = vrrp_send_garp(ifp, garpbuf, garpbuf_len);

	if (sent_len < 0)
		zlog_warn(VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			  "Error sending gratuitous ARP on %s for %s",
			  r->vr->vrid, family2str(r->family), ifp->name, astr);
	else
		++r->stats.garp_tx_cnt;
}

void vrrp_garp_send_all(struct vrrp_router *r)
{
	assert(r->family == AF_INET);

	struct interface *ifp = r->mvl_ifp;

	/* If the interface doesn't support ARP, don't try sending */
	if (ifp->flags & IFF_NOARP) {
		zlog_warn(
			VRRP_LOGPFX VRRP_LOGPFX_VRID VRRP_LOGPFX_FAM
			"Unable to send gratuitous ARP on %s; has IFF_NOARP",
			r->vr->vrid, family2str(r->family), ifp->name);
		return;
	}

	struct listnode *ln;
	struct ipaddr *ip;

	for (ALL_LIST_ELEMENTS_RO(r->addrs, ln, ip))
		vrrp_garp_send(r, &ip->ipaddr_v4);
}


void vrrp_garp_init(void)
{
	/* Create the socket descriptor */
	/* FIXME: why ETH_P_RARP? */
	errno = 0;
	frr_with_privs(&vrrp_privs) {
		garp_fd = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC,
				 htons(ETH_P_RARP));
	}

	if (garp_fd > 0) {
		DEBUGD(&vrrp_dbg_sock,
		       VRRP_LOGPFX "Initialized gratuitous ARP socket");
		DEBUGD(&vrrp_dbg_arp,
		       VRRP_LOGPFX "Initialized gratuitous ARP subsystem");
	} else {
		zlog_err(VRRP_LOGPFX
			 "Error initializing gratuitous ARP subsystem");
	}
}

void vrrp_garp_fini(void)
{
	close(garp_fd);
	garp_fd = -1;

	DEBUGD(&vrrp_dbg_arp,
	       VRRP_LOGPFX "Deinitialized gratuitous ARP subsystem");
}

bool vrrp_garp_is_init(void)
{
	return garp_fd > 0;
}
