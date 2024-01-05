// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2017 Cumulus Networks, Inc.  All rights reserved.
 *
 * bfd_packet.c: implements the BFD protocol packet handling.
 *
 * Authors
 * -------
 * Shrijeet Mukherjee [shm@cumulusnetworks.com]
 * Kanna Rajagopal [kanna@cumulusnetworks.com]
 * Radhika Mahankali [Radhika@cumulusnetworks.com]
 */

#include <zebra.h>
#include <sys/ioctl.h>

#ifdef GNU_LINUX
#include <linux/filter.h>
#endif

#ifdef BFD_LINUX
#include <linux/if_packet.h>
#endif /* BFD_LINUX */

#include <netinet/if_ether.h>
#include <netinet/udp.h>

#include "lib/sockopt.h"
#include "lib/checksum.h"
#include "lib/network.h"

#include "bfd.h"

/*
 * Prototypes
 */
static int ptm_bfd_process_echo_pkt(struct bfd_vrf_global *bvrf, int s);
int _ptm_bfd_send(struct bfd_session *bs, uint16_t *port, const void *data,
		  size_t datalen);

static void bfd_sd_reschedule(struct bfd_vrf_global *bvrf, int sd);
ssize_t bfd_recv_ipv4(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      ifindex_t *ifindex, struct sockaddr_any *local,
		      struct sockaddr_any *peer);
ssize_t bfd_recv_ipv6(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      ifindex_t *ifindex, struct sockaddr_any *local,
		      struct sockaddr_any *peer);
int bp_udp_send(int sd, uint8_t ttl, uint8_t *data, size_t datalen,
		struct sockaddr *to, socklen_t tolen);
int bp_bfd_echo_in(struct bfd_vrf_global *bvrf, int sd, uint8_t *ttl,
		   uint32_t *my_discr, uint64_t *my_rtt);
#ifdef BFD_LINUX
ssize_t bfd_recv_ipv4_fp(int sd, uint8_t *msgbuf, size_t msgbuflen,
			 uint8_t *ttl, ifindex_t *ifindex,
			 struct sockaddr_any *local, struct sockaddr_any *peer);
void bfd_peer_mac_set(int sd, struct bfd_session *bfd,
		      struct sockaddr_any *peer, struct interface *ifp);
int bp_udp_send_fp(int sd, uint8_t *data, size_t datalen,
		   struct bfd_session *bfd);
ssize_t bfd_recv_fp_echo(int sd, uint8_t *msgbuf, size_t msgbuflen,
			 uint8_t *ttl, ifindex_t *ifindex,
			 struct sockaddr_any *local, struct sockaddr_any *peer);
#endif

/* socket related prototypes */
static void bp_set_ipopts(int sd);
static void bp_bind_ip(int sd, uint16_t port);
static void bp_set_ipv6opts(int sd);
static void bp_bind_ipv6(int sd, uint16_t port);


/*
 * Functions
 */
int _ptm_bfd_send(struct bfd_session *bs, uint16_t *port, const void *data,
		  size_t datalen)
{
	struct sockaddr *sa;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	socklen_t slen;
	ssize_t rv;
	int sd = -1;

	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6)) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		memcpy(&sin6.sin6_addr, &bs->key.peer, sizeof(sin6.sin6_addr));
		if (bs->ifp && IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
			sin6.sin6_scope_id = bs->ifp->ifindex;

		sin6.sin6_port =
			(port) ? *port
			       : (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
					 ? htons(BFD_DEF_MHOP_DEST_PORT)
					 : htons(BFD_DEFDESTPORT);

		sd = bs->sock;
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(sin6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		memcpy(&sin.sin_addr, &bs->key.peer, sizeof(sin.sin_addr));
		sin.sin_port =
			(port) ? *port
			       : (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
					 ? htons(BFD_DEF_MHOP_DEST_PORT)
					 : htons(BFD_DEFDESTPORT);

		sd = bs->sock;
		sa = (struct sockaddr *)&sin;
		slen = sizeof(sin);
	}

#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sa->sa_len = slen;
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	rv = sendto(sd, data, datalen, 0, sa, slen);
	if (rv <= 0) {
		if (bglobal.debug_network)
			zlog_debug("packet-send: send failure: %s",
				   strerror(errno));
		return -1;
	}
	if (rv < (ssize_t)datalen) {
		if (bglobal.debug_network)
			zlog_debug("packet-send: send partial: %s",
				   strerror(errno));
	}

	return 0;
}

#ifdef BFD_LINUX
/*
 * Compute the UDP checksum.
 *
 * Checksum is not set in the packet, just computed.
 *
 * pkt
 *    Packet, fully filled out except for checksum field.
 *
 * pktsize
 *    sizeof(*pkt)
 *
 * ip
 *    IP address that pkt will be transmitted from and to.
 *
 * Returns:
 *    Checksum in network byte order.
 */
static uint16_t bfd_pkt_checksum(struct udphdr *pkt, size_t pktsize,
				 struct in6_addr *ip, sa_family_t family)
{
	uint16_t chksum;

	pkt->check = 0;

	if (family == AF_INET6) {
		struct ipv6_ph ph = {};

		memcpy(&ph.src, ip, sizeof(ph.src));
		memcpy(&ph.dst, ip, sizeof(ph.dst));
		ph.ulpl = htons(pktsize);
		ph.next_hdr = IPPROTO_UDP;
		chksum = in_cksum_with_ph6(&ph, pkt, pktsize);
	} else {
		struct ipv4_ph ph = {};

		memcpy(&ph.src, ip, sizeof(ph.src));
		memcpy(&ph.dst, ip, sizeof(ph.dst));
		ph.proto = IPPROTO_UDP;
		ph.len = htons(pktsize);
		chksum = in_cksum_with_ph4(&ph, pkt, pktsize);
	}

	return chksum;
}

/*
 * This routine creates the entire ECHO packet so that it will be looped
 * in the forwarding plane of the peer router instead of going up the
 * stack in BFD to be looped.  If we haven't learned the peers MAC yet
 * no echo is sent.
 *
 * echo packet with src/dst IP equal to local IP
 * dest MAC as peer's MAC
 *
 * currently support ipv4
 */
void ptm_bfd_echo_fp_snd(struct bfd_session *bfd)
{
	int sd;
	struct bfd_vrf_global *bvrf = bfd_vrf_look_by_session(bfd);
	int total_len = 0;
	struct ethhdr *eth;
	struct udphdr *uh;
	struct iphdr *iph;
	struct bfd_echo_pkt *beph;
	static char sendbuff[100];
	struct timeval time_sent;

	if (!bvrf)
		return;
	if (!CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MAC_SET))
		return;
	if (!CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
		SET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);

	memset(sendbuff, 0, sizeof(sendbuff));

	/* add eth hdr */
	eth = (struct ethhdr *)(sendbuff);
	memcpy(eth->h_source, bfd->ifp->hw_addr, sizeof(eth->h_source));
	memcpy(eth->h_dest, bfd->peer_hw_addr, sizeof(eth->h_dest));

	total_len += sizeof(struct ethhdr);

	sd = bvrf->bg_echo;
	eth->h_proto = htons(ETH_P_IP);

	/* add ip hdr */
	iph = (struct iphdr *)(sendbuff + sizeof(struct ethhdr));

	iph->ihl = sizeof(struct ip) >> 2;
	iph->version = IPVERSION;
	iph->tos = IPTOS_PREC_INTERNETCONTROL;
	iph->id = (uint16_t)frr_weak_random();
	iph->ttl = BFD_TTL_VAL;
	iph->protocol = IPPROTO_UDP;
	memcpy(&iph->saddr, &bfd->local_address.sa_sin.sin_addr,
	       sizeof(bfd->local_address.sa_sin.sin_addr));
	memcpy(&iph->daddr, &bfd->local_address.sa_sin.sin_addr,
	       sizeof(bfd->local_address.sa_sin.sin_addr));
	total_len += sizeof(struct iphdr);

	/* add udp hdr */
	uh = (struct udphdr *)(sendbuff + sizeof(struct iphdr) +
			       sizeof(struct ethhdr));
	uh->source = htons(BFD_DEF_ECHO_PORT);
	uh->dest = htons(BFD_DEF_ECHO_PORT);

	total_len += sizeof(struct udphdr);

	/* add bfd echo */
	beph = (struct bfd_echo_pkt *)(sendbuff + sizeof(struct udphdr) +
				       sizeof(struct iphdr) +
				       sizeof(struct ethhdr));

	beph->ver = BFD_ECHO_VERSION;
	beph->len = BFD_ECHO_PKT_LEN;
	beph->my_discr = htonl(bfd->discrs.my_discr);

	/* RTT calculation: add starting time in packet */
	monotime(&time_sent);
	beph->time_sent_sec = htobe64(time_sent.tv_sec);
	beph->time_sent_usec = htobe64(time_sent.tv_usec);

	total_len += sizeof(struct bfd_echo_pkt);
	uh->len =
		htons(total_len - sizeof(struct iphdr) - sizeof(struct ethhdr));
	uh->check = bfd_pkt_checksum(
		uh, (total_len - sizeof(struct iphdr) - sizeof(struct ethhdr)),
		(struct in6_addr *)&iph->saddr, AF_INET);

	iph->tot_len = htons(total_len - sizeof(struct ethhdr));
	iph->check = in_cksum((const void *)iph, sizeof(struct iphdr));

	if (bp_udp_send_fp(sd, (uint8_t *)&sendbuff, total_len, bfd) == -1)
		return;

	bfd->stats.tx_echo_pkt++;
}
#endif

void ptm_bfd_echo_snd(struct bfd_session *bfd)
{
	struct sockaddr *sa;
	socklen_t salen;
	int sd;
	struct bfd_echo_pkt bep;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct bfd_vrf_global *bvrf = bfd_vrf_look_by_session(bfd);

	if (!bvrf)
		return;
	if (!CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
		SET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);

	memset(&bep, 0, sizeof(bep));
	bep.ver = BFD_ECHO_VERSION;
	bep.len = BFD_ECHO_PKT_LEN;
	bep.my_discr = htonl(bfd->discrs.my_discr);

	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6)) {
		if (bvrf->bg_echov6 == -1)
			return;
		sd = bvrf->bg_echov6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		memcpy(&sin6.sin6_addr, &bfd->key.peer, sizeof(sin6.sin6_addr));
		if (bfd->ifp && IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
			sin6.sin6_scope_id = bfd->ifp->ifindex;

		sin6.sin6_port = htons(BFD_DEF_ECHO_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

		sa = (struct sockaddr *)&sin6;
		salen = sizeof(sin6);
	} else {
		sd = bvrf->bg_echo;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		memcpy(&sin.sin_addr, &bfd->key.peer, sizeof(sin.sin_addr));
		sin.sin_port = htons(BFD_DEF_ECHO_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin.sin_len = sizeof(sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

		sa = (struct sockaddr *)&sin;
		salen = sizeof(sin);
	}
	if (bp_udp_send(sd, BFD_TTL_VAL, (uint8_t *)&bep, sizeof(bep), sa,
			salen)
	    == -1)
		return;

	bfd->stats.tx_echo_pkt++;
}

static int ptm_bfd_process_echo_pkt(struct bfd_vrf_global *bvrf, int s)
{
	struct bfd_session *bfd;
	uint32_t my_discr = 0;
	uint64_t my_rtt = 0;
	uint8_t ttl = 0;

	/* Receive and parse echo packet. */
	if (bp_bfd_echo_in(bvrf, s, &ttl, &my_discr, &my_rtt) == -1)
		return 0;

	/* Your discriminator not zero - use it to find session */
	bfd = bfd_id_lookup(my_discr);
	if (bfd == NULL) {
		if (bglobal.debug_network)
			zlog_debug("echo-packet: no matching session (id:%u)",
				   my_discr);
		return -1;
	}

	if (!CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
		if (bglobal.debug_network)
			zlog_debug("echo-packet: echo disabled [%s] (id:%u)",
				   bs_to_string(bfd), my_discr);
		return -1;
	}

	/* RTT Calculation: add current RTT to samples */
	if (my_rtt != 0) {
		bfd->rtt[bfd->rtt_index] = my_rtt;
		bfd->rtt_index++;
		if (bfd->rtt_index >= BFD_RTT_SAMPLE)
			bfd->rtt_index = 0;
		if (bfd->rtt_valid < BFD_RTT_SAMPLE)
			bfd->rtt_valid++;
	}

	bfd->stats.rx_echo_pkt++;

	/* Compute detect time */
	bfd->echo_detect_TO = bfd->remote_detect_mult * bfd->echo_xmt_TO;

	/* Update echo receive timeout. */
	if (bfd->echo_detect_TO > 0)
		bfd_echo_recvtimer_update(bfd);

	return 0;
}

void ptm_bfd_snd(struct bfd_session *bfd, int fbit)
{
	struct bfd_pkt cp = {};

	/* Set fields according to section 6.5.7 */
	cp.diag = bfd->local_diag;
	BFD_SETVER(cp.diag, BFD_VERSION);
	cp.flags = 0;
	BFD_SETSTATE(cp.flags, bfd->ses_state);

	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_CBIT))
		BFD_SETCBIT(cp.flags, BFD_CBIT);

	BFD_SETDEMANDBIT(cp.flags, BFD_DEF_DEMAND);

	/*
	 * Polling and Final can't be set at the same time.
	 *
	 * RFC 5880, Section 6.5.
	 */
	BFD_SETFBIT(cp.flags, fbit);
	if (fbit == 0)
		BFD_SETPBIT(cp.flags, bfd->polling);

	cp.detect_mult = bfd->detect_mult;
	cp.len = BFD_PKT_LEN;
	cp.discrs.my_discr = htonl(bfd->discrs.my_discr);
	cp.discrs.remote_discr = htonl(bfd->discrs.remote_discr);
	if (bfd->polling) {
		cp.timers.desired_min_tx =
			htonl(bfd->timers.desired_min_tx);
		cp.timers.required_min_rx =
			htonl(bfd->timers.required_min_rx);
	} else {
		/*
		 * We can only announce current setting on poll, this
		 * avoids timing mismatch with our peer and give it
		 * the oportunity to learn. See `bs_final_handler` for
		 * more information.
		 */
		cp.timers.desired_min_tx =
			htonl(bfd->cur_timers.desired_min_tx);
		cp.timers.required_min_rx =
			htonl(bfd->cur_timers.required_min_rx);
	}
	cp.timers.required_min_echo = htonl(bfd->timers.required_min_echo_rx);

	if (_ptm_bfd_send(bfd, NULL, &cp, BFD_PKT_LEN) != 0)
		return;

	bfd->stats.tx_ctrl_pkt++;
}

#ifdef BFD_LINUX
/*
 * receive the ipv4 echo packet that was loopback in the peers forwarding plane
 */
ssize_t bfd_recv_ipv4_fp(int sd, uint8_t *msgbuf, size_t msgbuflen,
			 uint8_t *ttl, ifindex_t *ifindex,
			 struct sockaddr_any *local, struct sockaddr_any *peer)
{
	ssize_t mlen;
	struct sockaddr_ll msgaddr;
	struct msghdr msghdr;
	struct iovec iov[1];
	uint16_t recv_checksum;
	uint16_t checksum;
	struct iphdr *ip;
	struct udphdr *uh;

	/* Prepare the recvmsg params. */
	iov[0].iov_base = msgbuf;
	iov[0].iov_len = msgbuflen;

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_name = &msgaddr;
	msghdr.msg_namelen = sizeof(msgaddr);
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = 1;

	mlen = recvmsg(sd, &msghdr, MSG_DONTWAIT);
	if (mlen == -1) {
		if (errno != EAGAIN || errno != EWOULDBLOCK || errno != EINTR)
			zlog_err("%s: recv failed: %s", __func__,
				 strerror(errno));

		return -1;
	}

	ip = (struct iphdr *)(msgbuf + sizeof(struct ethhdr));

	/* verify ip checksum */
	recv_checksum = ip->check;
	ip->check = 0;
	checksum = in_cksum((const void *)ip, sizeof(struct iphdr));
	if (recv_checksum != checksum) {
		if (bglobal.debug_network)
			zlog_debug(
				"%s: invalid iphdr checksum expected 0x%x rcvd 0x%x",
				__func__, checksum, recv_checksum);
		return -1;
	}

	*ttl = ip->ttl;
	if (*ttl != 254) {
		if (bglobal.debug_network)
			zlog_debug("%s: invalid TTL: %u", __func__, *ttl);
		return -1;
	}

	local->sa_sin.sin_family = AF_INET;
	memcpy(&local->sa_sin.sin_addr, &ip->saddr, sizeof(ip->saddr));
	peer->sa_sin.sin_family = AF_INET;
	memcpy(&peer->sa_sin.sin_addr, &ip->daddr, sizeof(ip->daddr));

	*ifindex = msgaddr.sll_ifindex;

	/* verify udp checksum */
	uh = (struct udphdr *)(msgbuf + sizeof(struct iphdr) +
			       sizeof(struct ethhdr));
	recv_checksum = uh->check;
	uh->check = 0;
	checksum = bfd_pkt_checksum(uh, ntohs(uh->len),
				    (struct in6_addr *)&ip->saddr, AF_INET);
	if (recv_checksum != checksum) {
		if (bglobal.debug_network)
			zlog_debug(
				"%s: invalid udphdr checksum expected 0x%x rcvd 0x%x",
				__func__, checksum, recv_checksum);
		return -1;
	}
	return mlen;
}
#endif

ssize_t bfd_recv_ipv4(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      ifindex_t *ifindex, struct sockaddr_any *local,
		      struct sockaddr_any *peer)
{
	struct cmsghdr *cm;
	ssize_t mlen;
	struct sockaddr_in msgaddr;
	struct msghdr msghdr;
	struct iovec iov[1];
	uint8_t cmsgbuf[255];

	/* Prepare the recvmsg params. */
	iov[0].iov_base = msgbuf;
	iov[0].iov_len = msgbuflen;

	memset(&msghdr, 0, sizeof(msghdr));
	msghdr.msg_name = &msgaddr;
	msghdr.msg_namelen = sizeof(msgaddr);
	msghdr.msg_iov = iov;
	msghdr.msg_iovlen = 1;
	msghdr.msg_control = cmsgbuf;
	msghdr.msg_controllen = sizeof(cmsgbuf);

	mlen = recvmsg(sd, &msghdr, MSG_DONTWAIT);
	if (mlen == -1) {
		if (errno != EAGAIN)
			zlog_err("ipv4-recv: recv failed: %s", strerror(errno));

		return -1;
	}

	/* Get source address */
	peer->sa_sin = *((struct sockaddr_in *)(msghdr.msg_name));

	/* Get and check TTL */
	for (cm = CMSG_FIRSTHDR(&msghdr); cm != NULL;
	     cm = CMSG_NXTHDR(&msghdr, cm)) {
		if (cm->cmsg_level != IPPROTO_IP)
			continue;

		switch (cm->cmsg_type) {
#ifdef BFD_LINUX
		case IP_TTL: {
			uint32_t ttlval;

			memcpy(&ttlval, CMSG_DATA(cm), sizeof(ttlval));
			if (ttlval > 255) {
				if (bglobal.debug_network)
					zlog_debug("%s: invalid TTL: %u",
						   __func__, ttlval);
				return -1;
			}
			*ttl = ttlval;
			break;
		}

		case IP_PKTINFO: {
			struct in_pktinfo *pi =
				(struct in_pktinfo *)CMSG_DATA(cm);

			if (pi == NULL)
				break;

			local->sa_sin.sin_family = AF_INET;
			local->sa_sin.sin_addr = pi->ipi_addr;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			local->sa_sin.sin_len = sizeof(local->sa_sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

			*ifindex = pi->ipi_ifindex;
			break;
		}
#endif /* BFD_LINUX */
#ifdef BFD_BSD
		case IP_RECVTTL: {
			memcpy(ttl, CMSG_DATA(cm), sizeof(*ttl));
			break;
		}

		case IP_RECVDSTADDR: {
			struct in_addr ia;

			memcpy(&ia, CMSG_DATA(cm), sizeof(ia));
			local->sa_sin.sin_family = AF_INET;
			local->sa_sin.sin_addr = ia;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
			local->sa_sin.sin_len = sizeof(local->sa_sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
			break;
		}
#endif /* BFD_BSD */

		default:
			/*
			 * On *BSDs we expect to land here when skipping
			 * the IP_RECVIF header. It will be handled by
			 * getsockopt_ifindex() below.
			 */
			/* NOTHING */
			break;
		}
	}

	/* OS agnostic way of getting interface name. */
	if (*ifindex == IFINDEX_INTERNAL)
		*ifindex = getsockopt_ifindex(AF_INET, &msghdr);

	return mlen;
}

ssize_t bfd_recv_ipv6(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      ifindex_t *ifindex, struct sockaddr_any *local,
		      struct sockaddr_any *peer)
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi6 = NULL;
	ssize_t mlen;
	uint32_t ttlval;
	struct sockaddr_in6 msgaddr6;
	struct msghdr msghdr6;
	struct iovec iov[1];
	uint8_t cmsgbuf6[255];

	/* Prepare the recvmsg params. */
	iov[0].iov_base = msgbuf;
	iov[0].iov_len = msgbuflen;

	memset(&msghdr6, 0, sizeof(msghdr6));
	msghdr6.msg_name = &msgaddr6;
	msghdr6.msg_namelen = sizeof(msgaddr6);
	msghdr6.msg_iov = iov;
	msghdr6.msg_iovlen = 1;
	msghdr6.msg_control = cmsgbuf6;
	msghdr6.msg_controllen = sizeof(cmsgbuf6);

	mlen = recvmsg(sd, &msghdr6, MSG_DONTWAIT);
	if (mlen == -1) {
		if (errno != EAGAIN)
			zlog_err("ipv6-recv: recv failed: %s", strerror(errno));

		return -1;
	}

	/* Get source address */
	peer->sa_sin6 = *((struct sockaddr_in6 *)(msghdr6.msg_name));

	/* Get and check TTL */
	for (cm = CMSG_FIRSTHDR(&msghdr6); cm != NULL;
	     cm = CMSG_NXTHDR(&msghdr6, cm)) {
		if (cm->cmsg_level != IPPROTO_IPV6)
			continue;

		if (cm->cmsg_type == IPV6_HOPLIMIT) {
			memcpy(&ttlval, CMSG_DATA(cm), sizeof(ttlval));
			if (ttlval > 255) {
				if (bglobal.debug_network)
					zlog_debug("%s: invalid TTL: %u",
						   __func__, ttlval);
				return -1;
			}

			*ttl = ttlval;
		} else if (cm->cmsg_type == IPV6_PKTINFO) {
			pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
			if (pi6) {
				local->sa_sin6.sin6_family = AF_INET6;
				local->sa_sin6.sin6_addr = pi6->ipi6_addr;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
				local->sa_sin6.sin6_len = sizeof(local->sa_sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

				*ifindex = pi6->ipi6_ifindex;

				/* Set scope ID for link local addresses. */
				if (IN6_IS_ADDR_LINKLOCAL(
					    &peer->sa_sin6.sin6_addr))
					peer->sa_sin6.sin6_scope_id = *ifindex;
				if (IN6_IS_ADDR_LINKLOCAL(
					    &local->sa_sin6.sin6_addr))
					local->sa_sin6.sin6_scope_id = *ifindex;
			}
		}
	}

	return mlen;
}

static void bfd_sd_reschedule(struct bfd_vrf_global *bvrf, int sd)
{
	if (sd == bvrf->bg_shop) {
		EVENT_OFF(bvrf->bg_ev[0]);
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_shop,
			       &bvrf->bg_ev[0]);
	} else if (sd == bvrf->bg_mhop) {
		EVENT_OFF(bvrf->bg_ev[1]);
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_mhop,
			       &bvrf->bg_ev[1]);
	} else if (sd == bvrf->bg_shop6) {
		EVENT_OFF(bvrf->bg_ev[2]);
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_shop6,
			       &bvrf->bg_ev[2]);
	} else if (sd == bvrf->bg_mhop6) {
		EVENT_OFF(bvrf->bg_ev[3]);
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_mhop6,
			       &bvrf->bg_ev[3]);
	} else if (sd == bvrf->bg_echo) {
		EVENT_OFF(bvrf->bg_ev[4]);
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_echo,
			       &bvrf->bg_ev[4]);
	} else if (sd == bvrf->bg_echov6) {
		EVENT_OFF(bvrf->bg_ev[5]);
		event_add_read(master, bfd_recv_cb, bvrf, bvrf->bg_echov6,
			       &bvrf->bg_ev[5]);
	}
}

PRINTFRR(6, 7)
static void cp_debug(bool mhop, struct sockaddr_any *peer,
		     struct sockaddr_any *local, ifindex_t ifindex,
		     vrf_id_t vrfid, const char *fmt, ...)
{
	char buf[512], peerstr[128], localstr[128], portstr[64], vrfstr[64];
	va_list vl;

	/* Don't to any processing if debug is disabled. */
	if (bglobal.debug_network == false)
		return;

	if (peer->sa_sin.sin_family)
		snprintf(peerstr, sizeof(peerstr), " peer:%s", satostr(peer));
	else
		peerstr[0] = 0;

	if (local->sa_sin.sin_family)
		snprintf(localstr, sizeof(localstr), " local:%s",
			 satostr(local));
	else
		localstr[0] = 0;

	if (ifindex != IFINDEX_INTERNAL)
		snprintf(portstr, sizeof(portstr), " port:%u", ifindex);
	else
		portstr[0] = 0;

	if (vrfid != VRF_DEFAULT)
		snprintf(vrfstr, sizeof(vrfstr), " vrf:%u", vrfid);
	else
		vrfstr[0] = 0;

	va_start(vl, fmt);
	vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	zlog_debug("control-packet: %s [mhop:%s%s%s%s%s]", buf,
		   mhop ? "yes" : "no", peerstr, localstr, portstr, vrfstr);
}

static bool bfd_check_auth(const struct bfd_session *bfd,
			   const struct bfd_pkt *cp)
{
	if (CHECK_FLAG(cp->flags, BFD_ABIT)) {
		/* RFC5880 4.1: Authentication Section is present. */
		struct bfd_auth *auth = (struct bfd_auth *)(cp + 1);
		uint16_t pkt_auth_type = ntohs(auth->type);

		if (cp->len < BFD_PKT_LEN + sizeof(struct bfd_auth))
			return false;

		if (cp->len < BFD_PKT_LEN + auth->length)
			return false;

		switch (pkt_auth_type) {
		case BFD_AUTH_NULL:
			return false;
		case BFD_AUTH_SIMPLE:
			/* RFC5880 6.7: To be finshed. */
			return false;
		case BFD_AUTH_CRYPTOGRAPHIC:
			/* RFC5880 6.7: To be finshed. */
			return false;
		default:
			/* RFC5880 6.7: To be finshed. */
			return false;
		}
	}
	return true;
}

void bfd_recv_cb(struct event *t)
{
	int sd = EVENT_FD(t);
	struct bfd_session *bfd;
	struct bfd_pkt *cp;
	bool is_mhop;
	ssize_t mlen = 0;
	uint8_t ttl = 0;
	vrf_id_t vrfid;
	ifindex_t ifindex = IFINDEX_INTERNAL;
	struct sockaddr_any local, peer;
	uint8_t msgbuf[1516];
	struct interface *ifp = NULL;
	struct bfd_vrf_global *bvrf = EVENT_ARG(t);

	/* Schedule next read. */
	bfd_sd_reschedule(bvrf, sd);

	/* Handle echo packets. */
	if (sd == bvrf->bg_echo || sd == bvrf->bg_echov6) {
		ptm_bfd_process_echo_pkt(bvrf, sd);
		return;
	}

	/* Sanitize input/output. */
	memset(&local, 0, sizeof(local));
	memset(&peer, 0, sizeof(peer));

	/* Handle control packets. */
	is_mhop = false;
	if (sd == bvrf->bg_shop || sd == bvrf->bg_mhop) {
		is_mhop = sd == bvrf->bg_mhop;
		mlen = bfd_recv_ipv4(sd, msgbuf, sizeof(msgbuf), &ttl, &ifindex,
				     &local, &peer);
	} else if (sd == bvrf->bg_shop6 || sd == bvrf->bg_mhop6) {
		is_mhop = sd == bvrf->bg_mhop6;
		mlen = bfd_recv_ipv6(sd, msgbuf, sizeof(msgbuf), &ttl, &ifindex,
				     &local, &peer);
	}

	/*
	 * With netns backend, we have a separate socket in each VRF. It means
	 * that bvrf here is correct and we believe the bvrf->vrf->vrf_id.
	 * With VRF-lite backend, we have a single socket in the default VRF.
	 * It means that we can't believe the bvrf->vrf->vrf_id. But in
	 * VRF-lite, the ifindex is globally unique, so we can retrieve the
	 * correct vrf_id from the interface.
	 */
	vrfid = bvrf->vrf->vrf_id;
	if (ifindex) {
		ifp = if_lookup_by_index(ifindex, vrfid);
		if (ifp)
			vrfid = ifp->vrf->vrf_id;
	}

	/* Implement RFC 5880 6.8.6 */
	if (mlen < BFD_PKT_LEN) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "too small (%zd bytes)", mlen);
		return;
	}

	/* Validate single hop packet TTL. */
	if ((!is_mhop) && (ttl != BFD_TTL_VAL)) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "invalid TTL: %d expected %d", ttl, BFD_TTL_VAL);
		return;
	}

	/*
	 * Parse the control header for inconsistencies:
	 * - Invalid version;
	 * - Bad multiplier configuration;
	 * - Short packets;
	 * - Invalid discriminator;
	 */
	cp = (struct bfd_pkt *)(msgbuf);
	if (BFD_GETVER(cp->diag) != BFD_VERSION) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "bad version %d", BFD_GETVER(cp->diag));
		return;
	}

	if (cp->detect_mult == 0) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "detect multiplier set to zero");
		return;
	}

	if ((cp->len < BFD_PKT_LEN) || (cp->len > mlen)) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid, "too small");
		return;
	}

	if (cp->discrs.my_discr == 0) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "'my discriminator' is zero");
		return;
	}

	/* Find the session that this packet belongs. */
	bfd = ptm_bfd_sess_find(cp, &peer, &local, ifp, vrfid, is_mhop);
	if (bfd == NULL) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "no session found");
		return;
	}
	/*
	 * We may have a situation where received packet is on wrong vrf
	 */
	if (bfd && bfd->vrf && bfd->vrf->vrf_id != vrfid) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "wrong vrfid.");
		return;
	}

	/* Ensure that existing good sessions are not overridden. */
	if (!cp->discrs.remote_discr && bfd->ses_state != PTM_BFD_DOWN &&
	    bfd->ses_state != PTM_BFD_ADM_DOWN) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "'remote discriminator' is zero, not overridden");
		return;
	}

	/*
	 * Multi hop: validate packet TTL.
	 * Single hop: set local address that received the packet.
	 *             set peers mac address for echo packets
	 */
	if (is_mhop) {
		if (ttl < bfd->mh_ttl) {
			cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
				 "exceeded max hop count (expected %d, got %d)",
				 bfd->mh_ttl, ttl);
			return;
		}
	} else {

		if (bfd->local_address.sa_sin.sin_family == AF_UNSPEC)
			bfd->local_address = local;
#ifdef BFD_LINUX
		if (ifp)
			bfd_peer_mac_set(sd, bfd, &peer, ifp);
#endif
	}

	bfd->stats.rx_ctrl_pkt++;

	/*
	 * If no interface was detected, save the interface where the
	 * packet came in.
	 */
	if (!is_mhop && bfd->ifp == NULL)
		bfd->ifp = ifp;

	/* Log remote discriminator changes. */
	if ((bfd->discrs.remote_discr != 0)
	    && (bfd->discrs.remote_discr != ntohl(cp->discrs.my_discr)))
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "remote discriminator mismatch (expected %u, got %u)",
			 bfd->discrs.remote_discr, ntohl(cp->discrs.my_discr));

	bfd->discrs.remote_discr = ntohl(cp->discrs.my_discr);

	/* Check authentication. */
	if (!bfd_check_auth(bfd, cp)) {
		cp_debug(is_mhop, &peer, &local, ifindex, vrfid,
			 "Authentication failed");
		return;
	}

	/* Save remote diagnostics before state switch. */
	bfd->remote_diag = cp->diag & BFD_DIAGMASK;

	/* Update remote timers settings. */
	bfd->remote_timers.desired_min_tx = ntohl(cp->timers.desired_min_tx);
	bfd->remote_timers.required_min_rx = ntohl(cp->timers.required_min_rx);
	bfd->remote_timers.required_min_echo =
		ntohl(cp->timers.required_min_echo);
	bfd->remote_detect_mult = cp->detect_mult;

	if (BFD_GETCBIT(cp->flags))
		bfd->remote_cbit = 1;
	else
		bfd->remote_cbit = 0;

	/* State switch from section 6.2. */
	bs_state_handler(bfd, BFD_GETSTATE(cp->flags));

	/* RFC 5880, Section 6.5: handle POLL/FINAL negotiation sequence. */
	if (bfd->polling && BFD_GETFBIT(cp->flags)) {
		/* Disable polling. */
		bfd->polling = 0;

		/* Handle poll finalization. */
		bs_final_handler(bfd);
	}

	/*
	 * Detection timeout calculation:
	 * The minimum detection timeout is the remote detection
	 * multipler (number of packets to be missed) times the agreed
	 * transmission interval.
	 *
	 * RFC 5880, Section 6.8.4.
	 */
	if (bfd->cur_timers.required_min_rx > bfd->remote_timers.desired_min_tx)
		bfd->detect_TO = bfd->remote_detect_mult
				 * bfd->cur_timers.required_min_rx;
	else
		bfd->detect_TO = bfd->remote_detect_mult
				 * bfd->remote_timers.desired_min_tx;

	/* Apply new receive timer immediately. */
	bfd_recvtimer_update(bfd);

	/* Handle echo timers changes. */
	bs_echo_timer_handler(bfd);

	/*
	 * We've received a packet with the POLL bit set, we must send
	 * a control packet back with the FINAL bit set.
	 *
	 * RFC 5880, Section 6.5.
	 */
	if (BFD_GETPBIT(cp->flags)) {
		/* We are finalizing a poll negotiation. */
		bs_final_handler(bfd);

		/* Send the control packet with the final bit immediately. */
		ptm_bfd_snd(bfd, 1);
	}
}

/*
 * bp_bfd_echo_in: proccesses an BFD echo packet. On TTL == BFD_TTL_VAL
 * the packet is looped back or returns the my discriminator ID along
 * with the TTL.
 *
 * Returns -1 on error or loopback or 0 on success.
 */
int bp_bfd_echo_in(struct bfd_vrf_global *bvrf, int sd, uint8_t *ttl,
		   uint32_t *my_discr, uint64_t *my_rtt)
{
	struct bfd_echo_pkt *bep;
	ssize_t rlen;
	struct sockaddr_any local, peer;
	ifindex_t ifindex = IFINDEX_INTERNAL;
	vrf_id_t vrfid = VRF_DEFAULT;
	uint8_t msgbuf[1516];
	size_t bfd_offset = 0;

	if (sd == bvrf->bg_echo) {
#ifdef BFD_LINUX
		rlen = bfd_recv_ipv4_fp(sd, msgbuf, sizeof(msgbuf), ttl,
					&ifindex, &local, &peer);

		/* silently drop echo packet that is looped in fastpath but
		 * still comes up to BFD
		 */
		if (rlen == -1)
			return -1;
		bfd_offset = sizeof(struct udphdr) + sizeof(struct iphdr) +
			     sizeof(struct ethhdr);
#else
		rlen = bfd_recv_ipv4(sd, msgbuf, sizeof(msgbuf), ttl, &ifindex,
				     &local, &peer);
		bfd_offset = 0;
#endif
	} else {
		rlen = bfd_recv_ipv6(sd, msgbuf, sizeof(msgbuf), ttl, &ifindex,
				     &local, &peer);
		bfd_offset = 0;
	}

	/* Short packet, better not risk reading it. */
	if (rlen < (ssize_t)sizeof(*bep)) {
		cp_debug(false, &peer, &local, ifindex, vrfid,
			 "small echo packet");
		return -1;
	}

	/* Test for loopback for ipv6, ipv4 is looped in forwarding plane */
	if ((*ttl == BFD_TTL_VAL) && (sd == bvrf->bg_echov6)) {
		bp_udp_send(sd, *ttl - 1, msgbuf, rlen,
			    (struct sockaddr *)&peer,
			    (sd == bvrf->bg_echo) ? sizeof(peer.sa_sin)
						    : sizeof(peer.sa_sin6));
		return -1;
	}

	/* Read my discriminator from BFD Echo packet. */
	bep = (struct bfd_echo_pkt *)(msgbuf + bfd_offset);
	*my_discr = ntohl(bep->my_discr);
	if (*my_discr == 0) {
		cp_debug(false, &peer, &local, ifindex, vrfid,
			 "invalid echo packet discriminator (zero)");
		return -1;
	}

#ifdef BFD_LINUX
	/* RTT Calculation: determine RTT time of IPv4 echo pkt */
	if (sd == bvrf->bg_echo) {
		struct timeval time_sent = {0, 0};

		time_sent.tv_sec = be64toh(bep->time_sent_sec);
		time_sent.tv_usec = be64toh(bep->time_sent_usec);
		*my_rtt = monotime_since(&time_sent, NULL);
	}
#endif

	return 0;
}

#ifdef BFD_LINUX
/*
 * send a bfd packet with src/dst same IP so that the peer will receive
 * the packet and forward it back to sender in the forwarding plane
 */
int bp_udp_send_fp(int sd, uint8_t *data, size_t datalen,
		   struct bfd_session *bfd)
{
	ssize_t wlen;
	struct msghdr msg = {0};
	struct iovec iov[1];
	uint8_t msgctl[255];
	struct sockaddr_ll sadr_ll = {0};

	sadr_ll.sll_ifindex = bfd->ifp->ifindex;
	sadr_ll.sll_halen = ETH_ALEN;
	memcpy(sadr_ll.sll_addr, bfd->peer_hw_addr, sizeof(bfd->peer_hw_addr));
	sadr_ll.sll_protocol = htons(ETH_P_IP);

	/* Prepare message data. */
	iov[0].iov_base = data;
	iov[0].iov_len = datalen;

	memset(msgctl, 0, sizeof(msgctl));
	msg.msg_name = &sadr_ll;
	msg.msg_namelen = sizeof(sadr_ll);
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	/* Send echo to peer */
	wlen = sendmsg(sd, &msg, 0);

	if (wlen <= 0) {
		if (bglobal.debug_network)
			zlog_debug("%s: loopback failure: (%d) %s", __func__,
				   errno, strerror(errno));
		return -1;
	} else if (wlen < (ssize_t)datalen) {
		if (bglobal.debug_network)
			zlog_debug("%s: partial send: %zd expected %zu",
				   __func__, wlen, datalen);
		return -1;
	}

	return 0;
}
#endif

int bp_udp_send(int sd, uint8_t ttl, uint8_t *data, size_t datalen,
		struct sockaddr *to, socklen_t tolen)
{
	struct cmsghdr *cmsg;
	ssize_t wlen;
	int ttlval = ttl;
	bool is_ipv6 = to->sa_family == AF_INET6;
	struct msghdr msg;
	struct iovec iov[1];
	uint8_t msgctl[255];

	/* Prepare message data. */
	iov[0].iov_base = data;
	iov[0].iov_len = datalen;

	memset(&msg, 0, sizeof(msg));
	memset(msgctl, 0, sizeof(msgctl));
	msg.msg_name = to;
	msg.msg_namelen = tolen;
	msg.msg_iov = iov;
	msg.msg_iovlen = 1;

	/* Prepare the packet TTL information. */
	if (ttl > 0) {
		/* Use ancillary data. */
		msg.msg_control = msgctl;
		msg.msg_controllen = CMSG_LEN(sizeof(ttlval));

		/* Configure the ancillary data. */
		cmsg = CMSG_FIRSTHDR(&msg);
		cmsg->cmsg_len = CMSG_LEN(sizeof(ttlval));
		if (is_ipv6) {
			cmsg->cmsg_level = IPPROTO_IPV6;
			cmsg->cmsg_type = IPV6_HOPLIMIT;
		} else {
#ifdef BFD_LINUX
			cmsg->cmsg_level = IPPROTO_IP;
			cmsg->cmsg_type = IP_TTL;
#else
			/* FreeBSD does not support TTL in ancillary data. */
			msg.msg_control = NULL;
			msg.msg_controllen = 0;

			bp_set_ttl(sd, ttl);
#endif /* BFD_BSD */
		}
		memcpy(CMSG_DATA(cmsg), &ttlval, sizeof(ttlval));
	}

	/* Send echo back. */
	wlen = sendmsg(sd, &msg, 0);
	if (wlen <= 0) {
		if (bglobal.debug_network)
			zlog_debug("%s: loopback failure: (%d) %s", __func__,
				   errno, strerror(errno));
		return -1;
	} else if (wlen < (ssize_t)datalen) {
		if (bglobal.debug_network)
			zlog_debug("%s: partial send: %zd expected %zu",
				   __func__, wlen, datalen);
		return -1;
	}

	return 0;
}


/*
 * Sockets creation.
 */


/*
 * IPv4 sockets
 */
int bp_set_ttl(int sd, uint8_t value)
{
	int ttl = value;

	if (setsockopt(sd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
		zlog_warn("%s: setsockopt(IP_TTL, %d): %s", __func__, value,
			  strerror(errno));
		return -1;
	}

	return 0;
}

int bp_set_tos(int sd, uint8_t value)
{
	int tos = value;

	if (setsockopt(sd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
		zlog_warn("%s: setsockopt(IP_TOS, %d): %s", __func__, value,
			  strerror(errno));
		return -1;
	}

	return 0;
}

static bool bp_set_reuse_addr(int sd)
{
	int one = 1;

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == -1) {
		zlog_warn("%s: setsockopt(SO_REUSEADDR, %d): %s", __func__, one,
			  strerror(errno));
		return false;
	}
	return true;
}

static bool bp_set_reuse_port(int sd)
{
	int one = 1;

	if (setsockopt(sd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) == -1) {
		zlog_warn("%s: setsockopt(SO_REUSEPORT, %d): %s", __func__, one,
			  strerror(errno));
		return false;
	}
	return true;
}


static void bp_set_ipopts(int sd)
{
	int rcvttl = BFD_RCV_TTL_VAL;

	if (!bp_set_reuse_addr(sd))
		zlog_fatal("set-reuse-addr: failed");

	if (!bp_set_reuse_port(sd))
		zlog_fatal("set-reuse-port: failed");

	if (bp_set_ttl(sd, BFD_TTL_VAL) != 0)
		zlog_fatal("set-ipopts: TTL configuration failed");

	if (setsockopt(sd, IPPROTO_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl))
	    == -1)
		zlog_fatal("set-ipopts: setsockopt(IP_RECVTTL, %d): %s", rcvttl,
			   strerror(errno));

#ifdef BFD_LINUX
	int pktinfo = BFD_PKT_INFO_VAL;

	/* Figure out address and interface to do the peer matching. */
	if (setsockopt(sd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo))
	    == -1)
		zlog_fatal("set-ipopts: setsockopt(IP_PKTINFO, %d): %s",
			   pktinfo, strerror(errno));
#endif /* BFD_LINUX */
#ifdef BFD_BSD
	int yes = 1;

	/* Find out our address for peer matching. */
	if (setsockopt(sd, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes)) == -1)
		zlog_fatal("set-ipopts: setsockopt(IP_RECVDSTADDR, %d): %s",
			   yes, strerror(errno));

	/* Find out interface where the packet came in. */
	if (setsockopt_ifindex(AF_INET, sd, yes) == -1)
		zlog_fatal("set-ipopts: setsockopt_ipv4_ifindex(%d): %s", yes,
			   strerror(errno));
#endif /* BFD_BSD */
}

static void bp_bind_ip(int sd, uint16_t port)
{
	struct sockaddr_in sin;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(port);
	if (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) == -1)
		zlog_fatal("bind-ip: bind: %s", strerror(errno));
}

int bp_udp_shop(const struct vrf *vrf)
{
	int sd;

	frr_with_privs(&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id,
				vrf->name);
	}
	if (sd == -1)
		zlog_fatal("udp-shop: socket: %s", strerror(errno));

	bp_set_ipopts(sd);
	bp_bind_ip(sd, BFD_DEFDESTPORT);
	return sd;
}

int bp_udp_mhop(const struct vrf *vrf)
{
	int sd;

	frr_with_privs(&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id,
				vrf->name);
	}
	if (sd == -1)
		zlog_fatal("udp-mhop: socket: %s", strerror(errno));

	bp_set_ipopts(sd);
	bp_bind_ip(sd, BFD_DEF_MHOP_DEST_PORT);

	return sd;
}

int bp_peer_socket(const struct bfd_session *bs)
{
	int sd, pcount;
	struct sockaddr_in sin;
	static int srcPort = BFD_SRCPORTINIT;
	const char *device_to_bind = NULL;

	if (bs->key.ifname[0])
		device_to_bind = (const char *)bs->key.ifname;
	else if ((!vrf_is_backend_netns() && bs->vrf->vrf_id != VRF_DEFAULT)
		 || ((CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)
		      && bs->key.vrfname[0])))
		device_to_bind = (const char *)bs->key.vrfname;

	frr_with_privs(&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET, SOCK_DGRAM, PF_UNSPEC,
				bs->vrf->vrf_id, device_to_bind);
	}
	if (sd == -1) {
		zlog_err("ipv4-new: failed to create socket: %s",
			 strerror(errno));
		return -1;
	}

	/* Set TTL to 255 for all transmitted packets */
	if (bp_set_ttl(sd, BFD_TTL_VAL) != 0) {
		close(sd);
		return -1;
	}

	/* Set TOS to CS6 for all transmitted packets */
	if (bp_set_tos(sd, BFD_TOS_VAL) != 0) {
		close(sd);
		return -1;
	}

	/* Find an available source port in the proper range */
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin.sin_len = sizeof(sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	memcpy(&sin.sin_addr, &bs->key.local, sizeof(sin.sin_addr));

	pcount = 0;
	do {
		if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
			/* Searched all ports, none available */
			zlog_err("ipv4-new: failed to bind port: %s",
				 strerror(errno));
			close(sd);
			return -1;
		}
		if (srcPort >= BFD_SRCPORTMAX)
			srcPort = BFD_SRCPORTINIT;
		sin.sin_port = htons(srcPort++);
	} while (bind(sd, (struct sockaddr *)&sin, sizeof(sin)) < 0);

	return sd;
}


/*
 * IPv6 sockets
 */

int bp_peer_socketv6(const struct bfd_session *bs)
{
	int sd, pcount;
	struct sockaddr_in6 sin6;
	static int srcPort = BFD_SRCPORTINIT;
	const char *device_to_bind = NULL;

	if (bs->key.ifname[0])
		device_to_bind = (const char *)bs->key.ifname;
	else if ((!vrf_is_backend_netns() && bs->vrf->vrf_id != VRF_DEFAULT)
		 || ((CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH)
		      && bs->key.vrfname[0])))
		device_to_bind = (const char *)bs->key.vrfname;

	frr_with_privs(&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET6, SOCK_DGRAM, PF_UNSPEC,
				bs->vrf->vrf_id, device_to_bind);
	}
	if (sd == -1) {
		zlog_err("ipv6-new: failed to create socket: %s",
			 strerror(errno));
		return -1;
	}

	/* Set TTL to 255 for all transmitted packets */
	if (bp_set_ttlv6(sd, BFD_TTL_VAL) != 0) {
		close(sd);
		return -1;
	}

	/* Set TOS to CS6 for all transmitted packets */
	if (bp_set_tosv6(sd, BFD_TOS_VAL) != 0) {
		close(sd);
		return -1;
	}

	/* Find an available source port in the proper range */
	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	memcpy(&sin6.sin6_addr, &bs->key.local, sizeof(sin6.sin6_addr));
	if (bs->ifp && IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
		sin6.sin6_scope_id = bs->ifp->ifindex;

	pcount = 0;
	do {
		if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
			/* Searched all ports, none available */
			zlog_err("ipv6-new: failed to bind port: %s",
				 strerror(errno));
			close(sd);
			return -1;
		}
		if (srcPort >= BFD_SRCPORTMAX)
			srcPort = BFD_SRCPORTINIT;
		sin6.sin6_port = htons(srcPort++);
	} while (bind(sd, (struct sockaddr *)&sin6, sizeof(sin6)) < 0);

	return sd;
}

int bp_set_ttlv6(int sd, uint8_t value)
{
	int ttl = value;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl))
	    == -1) {
		zlog_warn("set-ttlv6: setsockopt(IPV6_UNICAST_HOPS, %d): %s",
			  value, strerror(errno));
		return -1;
	}

	return 0;
}

int bp_set_tosv6(int sd, uint8_t value)
{
	int tos = value;

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_TCLASS, &tos, sizeof(tos))
	    == -1) {
		zlog_warn("set-tosv6: setsockopt(IPV6_TCLASS, %d): %s", value,
			  strerror(errno));
		return -1;
	}

	return 0;
}

static void bp_set_ipv6opts(int sd)
{
	int ipv6_pktinfo = BFD_IPV6_PKT_INFO_VAL;
	int ipv6_only = BFD_IPV6_ONLY_VAL;

	if (!bp_set_reuse_addr(sd))
		zlog_fatal("set-reuse-addr: failed");

	if (!bp_set_reuse_port(sd))
		zlog_fatal("set-reuse-port: failed");

	if (bp_set_ttlv6(sd, BFD_TTL_VAL) == -1)
		zlog_fatal(
			"set-ipv6opts: setsockopt(IPV6_UNICAST_HOPS, %d): %s",
			BFD_TTL_VAL, strerror(errno));

	if (setsockopt_ipv6_hoplimit(sd, BFD_RCV_TTL_VAL) == -1)
		zlog_fatal("set-ipv6opts: setsockopt(IPV6_HOPLIMIT, %d): %s",
			   BFD_RCV_TTL_VAL, strerror(errno));

	if (setsockopt_ipv6_pktinfo(sd, ipv6_pktinfo) == -1)
		zlog_fatal("set-ipv6opts: setsockopt(IPV6_PKTINFO, %d): %s",
			   ipv6_pktinfo, strerror(errno));

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only,
		       sizeof(ipv6_only))
	    == -1)
		zlog_fatal("set-ipv6opts: setsockopt(IPV6_V6ONLY, %d): %s",
			   ipv6_only, strerror(errno));
}

static void bp_bind_ipv6(int sd, uint16_t port)
{
	struct sockaddr_in6 sin6;

	memset(&sin6, 0, sizeof(sin6));
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = in6addr_any;
	sin6.sin6_port = htons(port);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	if (bind(sd, (struct sockaddr *)&sin6, sizeof(sin6)) == -1)
		zlog_fatal("bind-ipv6: bind: %s", strerror(errno));
}

int bp_udp6_shop(const struct vrf *vrf)
{
	int sd;

	frr_with_privs(&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET6, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id,
				vrf->name);
	}
	if (sd == -1) {
		if (errno != EAFNOSUPPORT)
			zlog_fatal("udp6-shop: socket: %s", strerror(errno));
		else
			zlog_warn("udp6-shop: V6 is not supported, continuing");

		return -1;
	}

	bp_set_ipv6opts(sd);
	bp_bind_ipv6(sd, BFD_DEFDESTPORT);

	return sd;
}

int bp_udp6_mhop(const struct vrf *vrf)
{
	int sd;

	frr_with_privs(&bglobal.bfdd_privs) {
		sd = vrf_socket(AF_INET6, SOCK_DGRAM, PF_UNSPEC, vrf->vrf_id,
				vrf->name);
	}
	if (sd == -1) {
		if (errno != EAFNOSUPPORT)
			zlog_fatal("udp6-mhop: socket: %s", strerror(errno));
		else
			zlog_warn("udp6-mhop: V6 is not supported, continuing");

		return -1;
	}

	bp_set_ipv6opts(sd);
	bp_bind_ipv6(sd, BFD_DEF_MHOP_DEST_PORT);

	return sd;
}

#ifdef BFD_LINUX
/* tcpdump -dd udp dst port 3785 */
struct sock_filter my_filterudp[] = {
	{0x28, 0, 0, 0x0000000c}, {0x15, 0, 8, 0x00000800},
	{0x30, 0, 0, 0x00000017}, {0x15, 0, 6, 0x00000011},
	{0x28, 0, 0, 0x00000014}, {0x45, 4, 0, 0x00001fff},
	{0xb1, 0, 0, 0x0000000e}, {0x48, 0, 0, 0x00000010},
	{0x15, 0, 1, 0x00000ec9}, {0x6, 0, 0, 0x00040000},
	{0x6, 0, 0, 0x00000000},
};

#define MY_FILTER_LENGTH 11

int bp_echo_socket(const struct vrf *vrf)
{
	int s;

	frr_with_privs (&bglobal.bfdd_privs) {
		s = vrf_socket(AF_PACKET, SOCK_RAW, ETH_P_IP, vrf->vrf_id,
			       vrf->name);
	}

	if (s == -1)
		zlog_fatal("echo-socket: socket: %s", strerror(errno));

	struct sock_fprog pf;
	struct sockaddr_ll sll = {0};

	/* adjust filter for socket to only receive ECHO packets */
	pf.filter = my_filterudp;
	pf.len = MY_FILTER_LENGTH;
	if (setsockopt(s, SOL_SOCKET, SO_ATTACH_FILTER, &pf, sizeof(pf)) ==
	    -1) {
		zlog_warn("%s: setsockopt(SO_ATTACH_FILTER): %s", __func__,
			  strerror(errno));
		close(s);
		return -1;
	}

	memset(&sll, 0, sizeof(sll));
	sll.sll_family = AF_PACKET;
	sll.sll_protocol = htons(ETH_P_IP);
	sll.sll_ifindex = 0;
	if (bind(s, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
		zlog_warn("Failed to bind echo socket: %s",
			  safe_strerror(errno));
		close(s);
		return -1;
	}

	return s;
}
#else
int bp_echo_socket(const struct vrf *vrf)
{
	int s;

	frr_with_privs(&bglobal.bfdd_privs) {
		s = vrf_socket(AF_INET, SOCK_DGRAM, 0, vrf->vrf_id, vrf->name);
	}
	if (s == -1)
		zlog_fatal("echo-socket: socket: %s", strerror(errno));

	bp_set_ipopts(s);
	bp_bind_ip(s, BFD_DEF_ECHO_PORT);

	return s;
}
#endif

int bp_echov6_socket(const struct vrf *vrf)
{
	int s;

	frr_with_privs(&bglobal.bfdd_privs) {
		s = vrf_socket(AF_INET6, SOCK_DGRAM, 0, vrf->vrf_id, vrf->name);
	}
	if (s == -1) {
		if (errno != EAFNOSUPPORT)
			zlog_fatal("echov6-socket: socket: %s",
				   strerror(errno));
		else
			zlog_warn("echov6-socket: V6 is not supported, continuing");

		return -1;
	}

	bp_set_ipv6opts(s);
	bp_bind_ipv6(s, BFD_DEF_ECHO_PORT);

	return s;
}

#ifdef BFD_LINUX
/* get peer's mac address to be used with Echo packets when they are looped in
 * peers forwarding plane
 */
void bfd_peer_mac_set(int sd, struct bfd_session *bfd,
		      struct sockaddr_any *peer, struct interface *ifp)
{
	struct arpreq arpreq_;

	if (CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MAC_SET))
		return;
	if (ifp->flags & IFF_NOARP)
		return;

	if (peer->sa_sin.sin_family == AF_INET) {
		/* IPV4 */
		struct sockaddr_in *addr =
			(struct sockaddr_in *)&arpreq_.arp_pa;

		memset(&arpreq_, 0, sizeof(struct arpreq));
		addr->sin_family = AF_INET;
		memcpy(&addr->sin_addr.s_addr, &peer->sa_sin.sin_addr,
		       sizeof(addr->sin_addr));
		strlcpy(arpreq_.arp_dev, ifp->name, sizeof(arpreq_.arp_dev));

		if (ioctl(sd, SIOCGARP, &arpreq_) < 0) {
			if (bglobal.debug_network)
				zlog_debug(
					"BFD: getting peer's mac on %s failed error %s",
					ifp->name, strerror(errno));
			UNSET_FLAG(bfd->flags, BFD_SESS_FLAG_MAC_SET);
			memset(bfd->peer_hw_addr, 0, sizeof(bfd->peer_hw_addr));

		} else {
			memcpy(bfd->peer_hw_addr, arpreq_.arp_ha.sa_data,
			       sizeof(bfd->peer_hw_addr));
			SET_FLAG(bfd->flags, BFD_SESS_FLAG_MAC_SET);
		}
	}
}
#endif
