/*********************************************************************
 * Copyright 2017 Cumulus Networks, Inc.  All rights reserved.
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

#ifdef BFD_LINUX
#include <linux/if_packet.h>
#endif /* BFD_LINUX */

#include <netinet/if_ether.h>
#include <netinet/udp.h>

#include "lib/sockopt.h"

#include "bfd.h"


/*
 * Prototypes
 */
static int ptm_bfd_process_echo_pkt(int s);
int _ptm_bfd_send(struct bfd_session *bs, uint16_t *port, const void *data,
		  size_t datalen);

static void bfd_sd_reschedule(int sd);
ssize_t bfd_recv_ipv4(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      char *port, size_t portlen, char *vrfname,
		      size_t vrfnamelen, struct sockaddr_any *local,
		      struct sockaddr_any *peer);
ssize_t bfd_recv_ipv6(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      char *port, size_t portlen, char *vrfname,
		      size_t vrfnamelen, struct sockaddr_any *local,
		      struct sockaddr_any *peer);
int bp_udp_send(int sd, uint8_t ttl, uint8_t *data, size_t datalen,
		struct sockaddr *to, socklen_t tolen);
int bp_bfd_echo_in(int sd, uint8_t *ttl, uint32_t *my_discr);

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

	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_IPV6)) {
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_addr = bs->shop.peer.sa_sin6.sin6_addr;
		sin6.sin6_port =
			(port) ? *port
			       : (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
					 ? htons(BFD_DEF_MHOP_DEST_PORT)
					 : htons(BFD_DEFDESTPORT);

		sd = bs->sock;
		sa = (struct sockaddr *)&sin6;
		slen = sizeof(sin6);
	} else {
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_addr = bs->shop.peer.sa_sin.sin_addr;
		sin.sin_port =
			(port) ? *port
			       : (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_MH))
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
		log_debug("packet-send: send failure: %s", strerror(errno));
		return -1;
	}
	if (rv < (ssize_t)datalen)
		log_debug("packet-send: send partial", strerror(errno));

	return 0;
}

void ptm_bfd_echo_snd(struct bfd_session *bfd)
{
	struct sockaddr_any *sa;
	socklen_t salen;
	int sd;
	struct bfd_echo_pkt bep;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;

	if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE))
		BFD_SET_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE);

	memset(&bep, 0, sizeof(bep));
	bep.ver = BFD_ECHO_VERSION;
	bep.len = BFD_ECHO_PKT_LEN;
	bep.my_discr = htonl(bfd->discrs.my_discr);

	sa = BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_MH) ? &bfd->mhop.peer
							  : &bfd->shop.peer;
	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_IPV6)) {
		sd = bglobal.bg_echov6;
		sin6 = sa->sa_sin6;
		sin6.sin6_port = htons(BFD_DEF_ECHO_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin6.sin6_len = sizeof(sin6);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

		sa = (struct sockaddr_any *)&sin6;
		salen = sizeof(sin6);
	} else {
		sd = bglobal.bg_echo;
		sin = sa->sa_sin;
		sin.sin_port = htons(BFD_DEF_ECHO_PORT);
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
		sin.sin_len = sizeof(sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */

		sa = (struct sockaddr_any *)&sin;
		salen = sizeof(sin);
	}
	if (bp_udp_send(sd, BFD_TTL_VAL, (uint8_t *)&bep, sizeof(bep),
			(struct sockaddr *)sa, salen)
	    == -1)
		return;

	bfd->stats.tx_echo_pkt++;
}

static int ptm_bfd_process_echo_pkt(int s)
{
	struct bfd_session *bfd;
	uint32_t my_discr = 0;
	uint8_t ttl = 0;

	/* Receive and parse echo packet. */
	if (bp_bfd_echo_in(s, &ttl, &my_discr) == -1)
		return 0;

	/* Your discriminator not zero - use it to find session */
	bfd = bfd_id_lookup(my_discr);
	if (bfd == NULL) {
		log_debug("echo-packet: no matching session (id:%u)", my_discr);
		return -1;
	}

	if (!BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
		log_debug("echo-packet: echo disabled [%s] (id:%u)",
			  bs_to_string(bfd), my_discr);
		return -1;
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
	struct bfd_pkt cp;

	/* Set fields according to section 6.5.7 */
	cp.diag = bfd->local_diag;
	BFD_SETVER(cp.diag, BFD_VERSION);
	cp.flags = 0;
	BFD_SETSTATE(cp.flags, bfd->ses_state);
	BFD_SETDEMANDBIT(cp.flags, BFD_DEF_DEMAND);
	BFD_SETPBIT(cp.flags, bfd->polling);
	BFD_SETFBIT(cp.flags, fbit);
	cp.detect_mult = bfd->detect_mult;
	cp.len = BFD_PKT_LEN;
	cp.discrs.my_discr = htonl(bfd->discrs.my_discr);
	cp.discrs.remote_discr = htonl(bfd->discrs.remote_discr);
	if (bfd->polling) {
		cp.timers.desired_min_tx =
			htonl(bfd->new_timers.desired_min_tx);
		cp.timers.required_min_rx =
			htonl(bfd->new_timers.required_min_rx);
	} else {
		cp.timers.desired_min_tx = htonl(bfd->timers.desired_min_tx);
		cp.timers.required_min_rx = htonl(bfd->timers.required_min_rx);
	}
	cp.timers.required_min_echo = htonl(bfd->timers.required_min_echo);

	if (_ptm_bfd_send(bfd, NULL, &cp, BFD_PKT_LEN) != 0)
		return;

	bfd->stats.tx_ctrl_pkt++;
}

ssize_t bfd_recv_ipv4(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      char *port, size_t portlen, char *vrfname,
		      size_t vrfnamelen, struct sockaddr_any *local,
		      struct sockaddr_any *peer)
{
	struct cmsghdr *cm;
	int ifindex;
	ssize_t mlen;
	struct sockaddr_in msgaddr;
	struct msghdr msghdr;
	struct iovec iov[1];
	uint8_t cmsgbuf[255];

	port[0] = '\0';

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
			log_error("ipv4-recv: recv failed: %s",
				  strerror(errno));

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
				log_debug("ipv4-recv: invalid TTL: %u", ttlval);
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
			fetch_portname_from_ifindex(pi->ipi_ifindex, port,
						    portlen);
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
	if (port[0] == 0) {
		ifindex = getsockopt_ifindex(AF_INET, &msghdr);
		if (ifindex > 0)
			fetch_portname_from_ifindex(ifindex, port, portlen);
	}

	return mlen;
}

ssize_t bfd_recv_ipv6(int sd, uint8_t *msgbuf, size_t msgbuflen, uint8_t *ttl,
		      char *port, size_t portlen, char *vrfname,
		      size_t vrfnamelen, struct sockaddr_any *local,
		      struct sockaddr_any *peer)
{
	struct cmsghdr *cm;
	struct in6_pktinfo *pi6 = NULL;
	int ifindex = 0;
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
			log_error("ipv6-recv: recv failed: %s",
				  strerror(errno));

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
				log_debug("ipv6-recv: invalid TTL: %u", ttlval);
				return -1;
			}

			*ttl = ttlval;
		} else if (cm->cmsg_type == IPV6_PKTINFO) {
			pi6 = (struct in6_pktinfo *)CMSG_DATA(cm);
			if (pi6) {
				local->sa_sin.sin_family = AF_INET6;
				local->sa_sin6.sin6_addr = pi6->ipi6_addr;
				fetch_portname_from_ifindex(pi6->ipi6_ifindex,
							    port, portlen);
				ifindex = pi6->ipi6_ifindex;
			}
		}
	}

	/* Set scope ID for link local addresses. */
	if (IN6_IS_ADDR_LINKLOCAL(&peer->sa_sin6.sin6_addr))
		peer->sa_sin6.sin6_scope_id = ifindex;
	if (IN6_IS_ADDR_LINKLOCAL(&local->sa_sin6.sin6_addr))
		local->sa_sin6.sin6_scope_id = ifindex;

	return mlen;
}

static void bfd_sd_reschedule(int sd)
{
	if (sd == bglobal.bg_shop) {
		THREAD_OFF(bglobal.bg_ev[0]);
		thread_add_read(master, bfd_recv_cb, NULL, bglobal.bg_shop,
				&bglobal.bg_ev[0]);
	} else if (sd == bglobal.bg_mhop) {
		THREAD_OFF(bglobal.bg_ev[1]);
		thread_add_read(master, bfd_recv_cb, NULL, bglobal.bg_mhop,
				&bglobal.bg_ev[1]);
	} else if (sd == bglobal.bg_shop6) {
		THREAD_OFF(bglobal.bg_ev[2]);
		thread_add_read(master, bfd_recv_cb, NULL, bglobal.bg_shop6,
				&bglobal.bg_ev[2]);
	} else if (sd == bglobal.bg_mhop6) {
		THREAD_OFF(bglobal.bg_ev[3]);
		thread_add_read(master, bfd_recv_cb, NULL, bglobal.bg_mhop6,
				&bglobal.bg_ev[3]);
	} else if (sd == bglobal.bg_echo) {
		THREAD_OFF(bglobal.bg_ev[4]);
		thread_add_read(master, bfd_recv_cb, NULL, bglobal.bg_echo,
				&bglobal.bg_ev[4]);
	} else if (sd == bglobal.bg_echov6) {
		THREAD_OFF(bglobal.bg_ev[5]);
		thread_add_read(master, bfd_recv_cb, NULL, bglobal.bg_echov6,
				&bglobal.bg_ev[5]);
	}
}

static void cp_debug(bool mhop, struct sockaddr_any *peer,
		     struct sockaddr_any *local, const char *port,
		     const char *vrf, const char *fmt, ...)
{
	char buf[512], peerstr[128], localstr[128], portstr[64], vrfstr[64];
	va_list vl;

	if (peer->sa_sin.sin_family)
		snprintf(peerstr, sizeof(peerstr), " peer:%s", satostr(peer));
	else
		peerstr[0] = 0;

	if (local->sa_sin.sin_family)
		snprintf(localstr, sizeof(localstr), " local:%s",
			 satostr(local));
	else
		localstr[0] = 0;

	if (port[0])
		snprintf(portstr, sizeof(portstr), " port:%s", port);
	else
		portstr[0] = 0;

	if (vrf[0])
		snprintf(vrfstr, sizeof(vrfstr), " vrf:%s", port);
	else
		vrfstr[0] = 0;

	va_start(vl, fmt);
	vsnprintf(buf, sizeof(buf), fmt, vl);
	va_end(vl);

	log_debug("control-packet: %s [mhop:%s%s%s%s%s]", buf,
		  mhop ? "yes" : "no", peerstr, localstr, portstr, vrfstr);
}

int bfd_recv_cb(struct thread *t)
{
	int sd = THREAD_FD(t);
	struct bfd_session *bfd;
	struct bfd_pkt *cp;
	bool is_mhop;
	ssize_t mlen = 0;
	uint32_t oldEchoXmt_TO, oldXmtTime;
	uint8_t ttl;
	struct sockaddr_any local, peer;
	char port[MAXNAMELEN + 1], vrfname[MAXNAMELEN + 1];
	uint8_t msgbuf[1516];

	/* Schedule next read. */
	bfd_sd_reschedule(sd);

	/* Handle echo packets. */
	if (sd == bglobal.bg_echo || sd == bglobal.bg_echov6) {
		ptm_bfd_process_echo_pkt(sd);
		return 0;
	}

	/* Sanitize input/output. */
	memset(port, 0, sizeof(port));
	memset(vrfname, 0, sizeof(vrfname));
	memset(&local, 0, sizeof(local));
	memset(&peer, 0, sizeof(peer));

	/* Handle control packets. */
	is_mhop = false;
	if (sd == bglobal.bg_shop || sd == bglobal.bg_mhop) {
		is_mhop = sd == bglobal.bg_mhop;
		mlen = bfd_recv_ipv4(sd, msgbuf, sizeof(msgbuf), &ttl, port,
				     sizeof(port), vrfname, sizeof(vrfname),
				     &local, &peer);
	} else if (sd == bglobal.bg_shop6 || sd == bglobal.bg_mhop6) {
		is_mhop = sd == bglobal.bg_mhop6;
		mlen = bfd_recv_ipv6(sd, msgbuf, sizeof(msgbuf), &ttl, port,
				     sizeof(port), vrfname, sizeof(vrfname),
				     &local, &peer);
	}

	/* Implement RFC 5880 6.8.6 */
	if (mlen < BFD_PKT_LEN) {
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "too small (%ld bytes)", mlen);
		return 0;
	}

	/* Validate packet TTL. */
	if ((is_mhop == false) && (ttl != BFD_TTL_VAL)) {
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "invalid TTL: %d expected %d", ttl, BFD_TTL_VAL);
		return 0;
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
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "bad version %d", BFD_GETVER(cp->diag));
		return 0;
	}

	if (cp->detect_mult == 0) {
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "detect multiplier set to zero");
		return 0;
	}

	if ((cp->len < BFD_PKT_LEN) || (cp->len > mlen)) {
		cp_debug(is_mhop, &peer, &local, port, vrfname, "too small");
		return 0;
	}

	if (cp->discrs.my_discr == 0) {
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "'my discriminator' is zero");
		return 0;
	}

	/* Find the session that this packet belongs. */
	bfd = ptm_bfd_sess_find(cp, port, &peer, &local, vrfname, is_mhop);
	if (bfd == NULL) {
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "no session found");
		return 0;
	}

	bfd->stats.rx_ctrl_pkt++;

	/*
	 * Multi hop: validate packet TTL.
	 * Single hop: set local address that received the packet.
	 */
	if (is_mhop) {
		if ((BFD_TTL_VAL - bfd->mh_ttl) > BFD_TTL_VAL) {
			cp_debug(is_mhop, &peer, &local, port, vrfname,
				 "exceeded max hop count (expected %d, got %d)",
				 bfd->mh_ttl, BFD_TTL_VAL);
			return 0;
		}
	} else if (bfd->local_ip.sa_sin.sin_family == AF_UNSPEC) {
		bfd->local_ip = local;
	}

	/*
	 * If no interface was detected, save the interface where the
	 * packet came in.
	 */
	if (bfd->ifindex == 0)
		bfd->ifindex = ptm_bfd_fetch_ifindex(port);

	/* Log remote discriminator changes. */
	if ((bfd->discrs.remote_discr != 0)
	    && (bfd->discrs.remote_discr != ntohl(cp->discrs.my_discr)))
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "remote discriminator mismatch (expected %d, got %d)",
			 bfd->discrs.remote_discr, ntohl(cp->discrs.my_discr));

	bfd->discrs.remote_discr = ntohl(cp->discrs.my_discr);

	/* If received the Final bit, the new values should take effect */
	if (bfd->polling && BFD_GETFBIT(cp->flags)) {
		bfd->timers.desired_min_tx = bfd->new_timers.desired_min_tx;
		bfd->timers.required_min_rx = bfd->new_timers.required_min_rx;
		bfd->new_timers.desired_min_tx = 0;
		bfd->new_timers.required_min_rx = 0;
		bfd->polling = 0;
	}

	if (!bfd->demand_mode) {
		/* Compute detect time */
		bfd->detect_TO = cp->detect_mult
				 * ((bfd->timers.required_min_rx
				     > ntohl(cp->timers.desired_min_tx))
					    ? bfd->timers.required_min_rx
					    : ntohl(cp->timers.desired_min_tx));
		bfd->remote_detect_mult = cp->detect_mult;
	} else
		cp_debug(is_mhop, &peer, &local, port, vrfname,
			 "unsupported demand mode");

	/* Save remote diagnostics before state switch. */
	bfd->remote_diag = cp->diag & BFD_DIAGMASK;

	/* State switch from section 6.8.6 */
	if (BFD_GETSTATE(cp->flags) == PTM_BFD_ADM_DOWN) {
		if (bfd->ses_state != PTM_BFD_DOWN)
			ptm_bfd_ses_dn(bfd, BD_NEIGHBOR_DOWN);
	} else {
		switch (bfd->ses_state) {
		case (PTM_BFD_DOWN):
			if (BFD_GETSTATE(cp->flags) == PTM_BFD_INIT)
				ptm_bfd_ses_up(bfd);
			else if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN)
				bfd->ses_state = PTM_BFD_INIT;
			break;
		case (PTM_BFD_INIT):
			if (BFD_GETSTATE(cp->flags) == PTM_BFD_INIT
			    || BFD_GETSTATE(cp->flags) == PTM_BFD_UP)
				ptm_bfd_ses_up(bfd);
			break;
		case (PTM_BFD_UP):
			if (BFD_GETSTATE(cp->flags) == PTM_BFD_DOWN)
				ptm_bfd_ses_dn(bfd, BD_NEIGHBOR_DOWN);
			break;
		}
	}

	/*
	 * Handle echo packet status:
	 * - Start echo packets if configured and permitted
	 *   (required_min_echo > 0);
	 * - Stop echo packets if not allowed (required_min_echo == 0);
	 * - Recalculate echo packet interval;
	 */
	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO)) {
		if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
			if (!ntohl(cp->timers.required_min_echo)) {
				ptm_bfd_echo_stop(bfd, 1);
			} else {
				oldEchoXmt_TO = bfd->echo_xmt_TO;
				bfd->echo_xmt_TO =
					bfd->timers.required_min_echo;
				if (ntohl(cp->timers.required_min_echo)
				    > bfd->echo_xmt_TO)
					bfd->echo_xmt_TO = ntohl(
						cp->timers.required_min_echo);
				if (oldEchoXmt_TO != bfd->echo_xmt_TO)
					ptm_bfd_echo_start(bfd);
			}
		} else if (ntohl(cp->timers.required_min_echo)) {
			bfd->echo_xmt_TO = bfd->timers.required_min_echo;
			if (ntohl(cp->timers.required_min_echo)
			    > bfd->echo_xmt_TO)
				bfd->echo_xmt_TO =
					ntohl(cp->timers.required_min_echo);
			ptm_bfd_echo_start(bfd);
		}
	}

	if (BFD_CHECK_FLAG(bfd->flags, BFD_SESS_FLAG_ECHO_ACTIVE)) {
		bfd->echo_xmt_TO = bfd->timers.required_min_echo;
		if (ntohl(cp->timers.required_min_echo) > bfd->echo_xmt_TO)
			bfd->echo_xmt_TO = ntohl(cp->timers.required_min_echo);
	}

	/* Calculate new transmit time */
	oldXmtTime = bfd->xmt_TO;
	bfd->xmt_TO =
		(bfd->timers.desired_min_tx > ntohl(cp->timers.required_min_rx))
			? bfd->timers.desired_min_tx
			: ntohl(cp->timers.required_min_rx);

	/* If transmit time has changed, and too much time until next xmt,
	 * restart
	 */
	if (BFD_GETPBIT(cp->flags)) {
		ptm_bfd_xmt_TO(bfd, 1);
	} else if (oldXmtTime != bfd->xmt_TO) {
		/* XXX add some skid to this as well */
		ptm_bfd_start_xmt_timer(bfd, false);
	}

	/* Restart detection timer (packet received) */
	if (!bfd->demand_mode)
		bfd_recvtimer_update(bfd);

	/*
	 * Save the timers and state sent by the remote end
	 * for debugging and statistics.
	 */
	if (BFD_GETFBIT(cp->flags)) {
		bfd->remote_timers.desired_min_tx =
			ntohl(cp->timers.desired_min_tx);
		bfd->remote_timers.required_min_rx =
			ntohl(cp->timers.required_min_rx);
		bfd->remote_timers.required_min_echo =
			ntohl(cp->timers.required_min_echo);

		control_notify_config(BCM_NOTIFY_CONFIG_UPDATE, bfd);
	}

	return 0;
}

/*
 * bp_bfd_echo_in: proccesses an BFD echo packet. On TTL == BFD_TTL_VAL
 * the packet is looped back or returns the my discriminator ID along
 * with the TTL.
 *
 * Returns -1 on error or loopback or 0 on success.
 */
int bp_bfd_echo_in(int sd, uint8_t *ttl, uint32_t *my_discr)
{
	struct bfd_echo_pkt *bep;
	ssize_t rlen;
	struct sockaddr_any local, peer;
	char port[MAXNAMELEN + 1], vrfname[MAXNAMELEN + 1];
	uint8_t msgbuf[1516];

	if (sd == bglobal.bg_echo)
		rlen = bfd_recv_ipv4(sd, msgbuf, sizeof(msgbuf), ttl, port,
				     sizeof(port), vrfname, sizeof(vrfname),
				     &local, &peer);
	else
		rlen = bfd_recv_ipv6(sd, msgbuf, sizeof(msgbuf), ttl, port,
				     sizeof(port), vrfname, sizeof(vrfname),
				     &local, &peer);

	/* Short packet, better not risk reading it. */
	if (rlen < (ssize_t)sizeof(*bep)) {
		cp_debug(false, &peer, &local, port, vrfname,
			 "small echo packet");
		return -1;
	}

	/* Test for loopback. */
	if (*ttl == BFD_TTL_VAL) {
		bp_udp_send(sd, *ttl - 1, msgbuf, rlen,
			    (struct sockaddr *)&peer,
			    (sd == bglobal.bg_echo) ? sizeof(peer.sa_sin)
						    : sizeof(peer.sa_sin6));
		return -1;
	}

	/* Read my discriminator from BFD Echo packet. */
	bep = (struct bfd_echo_pkt *)msgbuf;
	*my_discr = ntohl(bep->my_discr);
	if (*my_discr == 0) {
		cp_debug(false, &peer, &local, port, vrfname,
			 "invalid echo packet discriminator (zero)");
		return -1;
	}

	return 0;
}

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
#if BFD_LINUX
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
		log_debug("udp-send: loopback failure: (%d) %s", errno, strerror(errno));
		return -1;
	} else if (wlen < (ssize_t)datalen) {
		log_debug("udp-send: partial send: %ld expected %ld", wlen,
			  datalen);
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
		log_warning("set-ttl: setsockopt(IP_TTL, %d): %s", value,
			    strerror(errno));
		return -1;
	}

	return 0;
}

int bp_set_tos(int sd, uint8_t value)
{
	int tos = value;

	if (setsockopt(sd, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)) == -1) {
		log_warning("set-tos: setsockopt(IP_TOS, %d): %s", value,
			    strerror(errno));
		return -1;
	}

	return 0;
}

static void bp_set_ipopts(int sd)
{
	int rcvttl = BFD_RCV_TTL_VAL;

	if (bp_set_ttl(sd, BFD_TTL_VAL) != 0)
		log_fatal("set-ipopts: TTL configuration failed");

	if (setsockopt(sd, IPPROTO_IP, IP_RECVTTL, &rcvttl, sizeof(rcvttl))
	    == -1)
		log_fatal("set-ipopts: setsockopt(IP_RECVTTL, %d): %s", rcvttl,
			  strerror(errno));

#ifdef BFD_LINUX
	int pktinfo = BFD_PKT_INFO_VAL;

	/* Figure out address and interface to do the peer matching. */
	if (setsockopt(sd, IPPROTO_IP, IP_PKTINFO, &pktinfo, sizeof(pktinfo))
	    == -1)
		log_fatal("set-ipopts: setsockopt(IP_PKTINFO, %d): %s", pktinfo,
			  strerror(errno));
#endif /* BFD_LINUX */
#ifdef BFD_BSD
	int yes = 1;

	/* Find out our address for peer matching. */
	if (setsockopt(sd, IPPROTO_IP, IP_RECVDSTADDR, &yes, sizeof(yes)) == -1)
		log_fatal("set-ipopts: setsockopt(IP_RECVDSTADDR, %d): %s", yes,
			  strerror(errno));

	/* Find out interface where the packet came in. */
	if (setsockopt_ifindex(AF_INET, sd, yes) == -1)
		log_fatal("set-ipopts: setsockopt_ipv4_ifindex(%d): %s", yes,
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
		log_fatal("bind-ip: bind: %s", strerror(errno));
}

int bp_udp_shop(void)
{
	int sd;

	sd = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
	if (sd == -1)
		log_fatal("udp-shop: socket: %s", strerror(errno));

	bp_set_ipopts(sd);
	bp_bind_ip(sd, BFD_DEFDESTPORT);

	return sd;
}

int bp_udp_mhop(void)
{
	int sd;

	sd = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
	if (sd == -1)
		log_fatal("udp-mhop: socket: %s", strerror(errno));

	bp_set_ipopts(sd);
	bp_bind_ip(sd, BFD_DEF_MHOP_DEST_PORT);

	return sd;
}

int bp_peer_socket(struct bfd_peer_cfg *bpc)
{
	int sd, pcount;
	struct sockaddr_in sin;
	static int srcPort = BFD_SRCPORTINIT;

	sd = socket(AF_INET, SOCK_DGRAM, PF_UNSPEC);
	if (sd == -1) {
		log_error("ipv4-new: failed to create socket: %s",
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

	if (bpc->bpc_has_localif) {
		if (bp_bind_dev(sd, bpc->bpc_localif) != 0) {
			close(sd);
			return -1;
		}
	} else if (bpc->bpc_mhop && bpc->bpc_has_vrfname) {
		if (bp_bind_dev(sd, bpc->bpc_vrfname) != 0) {
			close(sd);
			return -1;
		}
	}

	/* Find an available source port in the proper range */
	memset(&sin, 0, sizeof(sin));
	sin = bpc->bpc_local.sa_sin;
	sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_SA_LEN
	sin.sin_len = sizeof(sin);
#endif /* HAVE_STRUCT_SOCKADDR_SA_LEN */
	if (bpc->bpc_mhop)
		sin.sin_addr = bpc->bpc_local.sa_sin.sin_addr;
	else
		sin.sin_addr.s_addr = INADDR_ANY;

	pcount = 0;
	do {
		if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
			/* Searched all ports, none available */
			log_error("ipv4-new: failed to bind port: %s",
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

int bp_peer_socketv6(struct bfd_peer_cfg *bpc)
{
	int sd, pcount, ifindex;
	struct sockaddr_in6 sin6;
	static int srcPort = BFD_SRCPORTINIT;

	sd = socket(AF_INET6, SOCK_DGRAM, PF_UNSPEC);
	if (sd == -1) {
		log_error("ipv6-new: failed to create socket: %s",
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
	sin6 = bpc->bpc_local.sa_sin6;
	ifindex = ptm_bfd_fetch_ifindex(bpc->bpc_localif);
	if (IN6_IS_ADDR_LINKLOCAL(&sin6.sin6_addr))
		sin6.sin6_scope_id = ifindex;

	if (bpc->bpc_has_localif) {
		if (bp_bind_dev(sd, bpc->bpc_localif) != 0) {
			close(sd);
			return -1;
		}
	} else if (bpc->bpc_mhop && bpc->bpc_has_vrfname) {
		if (bp_bind_dev(sd, bpc->bpc_vrfname) != 0) {
			close(sd);
			return -1;
		}
	}

	pcount = 0;
	do {
		if ((++pcount) > (BFD_SRCPORTMAX - BFD_SRCPORTINIT)) {
			/* Searched all ports, none available */
			log_error("ipv6-new: failed to bind port: %s",
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
		log_warning("set-ttlv6: setsockopt(IPV6_UNICAST_HOPS, %d): %s",
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
		log_warning("set-tosv6: setsockopt(IPV6_TCLASS, %d): %s", value,
			    strerror(errno));
		return -1;
	}

	return 0;
}

static void bp_set_ipv6opts(int sd)
{
	int ipv6_pktinfo = BFD_IPV6_PKT_INFO_VAL;
	int ipv6_only = BFD_IPV6_ONLY_VAL;

	if (bp_set_ttlv6(sd, BFD_TTL_VAL) == -1)
		log_fatal("set-ipv6opts: setsockopt(IPV6_UNICAST_HOPS, %d): %s",
			  BFD_TTL_VAL, strerror(errno));

	if (setsockopt_ipv6_hoplimit(sd, BFD_RCV_TTL_VAL) == -1)
		log_fatal("set-ipv6opts: setsockopt(IPV6_HOPLIMIT, %d): %s",
			  BFD_RCV_TTL_VAL, strerror(errno));

	if (setsockopt_ipv6_pktinfo(sd, ipv6_pktinfo) == -1)
		log_fatal("set-ipv6opts: setsockopt(IPV6_PKTINFO, %d): %s",
			  ipv6_pktinfo, strerror(errno));

	if (setsockopt(sd, IPPROTO_IPV6, IPV6_V6ONLY, &ipv6_only,
		       sizeof(ipv6_only))
	    == -1)
		log_fatal("set-ipv6opts: setsockopt(IPV6_V6ONLY, %d): %s",
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
		log_fatal("bind-ipv6: bind: %s", strerror(errno));
}

int bp_udp6_shop(void)
{
	int sd;

	sd = socket(AF_INET6, SOCK_DGRAM, PF_UNSPEC);
	if (sd == -1)
		log_fatal("udp6-shop: socket: %s", strerror(errno));

	bp_set_ipv6opts(sd);
	bp_bind_ipv6(sd, BFD_DEFDESTPORT);

	return sd;
}

int bp_udp6_mhop(void)
{
	int sd;

	sd = socket(AF_INET6, SOCK_DGRAM, PF_UNSPEC);
	if (sd == -1)
		log_fatal("udp6-mhop: socket: %s", strerror(errno));

	bp_set_ipv6opts(sd);
	bp_bind_ipv6(sd, BFD_DEF_MHOP_DEST_PORT);

	return sd;
}

int bp_echo_socket(void)
{
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1)
		log_fatal("echo-socket: socket: %s", strerror(errno));

	bp_set_ipopts(s);
	bp_bind_ip(s, BFD_DEF_ECHO_PORT);

	return s;
}

int bp_echov6_socket(void)
{
	int s;

	s = socket(AF_INET6, SOCK_DGRAM, 0);
	if (s == -1)
		log_fatal("echov6-socket: socket: %s", strerror(errno));

	bp_set_ipv6opts(s);
	bp_bind_ipv6(s, BFD_DEF_ECHO_PORT);

	return s;
}
