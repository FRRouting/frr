/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "log.h"
#include "thread.h"
#include "memory.h"
#include "if.h"

#include "pimd.h"
#include "pim_pim.h"
#include "pim_time.h"
#include "pim_iface.h"
#include "pim_sock.h"
#include "pim_str.h"
#include "pim_util.h"
#include "pim_tlv.h"
#include "pim_neighbor.h"
#include "pim_hello.h"
#include "pim_join.h"
#include "pim_assert.h"
#include "pim_msg.h"
#include "pim_register.h"

static int on_pim_hello_send(struct thread *t);
static int pim_hello_send(struct interface *ifp, uint16_t holdtime);

static const char *pim_pim_msgtype2str(enum pim_msg_type type)
{
	switch (type) {
	case PIM_MSG_TYPE_HELLO:
		return "HELLO";
	case PIM_MSG_TYPE_REGISTER:
		return "REGISTER";
	case PIM_MSG_TYPE_REG_STOP:
		return "REGSTOP";
	case PIM_MSG_TYPE_JOIN_PRUNE:
		return "JOINPRUNE";
	case PIM_MSG_TYPE_BOOTSTRAP:
		return "BOOT";
	case PIM_MSG_TYPE_ASSERT:
		return "ASSERT";
	case PIM_MSG_TYPE_GRAFT:
		return "GRAFT";
	case PIM_MSG_TYPE_GRAFT_ACK:
		return "GACK";
	case PIM_MSG_TYPE_CANDIDATE:
		return "CANDIDATE";
	}

	return "UNKNOWN";
}

static void sock_close(struct interface *ifp)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (PIM_DEBUG_PIM_TRACE) {
		if (pim_ifp->t_pim_sock_read) {
			zlog_debug(
				"Cancelling READ event for PIM socket fd=%d on interface %s",
				pim_ifp->pim_sock_fd, ifp->name);
		}
	}
	THREAD_OFF(pim_ifp->t_pim_sock_read);

	if (PIM_DEBUG_PIM_TRACE) {
		if (pim_ifp->t_pim_hello_timer) {
			zlog_debug(
				"Cancelling PIM hello timer for interface %s",
				ifp->name);
		}
	}
	THREAD_OFF(pim_ifp->t_pim_hello_timer);

	if (PIM_DEBUG_PIM_TRACE) {
		zlog_debug("Deleting PIM socket fd=%d on interface %s",
			   pim_ifp->pim_sock_fd, ifp->name);
	}

	/*
	 * If the fd is already deleted no need to do anything here
	 */
	if (pim_ifp->pim_sock_fd > 0 && close(pim_ifp->pim_sock_fd)) {
		zlog_warn(
			"Failure closing PIM socket fd=%d on interface %s: errno=%d: %s",
			pim_ifp->pim_sock_fd, ifp->name, errno,
			safe_strerror(errno));
	}

	pim_ifp->pim_sock_fd = -1;
	pim_ifp->pim_sock_creation = 0;
}

void pim_sock_delete(struct interface *ifp, const char *delete_message)
{
	zlog_info("PIM INTERFACE DOWN: on interface %s: %s", ifp->name,
		  delete_message);

	if (!ifp->info) {
		zlog_err("%s: %s: but PIM not enabled on interface %s (!)",
			 __PRETTY_FUNCTION__, delete_message, ifp->name);
		return;
	}

	/*
	  RFC 4601: 4.3.1.  Sending Hello Messages

	  Before an interface goes down or changes primary IP address, a Hello
	  message with a zero HoldTime should be sent immediately (with the
	  old IP address if the IP address changed).
	*/
	pim_hello_send(ifp, 0 /* zero-sec holdtime */);

	pim_neighbor_delete_all(ifp, delete_message);

	sock_close(ifp);
}

int pim_pim_packet(struct interface *ifp, uint8_t *buf, size_t len)
{
	struct ip *ip_hdr;
	size_t ip_hlen; /* ip header length in bytes */
	char src_str[INET_ADDRSTRLEN];
	char dst_str[INET_ADDRSTRLEN];
	uint8_t *pim_msg;
	int pim_msg_len;
	uint16_t pim_checksum; /* received checksum */
	uint16_t checksum;     /* computed checksum */
	struct pim_neighbor *neigh;
	struct pim_msg_header *header;

	if (len < sizeof(*ip_hdr)) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"PIM packet size=%zu shorter than minimum=%zu",
				len, sizeof(*ip_hdr));
		return -1;
	}

	ip_hdr = (struct ip *)buf;
	ip_hlen = ip_hdr->ip_hl << 2; /* ip_hl gives length in 4-byte words */

	pim_msg = buf + ip_hlen;
	pim_msg_len = len - ip_hlen;

	header = (struct pim_msg_header *)pim_msg;
	if (pim_msg_len < PIM_PIM_MIN_LEN) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"PIM message size=%d shorter than minimum=%d",
				pim_msg_len, PIM_PIM_MIN_LEN);
		return -1;
	}

	if (header->ver != PIM_PROTO_VERSION) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"Ignoring PIM pkt from %s with unsupported version: %d",
				ifp->name, header->ver);
		return -1;
	}

	/* save received checksum */
	pim_checksum = header->checksum;

	/* for computing checksum */
	header->checksum = 0;

	if (header->type == PIM_MSG_TYPE_REGISTER) {
		/* First 8 byte header checksum */
		checksum = in_cksum(pim_msg, PIM_MSG_REGISTER_LEN);
		if (checksum != pim_checksum) {
			checksum = in_cksum(pim_msg, pim_msg_len);
			if (checksum != pim_checksum) {
				if (PIM_DEBUG_PIM_PACKETS)
					zlog_debug(
						"Ignoring PIM pkt from %s with invalid checksum: received=%x calculated=%x",
						ifp->name, pim_checksum,
						checksum);

				return -1;
			}
		}
	} else {
		checksum = in_cksum(pim_msg, pim_msg_len);
		if (checksum != pim_checksum) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"Ignoring PIM pkt from %s with invalid checksum: received=%x calculated=%x",
					ifp->name, pim_checksum, checksum);

			return -1;
		}
	}

	if (PIM_DEBUG_PIM_PACKETS) {
		pim_inet4_dump("<src?>", ip_hdr->ip_src, src_str,
			       sizeof(src_str));
		pim_inet4_dump("<dst?>", ip_hdr->ip_dst, dst_str,
			       sizeof(dst_str));
		zlog_debug(
			"Recv PIM %s packet from %s to %s on %s: ttl=%d pim_version=%d pim_msg_size=%d checksum=%x",
			pim_pim_msgtype2str(header->type), src_str, dst_str,
			ifp->name, ip_hdr->ip_ttl, header->ver, pim_msg_len,
			checksum);
		if (PIM_DEBUG_PIM_PACKETDUMP_RECV) {
			pim_pkt_dump(__PRETTY_FUNCTION__, pim_msg, pim_msg_len);
		}
	}

	switch (header->type) {
	case PIM_MSG_TYPE_HELLO:
		return pim_hello_recv(ifp, ip_hdr->ip_src,
				      pim_msg + PIM_MSG_HEADER_LEN,
				      pim_msg_len - PIM_MSG_HEADER_LEN);
		break;
	case PIM_MSG_TYPE_REGISTER:
		return pim_register_recv(ifp, ip_hdr->ip_dst, ip_hdr->ip_src,
					 pim_msg + PIM_MSG_HEADER_LEN,
					 pim_msg_len - PIM_MSG_HEADER_LEN);
		break;
	case PIM_MSG_TYPE_REG_STOP:
		return pim_register_stop_recv(ifp, pim_msg + PIM_MSG_HEADER_LEN,
					      pim_msg_len - PIM_MSG_HEADER_LEN);
		break;
	case PIM_MSG_TYPE_JOIN_PRUNE:
		neigh = pim_neighbor_find(ifp, ip_hdr->ip_src);
		if (!neigh) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s %s: non-hello PIM message type=%d from non-neighbor %s on %s",
					__FILE__, __PRETTY_FUNCTION__,
					header->type, src_str, ifp->name);
			return -1;
		}
		pim_neighbor_timer_reset(neigh, neigh->holdtime);
		return pim_joinprune_recv(ifp, neigh, ip_hdr->ip_src,
					  pim_msg + PIM_MSG_HEADER_LEN,
					  pim_msg_len - PIM_MSG_HEADER_LEN);
		break;
	case PIM_MSG_TYPE_ASSERT:
		neigh = pim_neighbor_find(ifp, ip_hdr->ip_src);
		if (!neigh) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s %s: non-hello PIM message type=%d from non-neighbor %s on %s",
					__FILE__, __PRETTY_FUNCTION__,
					header->type, src_str, ifp->name);
			return -1;
		}
		pim_neighbor_timer_reset(neigh, neigh->holdtime);
		return pim_assert_recv(ifp, neigh, ip_hdr->ip_src,
				       pim_msg + PIM_MSG_HEADER_LEN,
				       pim_msg_len - PIM_MSG_HEADER_LEN);
		break;
	default:
		if (PIM_DEBUG_PIM_PACKETS) {
			zlog_debug(
				"Recv PIM packet type %d which is not currently understood",
				header->type);
		}
		return -1;
	}
	return -1;
}

static void pim_sock_read_on(struct interface *ifp);

static int pim_sock_read(struct thread *t)
{
	struct interface *ifp, *orig_ifp;
	struct pim_interface *pim_ifp;
	int fd;
	struct sockaddr_in from;
	struct sockaddr_in to;
	socklen_t fromlen = sizeof(from);
	socklen_t tolen = sizeof(to);
	uint8_t buf[PIM_PIM_BUFSIZE_READ];
	int len;
	ifindex_t ifindex = -1;
	int result = -1; /* defaults to bad */
	static long long count = 0;
	int cont = 1;

	orig_ifp = ifp = THREAD_ARG(t);
	fd = THREAD_FD(t);

	pim_ifp = ifp->info;

	while (cont) {
		len = pim_socket_recvfromto(fd, buf, sizeof(buf), &from,
					    &fromlen, &to, &tolen, &ifindex);
		if (len < 0) {
			if (errno == EINTR)
				continue;
			if (errno == EWOULDBLOCK || errno == EAGAIN)
				break;

			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug("Received errno: %d %s", errno,
					   safe_strerror(errno));
			goto done;
		}

		/*
		 * What?  So with vrf's the incoming packet is received
		 * on the vrf interface but recvfromto above returns
		 * the right ifindex, so just use it.  We know
		 * it's the right interface because we bind to it
		 */
		ifp = if_lookup_by_index(ifindex, pim_ifp->pim->vrf_id);
		if (!ifp || !ifp->info) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug(
					"%s: Received incoming pim packet on interface not yet configured for pim",
					__PRETTY_FUNCTION__);
			goto done;
		}
		int fail = pim_pim_packet(ifp, buf, len);
		if (fail) {
			if (PIM_DEBUG_PIM_PACKETS)
				zlog_debug("%s: pim_pim_packet() return=%d",
					   __PRETTY_FUNCTION__, fail);
			goto done;
		}

		count++;
		if (count % qpim_packet_process == 0)
			cont = 0;
	}

	result = 0; /* good */

done:
	pim_sock_read_on(orig_ifp);

	if (result) {
		++pim_ifp->pim_ifstat_hello_recvfail;
	}

	return result;
}

static void pim_sock_read_on(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	zassert(ifp);
	zassert(ifp->info);

	pim_ifp = ifp->info;

	if (PIM_DEBUG_PIM_TRACE_DETAIL) {
		zlog_debug("Scheduling READ event on PIM socket fd=%d",
			   pim_ifp->pim_sock_fd);
	}
	pim_ifp->t_pim_sock_read = NULL;
	thread_add_read(master, pim_sock_read, ifp, pim_ifp->pim_sock_fd,
			&pim_ifp->t_pim_sock_read);
}

static int pim_sock_open(struct interface *ifp)
{
	int fd;
	struct pim_interface *pim_ifp = ifp->info;

	fd = pim_socket_mcast(IPPROTO_PIM, pim_ifp->primary_address, ifp,
			      0 /* loop=false */);
	if (fd < 0)
		return -1;

	if (pim_socket_join(fd, qpim_all_pim_routers_addr,
			    pim_ifp->primary_address, ifp->ifindex)) {
		close(fd);
		return -2;
	}

	return fd;
}

void pim_ifstat_reset(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	zassert(ifp);

	pim_ifp = ifp->info;
	if (!pim_ifp) {
		return;
	}

	pim_ifp->pim_ifstat_start = pim_time_monotonic_sec();
	pim_ifp->pim_ifstat_hello_sent = 0;
	pim_ifp->pim_ifstat_hello_sendfail = 0;
	pim_ifp->pim_ifstat_hello_recv = 0;
	pim_ifp->pim_ifstat_hello_recvfail = 0;
}

void pim_sock_reset(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	zassert(ifp);
	zassert(ifp->info);

	pim_ifp = ifp->info;

	pim_ifp->primary_address = pim_find_primary_addr(ifp);

	pim_ifp->pim_sock_fd = -1;
	pim_ifp->pim_sock_creation = 0;
	pim_ifp->t_pim_sock_read = NULL;

	pim_ifp->t_pim_hello_timer = NULL;
	pim_ifp->pim_hello_period = PIM_DEFAULT_HELLO_PERIOD;
	pim_ifp->pim_default_holdtime =
		-1; /* unset: means 3.5 * pim_hello_period */
	pim_ifp->pim_triggered_hello_delay = PIM_DEFAULT_TRIGGERED_HELLO_DELAY;
	pim_ifp->pim_dr_priority = PIM_DEFAULT_DR_PRIORITY;
	pim_ifp->pim_propagation_delay_msec =
		PIM_DEFAULT_PROPAGATION_DELAY_MSEC;
	pim_ifp->pim_override_interval_msec =
		PIM_DEFAULT_OVERRIDE_INTERVAL_MSEC;
	if (PIM_DEFAULT_CAN_DISABLE_JOIN_SUPPRESSION) {
		PIM_IF_DO_PIM_CAN_DISABLE_JOIN_SUPRESSION(pim_ifp->options);
	} else {
		PIM_IF_DONT_PIM_CAN_DISABLE_JOIN_SUPRESSION(pim_ifp->options);
	}

	/* neighbors without lan_delay */
	pim_ifp->pim_number_of_nonlandelay_neighbors = 0;
	pim_ifp->pim_neighbors_highest_propagation_delay_msec = 0;
	pim_ifp->pim_neighbors_highest_override_interval_msec = 0;

	/* DR Election */
	pim_ifp->pim_dr_election_last = 0; /* timestamp */
	pim_ifp->pim_dr_election_count = 0;
	pim_ifp->pim_dr_election_changes = 0;
	pim_ifp->pim_dr_num_nondrpri_neighbors =
		0; /* neighbors without dr_pri */
	pim_ifp->pim_dr_addr = pim_ifp->primary_address;

	pim_ifstat_reset(ifp);
}

static uint16_t ip_id = 0;


static int pim_msg_send_frame(int fd, char *buf, size_t len,
			      struct sockaddr *dst, size_t salen)
{
	struct ip *ip = (struct ip *)buf;

	while (sendto(fd, buf, len, MSG_DONTWAIT, dst, salen) < 0) {
		char dst_str[INET_ADDRSTRLEN];

		switch (errno) {
		case EMSGSIZE: {
			size_t hdrsize = sizeof(struct ip);
			size_t newlen1 = ((len - hdrsize) / 2) & 0xFFF8;
			size_t sendlen = newlen1 + hdrsize;
			size_t offset = ntohs(ip->ip_off);

			ip->ip_len = htons(sendlen);
			ip->ip_off = htons(offset | IP_MF);
			if (pim_msg_send_frame(fd, buf, sendlen, dst, salen)
			    == 0) {
				struct ip *ip2 = (struct ip *)(buf + newlen1);
				size_t newlen2 = len - sendlen;
				sendlen = newlen2 + hdrsize;

				memcpy(ip2, ip, hdrsize);
				ip2->ip_len = htons(sendlen);
				ip2->ip_off = htons(offset + (newlen1 >> 3));
				return pim_msg_send_frame(fd, (char *)ip2,
							  sendlen, dst, salen);
			}
		}

			return -1;
			break;
		default:
			if (PIM_DEBUG_PIM_PACKETS) {
				pim_inet4_dump("<dst?>", ip->ip_dst, dst_str,
					       sizeof(dst_str));
				zlog_warn(
					"%s: sendto() failure to %s: fd=%d msg_size=%zd: errno=%d: %s",
					__PRETTY_FUNCTION__, dst_str, fd, len,
					errno, safe_strerror(errno));
			}
			return -1;
			break;
		}
	}

	return 0;
}

int pim_msg_send(int fd, struct in_addr src, struct in_addr dst,
		 uint8_t *pim_msg, int pim_msg_size, const char *ifname)
{
	struct sockaddr_in to;
	socklen_t tolen;
	unsigned char buffer[10000];
	unsigned char *msg_start;
	uint8_t ttl;
	struct pim_msg_header *header;
	struct ip *ip;

	memset(buffer, 0, 10000);
	int sendlen = sizeof(struct ip) + pim_msg_size;

	msg_start = buffer + sizeof(struct ip);
	memcpy(msg_start, pim_msg, pim_msg_size);

	header = (struct pim_msg_header *)pim_msg;
/*
 * Omnios apparently doesn't have a #define for IP default
 * ttl that is the same as all other platforms.
 */
#ifndef IPDEFTTL
#define IPDEFTTL   64
#endif
	/* TTL for packets destine to ALL-PIM-ROUTERS is 1 */
	switch (header->type) {
	case PIM_MSG_TYPE_HELLO:
	case PIM_MSG_TYPE_JOIN_PRUNE:
	case PIM_MSG_TYPE_BOOTSTRAP:
	case PIM_MSG_TYPE_ASSERT:
		ttl = 1;
		break;
	case PIM_MSG_TYPE_REGISTER:
	case PIM_MSG_TYPE_REG_STOP:
	case PIM_MSG_TYPE_GRAFT:
	case PIM_MSG_TYPE_GRAFT_ACK:
	case PIM_MSG_TYPE_CANDIDATE:
		ttl = IPDEFTTL;
		break;
	default:
		ttl = MAXTTL;
		break;
	}

	ip = (struct ip *)buffer;
	ip->ip_id = htons(++ip_id);
	ip->ip_hl = 5;
	ip->ip_v = 4;
	ip->ip_p = PIM_IP_PROTO_PIM;
	ip->ip_src = src;
	ip->ip_dst = dst;
	ip->ip_ttl = ttl;
	ip->ip_len = htons(sendlen);

	if (PIM_DEBUG_PIM_PACKETS) {
		struct pim_msg_header *header =
			(struct pim_msg_header *)pim_msg;
		char dst_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", dst, dst_str, sizeof(dst_str));
		zlog_debug("%s: to %s on %s: msg_size=%d checksum=%x",
			   __PRETTY_FUNCTION__, dst_str, ifname, pim_msg_size,
			   header->checksum);
	}

	memset(&to, 0, sizeof(to));
	to.sin_family = AF_INET;
	to.sin_addr = dst;
	tolen = sizeof(to);

	if (PIM_DEBUG_PIM_PACKETDUMP_SEND) {
		pim_pkt_dump(__PRETTY_FUNCTION__, pim_msg, pim_msg_size);
	}

	pim_msg_send_frame(fd, (char *)buffer, sendlen, (struct sockaddr *)&to,
			   tolen);
	return 0;
}

static int hello_send(struct interface *ifp, uint16_t holdtime)
{
	uint8_t pim_msg[PIM_PIM_BUFSIZE_WRITE];
	struct pim_interface *pim_ifp;
	int pim_tlv_size;
	int pim_msg_size;

	pim_ifp = ifp->info;

	if (PIM_DEBUG_PIM_HELLO) {
		char dst_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<dst?>", qpim_all_pim_routers_addr, dst_str,
			       sizeof(dst_str));
		zlog_debug(
			"%s: to %s on %s: holdt=%u prop_d=%u overr_i=%u dis_join_supp=%d dr_prio=%u gen_id=%08x addrs=%d",
			__PRETTY_FUNCTION__, dst_str, ifp->name, holdtime,
			pim_ifp->pim_propagation_delay_msec,
			pim_ifp->pim_override_interval_msec,
			PIM_IF_TEST_PIM_CAN_DISABLE_JOIN_SUPRESSION(
				pim_ifp->options),
			pim_ifp->pim_dr_priority, pim_ifp->pim_generation_id,
			listcount(ifp->connected));
	}

	pim_tlv_size = pim_hello_build_tlv(
		ifp, pim_msg + PIM_PIM_MIN_LEN,
		sizeof(pim_msg) - PIM_PIM_MIN_LEN, holdtime,
		pim_ifp->pim_dr_priority, pim_ifp->pim_generation_id,
		pim_ifp->pim_propagation_delay_msec,
		pim_ifp->pim_override_interval_msec,
		PIM_IF_TEST_PIM_CAN_DISABLE_JOIN_SUPRESSION(pim_ifp->options));
	if (pim_tlv_size < 0) {
		return -1;
	}

	pim_msg_size = pim_tlv_size + PIM_PIM_MIN_LEN;

	zassert(pim_msg_size >= PIM_PIM_MIN_LEN);
	zassert(pim_msg_size <= PIM_PIM_BUFSIZE_WRITE);

	pim_msg_build_header(pim_msg, pim_msg_size, PIM_MSG_TYPE_HELLO);

	if (pim_msg_send(pim_ifp->pim_sock_fd, pim_ifp->primary_address,
			 qpim_all_pim_routers_addr, pim_msg, pim_msg_size,
			 ifp->name)) {
		if (PIM_DEBUG_PIM_HELLO) {
			zlog_debug(
				"%s: could not send PIM message on interface %s",
				__PRETTY_FUNCTION__, ifp->name);
		}
		return -2;
	}

	return 0;
}

static int pim_hello_send(struct interface *ifp, uint16_t holdtime)
{
	struct pim_interface *pim_ifp = ifp->info;

	if (pim_if_is_loopback(ifp))
		return 0;

	if (hello_send(ifp, holdtime)) {
		++pim_ifp->pim_ifstat_hello_sendfail;

		if (PIM_DEBUG_PIM_HELLO) {
			zlog_warn("Could not send PIM hello on interface %s",
				  ifp->name);
		}
		return -1;
	}

	++pim_ifp->pim_ifstat_hello_sent;

	return 0;
}

static void hello_resched(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;

	if (PIM_DEBUG_PIM_HELLO) {
		zlog_debug("Rescheduling %d sec hello on interface %s",
			   pim_ifp->pim_hello_period, ifp->name);
	}
	THREAD_OFF(pim_ifp->t_pim_hello_timer);
	thread_add_timer(master, on_pim_hello_send, ifp,
			 pim_ifp->pim_hello_period,
			 &pim_ifp->t_pim_hello_timer);
}

/*
  Periodic hello timer
 */
static int on_pim_hello_send(struct thread *t)
{
	struct pim_interface *pim_ifp;
	struct interface *ifp;

	ifp = THREAD_ARG(t);
	pim_ifp = ifp->info;

	/*
	 * Schedule next hello
	 */
	hello_resched(ifp);

	/*
	 * Send hello
	 */
	return pim_hello_send(ifp, PIM_IF_DEFAULT_HOLDTIME(pim_ifp));
}

/*
  RFC 4601: 4.3.1.  Sending Hello Messages

  Thus, if a router needs to send a Join/Prune or Assert message on an
  interface on which it has not yet sent a Hello message with the
  currently configured IP address, then it MUST immediately send the
  relevant Hello message without waiting for the Hello Timer to
  expire, followed by the Join/Prune or Assert message.
 */
void pim_hello_restart_now(struct interface *ifp)
{
	struct pim_interface *pim_ifp;

	pim_ifp = ifp->info;

	/*
	 * Reset next hello timer
	 */
	hello_resched(ifp);

	/*
	 * Immediately send hello
	 */
	pim_hello_send(ifp, PIM_IF_DEFAULT_HOLDTIME(pim_ifp));
}

/*
  RFC 4601: 4.3.1.  Sending Hello Messages

  To allow new or rebooting routers to learn of PIM neighbors quickly,
  when a Hello message is received from a new neighbor, or a Hello
  message with a new GenID is received from an existing neighbor, a
  new Hello message should be sent on this interface after a
  randomized delay between 0 and Triggered_Hello_Delay.
 */
void pim_hello_restart_triggered(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	int triggered_hello_delay_msec;
	int random_msec;

	pim_ifp = ifp->info;

	/*
	 * No need to ever start loopback or vrf device hello's
	 */
	if (pim_if_is_loopback(ifp))
		return;

	/*
	 * There exists situations where we have the a RPF out this
	 * interface, but we haven't formed a neighbor yet.  This
	 * happens especially during interface flaps.  While
	 * we would like to handle this more gracefully in other
	 * parts of the code.  In order to get us up and running
	 * let's just send the hello immediate'ish
	 * This should be revisited when we get nexthop tracking
	 * in and when we have a better handle on safely
	 * handling the rpf information for upstreams that
	 * we cannot legally reach yet.
	 */
	triggered_hello_delay_msec = 1;
	// triggered_hello_delay_msec = 1000 *
	// pim_ifp->pim_triggered_hello_delay;

	if (pim_ifp->t_pim_hello_timer) {
		long remain_msec =
			pim_time_timer_remain_msec(pim_ifp->t_pim_hello_timer);
		if (remain_msec <= triggered_hello_delay_msec) {
			/* Rescheduling hello would increase the delay, then
			   it's faster
			   to just wait for the scheduled periodic hello. */
			return;
		}

		THREAD_OFF(pim_ifp->t_pim_hello_timer);
	}

	random_msec = triggered_hello_delay_msec;
	// random_msec = random() % (triggered_hello_delay_msec + 1);

	if (PIM_DEBUG_PIM_HELLO) {
		zlog_debug("Scheduling %d msec triggered hello on interface %s",
			   random_msec, ifp->name);
	}

	thread_add_timer_msec(master, on_pim_hello_send, ifp, random_msec,
			      &pim_ifp->t_pim_hello_timer);
}

int pim_sock_add(struct interface *ifp)
{
	struct pim_interface *pim_ifp;
	uint32_t old_genid;

	pim_ifp = ifp->info;
	zassert(pim_ifp);

	if (pim_ifp->pim_sock_fd >= 0) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug(
				"Can't recreate existing PIM socket fd=%d for interface %s",
				pim_ifp->pim_sock_fd, ifp->name);
		return -1;
	}

	pim_ifp->pim_sock_fd = pim_sock_open(ifp);
	if (pim_ifp->pim_sock_fd < 0) {
		if (PIM_DEBUG_PIM_PACKETS)
			zlog_debug("Could not open PIM socket on interface %s",
				   ifp->name);
		return -2;
	}

	pim_socket_ip_hdr(pim_ifp->pim_sock_fd);

	pim_ifp->t_pim_sock_read = NULL;
	pim_ifp->pim_sock_creation = pim_time_monotonic_sec();

	/*
	 * Just ensure that the new generation id
	 * actually chooses something different.
	 * Actually ran across a case where this
	 * happened, pre-switch to random().
	 * While this is unlikely to happen now
	 * let's make sure it doesn't.
	 */
	old_genid = pim_ifp->pim_generation_id;

	while (old_genid == pim_ifp->pim_generation_id)
		pim_ifp->pim_generation_id = random();

	zlog_info("PIM INTERFACE UP: on interface %s ifindex=%d", ifp->name,
		  ifp->ifindex);

	/*
	 * Start receiving PIM messages
	 */
	pim_sock_read_on(ifp);

	/*
	 * Start sending PIM hello's
	 */
	pim_hello_restart_triggered(ifp);

	return 0;
}
