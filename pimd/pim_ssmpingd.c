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

#include "if.h"
#include "log.h"
#include "memory.h"
#include "sockopt.h"
#include "vrf.h"

#include "pimd.h"
#include "pim_ssmpingd.h"
#include "pim_time.h"
#include "pim_sock.h"

static const char *const PIM_SSMPINGD_REPLY_GROUP = "232.43.211.234";

enum { PIM_SSMPINGD_REQUEST = 'Q', PIM_SSMPINGD_REPLY = 'A' };

static void ssmpingd_read_on(struct ssmpingd_sock *ss);

void pim_ssmpingd_init(struct pim_instance *pim)
{
	int result;

	zassert(!pim->ssmpingd_list);

	result = inet_pton(AF_INET, PIM_SSMPINGD_REPLY_GROUP,
			   &pim->ssmpingd_group_addr);

	zassert(result > 0);
}

void pim_ssmpingd_destroy(struct pim_instance *pim)
{
	if (pim->ssmpingd_list)
		list_delete_and_null(&pim->ssmpingd_list);
}

static struct ssmpingd_sock *ssmpingd_find(struct pim_instance *pim,
					   struct in_addr source_addr)
{
	struct listnode *node;
	struct ssmpingd_sock *ss;

	if (!pim->ssmpingd_list)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(pim->ssmpingd_list, node, ss))
		if (source_addr.s_addr == ss->source_addr.s_addr)
			return ss;

	return 0;
}

static void ssmpingd_free(struct ssmpingd_sock *ss)
{
	XFREE(MTYPE_PIM_SSMPINGD, ss);
}

static int ssmpingd_socket(struct in_addr addr, int port, int mttl)
{
	struct sockaddr_in sockaddr;
	int fd;

	fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		zlog_err("%s: could not create socket: errno=%d: %s",
			 __PRETTY_FUNCTION__, errno, safe_strerror(errno));
		return -1;
	}

	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr = addr;
	sockaddr.sin_port = htons(port);

	if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
		char addr_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<addr?>", addr, addr_str, sizeof(addr_str));
		zlog_warn(
			"%s: bind(fd=%d,addr=%s,port=%d,len=%zu) failure: errno=%d: %s",
			__PRETTY_FUNCTION__, fd, addr_str, port,
			sizeof(sockaddr), errno, safe_strerror(errno));
		close(fd);
		return -1;
	}

	/* Needed to obtain destination address from recvmsg() */
	{
#if defined(HAVE_IP_PKTINFO)
		/* Linux and Solaris IP_PKTINFO */
		int opt = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt))) {
			zlog_warn(
				"%s: could not set IP_PKTINFO on socket fd=%d: errno=%d: %s",
				__PRETTY_FUNCTION__, fd, errno,
				safe_strerror(errno));
		}
#elif defined(HAVE_IP_RECVDSTADDR)
		/* BSD IP_RECVDSTADDR */
		int opt = 1;
		if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &opt,
			       sizeof(opt))) {
			zlog_warn(
				"%s: could not set IP_RECVDSTADDR on socket fd=%d: errno=%d: %s",
				__PRETTY_FUNCTION__, fd, errno,
				safe_strerror(errno));
		}
#else
		zlog_err(
			"%s %s: missing IP_PKTINFO and IP_RECVDSTADDR: unable to get dst addr from recvmsg()",
			__FILE__, __PRETTY_FUNCTION__);
		close(fd);
		return -1;
#endif
	}

	{
		int reuse = 1;
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void *)&reuse,
			       sizeof(reuse))) {
			zlog_warn(
				"%s: could not set Reuse Address Option on socket fd=%d: errno=%d: %s",
				__PRETTY_FUNCTION__, fd, errno,
				safe_strerror(errno));
			close(fd);
			return -1;
		}
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&mttl,
		       sizeof(mttl))) {
		zlog_warn(
			"%s: could not set multicast TTL=%d on socket fd=%d: errno=%d: %s",
			__PRETTY_FUNCTION__, mttl, fd, errno,
			safe_strerror(errno));
		close(fd);
		return -1;
	}

	if (setsockopt_ipv4_multicast_loop(fd, 0)) {
		zlog_warn(
			"%s: could not disable Multicast Loopback Option on socket fd=%d: errno=%d: %s",
			__PRETTY_FUNCTION__, fd, errno, safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_LOOP;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (void *)&addr,
		       sizeof(addr))) {
		zlog_warn(
			"%s: could not set Outgoing Interface Option on socket fd=%d: errno=%d: %s",
			__PRETTY_FUNCTION__, fd, errno, safe_strerror(errno));
		close(fd);
		return -1;
	}

	{
		long flags;

		flags = fcntl(fd, F_GETFL, 0);
		if (flags < 0) {
			zlog_warn(
				"%s: could not get fcntl(F_GETFL,O_NONBLOCK) on socket fd=%d: errno=%d: %s",
				__PRETTY_FUNCTION__, fd, errno,
				safe_strerror(errno));
			close(fd);
			return -1;
		}

		if (fcntl(fd, F_SETFL, flags | O_NONBLOCK)) {
			zlog_warn(
				"%s: could not set fcntl(F_SETFL,O_NONBLOCK) on socket fd=%d: errno=%d: %s",
				__PRETTY_FUNCTION__, fd, errno,
				safe_strerror(errno));
			close(fd);
			return -1;
		}
	}

	return fd;
}

static void ssmpingd_delete(struct ssmpingd_sock *ss)
{
	zassert(ss);

	THREAD_OFF(ss->t_sock_read);

	if (close(ss->sock_fd)) {
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", ss->source_addr, source_str,
			       sizeof(source_str));
		zlog_warn(
			"%s: failure closing ssmpingd sock_fd=%d for source %s: errno=%d: %s",
			__PRETTY_FUNCTION__, ss->sock_fd, source_str, errno,
			safe_strerror(errno));
		/* warning only */
	}

	listnode_delete(ss->pim->ssmpingd_list, ss);
	ssmpingd_free(ss);
}

static void ssmpingd_sendto(struct ssmpingd_sock *ss, const uint8_t *buf,
			    int len, struct sockaddr_in to)
{
	socklen_t tolen = sizeof(to);
	int sent;

	sent = sendto(ss->sock_fd, buf, len, MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);
	if (sent != len) {
		char to_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<to?>", to.sin_addr, to_str, sizeof(to_str));
		if (sent < 0) {
			zlog_warn(
				"%s: sendto() failure to %s,%d: fd=%d len=%d: errno=%d: %s",
				__PRETTY_FUNCTION__, to_str, ntohs(to.sin_port),
				ss->sock_fd, len, errno, safe_strerror(errno));
		} else {
			zlog_warn(
				"%s: sendto() partial to %s,%d: fd=%d len=%d: sent=%d",
				__PRETTY_FUNCTION__, to_str, ntohs(to.sin_port),
				ss->sock_fd, len, sent);
		}
	}
}

static int ssmpingd_read_msg(struct ssmpingd_sock *ss)
{
	struct interface *ifp;
	struct sockaddr_in from;
	struct sockaddr_in to;
	socklen_t fromlen = sizeof(from);
	socklen_t tolen = sizeof(to);
	ifindex_t ifindex = -1;
	uint8_t buf[1000];
	int len;

	++ss->requests;

	len = pim_socket_recvfromto(ss->sock_fd, buf, sizeof(buf), &from,
				    &fromlen, &to, &tolen, &ifindex);
	if (len < 0) {
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", ss->source_addr, source_str,
			       sizeof(source_str));
		zlog_warn(
			"%s: failure receiving ssmping for source %s on fd=%d: errno=%d: %s",
			__PRETTY_FUNCTION__, source_str, ss->sock_fd, errno,
			safe_strerror(errno));
		return -1;
	}

	ifp = if_lookup_by_index(ifindex, ss->pim->vrf_id);

	if (buf[0] != PIM_SSMPINGD_REQUEST) {
		char source_str[INET_ADDRSTRLEN];
		char from_str[INET_ADDRSTRLEN];
		char to_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", ss->source_addr, source_str,
			       sizeof(source_str));
		pim_inet4_dump("<from?>", from.sin_addr, from_str,
			       sizeof(from_str));
		pim_inet4_dump("<to?>", to.sin_addr, to_str, sizeof(to_str));
		zlog_warn(
			"%s: bad ssmping type=%d from %s,%d to %s,%d on interface %s ifindex=%d fd=%d src=%s",
			__PRETTY_FUNCTION__, buf[0], from_str,
			ntohs(from.sin_port), to_str, ntohs(to.sin_port),
			ifp ? ifp->name : "<iface?>", ifindex, ss->sock_fd,
			source_str);
		return 0;
	}

	if (PIM_DEBUG_SSMPINGD) {
		char source_str[INET_ADDRSTRLEN];
		char from_str[INET_ADDRSTRLEN];
		char to_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", ss->source_addr, source_str,
			       sizeof(source_str));
		pim_inet4_dump("<from?>", from.sin_addr, from_str,
			       sizeof(from_str));
		pim_inet4_dump("<to?>", to.sin_addr, to_str, sizeof(to_str));
		zlog_debug(
			"%s: recv ssmping from %s,%d to %s,%d on interface %s ifindex=%d fd=%d src=%s",
			__PRETTY_FUNCTION__, from_str, ntohs(from.sin_port),
			to_str, ntohs(to.sin_port),
			ifp ? ifp->name : "<iface?>", ifindex, ss->sock_fd,
			source_str);
	}

	buf[0] = PIM_SSMPINGD_REPLY;

	/* unicast reply */
	ssmpingd_sendto(ss, buf, len, from);

	/* multicast reply */
	from.sin_addr = ss->pim->ssmpingd_group_addr;
	ssmpingd_sendto(ss, buf, len, from);

	return 0;
}

static int ssmpingd_sock_read(struct thread *t)
{
	struct ssmpingd_sock *ss;
	int result;

	ss = THREAD_ARG(t);

	result = ssmpingd_read_msg(ss);

	/* Keep reading */
	ssmpingd_read_on(ss);

	return result;
}

static void ssmpingd_read_on(struct ssmpingd_sock *ss)
{
	thread_add_read(master, ssmpingd_sock_read, ss, ss->sock_fd,
			&ss->t_sock_read);
}

static struct ssmpingd_sock *ssmpingd_new(struct pim_instance *pim,
					  struct in_addr source_addr)
{
	struct ssmpingd_sock *ss;
	int sock_fd;

	if (!pim->ssmpingd_list) {
		pim->ssmpingd_list = list_new();
		if (!pim->ssmpingd_list) {
			zlog_err(
				"%s %s: failure: qpim_ssmpingd_list=list_new()",
				__FILE__, __PRETTY_FUNCTION__);
			return 0;
		}
		pim->ssmpingd_list->del = (void (*)(void *))ssmpingd_free;
	}

	sock_fd =
		ssmpingd_socket(source_addr, /* port: */ 4321, /* mTTL: */ 64);
	if (sock_fd < 0) {
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", source_addr, source_str,
			       sizeof(source_str));
		zlog_warn("%s: ssmpingd_socket() failure for source %s",
			  __PRETTY_FUNCTION__, source_str);
		return 0;
	}

	ss = XCALLOC(MTYPE_PIM_SSMPINGD, sizeof(*ss));
	if (!ss) {
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", source_addr, source_str,
			       sizeof(source_str));
		zlog_err("%s: XCALLOC(%zu) failure for ssmpingd source %s",
			 __PRETTY_FUNCTION__, sizeof(*ss), source_str);
		close(sock_fd);
		return 0;
	}

	ss->pim = pim;
	ss->sock_fd = sock_fd;
	ss->t_sock_read = NULL;
	ss->source_addr = source_addr;
	ss->creation = pim_time_monotonic_sec();
	ss->requests = 0;

	listnode_add(pim->ssmpingd_list, ss);

	ssmpingd_read_on(ss);

	return ss;
}

int pim_ssmpingd_start(struct pim_instance *pim, struct in_addr source_addr)
{
	struct ssmpingd_sock *ss;

	ss = ssmpingd_find(pim, source_addr);
	if (ss) {
		/* silently ignore request to recreate entry */
		return 0;
	}

	{
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", source_addr, source_str,
			       sizeof(source_str));
		zlog_info("%s: starting ssmpingd for source %s",
			  __PRETTY_FUNCTION__, source_str);
	}

	ss = ssmpingd_new(pim, source_addr);
	if (!ss) {
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", source_addr, source_str,
			       sizeof(source_str));
		zlog_warn("%s: ssmpingd_new() failure for source %s",
			  __PRETTY_FUNCTION__, source_str);
		return -1;
	}

	return 0;
}

int pim_ssmpingd_stop(struct pim_instance *pim, struct in_addr source_addr)
{
	struct ssmpingd_sock *ss;

	ss = ssmpingd_find(pim, source_addr);
	if (!ss) {
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", source_addr, source_str,
			       sizeof(source_str));
		zlog_warn("%s: could not find ssmpingd for source %s",
			  __PRETTY_FUNCTION__, source_str);
		return -1;
	}

	{
		char source_str[INET_ADDRSTRLEN];
		pim_inet4_dump("<src?>", source_addr, source_str,
			       sizeof(source_str));
		zlog_info("%s: stopping ssmpingd for source %s",
			  __PRETTY_FUNCTION__, source_str);
	}

	ssmpingd_delete(ss);

	return 0;
}
