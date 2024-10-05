// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include "if.h"
#include "log.h"
#include "memory.h"
#include "sockopt.h"
#include "vrf.h"
#include "lib_errors.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_ssmpingd.h"
#include "pim_time.h"
#include "pim_sock.h"
#include "network.h"

#if PIM_IPV == 4
static const char *const PIM_SSMPINGD_REPLY_GROUP = "232.43.211.234";
#else
static const char *const PIM_SSMPINGD_REPLY_GROUP = "ff3e::4321:1234";
#endif

enum { PIM_SSMPINGD_REQUEST = 'Q', PIM_SSMPINGD_REPLY = 'A' };

static void ssmpingd_read_on(struct ssmpingd_sock *ss);

void pim_ssmpingd_init(struct pim_instance *pim)
{
	int result;

	assert(!pim->ssmpingd_list);

	result = inet_pton(PIM_AF, PIM_SSMPINGD_REPLY_GROUP,
			   &pim->ssmpingd_group_addr);

	assert(result > 0);
}

void pim_ssmpingd_destroy(struct pim_instance *pim)
{
	if (pim->ssmpingd_list)
		list_delete(&pim->ssmpingd_list);
}

static struct ssmpingd_sock *ssmpingd_find(struct pim_instance *pim,
					   pim_addr source_addr)
{
	struct listnode *node;
	struct ssmpingd_sock *ss;

	if (!pim->ssmpingd_list)
		return 0;

	for (ALL_LIST_ELEMENTS_RO(pim->ssmpingd_list, node, ss))
		if (!pim_addr_cmp(source_addr, ss->source_addr))
			return ss;

	return 0;
}

static void ssmpingd_free(struct ssmpingd_sock *ss)
{
	XFREE(MTYPE_PIM_SSMPINGD, ss);
}

#if PIM_IPV == 4
static inline int ssmpingd_setsockopt(int fd, pim_addr addr, int mttl)
{
	/* Needed to obtain destination address from recvmsg() */
#if defined(HAVE_IP_PKTINFO)
	/* Linux and Solaris IP_PKTINFO */
	int opt = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_PKTINFO, &opt, sizeof(opt))) {
		zlog_warn(
			"%s: could not set IP_PKTINFO on socket fd=%d: errno=%d: %s",
			__func__, fd, errno, safe_strerror(errno));
	}
#elif defined(HAVE_IP_RECVDSTADDR)
	/* BSD IP_RECVDSTADDR */
	int opt = 1;
	if (setsockopt(fd, IPPROTO_IP, IP_RECVDSTADDR, &opt, sizeof(opt))) {
		zlog_warn(
			"%s: could not set IP_RECVDSTADDR on socket fd=%d: errno=%d: %s",
			__func__, fd, errno, safe_strerror(errno));
	}
#else
	flog_err(
		EC_LIB_DEVELOPMENT,
		"%s %s: missing IP_PKTINFO and IP_RECVDSTADDR: unable to get dst addr from recvmsg()",
		__FILE__, __func__);
	close(fd);
	return -1;
#endif

	if (setsockopt_ipv4_multicast_loop(fd, 0)) {
		zlog_warn(
			"%s: could not disable Multicast Loopback Option on socket fd=%d: errno=%d: %s",
			__func__, fd, errno, safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_LOOP;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, (void *)&addr,
		       sizeof(addr))) {
		zlog_warn(
			"%s: could not set Outgoing Interface Option on socket fd=%d: errno=%d: %s",
			__func__, fd, errno, safe_strerror(errno));
		close(fd);
		return -1;
	}

	if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, (void *)&mttl,
		       sizeof(mttl))) {
		zlog_warn(
			"%s: could not set multicast TTL=%d on socket fd=%d: errno=%d: %s",
			__func__, mttl, fd, errno, safe_strerror(errno));
		close(fd);
		return -1;
	}

	return 0;
}
#else
static inline int ssmpingd_setsockopt(int fd, pim_addr addr, int mttl)
{
	setsockopt_ipv6_pktinfo(fd, 1);
	setsockopt_ipv6_multicast_hops(fd, mttl);

	if (setsockopt_ipv6_multicast_loop(fd, 0)) {
		zlog_warn(
			"%s: could not disable Multicast Loopback Option on socket fd=%d: errno=%d: %s",
			__func__, fd, errno, safe_strerror(errno));
		close(fd);
		return PIM_SOCK_ERR_LOOP;
	}

	if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, (void *)&addr,
		       sizeof(addr))) {
		zlog_warn(
			"%s: could not set Outgoing Interface Option on socket fd=%d: errno=%d: %s",
			__func__, fd, errno, safe_strerror(errno));
		close(fd);
		return -1;
	}
	return 0;
}
#endif


static int ssmpingd_socket(pim_addr addr, int port, int mttl)
{
	struct sockaddr_storage sockaddr;
	int fd;
	int ret;
	socklen_t len = sizeof(sockaddr);

	fd = socket(PIM_AF, SOCK_DGRAM, IPPROTO_UDP);
	if (fd < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "%s: could not create socket: errno=%d: %s",
			     __func__, errno, safe_strerror(errno));
		return -1;
	}

	pim_socket_getsockname(fd, (struct sockaddr *)&sockaddr, &len);

	if (bind(fd, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
		zlog_warn(
			"%s: bind(fd=%d,addr=%pSUp,port=%d,len=%zu) failure: errno=%d: %s",
			__func__, fd, &sockaddr, port, sizeof(sockaddr), errno,
			safe_strerror(errno));
		close(fd);
		return -1;
	}

	set_nonblocking(fd);
	sockopt_reuseaddr(fd);

	ret = ssmpingd_setsockopt(fd, addr, mttl);
	if (ret) {
		zlog_warn("ssmpingd_setsockopt failed");
		return -1;
	}

	return fd;
}

static void ssmpingd_delete(struct ssmpingd_sock *ss)
{
	assert(ss);

	EVENT_OFF(ss->t_sock_read);

	if (close(ss->sock_fd)) {
		zlog_warn(
			"%s: failure closing ssmpingd sock_fd=%d for source %pPA: errno=%d: %s",
			__func__, ss->sock_fd, &ss->source_addr, errno,
			safe_strerror(errno));
		/* warning only */
	}

	listnode_delete(ss->pim->ssmpingd_list, ss);
	ssmpingd_free(ss);
}

static void ssmpingd_sendto(struct ssmpingd_sock *ss, const uint8_t *buf,
			    int len, struct sockaddr_storage to)
{
	socklen_t tolen = sizeof(to);
	int sent;

	sent = sendto(ss->sock_fd, buf, len, MSG_DONTWAIT,
		      (struct sockaddr *)&to, tolen);
	if (sent != len) {
		if (sent < 0) {
			zlog_warn(
				"%s: sendto() failure to %pSUp,fd=%d len=%d: errno=%d: %s",
				__func__, &to, ss->sock_fd, len, errno,
				safe_strerror(errno));
		} else {
			zlog_warn(
				"%s: sendto() partial to %pSUp, fd=%d len=%d: sent=%d",
				__func__, &to, ss->sock_fd, len, sent);
		}
	}
}

static int ssmpingd_read_msg(struct ssmpingd_sock *ss)
{
	struct interface *ifp;
	struct sockaddr_storage from;
	struct sockaddr_storage to;
	socklen_t fromlen = sizeof(from);
	socklen_t tolen = sizeof(to);
	ifindex_t ifindex = -1;
	uint8_t buf[1000];
	int len;

	++ss->requests;

	len = pim_socket_recvfromto(ss->sock_fd, buf, sizeof(buf), &from,
				    &fromlen, &to, &tolen, &ifindex);

	if (len < 0) {
		zlog_warn(
			"%s: failure receiving ssmping for source %pPA on fd=%d: errno=%d: %s",
			__func__, &ss->source_addr, ss->sock_fd, errno,
			safe_strerror(errno));
		return -1;
	}

	ifp = if_lookup_by_index(ifindex, ss->pim->vrf->vrf_id);

	if (buf[0] != PIM_SSMPINGD_REQUEST) {
		zlog_warn(
			"%s: bad ssmping type=%d from %pSUp to %pSUp on interface %s ifindex=%d fd=%d src=%pPA",
			__func__, buf[0], &from, &to,
			ifp ? ifp->name : "<iface?>", ifindex, ss->sock_fd,
			&ss->source_addr);
		return 0;
	}

	if (PIM_DEBUG_SSMPINGD) {
		zlog_debug(
			"%s: recv ssmping from %pSUp, to %pSUp, on interface %s ifindex=%d fd=%d src=%pPA",
			__func__, &from, &to, ifp ? ifp->name : "<iface?>",
			ifindex, ss->sock_fd, &ss->source_addr);
	}

	buf[0] = PIM_SSMPINGD_REPLY;

	/* unicast reply */
	ssmpingd_sendto(ss, buf, len, from);

	/* multicast reply */
	memcpy(&from, &ss->pim->ssmpingd_group_addr, sizeof(pim_addr));
	ssmpingd_sendto(ss, buf, len, from);

	return 0;
}

static void ssmpingd_sock_read(struct event *t)
{
	struct ssmpingd_sock *ss;

	ss = EVENT_ARG(t);

	ssmpingd_read_msg(ss);

	/* Keep reading */
	ssmpingd_read_on(ss);
}

static void ssmpingd_read_on(struct ssmpingd_sock *ss)
{
	event_add_read(router->master, ssmpingd_sock_read, ss, ss->sock_fd,
		       &ss->t_sock_read);
}

static struct ssmpingd_sock *ssmpingd_new(struct pim_instance *pim,
					  pim_addr source_addr)
{
	struct ssmpingd_sock *ss;
	int sock_fd;

	if (!pim->ssmpingd_list) {
		pim->ssmpingd_list = list_new();
		pim->ssmpingd_list->del = (void (*)(void *))ssmpingd_free;
	}

	sock_fd =
		ssmpingd_socket(source_addr, /* port: */ 4321, /* mTTL: */ 64);
	if (sock_fd < 0) {
		zlog_warn("%s: ssmpingd_socket() failure for source %pPA",
			  __func__, &source_addr);
		return 0;
	}

	ss = XCALLOC(MTYPE_PIM_SSMPINGD, sizeof(*ss));

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

int pim_ssmpingd_start(struct pim_instance *pim, pim_addr source_addr)
{
	struct ssmpingd_sock *ss;

	ss = ssmpingd_find(pim, source_addr);
	if (ss) {
		/* silently ignore request to recreate entry */
		return 0;
	}

	zlog_info("%s: starting ssmpingd for source %pPAs", __func__,
		  &source_addr);

	ss = ssmpingd_new(pim, source_addr);
	if (!ss) {
		zlog_warn("%s: ssmpingd_new() failure for source %pPAs",
			  __func__, &source_addr);
		return -1;
	}

	return 0;
}

int pim_ssmpingd_stop(struct pim_instance *pim, pim_addr source_addr)
{
	struct ssmpingd_sock *ss;

	ss = ssmpingd_find(pim, source_addr);
	if (!ss) {
		zlog_warn("%s: could not find ssmpingd for source %pPAs",
			  __func__, &source_addr);
		return -1;
	}

	zlog_info("%s: stopping ssmpingd for source %pPAs", __func__,
		  &source_addr);

	ssmpingd_delete(ss);

	return 0;
}
