/* Kernel communication using netlink interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#if defined(HANDLE_NETLINK_FUZZING)
#include <stdio.h>
#include <string.h>
#include "libfrr.h"
#endif /* HANDLE_NETLINK_FUZZING */

#ifdef HAVE_NETLINK

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "zebra_memory.h"
#include "rib.h"
#include "thread.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"
#include "lib_errors.h"

//#include "zebra/zserv.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/zebra_errors.h"

#ifndef SO_RCVBUFFORCE
#define SO_RCVBUFFORCE  (33)
#endif

/* Hack for GNU libc version 2. */
#ifndef MSG_TRUNC
#define MSG_TRUNC      0x20
#endif /* MSG_TRUNC */

#ifndef NLMSG_TAIL
#define NLMSG_TAIL(nmsg)                                                       \
	((struct rtattr *)(((uint8_t *)(nmsg))                                 \
			   + NLMSG_ALIGN((nmsg)->nlmsg_len)))
#endif

#ifndef RTA_TAIL
#define RTA_TAIL(rta)                                                          \
	((struct rtattr *)(((uint8_t *)(rta)) + RTA_ALIGN((rta)->rta_len)))
#endif

#ifndef RTNL_FAMILY_IP6MR
#define RTNL_FAMILY_IP6MR 129
#endif

#ifndef RTPROT_MROUTED
#define RTPROT_MROUTED 17
#endif

static const struct message nlmsg_str[] = {{RTM_NEWROUTE, "RTM_NEWROUTE"},
					   {RTM_DELROUTE, "RTM_DELROUTE"},
					   {RTM_GETROUTE, "RTM_GETROUTE"},
					   {RTM_NEWLINK, "RTM_NEWLINK"},
					   {RTM_DELLINK, "RTM_DELLINK"},
					   {RTM_GETLINK, "RTM_GETLINK"},
					   {RTM_NEWADDR, "RTM_NEWADDR"},
					   {RTM_DELADDR, "RTM_DELADDR"},
					   {RTM_GETADDR, "RTM_GETADDR"},
					   {RTM_NEWNEIGH, "RTM_NEWNEIGH"},
					   {RTM_DELNEIGH, "RTM_DELNEIGH"},
					   {RTM_GETNEIGH, "RTM_GETNEIGH"},
					   {RTM_NEWRULE, "RTM_NEWRULE"},
					   {RTM_DELRULE, "RTM_DELRULE"},
					   {RTM_GETRULE, "RTM_GETRULE"},
					   {RTM_NEWNEXTHOP, "RTM_NEWNEXTHOP"},
					   {RTM_DELNEXTHOP, "RTM_DELNEXTHOP"},
					   {RTM_GETNEXTHOP, "RTM_GETNEXTHOP"},
					   {0}};

static const struct message rtproto_str[] = {
	{RTPROT_REDIRECT, "redirect"},
	{RTPROT_KERNEL, "kernel"},
	{RTPROT_BOOT, "boot"},
	{RTPROT_STATIC, "static"},
	{RTPROT_GATED, "GateD"},
	{RTPROT_RA, "router advertisement"},
	{RTPROT_MRT, "MRT"},
	{RTPROT_ZEBRA, "Zebra"},
#ifdef RTPROT_BIRD
	{RTPROT_BIRD, "BIRD"},
#endif /* RTPROT_BIRD */
	{RTPROT_MROUTED, "mroute"},
	{RTPROT_BGP, "BGP"},
	{RTPROT_OSPF, "OSPF"},
	{RTPROT_ISIS, "IS-IS"},
	{RTPROT_RIP, "RIP"},
	{RTPROT_RIPNG, "RIPNG"},
	{RTPROT_ZSTATIC, "static"},
	{0}};

static const struct message family_str[] = {{AF_INET, "ipv4"},
					    {AF_INET6, "ipv6"},
					    {AF_BRIDGE, "bridge"},
					    {RTNL_FAMILY_IPMR, "ipv4MR"},
					    {RTNL_FAMILY_IP6MR, "ipv6MR"},
					    {0}};

static const struct message rttype_str[] = {{RTN_UNSPEC, "none"},
					    {RTN_UNICAST, "unicast"},
					    {RTN_LOCAL, "local"},
					    {RTN_BROADCAST, "broadcast"},
					    {RTN_ANYCAST, "anycast"},
					    {RTN_MULTICAST, "multicast"},
					    {RTN_BLACKHOLE, "blackhole"},
					    {RTN_UNREACHABLE, "unreachable"},
					    {RTN_PROHIBIT, "prohibited"},
					    {RTN_THROW, "throw"},
					    {RTN_NAT, "nat"},
					    {RTN_XRESOLVE, "resolver"},
					    {0}};

extern struct thread_master *master;
extern uint32_t nl_rcvbufsize;

extern struct zebra_privs_t zserv_privs;


int netlink_talk_filter(struct nlmsghdr *h, ns_id_t ns_id, int startup)
{
	/*
	 * This is an error condition that must be handled during
	 * development.
	 *
	 * The netlink_talk_filter function is used for communication
	 * down the netlink_cmd pipe and we are expecting
	 * an ack being received.  So if we get here
	 * then we did not receive the ack and instead
	 * received some other message in an unexpected
	 * way.
	 */
	zlog_debug("%s: ignoring message type 0x%04x(%s) NS %u", __func__,
		   h->nlmsg_type, nl_msg_type_to_str(h->nlmsg_type), ns_id);
	return 0;
}

static int netlink_recvbuf(struct nlsock *nl, uint32_t newsize)
{
	uint32_t oldsize;
	socklen_t newlen = sizeof(newsize);
	socklen_t oldlen = sizeof(oldsize);
	int ret;

	ret = getsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &oldsize, &oldlen);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "Can't get %s receive buffer size: %s", nl->name,
			     safe_strerror(errno));
		return -1;
	}

	/* Try force option (linux >= 2.6.14) and fall back to normal set */
	frr_with_privs(&zserv_privs) {
		ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUFFORCE,
				 &nl_rcvbufsize,
				 sizeof(nl_rcvbufsize));
	}
	if (ret < 0)
		ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF,
				 &nl_rcvbufsize, sizeof(nl_rcvbufsize));
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "Can't set %s receive buffer size: %s", nl->name,
			     safe_strerror(errno));
		return -1;
	}

	ret = getsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &newsize, &newlen);
	if (ret < 0) {
		flog_err_sys(EC_LIB_SOCKET,
			     "Can't get %s receive buffer size: %s", nl->name,
			     safe_strerror(errno));
		return -1;
	}

	zlog_info("Setting netlink socket receive buffer size: %u -> %u",
		  oldsize, newsize);
	return 0;
}

/* Make socket for Linux netlink interface. */
static int netlink_socket(struct nlsock *nl, unsigned long groups,
			  ns_id_t ns_id)
{
	int ret;
	struct sockaddr_nl snl;
	int sock;
	int namelen;

	frr_with_privs(&zserv_privs) {
		sock = ns_socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE, ns_id);
		if (sock < 0) {
			zlog_err("Can't open %s socket: %s", nl->name,
				 safe_strerror(errno));
			return -1;
		}

		memset(&snl, 0, sizeof(snl));
		snl.nl_family = AF_NETLINK;
		snl.nl_groups = groups;

		/* Bind the socket to the netlink structure for anything. */
		ret = bind(sock, (struct sockaddr *)&snl, sizeof(snl));
	}

	if (ret < 0) {
		zlog_err("Can't bind %s socket to group 0x%x: %s", nl->name,
			 snl.nl_groups, safe_strerror(errno));
		close(sock);
		return -1;
	}

	/* multiple netlink sockets will have different nl_pid */
	namelen = sizeof(snl);
	ret = getsockname(sock, (struct sockaddr *)&snl, (socklen_t *)&namelen);
	if (ret < 0 || namelen != sizeof(snl)) {
		flog_err_sys(EC_LIB_SOCKET, "Can't get %s socket name: %s",
			     nl->name, safe_strerror(errno));
		close(sock);
		return -1;
	}

	nl->snl = snl;
	nl->sock = sock;
	return ret;
}

static int netlink_information_fetch(struct nlmsghdr *h, ns_id_t ns_id,
				     int startup)
{
	/*
	 * When we handle new message types here
	 * because we are starting to install them
	 * then lets check the netlink_install_filter
	 * and see if we should add the corresponding
	 * allow through entry there.
	 * Probably not needed to do but please
	 * think about it.
	 */
	switch (h->nlmsg_type) {
	case RTM_NEWROUTE:
		return netlink_route_change(h, ns_id, startup);
	case RTM_DELROUTE:
		return netlink_route_change(h, ns_id, startup);
	case RTM_NEWLINK:
		return netlink_link_change(h, ns_id, startup);
	case RTM_DELLINK:
		return netlink_link_change(h, ns_id, startup);
	case RTM_NEWADDR:
		return netlink_interface_addr(h, ns_id, startup);
	case RTM_DELADDR:
		return netlink_interface_addr(h, ns_id, startup);
	case RTM_NEWNEIGH:
		return netlink_neigh_change(h, ns_id);
	case RTM_DELNEIGH:
		return netlink_neigh_change(h, ns_id);
	case RTM_GETNEIGH:
		/*
		 * Kernel in some situations when it expects
		 * user space to resolve arp entries, we will
		 * receive this notification.  As we don't
		 * need this notification and as that
		 * we don't want to spam the log file with
		 * below messages, just ignore.
		 */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("Received RTM_GETNEIGH, ignoring");
		break;
	case RTM_NEWRULE:
		return netlink_rule_change(h, ns_id, startup);
	case RTM_DELRULE:
		return netlink_rule_change(h, ns_id, startup);
	case RTM_NEWNEXTHOP:
		return netlink_nexthop_change(h, ns_id, startup);
	case RTM_DELNEXTHOP:
		return netlink_nexthop_change(h, ns_id, startup);
	default:
		/*
		 * If we have received this message then
		 * we have made a mistake during development
		 * and we need to write some code to handle
		 * this message type or not ask for
		 * it to be sent up to us
		 */
		flog_err(EC_ZEBRA_UNKNOWN_NLMSG,
			 "Unknown netlink nlmsg_type %s(%d) vrf %u\n",
			 nl_msg_type_to_str(h->nlmsg_type), h->nlmsg_type,
			 ns_id);
		break;
	}
	return 0;
}

#if defined(HANDLE_NETLINK_FUZZING)
/* Using globals here to avoid adding function parameters */

/* Keep distinct filenames for netlink fuzzy collection */
static unsigned int netlink_file_counter = 1;

/* File name to read fuzzed netlink from */
static char netlink_fuzz_file[MAXPATHLEN] = "";

/* Flag for whether to read from file or not */
bool netlink_read;

/**
 * netlink_read_init() - Starts the message parser
 * @fname:      Filename to read.
 */
void netlink_read_init(const char *fname)
{
	struct zebra_dplane_info dp_info;

	snprintf(netlink_fuzz_file, MAXPATHLEN, "%s", fname);
	/* Creating this fake socket for testing purposes */
	struct zebra_ns *zns = zebra_ns_lookup(NS_DEFAULT);

	/* Capture key info from zns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	netlink_parse_info(netlink_information_fetch, &zns->netlink,
			   &dp_info, 1, 0);
}

/**
 * netlink_write_incoming() - Writes all data received from netlink to a file
 * @buf:        Data from netlink.
 * @size:       Size of data.
 * @counter:    Counter for keeping filenames distinct.
 */
static void netlink_write_incoming(const char *buf, const unsigned int size,
				   unsigned int counter)
{
	char fname[MAXPATHLEN];
	FILE *f;

	snprintf(fname, MAXPATHLEN, "%s/%s_%u", frr_vtydir, "netlink", counter);
	frr_with_privs(&zserv_privs) {
		f = fopen(fname, "w");
	}
	if (f) {
		fwrite(buf, 1, size, f);
		fclose(f);
	}
}

/**
 * netlink_read_file() - Reads netlink data from file
 * @buf:        Netlink buffer being overwritten.
 * @fname:      File name to read from.
 *
 * Return:      Size of file.
 */
static long netlink_read_file(char *buf, const char *fname)
{
	FILE *f;
	long file_bytes = -1;

	frr_with_privs(&zserv_privs) {
		f = fopen(fname, "r");
	}
	if (f) {
		fseek(f, 0, SEEK_END);
		file_bytes = ftell(f);
		rewind(f);
		fread(buf, NL_RCV_PKT_BUF_SIZE, 1, f);
		fclose(f);
	}
	return file_bytes;
}

#endif /* HANDLE_NETLINK_FUZZING */

static int kernel_read(struct thread *thread)
{
	struct zebra_ns *zns = (struct zebra_ns *)THREAD_ARG(thread);
	struct zebra_dplane_info dp_info;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	netlink_parse_info(netlink_information_fetch, &zns->netlink, &dp_info,
			   5, 0);
	zns->t_netlink = NULL;
	thread_add_read(zrouter.master, kernel_read, zns, zns->netlink.sock,
			&zns->t_netlink);

	return 0;
}

/*
 * Filter out messages from self that occur on listener socket,
 * caused by our actions on the command socket(s)
 *
 * When we add new Netlink message types we probably
 * do not need to add them here as that we are filtering
 * on the routes we actually care to receive( which is rarer
 * then the normal course of operations).  We are intentionally
 * allowing some messages from ourselves through
 * ( I'm looking at you Interface based netlink messages )
 * so that we only had to write one way to handle incoming
 * address add/delete changes.
 */
static void netlink_install_filter(int sock, __u32 pid, __u32 dplane_pid)
{
	/*
	 * BPF_JUMP instructions and where you jump to are based upon
	 * 0 as being the next statement.  So count from 0.  Writing
	 * this down because every time I look at this I have to
	 * re-remember it.
	 */
	struct sock_filter filter[] = {
		/*
		 * Logic:
		 *   if (nlmsg_pid == pid ||
		 *       nlmsg_pid == dplane_pid) {
		 *       if (the incoming nlmsg_type ==
		 *           RTM_NEWADDR | RTM_DELADDR)
		 *           keep this message
		 *       else
		 *           skip this message
		 *   } else
		 *       keep this netlink message
		 */
		/*
		 * 0: Load the nlmsg_pid into the BPF register
		 */
		BPF_STMT(BPF_LD | BPF_ABS | BPF_W,
			 offsetof(struct nlmsghdr, nlmsg_pid)),
		/*
		 * 1: Compare to pid
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(pid), 1, 0),
		/*
		 * 2: Compare to dplane pid
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(dplane_pid), 0, 4),
		/*
		 * 3: Load the nlmsg_type into BPF register
		 */
		BPF_STMT(BPF_LD | BPF_ABS | BPF_H,
			 offsetof(struct nlmsghdr, nlmsg_type)),
		/*
		 * 4: Compare to RTM_NEWADDR
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(RTM_NEWADDR), 2, 0),
		/*
		 * 5: Compare to RTM_DELADDR
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(RTM_DELADDR), 1, 0),
		/*
		 * 6: This is the end state of we want to skip the
		 *    message
		 */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* 7: This is the end state of we want to keep
		 *     the message
		 */
		BPF_STMT(BPF_RET | BPF_K, 0xffff),
	};

	struct sock_fprog prog = {
		.len = array_size(filter), .filter = filter,
	};

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog))
	    < 0)
		flog_err_sys(EC_LIB_SOCKET, "Can't install socket filter: %s\n",
			     safe_strerror(errno));
}

void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len)
{
	while (RTA_OK(rta, len)) {
		if (rta->rta_type <= max)
			tb[rta->rta_type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

/**
 * netlink_parse_rtattr_nested() - Parses a nested route attribute
 * @tb:         Pointer to array for storing rtattr in.
 * @max:        Max number to store.
 * @rta:        Pointer to rtattr to look for nested items in.
 */
void netlink_parse_rtattr_nested(struct rtattr **tb, int max,
				 struct rtattr *rta)
{
	netlink_parse_rtattr(tb, max, RTA_DATA(rta), RTA_PAYLOAD(rta));
}

bool nl_attr_put(struct nlmsghdr *n, unsigned int maxlen, int type,
		 const void *data, unsigned int alen)
{
	int len;
	struct rtattr *rta;

	len = RTA_LENGTH(alen);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
		return false;

	rta = (struct rtattr *)(((char *)n) + NLMSG_ALIGN(n->nlmsg_len));
	rta->rta_type = type;
	rta->rta_len = len;

	if (data)
		memcpy(RTA_DATA(rta), data, alen);
	else
		assert(alen == 0);

	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return true;
}

bool nl_attr_put16(struct nlmsghdr *n, unsigned int maxlen, int type,
		   uint16_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint16_t));
}

bool nl_attr_put32(struct nlmsghdr *n, unsigned int maxlen, int type,
		   uint32_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint32_t));
}

struct rtattr *nl_attr_nest(struct nlmsghdr *n, unsigned int maxlen, int type)
{
	struct rtattr *nest = NLMSG_TAIL(n);

	if (!nl_attr_put(n, maxlen, type, NULL, 0))
		return NULL;

	nest->rta_type |= NLA_F_NESTED;
	return nest;
}

int nl_attr_nest_end(struct nlmsghdr *n, struct rtattr *nest)
{
	nest->rta_len = (uint8_t *)NLMSG_TAIL(n) - (uint8_t *)nest;
	return n->nlmsg_len;
}

struct rtnexthop *nl_attr_rtnh(struct nlmsghdr *n, unsigned int maxlen)
{
	struct rtnexthop *rtnh = (struct rtnexthop *)NLMSG_TAIL(n);

	if (NLMSG_ALIGN(n->nlmsg_len) + RTNH_ALIGN(sizeof(struct rtnexthop))
	    > maxlen)
		return NULL;

	memset(rtnh, 0, sizeof(struct rtnexthop));
	n->nlmsg_len =
		NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(sizeof(struct rtnexthop));

	return rtnh;
}

void nl_attr_rtnh_end(struct nlmsghdr *n, struct rtnexthop *rtnh)
{
	rtnh->rtnh_len = (uint8_t *)NLMSG_TAIL(n) - (uint8_t *)rtnh;
}

const char *nl_msg_type_to_str(uint16_t msg_type)
{
	return lookup_msg(nlmsg_str, msg_type, "");
}

const char *nl_rtproto_to_str(uint8_t rtproto)
{
	return lookup_msg(rtproto_str, rtproto, "");
}

const char *nl_family_to_str(uint8_t family)
{
	return lookup_msg(family_str, family, "");
}

const char *nl_rttype_to_str(uint8_t rttype)
{
	return lookup_msg(rttype_str, rttype, "");
}

#define NLA_OK(nla, len)                                                       \
	((len) >= (int)sizeof(struct nlattr)                                   \
	 && (nla)->nla_len >= sizeof(struct nlattr)                            \
	 && (nla)->nla_len <= (len))
#define NLA_NEXT(nla, attrlen)                                                 \
	((attrlen) -= NLA_ALIGN((nla)->nla_len),                               \
	 (struct nlattr *)(((char *)(nla)) + NLA_ALIGN((nla)->nla_len)))
#define NLA_LENGTH(len) (NLA_ALIGN(sizeof(struct nlattr)) + (len))
#define NLA_DATA(nla) ((struct nlattr *)(((char *)(nla)) + NLA_LENGTH(0)))

#define ERR_NLA(err, inner_len)                                                \
	((struct nlattr *)(((char *)(err))                                     \
			   + NLMSG_ALIGN(sizeof(struct nlmsgerr))              \
			   + NLMSG_ALIGN((inner_len))))

static void netlink_parse_nlattr(struct nlattr **tb, int max,
				 struct nlattr *nla, int len)
{
	while (NLA_OK(nla, len)) {
		if (nla->nla_type <= max)
			tb[nla->nla_type] = nla;
		nla = NLA_NEXT(nla, len);
	}
}

static void netlink_parse_extended_ack(struct nlmsghdr *h)
{
	struct nlattr *tb[NLMSGERR_ATTR_MAX + 1] = {};
	const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(h);
	const struct nlmsghdr *err_nlh = NULL;
	/* Length not including nlmsghdr */
	uint32_t len = 0;
	/* Inner error netlink message length */
	uint32_t inner_len = 0;
	const char *msg = NULL;
	uint32_t off = 0;

	if (!(h->nlmsg_flags & NLM_F_CAPPED))
		inner_len = (uint32_t)NLMSG_PAYLOAD(&err->msg, 0);

	len = (uint32_t)(NLMSG_PAYLOAD(h, sizeof(struct nlmsgerr)) - inner_len);

	netlink_parse_nlattr(tb, NLMSGERR_ATTR_MAX, ERR_NLA(err, inner_len),
			     len);

	if (tb[NLMSGERR_ATTR_MSG])
		msg = (const char *)NLA_DATA(tb[NLMSGERR_ATTR_MSG]);

	if (tb[NLMSGERR_ATTR_OFFS]) {
		off = *(uint32_t *)NLA_DATA(tb[NLMSGERR_ATTR_OFFS]);

		if (off > h->nlmsg_len) {
			zlog_err("Invalid offset for NLMSGERR_ATTR_OFFS");
		} else if (!(h->nlmsg_flags & NLM_F_CAPPED)) {
			/*
			 * Header of failed message
			 * we are not doing anything currently with it
			 * but noticing it for later.
			 */
			err_nlh = &err->msg;
			zlog_debug("%s: Received %s extended Ack", __func__,
				   nl_msg_type_to_str(err_nlh->nlmsg_type));
		}
	}

	if (msg && *msg != '\0') {
		bool is_err = !!err->error;

		if (is_err)
			zlog_err("Extended Error: %s", msg);
		else
			flog_warn(EC_ZEBRA_NETLINK_EXTENDED_WARNING,
				  "Extended Warning: %s", msg);
	}
}

/*
 * netlink_send_msg - send a netlink message of a certain size.
 *
 * Returns -1 on error. Otherwise, it returns the number of bytes sent.
 */
static int netlink_send_msg(const struct nlsock *nl, void *buf, size_t buflen)
{
	struct sockaddr_nl snl;
	struct iovec iov;
	struct msghdr msg;
	int status, save_errno = 0;

	memset(&snl, 0, sizeof(snl));
	memset(&iov, 0, sizeof(iov));
	memset(&msg, 0, sizeof(msg));

	iov.iov_base = buf;
	iov.iov_len = buflen;
	msg.msg_name = (void *)&snl;
	msg.msg_namelen = sizeof(snl);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	snl.nl_family = AF_NETLINK;

	/* Send message to netlink interface. */
	frr_with_privs(&zserv_privs) {
		status = sendmsg(nl->sock, &msg, 0);
		save_errno = errno;
	}

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND) {
		zlog_debug("%s: >> netlink message dump [sent]", __func__);
		zlog_hexdump(buf, buflen);
	}

	if (status < 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s error: %s", __func__,
			     safe_strerror(save_errno));
		return -1;
	}

	return status;
}

/*
 * netlink_recv_msg - receive a netlink message.
 *
 * Returns -1 on error, 0 if read would block or the number of bytes received.
 */
static int netlink_recv_msg(const struct nlsock *nl, struct msghdr msg,
			    void *buf, size_t buflen)
{
	struct iovec iov;
	int status;

	iov.iov_base = buf;
	iov.iov_len = buflen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
#if defined(HANDLE_NETLINK_FUZZING)
		/* Check if reading and filename is set */
		if (netlink_read && '\0' != netlink_fuzz_file[0]) {
			zlog_debug("Reading netlink fuzz file");
			status = netlink_read_file(buf, netlink_fuzz_file);
			((struct sockaddr_nl *)msg.msg_name)->nl_pid = 0;
		} else {
			status = recvmsg(nl->sock, &msg, 0);
		}
#else
		status = recvmsg(nl->sock, &msg, 0);
#endif /* HANDLE_NETLINK_FUZZING */
	} while (status < 0 && errno == EINTR);

	if (status < 0) {
		if (errno == EWOULDBLOCK || errno == EAGAIN)
			return 0;
		flog_err(EC_ZEBRA_RECVMSG_OVERRUN, "%s recvmsg overrun: %s",
			 nl->name, safe_strerror(errno));
		/*
		 * In this case we are screwed. There is no good way to recover
		 * zebra at this point.
		 */
		exit(-1);
	}

	if (status == 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s EOF", nl->name);
		return -1;
	}

	if (msg.msg_namelen != sizeof(struct sockaddr_nl)) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s sender address length error: length %d", nl->name,
			 msg.msg_namelen);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV) {
		zlog_debug("%s: << netlink message dump [recv]", __func__);
		zlog_hexdump(buf, status);
	}

#if defined(HANDLE_NETLINK_FUZZING)
	if (!netlink_read) {
		zlog_debug("Writing incoming netlink message");
		netlink_write_incoming(buf, status, netlink_file_counter++);
	}
#endif /* HANDLE_NETLINK_FUZZING */

	return status;
}

/*
 * netlink_parse_error - parse a netlink error message
 *
 * Returns 1 if this message is acknowledgement, 0 if this error should be
 * ignored, -1 otherwise.
 */
static int netlink_parse_error(const struct nlsock *nl, struct nlmsghdr *h,
			       const struct zebra_dplane_info *zns,
			       bool startup)
{
	struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
	int errnum = err->error;
	int msg_type = err->msg.nlmsg_type;

	if (h->nlmsg_len < NLMSG_LENGTH(sizeof(struct nlmsgerr))) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s error: message truncated", nl->name);
		return -1;
	}

	/*
	 * Parse the extended information before we actually handle it. At this
	 * point in time we do not do anything other than report the issue.
	 */
	if (h->nlmsg_flags & NLM_F_ACK_TLVS)
		netlink_parse_extended_ack(h);

	/* If the error field is zero, then this is an ACK. */
	if (err->error == 0) {
		if (IS_ZEBRA_DEBUG_KERNEL) {
			zlog_debug("%s: %s ACK: type=%s(%u), seq=%u, pid=%u",
				   __func__, nl->name,
				   nl_msg_type_to_str(err->msg.nlmsg_type),
				   err->msg.nlmsg_type, err->msg.nlmsg_seq,
				   err->msg.nlmsg_pid);
		}

		return 1;
	}

	/* Deal with errors that occur because of races in link handling. */
	if (zns->is_cmd
	    && ((msg_type == RTM_DELROUTE
		 && (-errnum == ENODEV || -errnum == ESRCH))
		|| (msg_type == RTM_NEWROUTE
		    && (-errnum == ENETDOWN || -errnum == EEXIST)))) {
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: error: %s type=%s(%u), seq=%u, pid=%u",
				   nl->name, safe_strerror(-errnum),
				   nl_msg_type_to_str(msg_type), msg_type,
				   err->msg.nlmsg_seq, err->msg.nlmsg_pid);
		return 0;
	}

	/*
	 * We see RTM_DELNEIGH when shutting down an interface with an IPv4
	 * link-local.  The kernel should have already deleted the neighbor so
	 * do not log these as an error.
	 */
	if (msg_type == RTM_DELNEIGH
	    || (zns->is_cmd && msg_type == RTM_NEWROUTE
		&& (-errnum == ESRCH || -errnum == ENETUNREACH))) {
		/*
		 * This is known to happen in some situations, don't log as
		 * error.
		 */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s error: %s, type=%s(%u), seq=%u, pid=%u",
				   nl->name, safe_strerror(-errnum),
				   nl_msg_type_to_str(msg_type), msg_type,
				   err->msg.nlmsg_seq, err->msg.nlmsg_pid);
	} else {
		if ((msg_type != RTM_GETNEXTHOP) || !startup)
			flog_err(EC_ZEBRA_UNEXPECTED_MESSAGE,
				 "%s error: %s, type=%s(%u), seq=%u, pid=%u",
				 nl->name, safe_strerror(-errnum),
				 nl_msg_type_to_str(msg_type), msg_type,
				 err->msg.nlmsg_seq, err->msg.nlmsg_pid);
	}

	return -1;
}

/*
 * netlink_parse_info
 *
 * Receive message from netlink interface and pass those information
 *  to the given function.
 *
 * filter  -> Function to call to read the results
 * nl      -> netlink socket information
 * zns     -> The zebra namespace data
 * count   -> How many we should read in, 0 means as much as possible
 * startup -> Are we reading in under startup conditions? passed to
 *            the filter.
 */
int netlink_parse_info(int (*filter)(struct nlmsghdr *, ns_id_t, int),
		       const struct nlsock *nl,
		       const struct zebra_dplane_info *zns,
		       int count, int startup)
{
	int status;
	int ret = 0;
	int error;
	int read_in = 0;

	while (1) {
		char buf[NL_RCV_PKT_BUF_SIZE];
		struct sockaddr_nl snl;
		struct msghdr msg = {.msg_name = (void *)&snl,
				     .msg_namelen = sizeof(snl)};
		struct nlmsghdr *h;

		if (count && read_in >= count)
			return 0;

		status = netlink_recv_msg(nl, msg, buf, sizeof(buf));
		if (status == -1)
			return -1;
		else if (status == 0)
			break;

		read_in++;
		for (h = (struct nlmsghdr *)buf;
		     (status >= 0 && NLMSG_OK(h, (unsigned int)status));
		     h = NLMSG_NEXT(h, status)) {
			/* Finish of reading. */
			if (h->nlmsg_type == NLMSG_DONE)
				return ret;

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				int err = netlink_parse_error(nl, h, zns,
							      startup);
				if (err == 1) {
					if (!(h->nlmsg_flags & NLM_F_MULTI))
						return 0;
					continue;
				} else
					return err;
			}

			/* OK we got netlink message. */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"netlink_parse_info: %s type %s(%u), len=%d, seq=%u, pid=%u",
					nl->name,
					nl_msg_type_to_str(h->nlmsg_type),
					h->nlmsg_type, h->nlmsg_len,
					h->nlmsg_seq, h->nlmsg_pid);


			/*
			 * Ignore messages that maybe sent from
			 * other actors besides the kernel
			 */
			if (snl.nl_pid != 0) {
				zlog_debug("Ignoring message from pid %u",
					   snl.nl_pid);
				continue;
			}

			error = (*filter)(h, zns->ns_id, startup);
			if (error < 0) {
				zlog_debug("%s filter function error",
					   nl->name);
				ret = error;
			}
		}

		/* After error care. */
		if (msg.msg_flags & MSG_TRUNC) {
			flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
				 "%s error: message truncated", nl->name);
			continue;
		}
		if (status) {
			flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
				 "%s error: data remnant size %d", nl->name,
				 status);
			return -1;
		}
	}
	return ret;
}

/*
 * netlink_talk_info
 *
 * sendmsg() to netlink socket then recvmsg().
 * Calls netlink_parse_info to parse returned data
 *
 * filter   -> The filter to read final results from kernel
 * nlmsghdr -> The data to send to the kernel
 * dp_info -> The dataplane and netlink socket information
 * startup  -> Are we reading in under startup conditions
 *             This is passed through eventually to filter.
 */
int netlink_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
		      struct nlmsghdr *n,
		      const struct zebra_dplane_info *dp_info, int startup)
{
	const struct nlsock *nl;

	nl = &(dp_info->nls);
	n->nlmsg_seq = nl->seq;
	n->nlmsg_pid = nl->snl.nl_pid;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"netlink_talk: %s type %s(%u), len=%d seq=%u flags 0x%x",
			nl->name, nl_msg_type_to_str(n->nlmsg_type),
			n->nlmsg_type, n->nlmsg_len, n->nlmsg_seq,
			n->nlmsg_flags);

	if (netlink_send_msg(nl, n, n->nlmsg_len) < 0)
		return -1;

	/*
	 * Get reply from netlink socket.
	 * The reply should either be an acknowlegement or an error.
	 */
	return netlink_parse_info(filter, nl, dp_info, 0, startup);
}

/*
 * Synchronous version of netlink_talk_info. Converts args to suit the
 * common version, which is suitable for both sync and async use.
 */
int netlink_talk(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
		 struct nlmsghdr *n, struct nlsock *nl, struct zebra_ns *zns,
		 int startup)
{
	struct zebra_dplane_info dp_info;

	/* Increment sequence number before capturing snapshot of ns socket
	 * info.
	 */
	nl->seq++;

	/* Capture info in intermediate info struct */
	zebra_dplane_info_from_zns(&dp_info, zns, (nl == &(zns->netlink_cmd)));

	return netlink_talk_info(filter, n, &dp_info, startup);
}

/* Issue request message to kernel via netlink socket. GET messages
 * are issued through this interface.
 */
int netlink_request(struct nlsock *nl, void *req)
{
	struct nlmsghdr *n = (struct nlmsghdr *)req;

	/* Check netlink socket. */
	if (nl->sock < 0) {
		flog_err_sys(EC_LIB_SOCKET, "%s socket isn't active.",
			     nl->name);
		return -1;
	}

	/* Fill common fields for all requests. */
	n->nlmsg_pid = nl->snl.nl_pid;
	n->nlmsg_seq = ++nl->seq;

	if (netlink_send_msg(nl, req, n->nlmsg_len) < 0)
		return -1;

	return 0;
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void kernel_init(struct zebra_ns *zns)
{
	uint32_t groups;
#if defined SOL_NETLINK
	int one, ret;
#endif

	/*
	 * Initialize netlink sockets
	 *
	 * If RTMGRP_XXX exists use that, but at some point
	 * I think the kernel developers realized that
	 * keeping track of all the different values would
	 * lead to confusion, so we need to convert the
	 * RTNLGRP_XXX to a bit position for ourself
	 */
	groups = RTMGRP_LINK                   |
		RTMGRP_IPV4_ROUTE              |
		RTMGRP_IPV4_IFADDR             |
		RTMGRP_IPV6_ROUTE              |
		RTMGRP_IPV6_IFADDR             |
		RTMGRP_IPV4_MROUTE             |
		RTMGRP_NEIGH                   |
		((uint32_t) 1 << (RTNLGRP_IPV4_RULE - 1)) |
		((uint32_t) 1 << (RTNLGRP_IPV6_RULE - 1)) |
		((uint32_t) 1 << (RTNLGRP_NEXTHOP - 1));

	snprintf(zns->netlink.name, sizeof(zns->netlink.name),
		 "netlink-listen (NS %u)", zns->ns_id);
	zns->netlink.sock = -1;
	if (netlink_socket(&zns->netlink, groups, zns->ns_id) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink.name);
		exit(-1);
	}

	snprintf(zns->netlink_cmd.name, sizeof(zns->netlink_cmd.name),
		 "netlink-cmd (NS %u)", zns->ns_id);
	zns->netlink_cmd.sock = -1;
	if (netlink_socket(&zns->netlink_cmd, 0, zns->ns_id) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink_cmd.name);
		exit(-1);
	}

	snprintf(zns->netlink_dplane.name, sizeof(zns->netlink_dplane.name),
		 "netlink-dp (NS %u)", zns->ns_id);
	zns->netlink_dplane.sock = -1;
	if (netlink_socket(&zns->netlink_dplane, 0, zns->ns_id) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink_dplane.name);
		exit(-1);
	}

	/*
	 * SOL_NETLINK is not available on all platforms yet
	 * apparently.  It's in bits/socket.h which I am not
	 * sure that we want to pull into our build system.
	 */
#if defined SOL_NETLINK
	/*
	 * Let's tell the kernel that we want to receive extended
	 * ACKS over our command socket(s)
	 */
	one = 1;
	ret = setsockopt(zns->netlink_cmd.sock, SOL_NETLINK, NETLINK_EXT_ACK,
			 &one, sizeof(one));

	if (ret < 0)
		zlog_notice("Registration for extended cmd ACK failed : %d %s",
			    errno, safe_strerror(errno));

	one = 1;
	ret = setsockopt(zns->netlink_dplane.sock, SOL_NETLINK, NETLINK_EXT_ACK,
			 &one, sizeof(one));

	if (ret < 0)
		zlog_notice("Registration for extended dp ACK failed : %d %s",
			    errno, safe_strerror(errno));
#endif

	/* Register kernel socket. */
	if (fcntl(zns->netlink.sock, F_SETFL, O_NONBLOCK) < 0)
		flog_err_sys(EC_LIB_SOCKET, "Can't set %s socket flags: %s",
			     zns->netlink.name, safe_strerror(errno));

	if (fcntl(zns->netlink_cmd.sock, F_SETFL, O_NONBLOCK) < 0)
		zlog_err("Can't set %s socket error: %s(%d)",
			 zns->netlink_cmd.name, safe_strerror(errno), errno);

	if (fcntl(zns->netlink_dplane.sock, F_SETFL, O_NONBLOCK) < 0)
		zlog_err("Can't set %s socket error: %s(%d)",
			 zns->netlink_dplane.name, safe_strerror(errno), errno);

	/* Set receive buffer size if it's set from command line */
	if (nl_rcvbufsize)
		netlink_recvbuf(&zns->netlink, nl_rcvbufsize);

	netlink_install_filter(zns->netlink.sock,
			       zns->netlink_cmd.snl.nl_pid,
			       zns->netlink_dplane.snl.nl_pid);

	zns->t_netlink = NULL;

	thread_add_read(zrouter.master, kernel_read, zns,
			zns->netlink.sock, &zns->t_netlink);

	rt_netlink_init();
}

void kernel_terminate(struct zebra_ns *zns, bool complete)
{
	THREAD_READ_OFF(zns->t_netlink);

	if (zns->netlink.sock >= 0) {
		close(zns->netlink.sock);
		zns->netlink.sock = -1;
	}

	if (zns->netlink_cmd.sock >= 0) {
		close(zns->netlink_cmd.sock);
		zns->netlink_cmd.sock = -1;
	}

	/* During zebra shutdown, we need to leave the dataplane socket
	 * around until all work is done.
	 */
	if (complete) {
		if (zns->netlink_dplane.sock >= 0) {
			close(zns->netlink_dplane.sock);
			zns->netlink_dplane.sock = -1;
		}
	}
}
#endif /* HAVE_NETLINK */
