// SPDX-License-Identifier: GPL-2.0-or-later
/* Kernel communication using netlink interface.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>
#include <fcntl.h>

#ifdef HAVE_NETLINK
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/filter.h>

#include "linklist.h"
#include "if.h"
#include "log.h"
#include "prefix.h"
#include "connected.h"
#include "table.h"
#include "memory.h"
#include "rib.h"
#include "frrevent.h"
#include "privs.h"
#include "nexthop.h"
#include "vrf.h"
#include "mpls.h"
#include "lib_errors.h"
#include "hash.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_ns.h"
#include "zebra/zebra_vrf.h"
#include "zebra/rt.h"
#include "zebra/debug.h"
#include "zebra/kernel_netlink.h"
#include "zebra/rt_netlink.h"
#include "zebra/if_netlink.h"
#include "zebra/rule_netlink.h"
#include "zebra/tc_netlink.h"
#include "zebra/netconf_netlink.h"
#include "zebra/zebra_errors.h"
#include "zebra/ge_netlink.h"

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

#define NL_DEFAULT_BATCH_BUFSIZE (16 * NL_PKT_BUF_SIZE)

/*
 * We limit the batch's size to a number smaller than the length of the
 * underlying buffer since the last message that wouldn't fit the batch would go
 * over the upper boundary and then it would have to be encoded again into a new
 * buffer. If the difference between the limit and the length of the buffer is
 * big enough (bigger than the biggest Netlink message) then this situation
 * won't occur.
 */
#define NL_DEFAULT_BATCH_SEND_THRESHOLD (15 * NL_PKT_BUF_SIZE)

static const struct message nlmsg_str[] = {
	{ RTM_NEWROUTE, "RTM_NEWROUTE" },
	{ RTM_DELROUTE, "RTM_DELROUTE" },
	{ RTM_GETROUTE, "RTM_GETROUTE" },
	{ RTM_NEWLINK, "RTM_NEWLINK" },
	{ RTM_SETLINK, "RTM_SETLINK" },
	{ RTM_DELLINK, "RTM_DELLINK" },
	{ RTM_GETLINK, "RTM_GETLINK" },
	{ RTM_NEWADDR, "RTM_NEWADDR" },
	{ RTM_DELADDR, "RTM_DELADDR" },
	{ RTM_GETADDR, "RTM_GETADDR" },
	{ RTM_NEWNEIGH, "RTM_NEWNEIGH" },
	{ RTM_DELNEIGH, "RTM_DELNEIGH" },
	{ RTM_GETNEIGH, "RTM_GETNEIGH" },
	{ RTM_NEWRULE, "RTM_NEWRULE" },
	{ RTM_DELRULE, "RTM_DELRULE" },
	{ RTM_GETRULE, "RTM_GETRULE" },
	{ RTM_NEWNEXTHOP, "RTM_NEWNEXTHOP" },
	{ RTM_DELNEXTHOP, "RTM_DELNEXTHOP" },
	{ RTM_GETNEXTHOP, "RTM_GETNEXTHOP" },
	{ RTM_NEWNETCONF, "RTM_NEWNETCONF" },
	{ RTM_DELNETCONF, "RTM_DELNETCONF" },
	{ RTM_NEWTUNNEL, "RTM_NEWTUNNEL" },
	{ RTM_DELTUNNEL, "RTM_DELTUNNEL" },
	{ RTM_GETTUNNEL, "RTM_GETTUNNEL" },
	{ RTM_NEWQDISC, "RTM_NEWQDISC" },
	{ RTM_DELQDISC, "RTM_DELQDISC" },
	{ RTM_GETQDISC, "RTM_GETQDISC" },
	{ RTM_NEWTCLASS, "RTM_NEWTCLASS" },
	{ RTM_DELTCLASS, "RTM_DELTCLASS" },
	{ RTM_GETTCLASS, "RTM_GETTCLASS" },
	{ RTM_NEWTFILTER, "RTM_NEWTFILTER" },
	{ RTM_DELTFILTER, "RTM_DELTFILTER" },
	{ RTM_GETTFILTER, "RTM_GETTFILTER" },
	{ RTM_NEWVLAN, "RTM_NEWVLAN" },
	{ RTM_DELVLAN, "RTM_DELVLAN" },
	{ RTM_GETVLAN, "RTM_GETVLAN" },
	{ RTM_NEWCHAIN, "RTM_NEWCHAIN" },
	{ RTM_DELCHAIN, "RTM_DELCHAIN" },
	{ RTM_GETCHAIN, "RTM_GETCHAIN" },
	{ 0 }
};

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

extern struct event_loop *master;

extern struct zebra_privs_t zserv_privs;

DEFINE_MTYPE_STATIC(ZEBRA, NL_BUF, "Zebra Netlink buffers");

/* Hashtable and mutex to allow lookup of nlsock structs by socket/fd value.
 * We have both the main and dplane pthreads using these structs, so we have
 * to protect the hash with a lock.
 */
static struct hash *nlsock_hash;
pthread_mutex_t nlsock_mutex;

/* Lock and unlock wrappers for nlsock hash */
#define NLSOCK_LOCK() pthread_mutex_lock(&nlsock_mutex)
#define NLSOCK_UNLOCK() pthread_mutex_unlock(&nlsock_mutex)

size_t nl_batch_tx_bufsize;
char *nl_batch_tx_buf;

_Atomic uint32_t nl_batch_bufsize = NL_DEFAULT_BATCH_BUFSIZE;
_Atomic uint32_t nl_batch_send_threshold = NL_DEFAULT_BATCH_SEND_THRESHOLD;

struct nl_batch {
	void *buf;
	size_t bufsiz;
	size_t limit;

	void *buf_head;
	size_t curlen;
	size_t msgcnt;

	const struct zebra_dplane_info *zns;

	struct dplane_ctx_list_head ctx_list;

	/*
	 * Pointer to the queue of completed contexts outbound back
	 * towards the dataplane module.
	 */
	struct dplane_ctx_list_head *ctx_out_q;
};

int netlink_config_write_helper(struct vty *vty)
{
	uint32_t size =
		atomic_load_explicit(&nl_batch_bufsize, memory_order_relaxed);
	uint32_t threshold = atomic_load_explicit(&nl_batch_send_threshold,
						  memory_order_relaxed);

	if (size != NL_DEFAULT_BATCH_BUFSIZE
	    || threshold != NL_DEFAULT_BATCH_SEND_THRESHOLD)
		vty_out(vty, "zebra kernel netlink batch-tx-buf %u %u\n", size,
			threshold);

	if (if_netlink_frr_protodown_r_bit_is_set())
		vty_out(vty, "zebra protodown reason-bit %u\n",
			if_netlink_get_frr_protodown_r_bit());

	return 0;
}

void netlink_set_batch_buffer_size(uint32_t size, uint32_t threshold, bool set)
{
	if (!set) {
		size = NL_DEFAULT_BATCH_BUFSIZE;
		threshold = NL_DEFAULT_BATCH_SEND_THRESHOLD;
	}

	atomic_store_explicit(&nl_batch_bufsize, size, memory_order_relaxed);
	atomic_store_explicit(&nl_batch_send_threshold, threshold,
			      memory_order_relaxed);
}

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
				 &rcvbufsize, sizeof(rcvbufsize));
	}
	if (ret < 0)
		ret = setsockopt(nl->sock, SOL_SOCKET, SO_RCVBUF, &rcvbufsize,
				 sizeof(rcvbufsize));
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
	return 0;
}

static const char *group2str(uint32_t group)
{
	switch (group) {
	case RTNLGRP_TUNNEL:
		return "RTNLGRP_TUNNEL";
	default:
		return "UNKNOWN";
	}
}

/* Make socket for Linux netlink interface. */
static int netlink_socket(struct nlsock *nl, unsigned long groups,
			  uint32_t ext_groups[], uint8_t ext_group_size,
			  ns_id_t ns_id, int nl_family)
{
	int ret;
	struct sockaddr_nl snl;
	int sock;
	int namelen;

	frr_with_privs(&zserv_privs) {
		sock = ns_socket(AF_NETLINK, SOCK_RAW, nl_family, ns_id);
		if (sock < 0) {
			zlog_err("Can't open %s socket: %s", nl->name,
				 safe_strerror(errno));
			return -1;
		}

		memset(&snl, 0, sizeof(snl));
		snl.nl_family = AF_NETLINK;
		snl.nl_groups = groups;

		if (ext_group_size) {
			uint8_t i;

			for (i = 0; i < ext_group_size; i++) {
#if defined SOL_NETLINK
				ret = setsockopt(sock, SOL_NETLINK,
						 NETLINK_ADD_MEMBERSHIP,
						 &ext_groups[i],
						 sizeof(ext_groups[i]));
				if (ret < 0) {
					zlog_notice(
						"can't setsockopt NETLINK_ADD_MEMBERSHIP for group %s(%u), this linux kernel does not support it: %s(%d)",
						group2str(ext_groups[i]),
						ext_groups[i],
						safe_strerror(errno), errno);
				}
#else
				zlog_notice(
					"Unable to use NETLINK_ADD_MEMBERSHIP via SOL_NETLINK for %s(%u) since the linux kernel does not support the socket option",
					group2str(ext_groups[i]),
					ext_groups[i]);
#endif
			}
		}

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
	nl->buflen = NL_RCV_PKT_BUF_SIZE;
	nl->buf = XMALLOC(MTYPE_NL_BUF, nl->buflen);

	return ret;
}

/*
 * Dispatch an incoming netlink message; used by the zebra main pthread's
 * netlink event reader.
 */
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
	case RTM_NEWNEIGH:
	case RTM_DELNEIGH:
	case RTM_GETNEIGH:
		return netlink_neigh_change(h, ns_id);
	case RTM_NEWRULE:
		return netlink_rule_change(h, ns_id, startup);
	case RTM_DELRULE:
		return netlink_rule_change(h, ns_id, startup);
	case RTM_NEWNEXTHOP:
		return netlink_nexthop_change(h, ns_id, startup);
	case RTM_DELNEXTHOP:
		return netlink_nexthop_change(h, ns_id, startup);
	case RTM_NEWQDISC:
	case RTM_DELQDISC:
		return netlink_qdisc_change(h, ns_id, startup);
	case RTM_NEWTCLASS:
	case RTM_DELTCLASS:
		return netlink_tclass_change(h, ns_id, startup);
	case RTM_NEWTFILTER:
	case RTM_DELTFILTER:
		return netlink_tfilter_change(h, ns_id, startup);

	/* Messages we may receive, but ignore */
	case RTM_NEWCHAIN:
	case RTM_DELCHAIN:
	case RTM_GETCHAIN:
		return 0;

	/* Messages handled in the dplane thread */
	case RTM_NEWLINK:
	case RTM_DELLINK:
	case RTM_NEWADDR:
	case RTM_DELADDR:
	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
	case RTM_NEWTUNNEL:
	case RTM_DELTUNNEL:
	case RTM_GETTUNNEL:
	case RTM_NEWVLAN:
	case RTM_DELVLAN:
		return 0;
	default:
		/*
		 * If we have received this message then
		 * we have made a mistake during development
		 * and we need to write some code to handle
		 * this message type or not ask for
		 * it to be sent up to us
		 */
		flog_err(EC_ZEBRA_UNKNOWN_NLMSG,
			 "Unknown netlink nlmsg_type %s(%d) vrf %u",
			 nl_msg_type_to_str(h->nlmsg_type), h->nlmsg_type,
			 ns_id);
		break;
	}
	return 0;
}

/*
 * Dispatch an incoming netlink message; used by the dataplane pthread's
 * netlink event reader code.
 */
static int dplane_netlink_information_fetch(struct nlmsghdr *h, ns_id_t ns_id,
					    int startup)
{
	/*
	 * Dispatch the incoming messages that the dplane pthread handles
	 */
	switch (h->nlmsg_type) {
	case RTM_NEWADDR:
	case RTM_DELADDR:
		return netlink_interface_addr_dplane(h, ns_id, startup);

	case RTM_NEWNETCONF:
	case RTM_DELNETCONF:
		return netlink_netconf_change(h, ns_id, startup);

	/* TODO -- other messages for the dplane socket and pthread */

	case RTM_NEWLINK:
	case RTM_DELLINK:
		return netlink_link_change(h, ns_id, startup);

	case RTM_NEWVLAN:
	case RTM_DELVLAN:
		return netlink_vlan_change(h, ns_id, startup);

	default:
		break;
	}

	return 0;
}

static void kernel_read(struct event *thread)
{
	struct zebra_ns *zns = (struct zebra_ns *)EVENT_ARG(thread);
	struct zebra_dplane_info dp_info;

	/* Capture key info from ns struct */
	zebra_dplane_info_from_zns(&dp_info, zns, false);

	netlink_parse_info(netlink_information_fetch, &zns->netlink, &dp_info,
			   5, false);

	event_add_read(zrouter.master, kernel_read, zns, zns->netlink.sock,
		       &zns->t_netlink);
}

/*
 * Called by the dplane pthread to read incoming OS messages and dispatch them.
 */
int kernel_dplane_read(struct zebra_dplane_info *info)
{
	struct nlsock *nl = kernel_netlink_nlsock_lookup(info->sock);

	netlink_parse_info(dplane_netlink_information_fetch, nl, info, 5,
			   false);

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
 * so that we only have to write one way to handle incoming
 * address add/delete and xxxNETCONF changes.
 */
static void netlink_install_filter(int sock, uint32_t pid, uint32_t dplane_pid)
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
		 *           RTM_NEWADDR || RTM_DELADDR || RTM_NEWNETCONF ||
		 *           RTM_DELNETCONF)
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
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htonl(dplane_pid), 0, 6),
		/*
		 * 3: Load the nlmsg_type into BPF register
		 */
		BPF_STMT(BPF_LD | BPF_ABS | BPF_H,
			 offsetof(struct nlmsghdr, nlmsg_type)),
		/*
		 * 4: Compare to RTM_NEWADDR
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(RTM_NEWADDR), 4, 0),
		/*
		 * 5: Compare to RTM_DELADDR
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(RTM_DELADDR), 3, 0),
		/*
		 * 6: Compare to RTM_NEWNETCONF
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(RTM_NEWNETCONF), 2,
			 0),
		/*
		 * 7: Compare to RTM_DELNETCONF
		 */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, htons(RTM_DELNETCONF), 1,
			 0),
		/*
		 * 8: This is the end state of we want to skip the
		 *    message
		 */
		BPF_STMT(BPF_RET | BPF_K, 0),
		/* 9: This is the end state of we want to keep
		 *     the message
		 */
		BPF_STMT(BPF_RET | BPF_K, 0xffff),
	};

	struct sock_fprog prog = {
		.len = array_size(filter), .filter = filter,
	};

	if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &prog, sizeof(prog))
	    < 0)
		flog_err_sys(EC_LIB_SOCKET, "Can't install socket filter: %s",
			     safe_strerror(errno));
}

/*
 * Please note, the assumption with this function is that the
 * flags passed in that are bit masked with type, we are implicitly
 * assuming that this is handling the NLA_F_NESTED ilk.
 */
void netlink_parse_rtattr_flags(struct rtattr **tb, int max, struct rtattr *rta,
				int len, unsigned short flags)
{
	unsigned short type;

	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		type = rta->rta_type & ~flags;
		if ((type <= max) && (!tb[type]))
			tb[type] = rta;
		rta = RTA_NEXT(rta, len);
	}
}

void netlink_parse_rtattr(struct rtattr **tb, int max, struct rtattr *rta,
			  int len)
{
	memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
	while (RTA_OK(rta, len)) {
		/*
		 * The type may be &'ed with NLA_F_NESTED
		 * which puts data in the upper 8 bits of the
		 * rta_type.  Mask it off and save the actual
		 * underlying value to be placed into the array.
		 * This way we don't accidently crash in the future
		 * when the kernel sends us new data and we try
		 * to write well beyond the end of the array.
		 */
		uint16_t type = rta->rta_type & NLA_TYPE_MASK;

		if (type <= max)
			tb[type] = rta;
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

bool nl_attr_put8(struct nlmsghdr *n, unsigned int maxlen, int type,
		  uint8_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint8_t));
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

bool nl_attr_put64(struct nlmsghdr *n, unsigned int maxlen, int type,
		   uint64_t data)
{
	return nl_attr_put(n, maxlen, type, &data, sizeof(uint64_t));
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
static ssize_t netlink_send_msg(const struct nlsock *nl, void *buf,
				size_t buflen)
{
	struct sockaddr_nl snl = {};
	struct iovec iov = {};
	struct msghdr msg = {};
	ssize_t status;
	int save_errno = 0;

	iov.iov_base = buf;
	iov.iov_len = buflen;
	msg.msg_name = &snl;
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
#ifdef NETLINK_DEBUG
		nl_dump(buf, buflen);
#else
		zlog_hexdump(buf, buflen);
#endif /* NETLINK_DEBUG */
	}

	if (status == -1) {
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
static int netlink_recv_msg(struct nlsock *nl, struct msghdr *msg)
{
	struct iovec iov;
	int status;

	iov.iov_base = nl->buf;
	iov.iov_len = nl->buflen;
	msg->msg_iov = &iov;
	msg->msg_iovlen = 1;

	do {
		int bytes;

		bytes = recv(nl->sock, NULL, 0, MSG_PEEK | MSG_TRUNC);

		if (bytes >= 0 && (size_t)bytes > nl->buflen) {
			nl->buf = XREALLOC(MTYPE_NL_BUF, nl->buf, bytes);
			nl->buflen = bytes;
			iov.iov_base = nl->buf;
			iov.iov_len = nl->buflen;
		}

		status = recvmsg(nl->sock, msg, 0);
	} while (status == -1 && errno == EINTR);

	if (status == -1) {
		if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EMSGSIZE)
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

	if (msg->msg_namelen != sizeof(struct sockaddr_nl)) {
		flog_err(EC_ZEBRA_NETLINK_LENGTH_ERROR,
			 "%s sender address length error: length %d", nl->name,
			 msg->msg_namelen);
		return -1;
	}

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV) {
		zlog_debug("%s: << netlink message dump [recv]", __func__);
#ifdef NETLINK_DEBUG
		nl_dump(nl->buf, status);
#else
		zlog_hexdump(nl->buf, status);
#endif /* NETLINK_DEBUG */
	}

	return status;
}

/*
 * netlink_parse_error - parse a netlink error message
 *
 * Returns 1 if this message is acknowledgement, 0 if this error should be
 * ignored, -1 otherwise.
 */
static int netlink_parse_error(const struct nlsock *nl, struct nlmsghdr *h,
			       bool is_cmd, bool startup)
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

	/*
	 * Deal with errors that occur because of races in link handling
	 * or types are not supported in kernel.
	 */
	if (is_cmd &&
	    ((msg_type == RTM_DELROUTE &&
	      (-errnum == ENODEV || -errnum == ESRCH)) ||
	     (msg_type == RTM_NEWROUTE &&
	      (-errnum == ENETDOWN || -errnum == EEXIST)) ||
	     ((msg_type == RTM_NEWTUNNEL || msg_type == RTM_DELTUNNEL ||
	       msg_type == RTM_GETTUNNEL) &&
	      (-errnum == EOPNOTSUPP)))) {
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
	    || (is_cmd && msg_type == RTM_NEWROUTE
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
		if ((msg_type != RTM_GETNEXTHOP && msg_type != RTM_GETVLAN) ||
		    !startup)
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
		       struct nlsock *nl, const struct zebra_dplane_info *zns,
		       int count, bool startup)
{
	int status;
	int ret = 0;
	int error;
	int read_in = 0;

	while (1) {
		struct sockaddr_nl snl;
		struct msghdr msg = {.msg_name = (void *)&snl,
				     .msg_namelen = sizeof(snl)};
		struct nlmsghdr *h;

		if (count && read_in >= count)
			return 0;

		status = netlink_recv_msg(nl, &msg);
		if (status == -1)
			return -1;
		else if (status == 0)
			break;

		read_in++;
		for (h = (struct nlmsghdr *)nl->buf;
		     (status >= 0 && NLMSG_OK(h, (unsigned int)status));
		     h = NLMSG_NEXT(h, status)) {
			/* Finish of reading. */
			if (h->nlmsg_type == NLMSG_DONE)
				return ret;

			/* Error handling. */
			if (h->nlmsg_type == NLMSG_ERROR) {
				int err = netlink_parse_error(
					nl, h, zns->is_cmd, startup);

				if (err == 1) {
					if (!(h->nlmsg_flags & NLM_F_MULTI))
						return 0;
					continue;
				} else
					return err;
			}

			/*
			 * What is the right thing to do?  The kernel
			 * is telling us that the dump request was interrupted
			 * and we more than likely are out of luck and have
			 * missed data from the kernel.  At this point in time
			 * lets just note that this is happening.
			 */
			if (h->nlmsg_flags & NLM_F_DUMP_INTR)
				flog_err(
					EC_ZEBRA_NETLINK_BAD_SEQUENCE,
					"netlink recvmsg: The Dump request was interrupted");

			/* OK we got netlink message. */
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"%s: %s type %s(%u), len=%d, seq=%u, pid=%u",
					__func__, nl->name,
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
static int netlink_talk_info(int (*filter)(struct nlmsghdr *, ns_id_t,
					   int startup),
			     struct nlmsghdr *n,
			     struct zebra_dplane_info *dp_info, bool startup)
{
	struct nlsock *nl;

	nl = kernel_netlink_nlsock_lookup(dp_info->sock);
	n->nlmsg_seq = dp_info->seq;
	n->nlmsg_pid = nl->snl.nl_pid;

	if (IS_ZEBRA_DEBUG_KERNEL)
		zlog_debug(
			"netlink_talk: %s type %s(%u), len=%d seq=%u flags 0x%x",
			nl->name, nl_msg_type_to_str(n->nlmsg_type),
			n->nlmsg_type, n->nlmsg_len, n->nlmsg_seq,
			n->nlmsg_flags);

	if (netlink_send_msg(nl, n, n->nlmsg_len) == -1)
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
		 bool startup)
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

/*
 * Synchronous version of netlink_talk_info. Converts args to suit the
 * common version, which is suitable for both sync and async use.
 */
int ge_netlink_talk(int (*filter)(struct nlmsghdr *, ns_id_t, int startup),
		    struct nlmsghdr *n, struct zebra_ns *zns, bool startup)
{
	struct zebra_dplane_info dp_info;

	if (zns->ge_netlink_cmd.sock < 0)
		return -1;

	/* Increment sequence number before capturing snapshot of ns socket
	 * info.
	 */
	zns->ge_netlink_cmd.seq = zebra_router_get_next_sequence();

	/* Capture info in intermediate info struct */
	dp_info.ns_id = zns->ns_id;

	dp_info.is_cmd = true;
	dp_info.sock = zns->ge_netlink_cmd.sock;
	dp_info.seq = zns->ge_netlink_cmd.seq;

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

	if (netlink_send_msg(nl, req, n->nlmsg_len) == -1)
		return -1;

	return 0;
}

static int nl_batch_read_resp(struct nl_batch *bth, struct nlsock *nl)
{
	struct nlmsghdr *h;
	struct sockaddr_nl snl;
	struct msghdr msg = {};
	int status, seq;
	struct zebra_dplane_ctx *ctx;
	bool ignore_msg;

	msg.msg_name = (void *)&snl;
	msg.msg_namelen = sizeof(snl);

	/*
	 * The responses are not batched, so we need to read and process one
	 * message at a time.
	 */
	while (true) {
		status = netlink_recv_msg(nl, &msg);
		/*
		 * status == -1 is a full on failure somewhere
		 * since we don't know where the problem happened
		 * we must mark all as failed
		 *
		 * Else we mark everything as worked
		 *
		 */
		if (status == -1 || status == 0) {
			while ((ctx = dplane_ctx_dequeue(&(bth->ctx_list))) !=
			       NULL) {
				if (status == -1)
					dplane_ctx_set_status(
						ctx,
						ZEBRA_DPLANE_REQUEST_FAILURE);
				dplane_ctx_enqueue_tail(bth->ctx_out_q, ctx);
			}
			return status;
		}

		h = (struct nlmsghdr *)nl->buf;
		ignore_msg = false;
		seq = h->nlmsg_seq;
		/*
		 * Find the corresponding context object. Received responses are
		 * in the same order as requests we sent, so we can simply
		 * iterate over the context list and match responses with
		 * requests at same time.
		 */
		while (true) {
			ctx = dplane_ctx_get_head(&(bth->ctx_list));
			if (ctx == NULL) {
				/*
				 * This is a situation where we have gotten
				 * into a bad spot.  We need to know that
				 * this happens( does it? )
				 */
				zlog_err(
					"%s:WARNING Received netlink Response for an error and no Contexts to associate with it",
					__func__);
				break;
			}

			/*
			 * 'update' context objects take two consecutive
			 * sequence numbers.
			 */
			if (dplane_ctx_is_update(ctx) &&
			    dplane_ctx_get_ns(ctx)->seq + 1 == seq) {
				/*
				 * This is the situation where we get a response
				 * to a message that should be ignored.
				 */
				ignore_msg = true;
				break;
			}

			ctx = dplane_ctx_dequeue(&(bth->ctx_list));
			dplane_ctx_enqueue_tail(bth->ctx_out_q, ctx);

			/* We have found corresponding context object. */
			if (dplane_ctx_get_ns(ctx)->seq == seq)
				break;

			if (dplane_ctx_get_ns(ctx)->seq > seq)
				zlog_warn(
					"%s:WARNING Received %u is less than any context on the queue ctx->seq %u",
					__func__, seq,
					dplane_ctx_get_ns(ctx)->seq);
		}

		if (ignore_msg) {
			/*
			 * If we ignore the message due to an update
			 * above we should still fricking decode the
			 * message for our operator to understand
			 * what is going on
			 */
			int err = netlink_parse_error(nl, h, bth->zns->is_cmd,
						      false);

			zlog_debug("%s: netlink error message seq=%d %d",
				   __func__, h->nlmsg_seq, err);
			continue;
		}

		/*
		 * We received a message with the sequence number that isn't
		 * associated with any dplane context object.
		 */
		if (ctx == NULL) {
			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug(
					"%s: skipping unassociated response, seq number %d NS %u",
					__func__, h->nlmsg_seq,
					bth->zns->ns_id);
			continue;
		}

		if (h->nlmsg_type == NLMSG_ERROR) {
			int err = netlink_parse_error(nl, h, bth->zns->is_cmd,
						      false);

			if (err == -1)
				dplane_ctx_set_status(
					ctx, ZEBRA_DPLANE_REQUEST_FAILURE);

			if (IS_ZEBRA_DEBUG_KERNEL)
				zlog_debug("%s: netlink error message seq=%d ",
					   __func__, h->nlmsg_seq);
			continue;
		}

		/*
		 * If we get here then we did not receive neither the ack nor
		 * the error and instead received some other message in an
		 * unexpected way.
		 */
		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: ignoring message type 0x%04x(%s) NS %u",
				   __func__, h->nlmsg_type,
				   nl_msg_type_to_str(h->nlmsg_type),
				   bth->zns->ns_id);
	}

	return 0;
}

static void nl_batch_reset(struct nl_batch *bth)
{
	bth->buf_head = bth->buf;
	bth->curlen = 0;
	bth->msgcnt = 0;
	bth->zns = NULL;

	dplane_ctx_q_init(&(bth->ctx_list));
}

static void nl_batch_init(struct nl_batch *bth,
			  struct dplane_ctx_list_head *ctx_out_q)
{
	/*
	 * If the size of the buffer has changed, free and then allocate a new
	 * one.
	 */
	size_t bufsize =
		atomic_load_explicit(&nl_batch_bufsize, memory_order_relaxed);
	if (bufsize != nl_batch_tx_bufsize) {
		if (nl_batch_tx_buf)
			XFREE(MTYPE_NL_BUF, nl_batch_tx_buf);

		nl_batch_tx_buf = XCALLOC(MTYPE_NL_BUF, bufsize);
		nl_batch_tx_bufsize = bufsize;
	}

	bth->buf = nl_batch_tx_buf;
	bth->bufsiz = bufsize;
	bth->limit = atomic_load_explicit(&nl_batch_send_threshold,
					  memory_order_relaxed);

	bth->ctx_out_q = ctx_out_q;

	nl_batch_reset(bth);
}

static void nl_batch_send(struct nl_batch *bth)
{
	struct zebra_dplane_ctx *ctx;
	bool err = false;

	if (bth->curlen != 0 && bth->zns != NULL) {
		struct nlsock *nl =
			kernel_netlink_nlsock_lookup(bth->zns->sock);

		if (IS_ZEBRA_DEBUG_KERNEL)
			zlog_debug("%s: %s, batch size=%zu, msg cnt=%zu",
				   __func__, nl->name, bth->curlen,
				   bth->msgcnt);

		if (netlink_send_msg(nl, bth->buf, bth->curlen) == -1)
			err = true;

		if (!err) {
			if (nl_batch_read_resp(bth, nl) == -1)
				err = true;
		}
	}

	/* Move remaining contexts to the outbound queue. */
	while (true) {
		ctx = dplane_ctx_dequeue(&(bth->ctx_list));
		if (ctx == NULL)
			break;

		if (err)
			dplane_ctx_set_status(ctx,
					      ZEBRA_DPLANE_REQUEST_FAILURE);

		dplane_ctx_enqueue_tail(bth->ctx_out_q, ctx);
	}

	nl_batch_reset(bth);
}

enum netlink_msg_status netlink_batch_add_msg(
	struct nl_batch *bth, struct zebra_dplane_ctx *ctx,
	ssize_t (*msg_encoder)(struct zebra_dplane_ctx *, void *, size_t),
	bool ignore_res)
{
	int seq;
	ssize_t size;
	struct nlmsghdr *msgh;
	struct nlsock *nl;

	size = (*msg_encoder)(ctx, bth->buf_head, bth->bufsiz - bth->curlen);

	/*
	 * If there was an error while encoding the message (other than buffer
	 * overflow) then return an error.
	 */
	if (size < 0)
		return FRR_NETLINK_ERROR;

	/*
	 * If the message doesn't fit entirely in the buffer then send the batch
	 * and retry.
	 */
	if (size == 0) {
		nl_batch_send(bth);
		size = (*msg_encoder)(ctx, bth->buf_head,
				      bth->bufsiz - bth->curlen);
		/*
		 * If the message doesn't fit in the empty buffer then just
		 * return an error.
		 */
		if (size <= 0)
			return FRR_NETLINK_ERROR;
	}

	seq = dplane_ctx_get_ns(ctx)->seq;
	nl = kernel_netlink_nlsock_lookup(dplane_ctx_get_ns_sock(ctx));

	if (ignore_res)
		seq++;

	msgh = (struct nlmsghdr *)bth->buf_head;
	msgh->nlmsg_seq = seq;
	msgh->nlmsg_pid = nl->snl.nl_pid;

	bth->zns = dplane_ctx_get_ns(ctx);
	bth->buf_head = ((char *)bth->buf_head) + size;
	bth->curlen += size;
	bth->msgcnt++;

	return FRR_NETLINK_QUEUED;
}

static enum netlink_msg_status nl_put_msg(struct nl_batch *bth,
					  struct zebra_dplane_ctx *ctx)
{
	if (dplane_ctx_is_skip_kernel(ctx))
		return FRR_NETLINK_SUCCESS;

	switch (dplane_ctx_get_op(ctx)) {

	case DPLANE_OP_ROUTE_INSTALL:
	case DPLANE_OP_ROUTE_UPDATE:
	case DPLANE_OP_ROUTE_DELETE:
		return netlink_put_route_update_msg(bth, ctx);

	case DPLANE_OP_NH_INSTALL:
	case DPLANE_OP_NH_UPDATE:
	case DPLANE_OP_NH_DELETE:
		return netlink_put_nexthop_update_msg(bth, ctx);

	case DPLANE_OP_LSP_INSTALL:
	case DPLANE_OP_LSP_UPDATE:
	case DPLANE_OP_LSP_DELETE:
		return netlink_put_lsp_update_msg(bth, ctx);

	case DPLANE_OP_PW_INSTALL:
	case DPLANE_OP_PW_UNINSTALL:
		return netlink_put_pw_update_msg(bth, ctx);

	case DPLANE_OP_ADDR_INSTALL:
	case DPLANE_OP_ADDR_UNINSTALL:
		return netlink_put_address_update_msg(bth, ctx);

	case DPLANE_OP_MAC_INSTALL:
	case DPLANE_OP_MAC_DELETE:
		return netlink_put_mac_update_msg(bth, ctx);

	case DPLANE_OP_NEIGH_INSTALL:
	case DPLANE_OP_NEIGH_UPDATE:
	case DPLANE_OP_NEIGH_DELETE:
	case DPLANE_OP_VTEP_ADD:
	case DPLANE_OP_VTEP_DELETE:
	case DPLANE_OP_NEIGH_DISCOVER:
	case DPLANE_OP_NEIGH_IP_INSTALL:
	case DPLANE_OP_NEIGH_IP_DELETE:
	case DPLANE_OP_NEIGH_TABLE_UPDATE:
		return netlink_put_neigh_update_msg(bth, ctx);

	case DPLANE_OP_RULE_ADD:
	case DPLANE_OP_RULE_DELETE:
	case DPLANE_OP_RULE_UPDATE:
		return netlink_put_rule_update_msg(bth, ctx);

	case DPLANE_OP_SYS_ROUTE_ADD:
	case DPLANE_OP_SYS_ROUTE_DELETE:
	case DPLANE_OP_ROUTE_NOTIFY:
	case DPLANE_OP_LSP_NOTIFY:
	case DPLANE_OP_BR_PORT_UPDATE:
		return FRR_NETLINK_SUCCESS;

	case DPLANE_OP_IPTABLE_ADD:
	case DPLANE_OP_IPTABLE_DELETE:
	case DPLANE_OP_IPSET_ADD:
	case DPLANE_OP_IPSET_DELETE:
	case DPLANE_OP_IPSET_ENTRY_ADD:
	case DPLANE_OP_IPSET_ENTRY_DELETE:
	case DPLANE_OP_STARTUP_STAGE:
	case DPLANE_OP_VLAN_INSTALL:
		return FRR_NETLINK_ERROR;

	case DPLANE_OP_GRE_SET:
		return netlink_put_gre_set_msg(bth, ctx);

	case DPLANE_OP_INTF_ADDR_ADD:
	case DPLANE_OP_INTF_ADDR_DEL:
	case DPLANE_OP_NONE:
		return FRR_NETLINK_ERROR;

	case DPLANE_OP_INTF_NETCONFIG:
		return netlink_put_intf_netconfig(bth, ctx);

	case DPLANE_OP_INTF_INSTALL:
	case DPLANE_OP_INTF_UPDATE:
	case DPLANE_OP_INTF_DELETE:
		return netlink_put_intf_update_msg(bth, ctx);

	case DPLANE_OP_TC_QDISC_INSTALL:
	case DPLANE_OP_TC_QDISC_UNINSTALL:
		return netlink_put_tc_qdisc_update_msg(bth, ctx);
	case DPLANE_OP_TC_CLASS_ADD:
	case DPLANE_OP_TC_CLASS_DELETE:
	case DPLANE_OP_TC_CLASS_UPDATE:
		return netlink_put_tc_class_update_msg(bth, ctx);
	case DPLANE_OP_TC_FILTER_ADD:
	case DPLANE_OP_TC_FILTER_DELETE:
	case DPLANE_OP_TC_FILTER_UPDATE:
		return netlink_put_tc_filter_update_msg(bth, ctx);

	case DPLANE_OP_SRV6_ENCAP_SRCADDR_SET:
		return netlink_put_sr_tunsrc_set_msg(bth, ctx);
	case DPLANE_OP_PIC_NH_INSTALL:
	case DPLANE_OP_PIC_NH_UPDATE:
	case DPLANE_OP_PIC_NH_DELETE:
		return FRR_NETLINK_SUCCESS;
	}

	return FRR_NETLINK_ERROR;
}

void kernel_update_multi(struct dplane_ctx_list_head *ctx_list)
{
	struct nl_batch batch;
	struct zebra_dplane_ctx *ctx;
	struct dplane_ctx_list_head handled_list;
	enum netlink_msg_status res;

	dplane_ctx_q_init(&handled_list);
	nl_batch_init(&batch, &handled_list);

	while (true) {
		ctx = dplane_ctx_dequeue(ctx_list);
		if (ctx == NULL)
			break;

		if (batch.zns != NULL
		    && batch.zns->ns_id != dplane_ctx_get_ns(ctx)->ns_id)
			nl_batch_send(&batch);

		/*
		 * Assume all messages will succeed and then mark only the ones
		 * that failed.
		 */
		dplane_ctx_set_status(ctx, ZEBRA_DPLANE_REQUEST_SUCCESS);

		res = nl_put_msg(&batch, ctx);

		dplane_ctx_enqueue_tail(&(batch.ctx_list), ctx);
		if (res == FRR_NETLINK_ERROR)
			dplane_ctx_set_status(ctx,
					      ZEBRA_DPLANE_REQUEST_FAILURE);

		if (batch.curlen > batch.limit)
			nl_batch_send(&batch);
	}

	nl_batch_send(&batch);

	dplane_ctx_q_init(ctx_list);
	dplane_ctx_list_append(ctx_list, &handled_list);
}

struct nlsock *kernel_netlink_nlsock_lookup(int sock)
{
	struct nlsock lookup, *retval;

	lookup.sock = sock;

	NLSOCK_LOCK();
	retval = hash_lookup(nlsock_hash, &lookup);
	NLSOCK_UNLOCK();

	return retval;
}

/* Insert nlsock entry into hash */
static void kernel_netlink_nlsock_insert(struct nlsock *nls)
{
	NLSOCK_LOCK();
	(void)hash_get(nlsock_hash, nls, hash_alloc_intern);
	NLSOCK_UNLOCK();
}

/* Remove nlsock entry from hash */
static void kernel_netlink_nlsock_remove(struct nlsock *nls)
{
	NLSOCK_LOCK();
	(void)hash_release(nlsock_hash, nls);
	NLSOCK_UNLOCK();
}

static uint32_t kernel_netlink_nlsock_key(const void *arg)
{
	const struct nlsock *nl = arg;

	return nl->sock;
}

static bool kernel_netlink_nlsock_hash_equal(const void *arg1, const void *arg2)
{
	const struct nlsock *nl1 = arg1;
	const struct nlsock *nl2 = arg2;

	if (nl1->sock == nl2->sock)
		return true;

	return false;
}

/* Exported interface function.  This function simply calls
   netlink_socket (). */
void kernel_init(struct zebra_ns *zns)
{
	uint32_t groups, dplane_groups, ext_groups;
#if defined SOL_NETLINK
	int one, ret, grp;
#endif

	/*
	 * Initialize netlink sockets
	 *
	 * If RTMGRP_XXX exists use that, but at some point
	 * I think the kernel developers realized that
	 * keeping track of all the different values would
	 * lead to confusion, so we need to convert the
	 * RTNLGRP_XXX to a bit position for ourself
	 *
	 *
	 * NOTE: If the bit is >= 32, you must use setsockopt(). Those
	 * groups are added further below after SOL_NETLINK is verified to
	 * exist.
	 */
	groups = RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE | RTMGRP_IPV4_MROUTE |
		 RTMGRP_NEIGH | ((uint32_t)1 << (RTNLGRP_IPV4_RULE - 1)) |
		 ((uint32_t)1 << (RTNLGRP_IPV6_RULE - 1)) |
		 ((uint32_t)1 << (RTNLGRP_NEXTHOP - 1)) |
		 ((uint32_t)1 << (RTNLGRP_TC - 1));

	dplane_groups = (RTMGRP_LINK            |
			 RTMGRP_IPV4_IFADDR     |
			 RTMGRP_IPV6_IFADDR     |
			 ((uint32_t) 1 << (RTNLGRP_IPV4_NETCONF - 1)) |
			 ((uint32_t) 1 << (RTNLGRP_IPV6_NETCONF - 1)) |
			 ((uint32_t) 1 << (RTNLGRP_MPLS_NETCONF - 1)));

	/* Use setsockopt for > 31 group */
	ext_groups = RTNLGRP_TUNNEL;

	snprintf(zns->netlink.name, sizeof(zns->netlink.name),
		 "netlink-listen (NS %u)", zns->ns_id);
	zns->netlink.sock = -1;
	if (netlink_socket(&zns->netlink, groups, &ext_groups, 1, zns->ns_id,
			   NETLINK_ROUTE) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink.name);
		exit(-1);
	}

	kernel_netlink_nlsock_insert(&zns->netlink);

	snprintf(zns->netlink_cmd.name, sizeof(zns->netlink_cmd.name),
		 "netlink-cmd (NS %u)", zns->ns_id);
	zns->netlink_cmd.sock = -1;
	if (netlink_socket(&zns->netlink_cmd, 0, 0, 0, zns->ns_id,
			   NETLINK_ROUTE) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink_cmd.name);
		exit(-1);
	}

	kernel_netlink_nlsock_insert(&zns->netlink_cmd);

	/* Outbound socket for dplane programming of the host OS. */
	snprintf(zns->netlink_dplane_out.name,
		 sizeof(zns->netlink_dplane_out.name), "netlink-dp (NS %u)",
		 zns->ns_id);
	zns->netlink_dplane_out.sock = -1;
	if (netlink_socket(&zns->netlink_dplane_out, 0, 0, 0, zns->ns_id,
			   NETLINK_ROUTE) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink_dplane_out.name);
		exit(-1);
	}

	kernel_netlink_nlsock_insert(&zns->netlink_dplane_out);

	/* Inbound socket for OS events coming to the dplane. */
	snprintf(zns->netlink_dplane_in.name,
		 sizeof(zns->netlink_dplane_in.name), "netlink-dp-in (NS %u)",
		 zns->ns_id);
	zns->netlink_dplane_in.sock = -1;
	if (netlink_socket(&zns->netlink_dplane_in, dplane_groups, 0, 0,
			   zns->ns_id, NETLINK_ROUTE) < 0) {
		zlog_err("Failure to create %s socket",
			 zns->netlink_dplane_in.name);
		exit(-1);
	}

	kernel_netlink_nlsock_insert(&zns->netlink_dplane_in);

	/* Generic Netlink socket. */
	snprintf(zns->ge_netlink_cmd.name, sizeof(zns->ge_netlink_cmd.name),
		 "generic-netlink-cmd (NS %u)", zns->ns_id);
	zns->ge_netlink_cmd.sock = -1;
	if (netlink_socket(&zns->ge_netlink_cmd, 0, 0, 0, zns->ns_id,
			   NETLINK_GENERIC) < 0) {
		zlog_warn("Failure to create %s socket",
			  zns->ge_netlink_cmd.name);
	}

	if (zns->ge_netlink_cmd.sock >= 0)
		kernel_netlink_nlsock_insert(&zns->ge_netlink_cmd);

	/*
	 * SOL_NETLINK is not available on all platforms yet
	 * apparently.  It's in bits/socket.h which I am not
	 * sure that we want to pull into our build system.
	 */
#if defined SOL_NETLINK

	/*
	 * setsockopt multicast group subscriptions that don't fit in nl_groups
	 */
	grp = RTNLGRP_BRVLAN;
	ret = setsockopt(zns->netlink_dplane_in.sock, SOL_NETLINK,
			 NETLINK_ADD_MEMBERSHIP, &grp, sizeof(grp));

	if (ret < 0)
		zlog_notice(
			"Registration for RTNLGRP_BRVLAN Membership failed : %d %s",
			errno, safe_strerror(errno));
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
	ret = setsockopt(zns->netlink_dplane_out.sock, SOL_NETLINK,
			 NETLINK_EXT_ACK, &one, sizeof(one));

	if (ret < 0)
		zlog_notice("Registration for extended dp ACK failed : %d %s",
			    errno, safe_strerror(errno));

	if (zns->ge_netlink_cmd.sock >= 0) {
		one = 1;
		ret = setsockopt(zns->ge_netlink_cmd.sock, SOL_NETLINK,
				 NETLINK_EXT_ACK, &one, sizeof(one));
		if (ret < 0)
			zlog_err("Registration for extended generic netlink cmd ACK failed : %d %s",
				 errno, safe_strerror(errno));
	}

	/*
	 * Trim off the payload of the original netlink message in the
	 * acknowledgment. This option is available since Linux 4.2, so if
	 * setsockopt fails, ignore the error.
	 */
	one = 1;
	ret = setsockopt(zns->netlink_dplane_out.sock, SOL_NETLINK,
			 NETLINK_CAP_ACK, &one, sizeof(one));
	if (ret < 0)
		zlog_notice(
			"Registration for reduced ACK packet size failed, probably running an early kernel");
#endif

	/* Register kernel socket. */
	if (fcntl(zns->netlink.sock, F_SETFL, O_NONBLOCK) < 0)
		flog_err_sys(EC_LIB_SOCKET, "Can't set %s socket flags: %s",
			     zns->netlink.name, safe_strerror(errno));

	if (fcntl(zns->netlink_cmd.sock, F_SETFL, O_NONBLOCK) < 0)
		zlog_err("Can't set %s socket error: %s(%d)",
			 zns->netlink_cmd.name, safe_strerror(errno), errno);

	if (fcntl(zns->netlink_dplane_out.sock, F_SETFL, O_NONBLOCK) < 0)
		zlog_err("Can't set %s socket error: %s(%d)",
			 zns->netlink_dplane_out.name, safe_strerror(errno),
			 errno);

	if (fcntl(zns->netlink_dplane_in.sock, F_SETFL, O_NONBLOCK) < 0)
		zlog_err("Can't set %s socket error: %s(%d)",
			 zns->netlink_dplane_in.name, safe_strerror(errno),
			 errno);

	if (zns->ge_netlink_cmd.sock >= 0) {
		if (fcntl(zns->ge_netlink_cmd.sock, F_SETFL, O_NONBLOCK) < 0)
			zlog_err("Can't set %s socket error: %s(%d)",
				 zns->ge_netlink_cmd.name, safe_strerror(errno),
				 errno);
	}

	/* Set receive buffer size if it's set from command line */
	if (rcvbufsize) {
		netlink_recvbuf(&zns->netlink, rcvbufsize);
		netlink_recvbuf(&zns->netlink_cmd, rcvbufsize);
		netlink_recvbuf(&zns->netlink_dplane_out, rcvbufsize);
		netlink_recvbuf(&zns->netlink_dplane_in, rcvbufsize);

		if (zns->ge_netlink_cmd.sock >= 0)
			netlink_recvbuf(&zns->ge_netlink_cmd, rcvbufsize);
	}

	/* Set filter for inbound sockets, to exclude events we've generated
	 * ourselves.
	 */
	netlink_install_filter(zns->netlink.sock, zns->netlink_cmd.snl.nl_pid,
			       zns->netlink_dplane_out.snl.nl_pid);

	netlink_install_filter(zns->netlink_dplane_in.sock,
			       zns->netlink_cmd.snl.nl_pid,
			       zns->netlink_dplane_out.snl.nl_pid);

	zns->t_netlink = NULL;

	event_add_read(zrouter.master, kernel_read, zns, zns->netlink.sock,
		       &zns->t_netlink);

	rt_netlink_init();

	ge_netlink_init(zns);
}

/* Helper to clean up an nlsock */
static void kernel_nlsock_fini(struct nlsock *nls)
{
	if (nls && nls->sock >= 0) {
		kernel_netlink_nlsock_remove(nls);
		close(nls->sock);
		nls->sock = -1;
		XFREE(MTYPE_NL_BUF, nls->buf);
		nls->buflen = 0;
	}
}

void kernel_terminate(struct zebra_ns *zns, bool complete)
{
	EVENT_OFF(zns->t_netlink);

	kernel_nlsock_fini(&zns->netlink);

	kernel_nlsock_fini(&zns->netlink_cmd);

	kernel_nlsock_fini(&zns->netlink_dplane_in);

	kernel_nlsock_fini(&zns->ge_netlink_cmd);

	/* During zebra shutdown, we need to leave the dataplane socket
	 * around until all work is done.
	 */
	if (complete) {
		kernel_nlsock_fini(&zns->netlink_dplane_out);

		XFREE(MTYPE_NL_BUF, nl_batch_tx_buf);
	}
}

/*
 * Global init for platform-/OS-specific things
 */
void kernel_router_init(void)
{
	/* Init nlsock hash and lock */
	pthread_mutex_init(&nlsock_mutex, NULL);
	nlsock_hash = hash_create_size(8, kernel_netlink_nlsock_key,
				       kernel_netlink_nlsock_hash_equal,
				       "Netlink Socket Hash");
}

/*
 * Global deinit for platform-/OS-specific things
 */
void kernel_router_terminate(void)
{
	pthread_mutex_destroy(&nlsock_mutex);

	hash_free(nlsock_hash);
	nlsock_hash = NULL;
}

#endif /* HAVE_NETLINK */
