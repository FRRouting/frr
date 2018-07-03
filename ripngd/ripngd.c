/* RIPng daemon
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
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

#include "prefix.h"
#include "filter.h"
#include "log.h"
#include "thread.h"
#include "memory.h"
#include "if.h"
#include "stream.h"
#include "table.h"
#include "command.h"
#include "sockopt.h"
#include "distribute.h"
#include "plist.h"
#include "routemap.h"
#include "if_rmap.h"
#include "privs.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_route.h"
#include "ripngd/ripng_debug.h"
#include "ripngd/ripng_nexthop.h"

/* RIPng structure which includes many parameters related to RIPng
   protocol. If ripng couldn't active or ripng doesn't configured,
   ripng->fd must be negative value. */
struct ripng *ripng = NULL;

enum { ripng_all_route,
       ripng_changed_route,
};

/* Prototypes. */
void ripng_output_process(struct interface *, struct sockaddr_in6 *, int);

int ripng_triggered_update(struct thread *);

/* RIPng next hop specification. */
struct ripng_nexthop {
	enum ripng_nexthop_type {
		RIPNG_NEXTHOP_UNSPEC,
		RIPNG_NEXTHOP_ADDRESS
	} flag;
	struct in6_addr address;
};

static int ripng_route_rte(struct ripng_info *rinfo)
{
	return (rinfo->type == ZEBRA_ROUTE_RIPNG
		&& rinfo->sub_type == RIPNG_ROUTE_RTE);
}

/* Allocate new ripng information. */
struct ripng_info *ripng_info_new()
{
	struct ripng_info *new;

	new = XCALLOC(MTYPE_RIPNG_ROUTE, sizeof(struct ripng_info));
	return new;
}

/* Free ripng information. */
void ripng_info_free(struct ripng_info *rinfo)
{
	XFREE(MTYPE_RIPNG_ROUTE, rinfo);
}

/* Create ripng socket. */
static int ripng_make_socket(void)
{
	int ret;
	int sock;
	struct sockaddr_in6 ripaddr;

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	if (sock < 0) {
		zlog_err("Can't make ripng socket");
		return sock;
	}

	setsockopt_so_recvbuf(sock, 8096);
	ret = setsockopt_ipv6_pktinfo(sock, 1);
	if (ret < 0)
		goto error;
#ifdef IPTOS_PREC_INTERNETCONTROL
	ret = setsockopt_ipv6_tclass(sock, IPTOS_PREC_INTERNETCONTROL);
	if (ret < 0)
		goto error;
#endif
	ret = setsockopt_ipv6_multicast_hops(sock, 255);
	if (ret < 0)
		goto error;
	ret = setsockopt_ipv6_multicast_loop(sock, 0);
	if (ret < 0)
		goto error;
	ret = setsockopt_ipv6_hoplimit(sock, 1);
	if (ret < 0)
		goto error;

	memset(&ripaddr, 0, sizeof(ripaddr));
	ripaddr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	ripaddr.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
	ripaddr.sin6_port = htons(RIPNG_PORT_DEFAULT);

	if (ripngd_privs.change(ZPRIVS_RAISE))
		zlog_err("ripng_make_socket: could not raise privs");

	ret = bind(sock, (struct sockaddr *)&ripaddr, sizeof(ripaddr));
	if (ret < 0) {
		zlog_err("Can't bind ripng socket: %s.", safe_strerror(errno));
		if (ripngd_privs.change(ZPRIVS_LOWER))
			zlog_err("ripng_make_socket: could not lower privs");
		goto error;
	}
	if (ripngd_privs.change(ZPRIVS_LOWER))
		zlog_err("ripng_make_socket: could not lower privs");
	return sock;

error:
	close(sock);
	return ret;
}

/* Send RIPng packet. */
int ripng_send_packet(caddr_t buf, int bufsize, struct sockaddr_in6 *to,
		      struct interface *ifp)
{
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsgptr;
	char adata[256];
	struct in6_pktinfo *pkt;
	struct sockaddr_in6 addr;

	if (IS_RIPNG_DEBUG_SEND) {
		if (to)
			zlog_debug("send to %s", inet6_ntoa(to->sin6_addr));
		zlog_debug("  send interface %s", ifp->name);
		zlog_debug("  send packet size %d", bufsize);
	}

	memset(&addr, 0, sizeof(struct sockaddr_in6));
	addr.sin6_family = AF_INET6;
#ifdef SIN6_LEN
	addr.sin6_len = sizeof(struct sockaddr_in6);
#endif /* SIN6_LEN */
	addr.sin6_flowinfo = htonl(RIPNG_PRIORITY_DEFAULT);

	/* When destination is specified. */
	if (to != NULL) {
		addr.sin6_addr = to->sin6_addr;
		addr.sin6_port = to->sin6_port;
	} else {
		inet_pton(AF_INET6, RIPNG_GROUP, &addr.sin6_addr);
		addr.sin6_port = htons(RIPNG_PORT_DEFAULT);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&addr;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in6_pktinfo));

	iov.iov_base = buf;
	iov.iov_len = bufsize;

	cmsgptr = (struct cmsghdr *)adata;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
	cmsgptr->cmsg_level = IPPROTO_IPV6;
	cmsgptr->cmsg_type = IPV6_PKTINFO;

	pkt = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
	memset(&pkt->ipi6_addr, 0, sizeof(struct in6_addr));
	pkt->ipi6_ifindex = ifp->ifindex;

	ret = sendmsg(ripng->sock, &msg, 0);

	if (ret < 0) {
		if (to)
			zlog_err("RIPng send fail on %s to %s: %s", ifp->name,
				 inet6_ntoa(to->sin6_addr),
				 safe_strerror(errno));
		else
			zlog_err("RIPng send fail on %s: %s", ifp->name,
				 safe_strerror(errno));
	}

	return ret;
}

/* Receive UDP RIPng packet from socket. */
static int ripng_recv_packet(int sock, uint8_t *buf, int bufsize,
			     struct sockaddr_in6 *from, ifindex_t *ifindex,
			     int *hoplimit)
{
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsgptr;
	struct in6_addr dst = {.s6_addr = {0}};

	memset(&dst, 0, sizeof(struct in6_addr));

	/* Ancillary data.  This store cmsghdr and in6_pktinfo.  But at this
	   point I can't determine size of cmsghdr */
	char adata[1024];

	/* Fill in message and iovec. */
	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)from;
	msg.msg_namelen = sizeof(struct sockaddr_in6);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (void *)adata;
	msg.msg_controllen = sizeof adata;
	iov.iov_base = buf;
	iov.iov_len = bufsize;

	/* If recvmsg fail return minus value. */
	ret = recvmsg(sock, &msg, 0);
	if (ret < 0)
		return ret;

	for (cmsgptr = ZCMSG_FIRSTHDR(&msg); cmsgptr != NULL;
	     cmsgptr = CMSG_NXTHDR(&msg, cmsgptr)) {
		/* I want interface index which this packet comes from. */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6
		    && cmsgptr->cmsg_type == IPV6_PKTINFO) {
			struct in6_pktinfo *ptr;

			ptr = (struct in6_pktinfo *)CMSG_DATA(cmsgptr);
			*ifindex = ptr->ipi6_ifindex;
			dst = ptr->ipi6_addr;

			if (*ifindex == 0)
				zlog_warn(
					"Interface index returned by IPV6_PKTINFO is zero");
		}

		/* Incoming packet's multicast hop limit. */
		if (cmsgptr->cmsg_level == IPPROTO_IPV6
		    && cmsgptr->cmsg_type == IPV6_HOPLIMIT) {
			int *phoplimit = (int *)CMSG_DATA(cmsgptr);
			*hoplimit = *phoplimit;
		}
	}

	/* Hoplimit check shold be done when destination address is
	   multicast address. */
	if (!IN6_IS_ADDR_MULTICAST(&dst))
		*hoplimit = -1;

	return ret;
}

/* Dump rip packet */
void ripng_packet_dump(struct ripng_packet *packet, int size,
		       const char *sndrcv)
{
	caddr_t lim;
	struct rte *rte;
	const char *command_str;

	/* Set command string. */
	if (packet->command == RIPNG_REQUEST)
		command_str = "request";
	else if (packet->command == RIPNG_RESPONSE)
		command_str = "response";
	else
		command_str = "unknown";

	/* Dump packet header. */
	zlog_debug("%s %s version %d packet size %d", sndrcv, command_str,
		   packet->version, size);

	/* Dump each routing table entry. */
	rte = packet->rte;

	for (lim = (caddr_t)packet + size; (caddr_t)rte < lim; rte++) {
		if (rte->metric == RIPNG_METRIC_NEXTHOP)
			zlog_debug("  nexthop %s/%d", inet6_ntoa(rte->addr),
				   rte->prefixlen);
		else
			zlog_debug("  %s/%d metric %d tag %" ROUTE_TAG_PRI,
				   inet6_ntoa(rte->addr), rte->prefixlen,
				   rte->metric, (route_tag_t)ntohs(rte->tag));
	}
}

/* RIPng next hop address RTE (Route Table Entry). */
static void ripng_nexthop_rte(struct rte *rte, struct sockaddr_in6 *from,
			      struct ripng_nexthop *nexthop)
{
	char buf[INET6_BUFSIZ];

	/* Logging before checking RTE. */
	if (IS_RIPNG_DEBUG_RECV)
		zlog_debug("RIPng nexthop RTE address %s tag %" ROUTE_TAG_PRI
			   " prefixlen %d",
			   inet6_ntoa(rte->addr), (route_tag_t)ntohs(rte->tag),
			   rte->prefixlen);

	/* RFC2080 2.1.1 Next Hop:
	 The route tag and prefix length in the next hop RTE must be
	 set to zero on sending and ignored on receiption.  */
	if (ntohs(rte->tag) != 0)
		zlog_warn(
			"RIPng nexthop RTE with non zero tag value %" ROUTE_TAG_PRI
			" from %s",
			(route_tag_t)ntohs(rte->tag),
			inet6_ntoa(from->sin6_addr));

	if (rte->prefixlen != 0)
		zlog_warn(
			"RIPng nexthop RTE with non zero prefixlen value %d from %s",
			rte->prefixlen, inet6_ntoa(from->sin6_addr));

	/* Specifying a value of 0:0:0:0:0:0:0:0 in the prefix field of a
	 next hop RTE indicates that the next hop address should be the
	 originator of the RIPng advertisement.  An address specified as a
	 next hop must be a link-local address.  */
	if (IN6_IS_ADDR_UNSPECIFIED(&rte->addr)) {
		nexthop->flag = RIPNG_NEXTHOP_UNSPEC;
		memset(&nexthop->address, 0, sizeof(struct in6_addr));
		return;
	}

	if (IN6_IS_ADDR_LINKLOCAL(&rte->addr)) {
		nexthop->flag = RIPNG_NEXTHOP_ADDRESS;
		IPV6_ADDR_COPY(&nexthop->address, &rte->addr);
		return;
	}

	/* The purpose of the next hop RTE is to eliminate packets being
	 routed through extra hops in the system.  It is particularly useful
	 when RIPng is not being run on all of the routers on a network.
	 Note that next hop RTE is "advisory".  That is, if the provided
	 information is ignored, a possibly sub-optimal, but absolutely
	 valid, route may be taken.  If the received next hop address is not
	 a link-local address, it should be treated as 0:0:0:0:0:0:0:0.  */
	zlog_warn("RIPng nexthop RTE with non link-local address %s from %s",
		  inet6_ntoa(rte->addr),
		  inet_ntop(AF_INET6, &from->sin6_addr, buf, INET6_BUFSIZ));

	nexthop->flag = RIPNG_NEXTHOP_UNSPEC;
	memset(&nexthop->address, 0, sizeof(struct in6_addr));

	return;
}

/* If ifp has same link-local address then return 1. */
static int ripng_lladdr_check(struct interface *ifp, struct in6_addr *addr)
{
	struct listnode *node;
	struct connected *connected;
	struct prefix *p;

	for (ALL_LIST_ELEMENTS_RO(ifp->connected, node, connected)) {
		p = connected->address;

		if (p->family == AF_INET6
		    && IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6)
		    && IN6_ARE_ADDR_EQUAL(&p->u.prefix6, addr))
			return 1;
	}
	return 0;
}

/* RIPng route garbage collect timer. */
static int ripng_garbage_collect(struct thread *t)
{
	struct ripng_info *rinfo;
	struct route_node *rp;

	rinfo = THREAD_ARG(t);
	rinfo->t_garbage_collect = NULL;

	/* Off timeout timer. */
	RIPNG_TIMER_OFF(rinfo->t_timeout);

	/* Get route_node pointer. */
	rp = rinfo->rp;

	/* Unlock route_node. */
	listnode_delete(rp->info, rinfo);
	if (list_isempty((struct list *)rp->info)) {
		list_delete_and_null((struct list **)&rp->info);
		route_unlock_node(rp);
	}

	/* Free RIPng routing information. */
	ripng_info_free(rinfo);

	return 0;
}

static void ripng_timeout_update(struct ripng_info *rinfo);

/* Add new route to the ECMP list.
 * RETURN: the new entry added in the list, or NULL if it is not the first
 *         entry and ECMP is not allowed.
 */
struct ripng_info *ripng_ecmp_add(struct ripng_info *rinfo_new)
{
	struct route_node *rp = rinfo_new->rp;
	struct ripng_info *rinfo = NULL;
	struct list *list = NULL;

	if (rp->info == NULL)
		rp->info = list_new();
	list = (struct list *)rp->info;

	/* If ECMP is not allowed and some entry already exists in the list,
	 * do nothing. */
	if (listcount(list) && !ripng->ecmp)
		return NULL;

	rinfo = ripng_info_new();
	memcpy(rinfo, rinfo_new, sizeof(struct ripng_info));
	listnode_add(list, rinfo);

	if (ripng_route_rte(rinfo)) {
		ripng_timeout_update(rinfo);
		ripng_zebra_ipv6_add(rp);
	}

	ripng_aggregate_increment(rp, rinfo);

	/* Set the route change flag on the first entry. */
	rinfo = listgetdata(listhead(list));
	SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

	/* Signal the output process to trigger an update. */
	ripng_event(RIPNG_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Replace the ECMP list with the new route.
 * RETURN: the new entry added in the list
 */
struct ripng_info *ripng_ecmp_replace(struct ripng_info *rinfo_new)
{
	struct route_node *rp = rinfo_new->rp;
	struct list *list = (struct list *)rp->info;
	struct ripng_info *rinfo = NULL, *tmp_rinfo = NULL;
	struct listnode *node = NULL, *nextnode = NULL;

	if (list == NULL || listcount(list) == 0)
		return ripng_ecmp_add(rinfo_new);

	/* Get the first entry */
	rinfo = listgetdata(listhead(list));

	/* Learnt route replaced by a local one. Delete it from zebra. */
	if (ripng_route_rte(rinfo) && !ripng_route_rte(rinfo_new))
		if (CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
			ripng_zebra_ipv6_delete(rp);

	if (rinfo->metric != RIPNG_METRIC_INFINITY)
		ripng_aggregate_decrement_list(rp, list);

	/* Re-use the first entry, and delete the others. */
	for (ALL_LIST_ELEMENTS(list, node, nextnode, tmp_rinfo))
		if (tmp_rinfo != rinfo) {
			RIPNG_TIMER_OFF(tmp_rinfo->t_timeout);
			RIPNG_TIMER_OFF(tmp_rinfo->t_garbage_collect);
			list_delete_node(list, node);
			ripng_info_free(tmp_rinfo);
		}

	RIPNG_TIMER_OFF(rinfo->t_timeout);
	RIPNG_TIMER_OFF(rinfo->t_garbage_collect);
	memcpy(rinfo, rinfo_new, sizeof(struct ripng_info));

	if (ripng_route_rte(rinfo)) {
		ripng_timeout_update(rinfo);
		/* The ADD message implies an update. */
		ripng_zebra_ipv6_add(rp);
	}

	ripng_aggregate_increment(rp, rinfo);

	/* Set the route change flag. */
	SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

	/* Signal the output process to trigger an update. */
	ripng_event(RIPNG_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Delete one route from the ECMP list.
 * RETURN:
 *  null - the entry is freed, and other entries exist in the list
 *  the entry - the entry is the last one in the list; its metric is set
 *              to INFINITY, and the garbage collector is started for it
 */
struct ripng_info *ripng_ecmp_delete(struct ripng_info *rinfo)
{
	struct route_node *rp = rinfo->rp;
	struct list *list = (struct list *)rp->info;

	RIPNG_TIMER_OFF(rinfo->t_timeout);

	if (rinfo->metric != RIPNG_METRIC_INFINITY)
		ripng_aggregate_decrement(rp, rinfo);

	if (listcount(list) > 1) {
		/* Some other ECMP entries still exist. Just delete this entry.
		 */
		RIPNG_TIMER_OFF(rinfo->t_garbage_collect);
		listnode_delete(list, rinfo);
		if (ripng_route_rte(rinfo)
		    && CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
			/* The ADD message implies the update. */
			ripng_zebra_ipv6_add(rp);
		ripng_info_free(rinfo);
		rinfo = NULL;
	} else {
		assert(rinfo == listgetdata(listhead(list)));

		/* This is the only entry left in the list. We must keep it in
		 * the list for garbage collection time, with INFINITY metric.
		 */

		rinfo->metric = RIPNG_METRIC_INFINITY;
		RIPNG_TIMER_ON(rinfo->t_garbage_collect, ripng_garbage_collect,
			       ripng->garbage_time);

		if (ripng_route_rte(rinfo)
		    && CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
			ripng_zebra_ipv6_delete(rp);
	}

	/* Set the route change flag on the first entry. */
	rinfo = listgetdata(listhead(list));
	SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

	/* Signal the output process to trigger an update. */
	ripng_event(RIPNG_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Timeout RIPng routes. */
static int ripng_timeout(struct thread *t)
{
	ripng_ecmp_delete((struct ripng_info *)THREAD_ARG(t));
	return 0;
}

static void ripng_timeout_update(struct ripng_info *rinfo)
{
	if (rinfo->metric != RIPNG_METRIC_INFINITY) {
		RIPNG_TIMER_OFF(rinfo->t_timeout);
		RIPNG_TIMER_ON(rinfo->t_timeout, ripng_timeout,
			       ripng->timeout_time);
	}
}

static int ripng_filter(int ripng_distribute, struct prefix_ipv6 *p,
			struct ripng_interface *ri)
{
	struct distribute *dist;
	struct access_list *alist;
	struct prefix_list *plist;
	int distribute = ripng_distribute == RIPNG_FILTER_OUT
				 ? DISTRIBUTE_V6_OUT
				 : DISTRIBUTE_V6_IN;
	const char *inout = ripng_distribute == RIPNG_FILTER_OUT ? "out" : "in";

	/* Input distribute-list filtering. */
	if (ri->list[ripng_distribute]) {
		if (access_list_apply(ri->list[ripng_distribute],
				      (struct prefix *)p)
		    == FILTER_DENY) {
			if (IS_RIPNG_DEBUG_PACKET)
				zlog_debug("%s/%d filtered by distribute %s",
					   inet6_ntoa(p->prefix), p->prefixlen,
					   inout);
			return -1;
		}
	}
	if (ri->prefix[ripng_distribute]) {
		if (prefix_list_apply(ri->prefix[ripng_distribute],
				      (struct prefix *)p)
		    == PREFIX_DENY) {
			if (IS_RIPNG_DEBUG_PACKET)
				zlog_debug("%s/%d filtered by prefix-list %s",
					   inet6_ntoa(p->prefix), p->prefixlen,
					   inout);
			return -1;
		}
	}

	/* All interface filter check. */
	dist = distribute_lookup(NULL);
	if (dist) {
		if (dist->list[distribute]) {
			alist = access_list_lookup(AFI_IP6,
						   dist->list[distribute]);

			if (alist) {
				if (access_list_apply(alist, (struct prefix *)p)
				    == FILTER_DENY) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"%s/%d filtered by distribute %s",
							inet6_ntoa(p->prefix),
							p->prefixlen, inout);
					return -1;
				}
			}
		}
		if (dist->prefix[distribute]) {
			plist = prefix_list_lookup(AFI_IP6,
						   dist->prefix[distribute]);

			if (plist) {
				if (prefix_list_apply(plist, (struct prefix *)p)
				    == PREFIX_DENY) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"%s/%d filtered by prefix-list %s",
							inet6_ntoa(p->prefix),
							p->prefixlen, inout);
					return -1;
				}
			}
		}
	}
	return 0;
}

/* Process RIPng route according to RFC2080. */
static void ripng_route_process(struct rte *rte, struct sockaddr_in6 *from,
				struct ripng_nexthop *ripng_nexthop,
				struct interface *ifp)
{
	int ret;
	struct prefix_ipv6 p;
	struct route_node *rp;
	struct ripng_info *rinfo = NULL, newinfo;
	struct ripng_interface *ri;
	struct in6_addr *nexthop;
	int same = 0;
	struct list *list = NULL;
	struct listnode *node = NULL;

	/* Make prefix structure. */
	memset(&p, 0, sizeof(struct prefix_ipv6));
	p.family = AF_INET6;
	/* p.prefix = rte->addr; */
	IPV6_ADDR_COPY(&p.prefix, &rte->addr);
	p.prefixlen = rte->prefixlen;

	/* Make sure mask is applied. */
	/* XXX We have to check the prefix is valid or not before call
	   apply_mask_ipv6. */
	apply_mask_ipv6(&p);

	/* Apply input filters. */
	ri = ifp->info;

	ret = ripng_filter(RIPNG_FILTER_IN, &p, ri);
	if (ret < 0)
		return;

	memset(&newinfo, 0, sizeof(newinfo));
	newinfo.type = ZEBRA_ROUTE_RIPNG;
	newinfo.sub_type = RIPNG_ROUTE_RTE;
	if (ripng_nexthop->flag == RIPNG_NEXTHOP_ADDRESS)
		newinfo.nexthop = ripng_nexthop->address;
	else
		newinfo.nexthop = from->sin6_addr;
	newinfo.from = from->sin6_addr;
	newinfo.ifindex = ifp->ifindex;
	newinfo.metric = rte->metric;
	newinfo.metric_out = rte->metric; /* XXX */
	newinfo.tag = ntohs(rte->tag);    /* XXX */

	/* Modify entry. */
	if (ri->routemap[RIPNG_FILTER_IN]) {
		int ret;

		ret = route_map_apply(ri->routemap[RIPNG_FILTER_IN],
				      (struct prefix *)&p, RMAP_RIPNG,
				      &newinfo);

		if (ret == RMAP_DENYMATCH) {
			if (IS_RIPNG_DEBUG_PACKET)
				zlog_debug(
					"RIPng %s/%d is filtered by route-map in",
					inet6_ntoa(p.prefix), p.prefixlen);
			return;
		}

		/* Get back the object */
		if (ripng_nexthop->flag == RIPNG_NEXTHOP_ADDRESS) {
			if (!IPV6_ADDR_SAME(&newinfo.nexthop,
					    &ripng_nexthop->address)) {
				/* the nexthop get changed by the routemap */
				if (IN6_IS_ADDR_LINKLOCAL(&newinfo.nexthop))
					ripng_nexthop->address =
						newinfo.nexthop;
				else
					ripng_nexthop->address = in6addr_any;
			}
		} else {
			if (!IPV6_ADDR_SAME(&newinfo.nexthop,
					    &from->sin6_addr)) {
				/* the nexthop get changed by the routemap */
				if (IN6_IS_ADDR_LINKLOCAL(&newinfo.nexthop)) {
					ripng_nexthop->flag =
						RIPNG_NEXTHOP_ADDRESS;
					ripng_nexthop->address =
						newinfo.nexthop;
				}
			}
		}
		rte->tag = htons(newinfo.tag_out); /* XXX */
		rte->metric =
			newinfo.metric_out; /* XXX: the routemap uses the
					       metric_out field */
	}

	/* Once the entry has been validated, update the metric by
	 * adding the cost of the network on wich the message
	 * arrived. If the result is greater than infinity, use infinity
	 * (RFC2453 Sec. 3.9.2)
	 **/

	/* Zebra ripngd can handle offset-list in. */
	ret = ripng_offset_list_apply_in(&p, ifp, &rte->metric);

	/* If offset-list does not modify the metric use interface's
	 * one. */
	if (!ret)
		rte->metric += ifp->metric ? ifp->metric : 1;

	if (rte->metric > RIPNG_METRIC_INFINITY)
		rte->metric = RIPNG_METRIC_INFINITY;

	/* Set nexthop pointer. */
	if (ripng_nexthop->flag == RIPNG_NEXTHOP_ADDRESS)
		nexthop = &ripng_nexthop->address;
	else
		nexthop = &from->sin6_addr;

	/* Lookup RIPng routing table. */
	rp = route_node_get(ripng->table, (struct prefix *)&p);

	newinfo.rp = rp;
	newinfo.nexthop = *nexthop;
	newinfo.metric = rte->metric;
	newinfo.tag = ntohs(rte->tag);

	/* Check to see whether there is already RIPng route on the table. */
	if ((list = rp->info) != NULL)
		for (ALL_LIST_ELEMENTS_RO(list, node, rinfo)) {
			/* Need to compare with redistributed entry or local
			 * entry */
			if (!ripng_route_rte(rinfo))
				break;

			if (IPV6_ADDR_SAME(&rinfo->from, &from->sin6_addr)
			    && IPV6_ADDR_SAME(&rinfo->nexthop, nexthop))
				break;

			if (!listnextnode(node)) {
				/* Not found in the list */

				if (rte->metric > rinfo->metric) {
					/* New route has a greater metric.
					 * Discard it. */
					route_unlock_node(rp);
					return;
				}

				if (rte->metric < rinfo->metric)
					/* New route has a smaller metric.
					 * Replace the ECMP list
					 * with the new one in below. */
					break;

				/* Metrics are same. Unless ECMP is disabled,
				 * keep "rinfo" null and
				 * the new route is added in the ECMP list in
				 * below. */
				if (!ripng->ecmp)
					break;
			}
		}

	if (rinfo) {
		/* Redistributed route check. */
		if (rinfo->type != ZEBRA_ROUTE_RIPNG
		    && rinfo->metric != RIPNG_METRIC_INFINITY) {
			route_unlock_node(rp);
			return;
		}

		/* Local static route. */
		if (rinfo->type == ZEBRA_ROUTE_RIPNG
		    && ((rinfo->sub_type == RIPNG_ROUTE_STATIC)
			|| (rinfo->sub_type == RIPNG_ROUTE_DEFAULT))
		    && rinfo->metric != RIPNG_METRIC_INFINITY) {
			route_unlock_node(rp);
			return;
		}
	}

	if (!rinfo) {
		/* Now, check to see whether there is already an explicit route
		   for the destination prefix.  If there is no such route, add
		   this route to the routing table, unless the metric is
		   infinity (there is no point in adding a route which
		   unusable). */
		if (rte->metric != RIPNG_METRIC_INFINITY)
			ripng_ecmp_add(&newinfo);
		else
			route_unlock_node(rp);
	} else {
		/* If there is an existing route, compare the next hop address
		   to the address of the router from which the datagram came.
		   If this datagram is from the same router as the existing
		   route, reinitialize the timeout.  */
		same = (IN6_ARE_ADDR_EQUAL(&rinfo->from, &from->sin6_addr)
			&& (rinfo->ifindex == ifp->ifindex));

		/*
		 * RFC 2080 - Section 2.4.2:
		 * "If the new metric is the same as the old one, examine the
		 * timeout
		 * for the existing route.  If it is at least halfway to the
		 * expiration
		 * point, switch to the new route.  This heuristic is optional,
		 * but
		 * highly recommended".
		 */
		if (!ripng->ecmp && !same && rinfo->metric == rte->metric
		    && rinfo->t_timeout
		    && (thread_timer_remain_second(rinfo->t_timeout)
			< (ripng->timeout_time / 2))) {
			ripng_ecmp_replace(&newinfo);
		}
		/* Next, compare the metrics.  If the datagram is from the same
		   router as the existing route, and the new metric is different
		   than the old one; or, if the new metric is lower than the old
		   one; do the following actions: */
		else if ((same && rinfo->metric != rte->metric)
			 || rte->metric < rinfo->metric) {
			if (listcount(list) == 1) {
				if (newinfo.metric != RIPNG_METRIC_INFINITY)
					ripng_ecmp_replace(&newinfo);
				else
					ripng_ecmp_delete(rinfo);
			} else {
				if (newinfo.metric < rinfo->metric)
					ripng_ecmp_replace(&newinfo);
				else /* newinfo.metric > rinfo->metric */
					ripng_ecmp_delete(rinfo);
			}
		} else /* same & no change */
			ripng_timeout_update(rinfo);

		/* Unlock tempolary lock of the route. */
		route_unlock_node(rp);
	}
}

/* Add redistributed route to RIPng table. */
void ripng_redistribute_add(int type, int sub_type, struct prefix_ipv6 *p,
			    ifindex_t ifindex, struct in6_addr *nexthop,
			    route_tag_t tag)
{
	struct route_node *rp;
	struct ripng_info *rinfo = NULL, newinfo;
	struct list *list = NULL;

	/* Redistribute route  */
	if (IN6_IS_ADDR_LINKLOCAL(&p->prefix))
		return;
	if (IN6_IS_ADDR_LOOPBACK(&p->prefix))
		return;

	rp = route_node_get(ripng->table, (struct prefix *)p);

	memset(&newinfo, 0, sizeof(struct ripng_info));
	newinfo.type = type;
	newinfo.sub_type = sub_type;
	newinfo.ifindex = ifindex;
	newinfo.metric = 1;
	if (tag <= UINT16_MAX) /* RIPng only supports 16 bit tags */
		newinfo.tag = tag;
	newinfo.rp = rp;
	if (nexthop && IN6_IS_ADDR_LINKLOCAL(nexthop))
		newinfo.nexthop = *nexthop;

	if ((list = rp->info) != NULL && listcount(list) != 0) {
		rinfo = listgetdata(listhead(list));

		if (rinfo->type == ZEBRA_ROUTE_CONNECT
		    && rinfo->sub_type == RIPNG_ROUTE_INTERFACE
		    && rinfo->metric != RIPNG_METRIC_INFINITY) {
			route_unlock_node(rp);
			return;
		}

		/* Manually configured RIPng route check.
		 * They have the precedence on all the other entries.
		 **/
		if (rinfo->type == ZEBRA_ROUTE_RIPNG
		    && ((rinfo->sub_type == RIPNG_ROUTE_STATIC)
			|| (rinfo->sub_type == RIPNG_ROUTE_DEFAULT))) {
			if (type != ZEBRA_ROUTE_RIPNG
			    || ((sub_type != RIPNG_ROUTE_STATIC)
				&& (sub_type != RIPNG_ROUTE_DEFAULT))) {
				route_unlock_node(rp);
				return;
			}
		}

		ripng_ecmp_replace(&newinfo);
		route_unlock_node(rp);
	} else
		ripng_ecmp_add(&newinfo);

	if (IS_RIPNG_DEBUG_EVENT) {
		if (!nexthop)
			zlog_debug(
				"Redistribute new prefix %s/%d on the interface %s",
				inet6_ntoa(p->prefix), p->prefixlen,
				ifindex2ifname(ifindex, VRF_DEFAULT));
		else
			zlog_debug(
				"Redistribute new prefix %s/%d with nexthop %s on the interface %s",
				inet6_ntoa(p->prefix), p->prefixlen,
				inet6_ntoa(*nexthop),
				ifindex2ifname(ifindex, VRF_DEFAULT));
	}

	ripng_event(RIPNG_TRIGGERED_UPDATE, 0);
}

/* Delete redistributed route to RIPng table. */
void ripng_redistribute_delete(int type, int sub_type, struct prefix_ipv6 *p,
			       ifindex_t ifindex)
{
	struct route_node *rp;
	struct ripng_info *rinfo;

	if (IN6_IS_ADDR_LINKLOCAL(&p->prefix))
		return;
	if (IN6_IS_ADDR_LOOPBACK(&p->prefix))
		return;

	rp = route_node_lookup(ripng->table, (struct prefix *)p);

	if (rp) {
		struct list *list = rp->info;

		if (list != NULL && listcount(list) != 0) {
			rinfo = listgetdata(listhead(list));
			if (rinfo != NULL && rinfo->type == type
			    && rinfo->sub_type == sub_type
			    && rinfo->ifindex == ifindex) {
				/* Perform poisoned reverse. */
				rinfo->metric = RIPNG_METRIC_INFINITY;
				RIPNG_TIMER_ON(rinfo->t_garbage_collect,
					       ripng_garbage_collect,
					       ripng->garbage_time);
				RIPNG_TIMER_OFF(rinfo->t_timeout);

				/* Aggregate count decrement. */
				ripng_aggregate_decrement(rp, rinfo);

				rinfo->flags |= RIPNG_RTF_CHANGED;

				if (IS_RIPNG_DEBUG_EVENT)
					zlog_debug(
						"Poisone %s/%d on the interface %s with an "
						"infinity metric [delete]",
						inet6_ntoa(p->prefix),
						p->prefixlen,
						ifindex2ifname(ifindex,
							       VRF_DEFAULT));

				ripng_event(RIPNG_TRIGGERED_UPDATE, 0);
			}
		}
		route_unlock_node(rp);
	}
}

/* Withdraw redistributed route. */
void ripng_redistribute_withdraw(int type)
{
	struct route_node *rp;
	struct ripng_info *rinfo = NULL;
	struct list *list = NULL;

	if (!ripng)
		return;

	for (rp = route_top(ripng->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL) {
			rinfo = listgetdata(listhead(list));
			if ((rinfo->type == type)
			    && (rinfo->sub_type != RIPNG_ROUTE_INTERFACE)) {
				/* Perform poisoned reverse. */
				rinfo->metric = RIPNG_METRIC_INFINITY;
				RIPNG_TIMER_ON(rinfo->t_garbage_collect,
					       ripng_garbage_collect,
					       ripng->garbage_time);
				RIPNG_TIMER_OFF(rinfo->t_timeout);

				/* Aggregate count decrement. */
				ripng_aggregate_decrement(rp, rinfo);

				rinfo->flags |= RIPNG_RTF_CHANGED;

				if (IS_RIPNG_DEBUG_EVENT) {
					struct prefix_ipv6 *p =
						(struct prefix_ipv6 *)&rp->p;

					zlog_debug(
						"Poisone %s/%d on the interface %s [withdraw]",
						inet6_ntoa(p->prefix),
						p->prefixlen,
						ifindex2ifname(rinfo->ifindex,
							       VRF_DEFAULT));
				}

				ripng_event(RIPNG_TRIGGERED_UPDATE, 0);
			}
		}
}

/* RIP routing information. */
static void ripng_response_process(struct ripng_packet *packet, int size,
				   struct sockaddr_in6 *from,
				   struct interface *ifp, int hoplimit)
{
	caddr_t lim;
	struct rte *rte;
	struct ripng_nexthop nexthop;

	/* RFC2080 2.4.2  Response Messages:
	 The Response must be ignored if it is not from the RIPng port.  */
	if (ntohs(from->sin6_port) != RIPNG_PORT_DEFAULT) {
		zlog_warn("RIPng packet comes from non RIPng port %d from %s",
			  ntohs(from->sin6_port), inet6_ntoa(from->sin6_addr));
		ripng_peer_bad_packet(from);
		return;
	}

	/* The datagram's IPv6 source address should be checked to see
	 whether the datagram is from a valid neighbor; the source of the
	 datagram must be a link-local address.  */
	if (!IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr)) {
		zlog_warn("RIPng packet comes from non link local address %s",
			  inet6_ntoa(from->sin6_addr));
		ripng_peer_bad_packet(from);
		return;
	}

	/* It is also worth checking to see whether the response is from one
	 of the router's own addresses.  Interfaces on broadcast networks
	 may receive copies of their own multicasts immediately.  If a
	 router processes its own output as new input, confusion is likely,
	 and such datagrams must be ignored. */
	if (ripng_lladdr_check(ifp, &from->sin6_addr)) {
		zlog_warn(
			"RIPng packet comes from my own link local address %s",
			inet6_ntoa(from->sin6_addr));
		ripng_peer_bad_packet(from);
		return;
	}

	/* As an additional check, periodic advertisements must have their
	 hop counts set to 255, and inbound, multicast packets sent from the
	 RIPng port (i.e. periodic advertisement or triggered update
	 packets) must be examined to ensure that the hop count is 255. */
	if (hoplimit >= 0 && hoplimit != 255) {
		zlog_warn(
			"RIPng packet comes with non 255 hop count %d from %s",
			hoplimit, inet6_ntoa(from->sin6_addr));
		ripng_peer_bad_packet(from);
		return;
	}

	/* Update RIPng peer. */
	ripng_peer_update(from, packet->version);

	/* Reset nexthop. */
	memset(&nexthop, 0, sizeof(struct ripng_nexthop));
	nexthop.flag = RIPNG_NEXTHOP_UNSPEC;

	/* Set RTE pointer. */
	rte = packet->rte;

	for (lim = ((caddr_t)packet) + size; (caddr_t)rte < lim; rte++) {
		/* First of all, we have to check this RTE is next hop RTE or
		   not.  Next hop RTE is completely different with normal RTE so
		   we need special treatment. */
		if (rte->metric == RIPNG_METRIC_NEXTHOP) {
			ripng_nexthop_rte(rte, from, &nexthop);
			continue;
		}

		/* RTE information validation. */

		/* - is the destination prefix valid (e.g., not a multicast
		   prefix and not a link-local address) A link-local address
		   should never be present in an RTE. */
		if (IN6_IS_ADDR_MULTICAST(&rte->addr)) {
			zlog_warn(
				"Destination prefix is a multicast address %s/%d [%d]",
				inet6_ntoa(rte->addr), rte->prefixlen,
				rte->metric);
			ripng_peer_bad_route(from);
			continue;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&rte->addr)) {
			zlog_warn(
				"Destination prefix is a link-local address %s/%d [%d]",
				inet6_ntoa(rte->addr), rte->prefixlen,
				rte->metric);
			ripng_peer_bad_route(from);
			continue;
		}
		if (IN6_IS_ADDR_LOOPBACK(&rte->addr)) {
			zlog_warn(
				"Destination prefix is a loopback address %s/%d [%d]",
				inet6_ntoa(rte->addr), rte->prefixlen,
				rte->metric);
			ripng_peer_bad_route(from);
			continue;
		}

		/* - is the prefix length valid (i.e., between 0 and 128,
		   inclusive) */
		if (rte->prefixlen > 128) {
			zlog_warn("Invalid prefix length %s/%d from %s%%%s",
				  inet6_ntoa(rte->addr), rte->prefixlen,
				  inet6_ntoa(from->sin6_addr), ifp->name);
			ripng_peer_bad_route(from);
			continue;
		}

		/* - is the metric valid (i.e., between 1 and 16, inclusive) */
		if (!(rte->metric >= 1 && rte->metric <= 16)) {
			zlog_warn("Invalid metric %d from %s%%%s", rte->metric,
				  inet6_ntoa(from->sin6_addr), ifp->name);
			ripng_peer_bad_route(from);
			continue;
		}

		/* Vincent: XXX Should we compute the direclty reachable nexthop
		 * for our RIPng network ?
		 **/

		/* Routing table updates. */
		ripng_route_process(rte, from, &nexthop, ifp);
	}
}

/* Response to request message. */
static void ripng_request_process(struct ripng_packet *packet, int size,
				  struct sockaddr_in6 *from,
				  struct interface *ifp)
{
	caddr_t lim;
	struct rte *rte;
	struct prefix_ipv6 p;
	struct route_node *rp;
	struct ripng_info *rinfo;
	struct ripng_interface *ri;

	/* Does not reponse to the requests on the loopback interfaces */
	if (if_is_loopback(ifp))
		return;

	/* Check RIPng process is enabled on this interface. */
	ri = ifp->info;
	if (!ri->running)
		return;

	/* When passive interface is specified, suppress responses */
	if (ri->passive)
		return;

	/* RIPng peer update. */
	ripng_peer_update(from, packet->version);

	lim = ((caddr_t)packet) + size;
	rte = packet->rte;

	/* The Request is processed entry by entry.  If there are no
	   entries, no response is given. */
	if (lim == (caddr_t)rte)
		return;

	/* There is one special case.  If there is exactly one entry in the
	   request, and it has a destination prefix of zero, a prefix length
	   of zero, and a metric of infinity (i.e., 16), then this is a
	   request to send the entire routing table.  In that case, a call
	   is made to the output process to send the routing table to the
	   requesting address/port. */
	if (lim == ((caddr_t)(rte + 1)) && IN6_IS_ADDR_UNSPECIFIED(&rte->addr)
	    && rte->prefixlen == 0 && rte->metric == RIPNG_METRIC_INFINITY) {
		/* All route with split horizon */
		ripng_output_process(ifp, from, ripng_all_route);
	} else {
		/* Except for this special case, processing is quite simple.
		   Examine the list of RTEs in the Request one by one.  For each
		   entry, look up the destination in the router's routing
		   database and, if there is a route, put that route's metric in
		   the metric field of the RTE.  If there is no explicit route
		   to the specified destination, put infinity in the metric
		   field.  Once all the entries have been filled in, change the
		   command from Request to Response and send the datagram back
		   to the requestor. */
		memset(&p, 0, sizeof(struct prefix_ipv6));
		p.family = AF_INET6;

		for (; ((caddr_t)rte) < lim; rte++) {
			p.prefix = rte->addr;
			p.prefixlen = rte->prefixlen;
			apply_mask_ipv6(&p);

			rp = route_node_lookup(ripng->table,
					       (struct prefix *)&p);

			if (rp) {
				rinfo = listgetdata(
					listhead((struct list *)rp->info));
				rte->metric = rinfo->metric;
				route_unlock_node(rp);
			} else
				rte->metric = RIPNG_METRIC_INFINITY;
		}
		packet->command = RIPNG_RESPONSE;

		ripng_send_packet((caddr_t)packet, size, from, ifp);
	}
}

/* First entry point of reading RIPng packet. */
static int ripng_read(struct thread *thread)
{
	int len;
	int sock;
	struct sockaddr_in6 from;
	struct ripng_packet *packet;
	ifindex_t ifindex = 0;
	struct interface *ifp;
	int hoplimit = -1;

	/* Check ripng is active and alive. */
	assert(ripng != NULL);
	assert(ripng->sock >= 0);

	/* Fetch thread data and set read pointer to empty for event
	   managing.  `sock' sould be same as ripng->sock. */
	sock = THREAD_FD(thread);
	ripng->t_read = NULL;

	/* Add myself to the next event. */
	ripng_event(RIPNG_READ, sock);

	/* Read RIPng packet. */
	len = ripng_recv_packet(sock, STREAM_DATA(ripng->ibuf),
				STREAM_SIZE(ripng->ibuf), &from, &ifindex,
				&hoplimit);
	if (len < 0) {
		zlog_warn("RIPng recvfrom failed: %s.", safe_strerror(errno));
		return len;
	}

	/* Check RTE boundary.  RTE size (Packet length - RIPng header size
	   (4)) must be multiple size of one RTE size (20). */
	if (((len - 4) % 20) != 0) {
		zlog_warn("RIPng invalid packet size %d from %s", len,
			  inet6_ntoa(from.sin6_addr));
		ripng_peer_bad_packet(&from);
		return 0;
	}

	packet = (struct ripng_packet *)STREAM_DATA(ripng->ibuf);
	ifp = if_lookup_by_index(ifindex, VRF_DEFAULT);

	/* RIPng packet received. */
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("RIPng packet received from %s port %d on %s",
			   inet6_ntoa(from.sin6_addr), ntohs(from.sin6_port),
			   ifp ? ifp->name : "unknown");

	/* Logging before packet checking. */
	if (IS_RIPNG_DEBUG_RECV)
		ripng_packet_dump(packet, len, "RECV");

	/* Packet comes from unknown interface. */
	if (ifp == NULL) {
		zlog_warn("RIPng packet comes from unknown interface %d",
			  ifindex);
		return 0;
	}

	/* Packet version mismatch checking. */
	if (packet->version != ripng->version) {
		zlog_warn(
			"RIPng packet version %d doesn't fit to my version %d",
			packet->version, ripng->version);
		ripng_peer_bad_packet(&from);
		return 0;
	}

	/* Process RIPng packet. */
	switch (packet->command) {
	case RIPNG_REQUEST:
		ripng_request_process(packet, len, &from, ifp);
		break;
	case RIPNG_RESPONSE:
		ripng_response_process(packet, len, &from, ifp, hoplimit);
		break;
	default:
		zlog_warn("Invalid RIPng command %d", packet->command);
		ripng_peer_bad_packet(&from);
		break;
	}
	return 0;
}

/* Walk down the RIPng routing table then clear changed flag. */
static void ripng_clear_changed_flag(void)
{
	struct route_node *rp;
	struct ripng_info *rinfo = NULL;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	for (rp = route_top(ripng->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
				UNSET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);
				/* This flag can be set only on the first entry.
				 */
				break;
			}
}

/* Regular update of RIPng route.  Send all routing formation to RIPng
   enabled interface. */
static int ripng_update(struct thread *t)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct ripng_interface *ri;

	/* Clear update timer thread. */
	ripng->t_update = NULL;

	/* Logging update event. */
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("RIPng update timer expired!");

	/* Supply routes to each interface. */
	FOR_ALL_INTERFACES (vrf, ifp) {
		ri = ifp->info;

		if (if_is_loopback(ifp) || !if_is_up(ifp))
			continue;

		if (!ri->running)
			continue;

		/* When passive interface is specified, suppress announce to the
		   interface. */
		if (ri->passive)
			continue;

#if RIPNG_ADVANCED
		if (ri->ri_send == RIPNG_SEND_OFF) {
			if (IS_RIPNG_DEBUG_EVENT)
				zlog_debug(
					"[Event] RIPng send to if %d is suppressed by config",
					ifp->ifindex);
			continue;
		}
#endif /* RIPNG_ADVANCED */

		ripng_output_process(ifp, NULL, ripng_all_route);
	}

	/* Triggered updates may be suppressed if a regular update is due by
	   the time the triggered update would be sent. */
	if (ripng->t_triggered_interval) {
		thread_cancel(ripng->t_triggered_interval);
		ripng->t_triggered_interval = NULL;
	}
	ripng->trigger = 0;

	/* Reset flush event. */
	ripng_event(RIPNG_UPDATE_EVENT, 0);

	return 0;
}

/* Triggered update interval timer. */
static int ripng_triggered_interval(struct thread *t)
{
	ripng->t_triggered_interval = NULL;

	if (ripng->trigger) {
		ripng->trigger = 0;
		ripng_triggered_update(t);
	}
	return 0;
}

/* Execute triggered update. */
int ripng_triggered_update(struct thread *t)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct ripng_interface *ri;
	int interval;

	ripng->t_triggered_update = NULL;

	/* Cancel interval timer. */
	if (ripng->t_triggered_interval) {
		thread_cancel(ripng->t_triggered_interval);
		ripng->t_triggered_interval = NULL;
	}
	ripng->trigger = 0;

	/* Logging triggered update. */
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("RIPng triggered update!");

	/* Split Horizon processing is done when generating triggered
	   updates as well as normal updates (see section 2.6). */
	FOR_ALL_INTERFACES (vrf, ifp) {
		ri = ifp->info;

		if (if_is_loopback(ifp) || !if_is_up(ifp))
			continue;

		if (!ri->running)
			continue;

		/* When passive interface is specified, suppress announce to the
		   interface. */
		if (ri->passive)
			continue;

		ripng_output_process(ifp, NULL, ripng_changed_route);
	}

	/* Once all of the triggered updates have been generated, the route
	   change flags should be cleared. */
	ripng_clear_changed_flag();

	/* After a triggered update is sent, a timer should be set for a
	   random interval between 1 and 5 seconds.  If other changes that
	   would trigger updates occur before the timer expires, a single
	   update is triggered when the timer expires. */
	interval = (random() % 5) + 1;

	ripng->t_triggered_interval = NULL;
	thread_add_timer(master, ripng_triggered_interval, NULL, interval,
			 &ripng->t_triggered_interval);

	return 0;
}

/* Write routing table entry to the stream and return next index of
   the routing table entry in the stream. */
int ripng_write_rte(int num, struct stream *s, struct prefix_ipv6 *p,
		    struct in6_addr *nexthop, uint16_t tag, uint8_t metric)
{
	/* RIPng packet header. */
	if (num == 0) {
		stream_putc(s, RIPNG_RESPONSE);
		stream_putc(s, RIPNG_V1);
		stream_putw(s, 0);
	}

	/* Write routing table entry. */
	if (!nexthop) {
		assert(p);
		stream_write(s, (uint8_t *)&p->prefix, sizeof(struct in6_addr));
	} else
		stream_write(s, (uint8_t *)nexthop, sizeof(struct in6_addr));
	stream_putw(s, tag);
	if (p)
		stream_putc(s, p->prefixlen);
	else
		stream_putc(s, 0);
	stream_putc(s, metric);

	return ++num;
}

/* Send RESPONSE message to specified destination. */
void ripng_output_process(struct interface *ifp, struct sockaddr_in6 *to,
			  int route_type)
{
	int ret;
	struct route_node *rp;
	struct ripng_info *rinfo;
	struct ripng_interface *ri;
	struct ripng_aggregate *aggregate;
	struct prefix_ipv6 *p;
	struct list *ripng_rte_list;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	if (IS_RIPNG_DEBUG_EVENT) {
		if (to)
			zlog_debug("RIPng update routes to neighbor %s",
				   inet6_ntoa(to->sin6_addr));
		else
			zlog_debug("RIPng update routes on interface %s",
				   ifp->name);
	}

	/* Get RIPng interface. */
	ri = ifp->info;

	ripng_rte_list = ripng_rte_new();

	for (rp = route_top(ripng->table); rp; rp = route_next(rp)) {
		if ((list = rp->info) != NULL
		    && (rinfo = listgetdata(listhead(list))) != NULL
		    && rinfo->suppress == 0) {
			/* If no route-map are applied, the RTE will be these
			 * following
			 * informations.
			 */
			p = (struct prefix_ipv6 *)&rp->p;
			rinfo->metric_out = rinfo->metric;
			rinfo->tag_out = rinfo->tag;
			memset(&rinfo->nexthop_out, 0,
			       sizeof(rinfo->nexthop_out));
			/* In order to avoid some local loops,
			 * if the RIPng route has a nexthop via this interface,
			 * keep the nexthop,
			 * otherwise set it to 0. The nexthop should not be
			 * propagated
			 * beyond the local broadcast/multicast area in order
			 * to avoid an IGP multi-level recursive look-up.
			 */
			if (rinfo->ifindex == ifp->ifindex)
				rinfo->nexthop_out = rinfo->nexthop;

			/* Apply output filters. */
			ret = ripng_filter(RIPNG_FILTER_OUT, p, ri);
			if (ret < 0)
				continue;

			/* Changed route only output. */
			if (route_type == ripng_changed_route
			    && (!(rinfo->flags & RIPNG_RTF_CHANGED)))
				continue;

			/* Split horizon. */
			if (ri->split_horizon == RIPNG_SPLIT_HORIZON) {
				/* We perform split horizon for RIPng routes. */
				int suppress = 0;
				struct ripng_info *tmp_rinfo = NULL;

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  tmp_rinfo))
					if (tmp_rinfo->type == ZEBRA_ROUTE_RIPNG
					    && tmp_rinfo->ifindex
						       == ifp->ifindex) {
						suppress = 1;
						break;
					}
				if (suppress)
					continue;
			}

			/* Preparation for route-map. */
			rinfo->metric_set = 0;
			/* nexthop_out,
			 * metric_out
			 * and tag_out are already initialized.
			 */

			/* Interface route-map */
			if (ri->routemap[RIPNG_FILTER_OUT]) {
				int ret;

				ret = route_map_apply(
					ri->routemap[RIPNG_FILTER_OUT],
					(struct prefix *)p, RMAP_RIPNG, rinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"RIPng %s/%d is filtered by route-map out",
							inet6_ntoa(p->prefix),
							p->prefixlen);
					continue;
				}
			}

			/* Redistribute route-map. */
			if (ripng->route_map[rinfo->type].name) {
				int ret;

				ret = route_map_apply(
					ripng->route_map[rinfo->type].map,
					(struct prefix *)p, RMAP_RIPNG, rinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"RIPng %s/%d is filtered by route-map",
							inet6_ntoa(p->prefix),
							p->prefixlen);
					continue;
				}
			}

			/* When the route-map does not set metric. */
			if (!rinfo->metric_set) {
				/* If the redistribute metric is set. */
				if (ripng->route_map[rinfo->type].metric_config
				    && rinfo->metric != RIPNG_METRIC_INFINITY) {
					rinfo->metric_out =
						ripng->route_map[rinfo->type]
							.metric;
				} else {
					/* If the route is not connected or
					   localy generated
					   one, use default-metric value */
					if (rinfo->type != ZEBRA_ROUTE_RIPNG
					    && rinfo->type
						       != ZEBRA_ROUTE_CONNECT
					    && rinfo->metric
						       != RIPNG_METRIC_INFINITY)
						rinfo->metric_out =
							ripng->default_metric;
				}
			}

			/* Apply offset-list */
			if (rinfo->metric_out != RIPNG_METRIC_INFINITY)
				ripng_offset_list_apply_out(p, ifp,
							    &rinfo->metric_out);

			if (rinfo->metric_out > RIPNG_METRIC_INFINITY)
				rinfo->metric_out = RIPNG_METRIC_INFINITY;

			/* Perform split-horizon with poisoned reverse
			 * for RIPng routes.
			 **/
			if (ri->split_horizon
			    == RIPNG_SPLIT_HORIZON_POISONED_REVERSE) {
				struct ripng_info *tmp_rinfo = NULL;

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  tmp_rinfo))
					if ((tmp_rinfo->type
					     == ZEBRA_ROUTE_RIPNG)
					    && tmp_rinfo->ifindex
						       == ifp->ifindex)
						rinfo->metric_out =
							RIPNG_METRIC_INFINITY;
			}

			/* Add RTE to the list */
			ripng_rte_add(ripng_rte_list, p, rinfo, NULL);
		}

		/* Process the aggregated RTE entry */
		if ((aggregate = rp->aggregate) != NULL && aggregate->count > 0
		    && aggregate->suppress == 0) {
			/* If no route-map are applied, the RTE will be these
			 * following
			 * informations.
			 */
			p = (struct prefix_ipv6 *)&rp->p;
			aggregate->metric_set = 0;
			aggregate->metric_out = aggregate->metric;
			aggregate->tag_out = aggregate->tag;
			memset(&aggregate->nexthop_out, 0,
			       sizeof(aggregate->nexthop_out));

			/* Apply output filters.*/
			ret = ripng_filter(RIPNG_FILTER_OUT, p, ri);
			if (ret < 0)
				continue;

			/* Interface route-map */
			if (ri->routemap[RIPNG_FILTER_OUT]) {
				int ret;
				struct ripng_info newinfo;

				/* let's cast the aggregate structure to
				 * ripng_info */
				memset(&newinfo, 0, sizeof(struct ripng_info));
				/* the nexthop is :: */
				newinfo.metric = aggregate->metric;
				newinfo.metric_out = aggregate->metric_out;
				newinfo.tag = aggregate->tag;
				newinfo.tag_out = aggregate->tag_out;

				ret = route_map_apply(
					ri->routemap[RIPNG_FILTER_OUT],
					(struct prefix *)p, RMAP_RIPNG,
					&newinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"RIPng %s/%d is filtered by route-map out",
							inet6_ntoa(p->prefix),
							p->prefixlen);
					continue;
				}

				aggregate->metric_out = newinfo.metric_out;
				aggregate->tag_out = newinfo.tag_out;
				if (IN6_IS_ADDR_LINKLOCAL(&newinfo.nexthop_out))
					aggregate->nexthop_out =
						newinfo.nexthop_out;
			}

			/* There is no redistribute routemap for the aggregated
			 * RTE */

			/* Changed route only output. */
			/* XXX, vincent, in order to increase time convergence,
			 * it should be announced if a child has changed.
			 */
			if (route_type == ripng_changed_route)
				continue;

			/* Apply offset-list */
			if (aggregate->metric_out != RIPNG_METRIC_INFINITY)
				ripng_offset_list_apply_out(
					p, ifp, &aggregate->metric_out);

			if (aggregate->metric_out > RIPNG_METRIC_INFINITY)
				aggregate->metric_out = RIPNG_METRIC_INFINITY;

			/* Add RTE to the list */
			ripng_rte_add(ripng_rte_list, p, NULL, aggregate);
		}
	}

	/* Flush the list */
	ripng_rte_send(ripng_rte_list, ifp, to);
	ripng_rte_free(ripng_rte_list);
}

/* Create new RIPng instance and set it to global variable. */
static int ripng_create(void)
{
	/* ripng should be NULL. */
	assert(ripng == NULL);

	/* Allocaste RIPng instance. */
	ripng = XCALLOC(MTYPE_RIPNG, sizeof(struct ripng));

	/* Default version and timer values. */
	ripng->version = RIPNG_V1;
	ripng->update_time = RIPNG_UPDATE_TIMER_DEFAULT;
	ripng->timeout_time = RIPNG_TIMEOUT_TIMER_DEFAULT;
	ripng->garbage_time = RIPNG_GARBAGE_TIMER_DEFAULT;
	ripng->default_metric = RIPNG_DEFAULT_METRIC_DEFAULT;

	/* Make buffer.  */
	ripng->ibuf = stream_new(RIPNG_MAX_PACKET_SIZE * 5);
	ripng->obuf = stream_new(RIPNG_MAX_PACKET_SIZE);

	/* Initialize RIPng routig table. */
	ripng->table = route_table_init();
	ripng->route = route_table_init();
	ripng->aggregate = route_table_init();

	/* Make socket. */
	ripng->sock = ripng_make_socket();
	if (ripng->sock < 0)
		return ripng->sock;

	/* Threads. */
	ripng_event(RIPNG_READ, ripng->sock);
	ripng_event(RIPNG_UPDATE_EVENT, 1);

	return 0;
}

/* Send RIPng request to the interface. */
int ripng_request(struct interface *ifp)
{
	struct rte *rte;
	struct ripng_packet ripng_packet;

	/* In default ripd doesn't send RIP_REQUEST to the loopback interface.
	 */
	if (if_is_loopback(ifp))
		return 0;

	/* If interface is down, don't send RIP packet. */
	if (!if_is_up(ifp))
		return 0;

	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("RIPng send request to %s", ifp->name);

	memset(&ripng_packet, 0, sizeof(ripng_packet));
	ripng_packet.command = RIPNG_REQUEST;
	ripng_packet.version = RIPNG_V1;
	rte = ripng_packet.rte;
	rte->metric = RIPNG_METRIC_INFINITY;

	return ripng_send_packet((caddr_t)&ripng_packet, sizeof(ripng_packet),
				 NULL, ifp);
}


static int ripng_update_jitter(int time)
{
	return ((random() % (time + 1)) - (time / 2));
}

void ripng_event(enum ripng_event event, int sock)
{
	int jitter = 0;

	switch (event) {
	case RIPNG_READ:
		thread_add_read(master, ripng_read, NULL, sock, &ripng->t_read);
		break;
	case RIPNG_UPDATE_EVENT:
		if (ripng->t_update) {
			thread_cancel(ripng->t_update);
			ripng->t_update = NULL;
		}
		/* Update timer jitter. */
		jitter = ripng_update_jitter(ripng->update_time);

		ripng->t_update = NULL;
		thread_add_timer(master, ripng_update, NULL,
				 sock ? 2 : ripng->update_time + jitter,
				 &ripng->t_update);
		break;
	case RIPNG_TRIGGERED_UPDATE:
		if (ripng->t_triggered_interval)
			ripng->trigger = 1;
		else
			thread_add_event(master, ripng_triggered_update, NULL,
					 0, &ripng->t_triggered_update);
		break;
	default:
		break;
	}
}


/* Print out routes update time. */
static void ripng_vty_out_uptime(struct vty *vty, struct ripng_info *rinfo)
{
	time_t clock;
	struct tm *tm;
#define TIME_BUF 25
	char timebuf[TIME_BUF];
	struct thread *thread;

	if ((thread = rinfo->t_timeout) != NULL) {
		clock = thread_timer_remain_second(thread);
		tm = gmtime(&clock);
		strftime(timebuf, TIME_BUF, "%M:%S", tm);
		vty_out(vty, "%5s", timebuf);
	} else if ((thread = rinfo->t_garbage_collect) != NULL) {
		clock = thread_timer_remain_second(thread);
		tm = gmtime(&clock);
		strftime(timebuf, TIME_BUF, "%M:%S", tm);
		vty_out(vty, "%5s", timebuf);
	}
}

static char *ripng_route_subtype_print(struct ripng_info *rinfo)
{
	static char str[3];
	memset(str, 0, 3);

	if (rinfo->suppress)
		strcat(str, "S");

	switch (rinfo->sub_type) {
	case RIPNG_ROUTE_RTE:
		strcat(str, "n");
		break;
	case RIPNG_ROUTE_STATIC:
		strcat(str, "s");
		break;
	case RIPNG_ROUTE_DEFAULT:
		strcat(str, "d");
		break;
	case RIPNG_ROUTE_REDISTRIBUTE:
		strcat(str, "r");
		break;
	case RIPNG_ROUTE_INTERFACE:
		strcat(str, "i");
		break;
	default:
		strcat(str, "?");
		break;
	}

	return str;
}

DEFUN (show_ipv6_ripng,
       show_ipv6_ripng_cmd,
       "show ipv6 ripng",
       SHOW_STR
       IPV6_STR
       "Show RIPng routes\n")
{
	struct route_node *rp;
	struct ripng_info *rinfo;
	struct ripng_aggregate *aggregate;
	struct prefix_ipv6 *p;
	struct list *list = NULL;
	struct listnode *listnode = NULL;
	int len;

	if (!ripng)
		return CMD_SUCCESS;

	/* Header of display. */
	vty_out(vty,
		"Codes: R - RIPng, C - connected, S - Static, O - OSPF, B - BGP\n"
		"Sub-codes:\n"
		"      (n) - normal, (s) - static, (d) - default, (r) - redistribute,\n"
		"      (i) - interface, (a/S) - aggregated/Suppressed\n\n"
		"   Network      Next Hop                      Via     Metric Tag Time\n");

	for (rp = route_top(ripng->table); rp; rp = route_next(rp)) {
		if ((aggregate = rp->aggregate) != NULL) {
			p = (struct prefix_ipv6 *)&rp->p;

#ifdef DEBUG
			vty_out(vty, "R(a) %d/%d %s/%d ", aggregate->count,
				aggregate->suppress, inet6_ntoa(p->prefix),
				p->prefixlen);
#else
			vty_out(vty, "R(a) %s/%d ", inet6_ntoa(p->prefix),
				p->prefixlen);
#endif /* DEBUG */
			vty_out(vty, "\n");
			vty_out(vty, "%*s", 18, " ");

			vty_out(vty, "%*s", 28, " ");
			vty_out(vty, "self      %2d  %3" ROUTE_TAG_PRI "\n",
				aggregate->metric, (route_tag_t)aggregate->tag);
		}

		if ((list = rp->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
				p = (struct prefix_ipv6 *)&rp->p;

#ifdef DEBUG
				vty_out(vty, "%c(%s) 0/%d %s/%d ",
					zebra_route_char(rinfo->type),
					ripng_route_subtype_print(rinfo),
					rinfo->suppress, inet6_ntoa(p->prefix),
					p->prefixlen);
#else
				vty_out(vty, "%c(%s) %s/%d ",
					zebra_route_char(rinfo->type),
					ripng_route_subtype_print(rinfo),
					inet6_ntoa(p->prefix), p->prefixlen);
#endif /* DEBUG */
				vty_out(vty, "\n");
				vty_out(vty, "%*s", 18, " ");
				len = vty_out(vty, "%s",
					      inet6_ntoa(rinfo->nexthop));

				len = 28 - len;
				if (len > 0)
					vty_out(vty, "%*s", len, " ");

				/* from */
				if ((rinfo->type == ZEBRA_ROUTE_RIPNG)
				    && (rinfo->sub_type == RIPNG_ROUTE_RTE)) {
					len = vty_out(
						vty, "%s",
						ifindex2ifname(rinfo->ifindex,
							       VRF_DEFAULT));
				} else if (rinfo->metric
					   == RIPNG_METRIC_INFINITY) {
					len = vty_out(vty, "kill");
				} else
					len = vty_out(vty, "self");

				len = 9 - len;
				if (len > 0)
					vty_out(vty, "%*s", len, " ");

				vty_out(vty, " %2d  %3" ROUTE_TAG_PRI "  ",
					rinfo->metric, (route_tag_t)rinfo->tag);

				/* time */
				if ((rinfo->type == ZEBRA_ROUTE_RIPNG)
				    && (rinfo->sub_type == RIPNG_ROUTE_RTE)) {
					/* RTE from remote RIP routers */
					ripng_vty_out_uptime(vty, rinfo);
				} else if (rinfo->metric
					   == RIPNG_METRIC_INFINITY) {
					/* poisonous reversed routes (gc) */
					ripng_vty_out_uptime(vty, rinfo);
				}

				vty_out(vty, "\n");
			}
	}

	return CMD_SUCCESS;
}

DEFUN (show_ipv6_ripng_status,
       show_ipv6_ripng_status_cmd,
       "show ipv6 ripng status",
       SHOW_STR
       IPV6_STR
       "Show RIPng routes\n"
       "IPv6 routing protocol process parameters and statistics\n")
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	if (!ripng)
		return CMD_SUCCESS;

	vty_out(vty, "Routing Protocol is \"RIPng\"\n");
	vty_out(vty, "  Sending updates every %ld seconds with +/-50%%,",
		ripng->update_time);
	vty_out(vty, " next due in %lu seconds\n",
		thread_timer_remain_second(ripng->t_update));
	vty_out(vty, "  Timeout after %ld seconds,", ripng->timeout_time);
	vty_out(vty, " garbage collect after %ld seconds\n",
		ripng->garbage_time);

	/* Filtering status show. */
	config_show_distribute(vty);

	/* Default metric information. */
	vty_out(vty, "  Default redistribution metric is %d\n",
		ripng->default_metric);

	/* Redistribute information. */
	vty_out(vty, "  Redistributing:");
	ripng_redistribute_write(vty, 0);
	vty_out(vty, "\n");

	vty_out(vty, "  Default version control: send version %d,",
		ripng->version);
	vty_out(vty, " receive version %d \n", ripng->version);

	vty_out(vty, "    Interface        Send  Recv\n");

	FOR_ALL_INTERFACES (vrf, ifp) {
		struct ripng_interface *ri;

		ri = ifp->info;

		if (ri->enable_network || ri->enable_interface) {

			vty_out(vty, "    %-17s%-3d   %-3d\n", ifp->name,
				ripng->version, ripng->version);
		}
	}

	vty_out(vty, "  Routing for Networks:\n");
	ripng_network_write(vty, 0);

	vty_out(vty, "  Routing Information Sources:\n");
	vty_out(vty,
		"    Gateway          BadPackets BadRoutes  Distance Last Update\n");
	ripng_peer_display(vty);

	return CMD_SUCCESS;
}

DEFUN (clear_ipv6_rip,
       clear_ipv6_rip_cmd,
       "clear ipv6 ripng",
       CLEAR_STR
       IPV6_STR
       "Clear IPv6 RIP database\n")
{
	struct route_node *rp;
	struct ripng_info *rinfo;
	struct list *list;
	struct listnode *listnode;

	/* Clear received RIPng routes */
	for (rp = route_top(ripng->table); rp; rp = route_next(rp)) {
		list = rp->info;
		if (list == NULL)
			continue;

		for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
			if (!ripng_route_rte(rinfo))
				continue;

			if (CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
				ripng_zebra_ipv6_delete(rp);
			break;
		}

		if (rinfo) {
			RIPNG_TIMER_OFF(rinfo->t_timeout);
			RIPNG_TIMER_OFF(rinfo->t_garbage_collect);
			listnode_delete(list, rinfo);
			ripng_info_free(rinfo);
		}

		if (list_isempty(list)) {
			list_delete_and_null(&list);
			rp->info = NULL;
			route_unlock_node(rp);
		}
	}

	return CMD_SUCCESS;
}

DEFUN_NOSH (router_ripng,
       router_ripng_cmd,
       "router ripng",
       "Enable a routing process\n"
       "Make RIPng instance command\n")
{
	int ret;

	vty->node = RIPNG_NODE;

	if (!ripng) {
		ret = ripng_create();

		/* Notice to user we couldn't create RIPng. */
		if (ret < 0) {
			zlog_warn("can't create RIPng");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_router_ripng,
       no_router_ripng_cmd,
       "no router ripng",
       NO_STR
       "Enable a routing process\n"
       "Make RIPng instance command\n")
{
	if (ripng)
		ripng_clean();
	return CMD_SUCCESS;
}

DEFUN (ripng_route,
       ripng_route_cmd,
       "route IPV6ADDR",
       "Static route setup\n"
       "Set static RIPng route announcement\n")
{
	int idx_ipv6addr = 1;
	int ret;
	struct prefix_ipv6 p;
	struct route_node *rp;

	ret = str2prefix_ipv6(argv[idx_ipv6addr]->arg,
			      (struct prefix_ipv6 *)&p);
	if (ret <= 0) {
		vty_out(vty, "Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask_ipv6(&p);

	rp = route_node_get(ripng->route, (struct prefix *)&p);
	if (rp->info) {
		vty_out(vty, "There is already same static route.\n");
		route_unlock_node(rp);
		return CMD_WARNING;
	}
	rp->info = (void *)1;

	ripng_redistribute_add(ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0,
			       NULL, 0);

	return CMD_SUCCESS;
}

DEFUN (no_ripng_route,
       no_ripng_route_cmd,
       "no route IPV6ADDR",
       NO_STR
       "Static route setup\n"
       "Delete static RIPng route announcement\n")
{
	int idx_ipv6addr = 2;
	int ret;
	struct prefix_ipv6 p;
	struct route_node *rp;

	ret = str2prefix_ipv6(argv[idx_ipv6addr]->arg,
			      (struct prefix_ipv6 *)&p);
	if (ret <= 0) {
		vty_out(vty, "Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	apply_mask_ipv6(&p);

	rp = route_node_lookup(ripng->route, (struct prefix *)&p);
	if (!rp) {
		vty_out(vty, "Can't find static route.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ripng_redistribute_delete(ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_STATIC, &p, 0);
	route_unlock_node(rp);

	rp->info = NULL;
	route_unlock_node(rp);

	return CMD_SUCCESS;
}

DEFUN (ripng_aggregate_address,
       ripng_aggregate_address_cmd,
       "aggregate-address X:X::X:X/M",
       "Set aggregate RIPng route announcement\n"
       "Aggregate network\n")
{
	int idx_ipv6_prefixlen = 1;
	int ret;
	struct prefix p;
	struct route_node *node;

	ret = str2prefix_ipv6(argv[idx_ipv6_prefixlen]->arg,
			      (struct prefix_ipv6 *)&p);
	if (ret <= 0) {
		vty_out(vty, "Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Check aggregate alredy exist or not. */
	node = route_node_get(ripng->aggregate, &p);
	if (node->info) {
		vty_out(vty, "There is already same aggregate route.\n");
		route_unlock_node(node);
		return CMD_WARNING;
	}
	node->info = (void *)1;

	ripng_aggregate_add(&p);

	return CMD_SUCCESS;
}

DEFUN (no_ripng_aggregate_address,
       no_ripng_aggregate_address_cmd,
       "no aggregate-address X:X::X:X/M",
       NO_STR
       "Delete aggregate RIPng route announcement\n"
       "Aggregate network\n")
{
	int idx_ipv6_prefixlen = 2;
	int ret;
	struct prefix p;
	struct route_node *rn;

	ret = str2prefix_ipv6(argv[idx_ipv6_prefixlen]->arg,
			      (struct prefix_ipv6 *)&p);
	if (ret <= 0) {
		vty_out(vty, "Malformed address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	rn = route_node_lookup(ripng->aggregate, &p);
	if (!rn) {
		vty_out(vty, "Can't find aggregate route.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	route_unlock_node(rn);
	rn->info = NULL;
	route_unlock_node(rn);

	ripng_aggregate_delete(&p);

	return CMD_SUCCESS;
}

DEFUN (ripng_default_metric,
       ripng_default_metric_cmd,
       "default-metric (1-16)",
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	int idx_number = 1;
	if (ripng) {
		ripng->default_metric = atoi(argv[idx_number]->arg);
	}
	return CMD_SUCCESS;
}

DEFUN (no_ripng_default_metric,
       no_ripng_default_metric_cmd,
       "no default-metric [(1-16)]",
       NO_STR
       "Set a metric of redistribute routes\n"
       "Default metric\n")
{
	if (ripng) {
		ripng->default_metric = RIPNG_DEFAULT_METRIC_DEFAULT;
	}
	return CMD_SUCCESS;
}


#if 0
/* RIPng update timer setup. */
DEFUN (ripng_update_timer,
       ripng_update_timer_cmd,
       "update-timer SECOND",
       "Set RIPng update timer in seconds\n"
       "Seconds\n")
{
  unsigned long update;
  char *endptr = NULL;

  update = strtoul (argv[0], &endptr, 10);
  if (update == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "update timer value error\n");
      return CMD_WARNING_CONFIG_FAILED;
    }

  ripng->update_time = update;

  ripng_event (RIPNG_UPDATE_EVENT, 0);
  return CMD_SUCCESS;
}

DEFUN (no_ripng_update_timer,
       no_ripng_update_timer_cmd,
       "no update-timer SECOND",
       NO_STR
       "Unset RIPng update timer in seconds\n"
       "Seconds\n")
{
  ripng->update_time = RIPNG_UPDATE_TIMER_DEFAULT;
  ripng_event (RIPNG_UPDATE_EVENT, 0);
  return CMD_SUCCESS;
}

/* RIPng timeout timer setup. */
DEFUN (ripng_timeout_timer,
       ripng_timeout_timer_cmd,
       "timeout-timer SECOND",
       "Set RIPng timeout timer in seconds\n"
       "Seconds\n")
{
  unsigned long timeout;
  char *endptr = NULL;

  timeout = strtoul (argv[0], &endptr, 10);
  if (timeout == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "timeout timer value error\n");
      return CMD_WARNING_CONFIG_FAILED;
    }

  ripng->timeout_time = timeout;

  return CMD_SUCCESS;
}

DEFUN (no_ripng_timeout_timer,
       no_ripng_timeout_timer_cmd,
       "no timeout-timer SECOND",
       NO_STR
       "Unset RIPng timeout timer in seconds\n"
       "Seconds\n")
{
  ripng->timeout_time = RIPNG_TIMEOUT_TIMER_DEFAULT;
  return CMD_SUCCESS;
}

/* RIPng garbage timer setup. */
DEFUN (ripng_garbage_timer,
       ripng_garbage_timer_cmd,
       "garbage-timer SECOND",
       "Set RIPng garbage timer in seconds\n"
       "Seconds\n")
{
  unsigned long garbage;
  char *endptr = NULL;

  garbage = strtoul (argv[0], &endptr, 10);
  if (garbage == ULONG_MAX || *endptr != '\0')
    {
      vty_out (vty, "garbage timer value error\n");
      return CMD_WARNING_CONFIG_FAILED;
    }

  ripng->garbage_time = garbage;

  return CMD_SUCCESS;
}

DEFUN (no_ripng_garbage_timer,
       no_ripng_garbage_timer_cmd,
       "no garbage-timer SECOND",
       NO_STR
       "Unset RIPng garbage timer in seconds\n"
       "Seconds\n")
{
  ripng->garbage_time = RIPNG_GARBAGE_TIMER_DEFAULT;
  return CMD_SUCCESS;
}
#endif /* 0 */

DEFUN (ripng_timers,
       ripng_timers_cmd,
       "timers basic (0-65535) (0-65535) (0-65535)",
       "RIPng timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	int idx_number = 2;
	int idx_number_2 = 3;
	int idx_number_3 = 4;
	unsigned long update;
	unsigned long timeout;
	unsigned long garbage;

	update = strtoul(argv[idx_number]->arg, NULL, 10);
	timeout = strtoul(argv[idx_number_2]->arg, NULL, 10);
	garbage = strtoul(argv[idx_number_3]->arg, NULL, 10);

	/* Set each timer value. */
	ripng->update_time = update;
	ripng->timeout_time = timeout;
	ripng->garbage_time = garbage;

	/* Reset update timer thread. */
	ripng_event(RIPNG_UPDATE_EVENT, 0);

	return CMD_SUCCESS;
}

DEFUN (no_ripng_timers,
       no_ripng_timers_cmd,
       "no timers basic [(0-65535) (0-65535) (0-65535)]",
       NO_STR
       "RIPng timers setup\n"
       "Basic timer\n"
       "Routing table update timer value in second. Default is 30.\n"
       "Routing information timeout timer. Default is 180.\n"
       "Garbage collection timer. Default is 120.\n")
{
	/* Set each timer value to the default. */
	ripng->update_time = RIPNG_UPDATE_TIMER_DEFAULT;
	ripng->timeout_time = RIPNG_TIMEOUT_TIMER_DEFAULT;
	ripng->garbage_time = RIPNG_GARBAGE_TIMER_DEFAULT;

	/* Reset update timer thread. */
	ripng_event(RIPNG_UPDATE_EVENT, 0);

	return CMD_SUCCESS;
}

#if 0
DEFUN (show_ipv6_protocols,
       show_ipv6_protocols_cmd,
       "show ipv6 protocols",
       SHOW_STR
       IPV6_STR
       "Routing protocol information\n")
{
  if (! ripng)
    return CMD_SUCCESS;

  vty_out (vty, "Routing Protocol is \"ripng\"\n");
  
  vty_out (vty, "Sending updates every %ld seconds, next due in %d seconds\n",
	   ripng->update_time, 0);

  vty_out (vty, "Timerout after %ld seconds, garbage correct %ld\n",
	   ripng->timeout_time,
	   ripng->garbage_time);

  vty_out (vty, "Outgoing update filter list for all interfaces is not set");
  vty_out (vty, "Incoming update filter list for all interfaces is not set");

  return CMD_SUCCESS;
}
#endif

/* Please be carefull to use this command. */
DEFUN (ripng_default_information_originate,
       ripng_default_information_originate_cmd,
       "default-information originate",
       "Default route information\n"
       "Distribute default route\n")
{
	struct prefix_ipv6 p;

	if (!ripng->default_information) {
		ripng->default_information = 1;

		str2prefix_ipv6("::/0", &p);
		ripng_redistribute_add(ZEBRA_ROUTE_RIPNG, RIPNG_ROUTE_DEFAULT,
				       &p, 0, NULL, 0);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ripng_default_information_originate,
       no_ripng_default_information_originate_cmd,
       "no default-information originate",
       NO_STR
       "Default route information\n"
       "Distribute default route\n")
{
	struct prefix_ipv6 p;

	if (ripng->default_information) {
		ripng->default_information = 0;

		str2prefix_ipv6("::/0", &p);
		ripng_redistribute_delete(ZEBRA_ROUTE_RIPNG,
					  RIPNG_ROUTE_DEFAULT, &p, 0);
	}

	return CMD_SUCCESS;
}

/* Update ECMP routes to zebra when ECMP is disabled. */
static void ripng_ecmp_disable(void)
{
	struct route_node *rp;
	struct ripng_info *rinfo, *tmp_rinfo;
	struct list *list;
	struct listnode *node, *nextnode;

	if (!ripng)
		return;

	for (rp = route_top(ripng->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL && listcount(list) > 1) {
			rinfo = listgetdata(listhead(list));
			if (!ripng_route_rte(rinfo))
				continue;

			/* Drop all other entries, except the first one. */
			for (ALL_LIST_ELEMENTS(list, node, nextnode, tmp_rinfo))
				if (tmp_rinfo != rinfo) {
					RIPNG_TIMER_OFF(tmp_rinfo->t_timeout);
					RIPNG_TIMER_OFF(
						tmp_rinfo->t_garbage_collect);
					list_delete_node(list, node);
					ripng_info_free(tmp_rinfo);
				}

			/* Update zebra. */
			ripng_zebra_ipv6_add(rp);

			/* Set the route change flag. */
			SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

			/* Signal the output process to trigger an update. */
			ripng_event(RIPNG_TRIGGERED_UPDATE, 0);
		}
}

DEFUN (ripng_allow_ecmp,
       ripng_allow_ecmp_cmd,
       "allow-ecmp",
       "Allow Equal Cost MultiPath\n")
{
	if (ripng->ecmp) {
		vty_out(vty, "ECMP is already enabled.\n");
		return CMD_WARNING;
	}

	ripng->ecmp = 1;
	zlog_info("ECMP is enabled.");
	return CMD_SUCCESS;
}

DEFUN (no_ripng_allow_ecmp,
       no_ripng_allow_ecmp_cmd,
       "no allow-ecmp",
       NO_STR
       "Allow Equal Cost MultiPath\n")
{
	if (!ripng->ecmp) {
		vty_out(vty, "ECMP is already disabled.\n");
		return CMD_WARNING;
	}

	ripng->ecmp = 0;
	zlog_info("ECMP is disabled.");
	ripng_ecmp_disable();
	return CMD_SUCCESS;
}

/* RIPng configuration write function. */
static int ripng_config_write(struct vty *vty)
{
	int ripng_network_write(struct vty *, int);
	void ripng_redistribute_write(struct vty *, int);
	int write = 0;
	struct route_node *rp;

	if (ripng) {

		/* RIPng router. */
		vty_out(vty, "router ripng\n");

		if (ripng->default_information)
			vty_out(vty, " default-information originate\n");

		ripng_network_write(vty, 1);

		/* RIPng default metric configuration */
		if (ripng->default_metric != RIPNG_DEFAULT_METRIC_DEFAULT)
			vty_out(vty, " default-metric %d\n",
				ripng->default_metric);

		ripng_redistribute_write(vty, 1);

		/* RIP offset-list configuration. */
		config_write_ripng_offset_list(vty);

		/* RIPng aggregate routes. */
		for (rp = route_top(ripng->aggregate); rp; rp = route_next(rp))
			if (rp->info != NULL)
				vty_out(vty, " aggregate-address %s/%d\n",
					inet6_ntoa(rp->p.u.prefix6),
					rp->p.prefixlen);

		/* ECMP configuration. */
		if (ripng->ecmp)
			vty_out(vty, " allow-ecmp\n");

		/* RIPng static routes. */
		for (rp = route_top(ripng->route); rp; rp = route_next(rp))
			if (rp->info != NULL)
				vty_out(vty, " route %s/%d\n",
					inet6_ntoa(rp->p.u.prefix6),
					rp->p.prefixlen);

		/* RIPng timers configuration. */
		if (ripng->update_time != RIPNG_UPDATE_TIMER_DEFAULT
		    || ripng->timeout_time != RIPNG_TIMEOUT_TIMER_DEFAULT
		    || ripng->garbage_time != RIPNG_GARBAGE_TIMER_DEFAULT) {
			vty_out(vty, " timers basic %ld %ld %ld\n",
				ripng->update_time, ripng->timeout_time,
				ripng->garbage_time);
		}
#if 0
      if (ripng->update_time != RIPNG_UPDATE_TIMER_DEFAULT)
	vty_out (vty, " update-timer %d\n", ripng->update_time);
      if (ripng->timeout_time != RIPNG_TIMEOUT_TIMER_DEFAULT)
	vty_out (vty, " timeout-timer %d\n", ripng->timeout_time);
      if (ripng->garbage_time != RIPNG_GARBAGE_TIMER_DEFAULT)
	vty_out (vty, " garbage-timer %d\n", ripng->garbage_time);
#endif /* 0 */

		write += config_write_distribute(vty);

		write += config_write_if_rmap(vty);

		write++;
	}
	return write;
}

/* RIPng node structure. */
static struct cmd_node cmd_ripng_node = {
	RIPNG_NODE, "%s(config-router)# ", 1,
};

static void ripng_distribute_update(struct distribute *dist)
{
	struct interface *ifp;
	struct ripng_interface *ri;
	struct access_list *alist;
	struct prefix_list *plist;

	if (!dist->ifname)
		return;

	ifp = if_lookup_by_name(dist->ifname, VRF_DEFAULT);
	if (ifp == NULL)
		return;

	ri = ifp->info;

	if (dist->list[DISTRIBUTE_V6_IN]) {
		alist = access_list_lookup(AFI_IP6,
					   dist->list[DISTRIBUTE_V6_IN]);
		if (alist)
			ri->list[RIPNG_FILTER_IN] = alist;
		else
			ri->list[RIPNG_FILTER_IN] = NULL;
	} else
		ri->list[RIPNG_FILTER_IN] = NULL;

	if (dist->list[DISTRIBUTE_V6_OUT]) {
		alist = access_list_lookup(AFI_IP6,
					   dist->list[DISTRIBUTE_V6_OUT]);
		if (alist)
			ri->list[RIPNG_FILTER_OUT] = alist;
		else
			ri->list[RIPNG_FILTER_OUT] = NULL;
	} else
		ri->list[RIPNG_FILTER_OUT] = NULL;

	if (dist->prefix[DISTRIBUTE_V6_IN]) {
		plist = prefix_list_lookup(AFI_IP6,
					   dist->prefix[DISTRIBUTE_V6_IN]);
		if (plist)
			ri->prefix[RIPNG_FILTER_IN] = plist;
		else
			ri->prefix[RIPNG_FILTER_IN] = NULL;
	} else
		ri->prefix[RIPNG_FILTER_IN] = NULL;

	if (dist->prefix[DISTRIBUTE_V6_OUT]) {
		plist = prefix_list_lookup(AFI_IP6,
					   dist->prefix[DISTRIBUTE_V6_OUT]);
		if (plist)
			ri->prefix[RIPNG_FILTER_OUT] = plist;
		else
			ri->prefix[RIPNG_FILTER_OUT] = NULL;
	} else
		ri->prefix[RIPNG_FILTER_OUT] = NULL;
}

void ripng_distribute_update_interface(struct interface *ifp)
{
	struct distribute *dist;

	dist = distribute_lookup(ifp->name);
	if (dist)
		ripng_distribute_update(dist);
}

/* Update all interface's distribute list. */
static void ripng_distribute_update_all(struct prefix_list *notused)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		ripng_distribute_update_interface(ifp);
}

static void ripng_distribute_update_all_wrapper(struct access_list *notused)
{
	ripng_distribute_update_all(NULL);
}

/* delete all the added ripng routes. */
void ripng_clean()
{
	int i;
	struct route_node *rp;
	struct ripng_info *rinfo;
	struct ripng_aggregate *aggregate;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	if (ripng) {
		/* Clear RIPng routes */
		for (rp = route_top(ripng->table); rp; rp = route_next(rp)) {
			if ((list = rp->info) != NULL) {
				rinfo = listgetdata(listhead(list));
				if (ripng_route_rte(rinfo))
					ripng_zebra_ipv6_delete(rp);

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  rinfo)) {
					RIPNG_TIMER_OFF(rinfo->t_timeout);
					RIPNG_TIMER_OFF(
						rinfo->t_garbage_collect);
					ripng_info_free(rinfo);
				}
				list_delete_and_null(&list);
				rp->info = NULL;
				route_unlock_node(rp);
			}

			if ((aggregate = rp->aggregate) != NULL) {
				ripng_aggregate_free(aggregate);
				rp->aggregate = NULL;
				route_unlock_node(rp);
			}
		}

		/* Cancel the RIPng timers */
		RIPNG_TIMER_OFF(ripng->t_update);
		RIPNG_TIMER_OFF(ripng->t_triggered_update);
		RIPNG_TIMER_OFF(ripng->t_triggered_interval);

		/* Cancel the read thread */
		if (ripng->t_read) {
			thread_cancel(ripng->t_read);
			ripng->t_read = NULL;
		}

		/* Close the RIPng socket */
		if (ripng->sock >= 0) {
			close(ripng->sock);
			ripng->sock = -1;
		}

		/* Static RIPng route configuration. */
		for (rp = route_top(ripng->route); rp; rp = route_next(rp))
			if (rp->info) {
				rp->info = NULL;
				route_unlock_node(rp);
			}

		/* RIPng aggregated prefixes */
		for (rp = route_top(ripng->aggregate); rp; rp = route_next(rp))
			if (rp->info) {
				rp->info = NULL;
				route_unlock_node(rp);
			}

		for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
			if (ripng->route_map[i].name)
				free(ripng->route_map[i].name);

		XFREE(MTYPE_ROUTE_TABLE, ripng->table);
		XFREE(MTYPE_ROUTE_TABLE, ripng->route);
		XFREE(MTYPE_ROUTE_TABLE, ripng->aggregate);

		stream_free(ripng->ibuf);
		stream_free(ripng->obuf);

		XFREE(MTYPE_RIPNG, ripng);
		ripng = NULL;
	} /* if (ripng) */

	ripng_clean_network();
	ripng_passive_interface_clean();
	ripng_offset_clean();
	ripng_interface_clean();
	ripng_redistribute_clean();
}

/* Reset all values to the default settings. */
void ripng_reset()
{
	/* Call ripd related reset functions. */
	ripng_debug_reset();
	ripng_route_map_reset();

	/* Call library reset functions. */
	vty_reset();
	access_list_reset();
	prefix_list_reset();

	distribute_list_reset();

	ripng_interface_reset();

	ripng_zclient_reset();
}

static void ripng_if_rmap_update(struct if_rmap *if_rmap)
{
	struct interface *ifp;
	struct ripng_interface *ri;
	struct route_map *rmap;

	ifp = if_lookup_by_name(if_rmap->ifname, VRF_DEFAULT);
	if (ifp == NULL)
		return;

	ri = ifp->info;

	if (if_rmap->routemap[IF_RMAP_IN]) {
		rmap = route_map_lookup_by_name(if_rmap->routemap[IF_RMAP_IN]);
		if (rmap)
			ri->routemap[IF_RMAP_IN] = rmap;
		else
			ri->routemap[IF_RMAP_IN] = NULL;
	} else
		ri->routemap[RIPNG_FILTER_IN] = NULL;

	if (if_rmap->routemap[IF_RMAP_OUT]) {
		rmap = route_map_lookup_by_name(if_rmap->routemap[IF_RMAP_OUT]);
		if (rmap)
			ri->routemap[IF_RMAP_OUT] = rmap;
		else
			ri->routemap[IF_RMAP_OUT] = NULL;
	} else
		ri->routemap[RIPNG_FILTER_OUT] = NULL;
}

void ripng_if_rmap_update_interface(struct interface *ifp)
{
	struct if_rmap *if_rmap;

	if_rmap = if_rmap_lookup(ifp->name);
	if (if_rmap)
		ripng_if_rmap_update(if_rmap);
}

static void ripng_routemap_update_redistribute(void)
{
	int i;

	if (ripng) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			if (ripng->route_map[i].name)
				ripng->route_map[i].map =
					route_map_lookup_by_name(
						ripng->route_map[i].name);
		}
	}
}

static void ripng_routemap_update(const char *unused)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		ripng_if_rmap_update_interface(ifp);

	ripng_routemap_update_redistribute();
}

/* Initialize ripng structure and set commands. */
void ripng_init()
{
	/* Install RIPNG_NODE. */
	install_node(&cmd_ripng_node, ripng_config_write);

	/* Install ripng commands. */
	install_element(VIEW_NODE, &show_ipv6_ripng_cmd);
	install_element(VIEW_NODE, &show_ipv6_ripng_status_cmd);

	install_element(ENABLE_NODE, &clear_ipv6_rip_cmd);

	install_element(CONFIG_NODE, &router_ripng_cmd);
	install_element(CONFIG_NODE, &no_router_ripng_cmd);

	install_default(RIPNG_NODE);
	install_element(RIPNG_NODE, &ripng_route_cmd);
	install_element(RIPNG_NODE, &no_ripng_route_cmd);
	install_element(RIPNG_NODE, &ripng_aggregate_address_cmd);
	install_element(RIPNG_NODE, &no_ripng_aggregate_address_cmd);

	install_element(RIPNG_NODE, &ripng_default_metric_cmd);
	install_element(RIPNG_NODE, &no_ripng_default_metric_cmd);

	install_element(RIPNG_NODE, &ripng_timers_cmd);
	install_element(RIPNG_NODE, &no_ripng_timers_cmd);
#if 0
  install_element (VIEW_NODE, &show_ipv6_protocols_cmd);
  install_element (RIPNG_NODE, &ripng_update_timer_cmd);
  install_element (RIPNG_NODE, &no_ripng_update_timer_cmd);
  install_element (RIPNG_NODE, &ripng_timeout_timer_cmd);
  install_element (RIPNG_NODE, &no_ripng_timeout_timer_cmd);
  install_element (RIPNG_NODE, &ripng_garbage_timer_cmd);
  install_element (RIPNG_NODE, &no_ripng_garbage_timer_cmd);
#endif /* 0 */

	install_element(RIPNG_NODE, &ripng_default_information_originate_cmd);
	install_element(RIPNG_NODE,
			&no_ripng_default_information_originate_cmd);

	install_element(RIPNG_NODE, &ripng_allow_ecmp_cmd);
	install_element(RIPNG_NODE, &no_ripng_allow_ecmp_cmd);

	ripng_if_init();
	ripng_debug_init();

	/* Access list install. */
	access_list_init();
	access_list_add_hook(ripng_distribute_update_all_wrapper);
	access_list_delete_hook(ripng_distribute_update_all_wrapper);

	/* Prefix list initialize.*/
	prefix_list_init();
	prefix_list_add_hook(ripng_distribute_update_all);
	prefix_list_delete_hook(ripng_distribute_update_all);

	/* Distribute list install. */
	distribute_list_init(RIPNG_NODE);
	distribute_list_add_hook(ripng_distribute_update);
	distribute_list_delete_hook(ripng_distribute_update);

	/* Route-map for interface. */
	ripng_route_map_init();
	ripng_offset_init();

	route_map_add_hook(ripng_routemap_update);
	route_map_delete_hook(ripng_routemap_update);

	if_rmap_init(RIPNG_NODE);
	if_rmap_hook_add(ripng_if_rmap_update);
	if_rmap_hook_delete(ripng_if_rmap_update);
}
