// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPng daemon
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "prefix.h"
#include "filter.h"
#include "log.h"
#include "frrevent.h"
#include "memory.h"
#include "if.h"
#include "stream.h"
#include "agg_table.h"
#include "command.h"
#include "sockopt.h"
#include "distribute.h"
#include "plist.h"
#include "routemap.h"
#include "if_rmap.h"
#include "privs.h"
#include "lib_errors.h"
#include "northbound_cli.h"
#include "network.h"
#include "mgmt_be_client.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_route.h"
#include "ripngd/ripng_debug.h"
#include "ripngd/ripng_nexthop.h"

DEFINE_MGROUP(RIPNGD, "ripngd");
DEFINE_MTYPE_STATIC(RIPNGD, RIPNG, "RIPng structure");
DEFINE_MTYPE_STATIC(RIPNGD, RIPNG_VRF_NAME, "RIPng VRF name");
DEFINE_MTYPE_STATIC(RIPNGD, RIPNG_ROUTE, "RIPng route info");

enum { ripng_all_route,
       ripng_changed_route,
};

static void ripng_distribute_update(struct distribute_ctx *ctx,
				    struct distribute *dist);

/* Prototypes. */
void ripng_output_process(struct interface *, struct sockaddr_in6 *, int);
static void ripng_instance_enable(struct ripng *ripng, struct vrf *vrf,
				  int sock);
static void ripng_instance_disable(struct ripng *ripng);
static void ripng_triggered_update(struct event *);
static void ripng_if_rmap_update(struct if_rmap_ctx *ctx,
				 struct if_rmap *if_rmap);

/* Generate rb-tree of RIPng instances. */
static inline int ripng_instance_compare(const struct ripng *a,
					 const struct ripng *b)
{
	return strcmp(a->vrf_name, b->vrf_name);
}
RB_GENERATE(ripng_instance_head, ripng, entry, ripng_instance_compare)

struct ripng_instance_head ripng_instances = RB_INITIALIZER(&ripng_instances);

/* RIPng next hop specification. */
struct ripng_nexthop {
	enum ripng_nexthop_type {
		RIPNG_NEXTHOP_UNSPEC,
		RIPNG_NEXTHOP_ADDRESS
	} flag;
	struct in6_addr address;
};

int ripng_route_rte(struct ripng_info *rinfo)
{
	return (rinfo->type == ZEBRA_ROUTE_RIPNG
		&& rinfo->sub_type == RIPNG_ROUTE_RTE);
}

/* Allocate new ripng information. */
struct ripng_info *ripng_info_new(void)
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

struct ripng *ripng_info_get_instance(const struct ripng_info *rinfo)
{
	return agg_get_table_info(agg_get_table(rinfo->rp));
}

/* Create ripng socket. */
int ripng_make_socket(struct vrf *vrf)
{
	int ret;
	int sock;
	struct sockaddr_in6 ripaddr;
	const char *vrf_dev = NULL;

	/* Make datagram socket. */
	if (vrf->vrf_id != VRF_DEFAULT)
		vrf_dev = vrf->name;
	frr_with_privs(&ripngd_privs) {
		sock = vrf_socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP,
				  vrf->vrf_id, vrf_dev);
		if (sock < 0) {
			flog_err_sys(EC_LIB_SOCKET,
				     "Cannot create UDP socket: %s",
				     safe_strerror(errno));
			return -1;
		}
	}

	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);
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

	frr_with_privs(&ripngd_privs) {
		ret = bind(sock, (struct sockaddr *)&ripaddr, sizeof(ripaddr));
		if (ret < 0) {
			zlog_err("Can't bind ripng socket: %s.",
				 safe_strerror(errno));
			goto error;
		}
	}
	return sock;

error:
	close(sock);
	return ret;
}

/* Send RIPng packet. */
int ripng_send_packet(caddr_t buf, int bufsize, struct sockaddr_in6 *to,
		      struct interface *ifp)
{
	struct ripng_interface *ri = ifp->info;
	struct ripng *ripng = ri->ripng;
	int ret;
	struct msghdr msg;
	struct iovec iov;
	struct cmsghdr *cmsgptr;
	char adata[256] = {};
	struct in6_pktinfo *pkt;
	struct sockaddr_in6 addr;

	if (IS_RIPNG_DEBUG_SEND) {
		if (to)
			zlog_debug("send to %pI6", &to->sin6_addr);
		zlog_debug("  send interface %s", ifp->name);
		zlog_debug("  send packet size %d", bufsize);
	}

	memset(&addr, 0, sizeof(addr));
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
	msg.msg_control = adata;
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
			flog_err_sys(EC_LIB_SOCKET,
				     "RIPng send fail on %s to %pI6: %s",
				     ifp->name, &to->sin6_addr,
				     safe_strerror(errno));
		else
			flog_err_sys(EC_LIB_SOCKET, "RIPng send fail on %s: %s",
				     ifp->name, safe_strerror(errno));
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

	memset(&dst, 0, sizeof(dst));

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
	msg.msg_controllen = sizeof(adata);
	iov.iov_base = buf;
	iov.iov_len = bufsize;

	/* If recvmsg fail return minus value. */
	ret = recvmsg(sock, &msg, 0);
	if (ret < 0)
		return ret;

	for (cmsgptr = CMSG_FIRSTHDR(&msg); cmsgptr != NULL;
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
			zlog_debug("  nexthop %pI6/%d", &rte->addr,
				   rte->prefixlen);
		else
			zlog_debug("  %pI6/%d metric %d tag %" ROUTE_TAG_PRI,
				   &rte->addr, rte->prefixlen,
				   rte->metric, (route_tag_t)ntohs(rte->tag));
	}
}

/* RIPng next hop address RTE (Route Table Entry). */
static void ripng_nexthop_rte(struct rte *rte, struct sockaddr_in6 *from,
			      struct ripng_nexthop *nexthop)
{
	/* Logging before checking RTE. */
	if (IS_RIPNG_DEBUG_RECV)
		zlog_debug("RIPng nexthop RTE address %pI6 tag %" ROUTE_TAG_PRI
			   " prefixlen %d",
			   &rte->addr, (route_tag_t)ntohs(rte->tag),
			   rte->prefixlen);

	/* RFC2080 2.1.1 Next Hop:
	 The route tag and prefix length in the next hop RTE must be
	 set to zero on sending and ignored on receiption.  */
	if (ntohs(rte->tag) != 0)
		zlog_warn(
			"RIPng nexthop RTE with non zero tag value %" ROUTE_TAG_PRI
			" from %pI6",
			(route_tag_t)ntohs(rte->tag), &from->sin6_addr);

	if (rte->prefixlen != 0)
		zlog_warn(
			"RIPng nexthop RTE with non zero prefixlen value %d from %pI6",
			rte->prefixlen, &from->sin6_addr);

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
	zlog_warn("RIPng nexthop RTE with non link-local address %pI6 from %pI6",
		  &rte->addr, &from->sin6_addr);

	nexthop->flag = RIPNG_NEXTHOP_UNSPEC;
	memset(&nexthop->address, 0, sizeof(struct in6_addr));

	return;
}

/* If ifp has same link-local address then return 1. */
static int ripng_lladdr_check(struct interface *ifp, struct in6_addr *addr)
{
	struct connected *connected;
	struct prefix *p;

	frr_each (if_connected, ifp->connected, connected) {
		p = connected->address;

		if (p->family == AF_INET6
		    && IN6_IS_ADDR_LINKLOCAL(&p->u.prefix6)
		    && IN6_ARE_ADDR_EQUAL(&p->u.prefix6, addr))
			return 1;
	}
	return 0;
}

/* RIPng route garbage collect timer. */
static void ripng_garbage_collect(struct event *t)
{
	struct ripng_info *rinfo;
	struct agg_node *rp;

	rinfo = EVENT_ARG(t);

	/* Off timeout timer. */
	EVENT_OFF(rinfo->t_timeout);

	/* Get route_node pointer. */
	rp = rinfo->rp;

	/* Unlock route_node. */
	listnode_delete(rp->info, rinfo);
	if (list_isempty((struct list *)rp->info)) {
		list_delete((struct list **)&rp->info);
		agg_unlock_node(rp);
	}

	/* Free RIPng routing information. */
	ripng_info_free(rinfo);
}

static void ripng_timeout_update(struct ripng *ripng, struct ripng_info *rinfo);

/* Add new route to the ECMP list.
 * RETURN: the new entry added in the list, or NULL if it is not the first
 *         entry and ECMP is not allowed.
 */
struct ripng_info *ripng_ecmp_add(struct ripng *ripng,
				  struct ripng_info *rinfo_new)
{
	struct agg_node *rp = rinfo_new->rp;
	struct ripng_info *rinfo = NULL;
	struct ripng_info *rinfo_exist = NULL;
	struct list *list = NULL;
	struct listnode *node = NULL;
	struct listnode *nnode = NULL;

	if (rp->info == NULL)
		rp->info = list_new();
	list = (struct list *)rp->info;

	/* If ECMP is not allowed and some entry already exists in the list,
	 * do nothing. */
	if (listcount(list) && !ripng->ecmp)
		return NULL;

	/* Add or replace an existing ECMP path with lower neighbor IP */
	if (listcount(list) && listcount(list) >= ripng->ecmp) {
		struct ripng_info *from_highest = NULL;

		/* Find the rip_info struct that has the highest nexthop IP */
		for (ALL_LIST_ELEMENTS(list, node, nnode, rinfo_exist))
			if (!from_highest ||
			    (from_highest &&
			     IPV6_ADDR_CMP(&rinfo_exist->from,
					   &from_highest->from) > 0)) {
				from_highest = rinfo_exist;
			}

		/* If we have a route in ECMP group, delete the old
		 * one that has a higher next-hop address. Lower IP is
		 * preferred.
		 */
		if (ripng->ecmp > 1 && from_highest &&
		    IPV6_ADDR_CMP(&from_highest->from, &rinfo_new->from) > 0) {
			ripng_ecmp_delete(ripng, from_highest);
			goto add_or_replace;
		}

		return NULL;
	}

add_or_replace:
	rinfo = ripng_info_new();
	memcpy(rinfo, rinfo_new, sizeof(struct ripng_info));
	listnode_add(list, rinfo);

	if (ripng_route_rte(rinfo)) {
		ripng_timeout_update(ripng, rinfo);
		ripng_zebra_ipv6_add(ripng, rp);
	}

	ripng_aggregate_increment(rp, rinfo);

	/* Set the route change flag on the first entry. */
	rinfo = listgetdata(listhead(list));
	SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

	/* Signal the output process to trigger an update. */
	ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Update ECMP routes to zebra when `allow-ecmp` changed. */
void ripng_ecmp_change(struct ripng *ripng)
{
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct list *list;
	struct listnode *node, *nextnode;

	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp)) {
		list = rp->info;
		if (list && listcount(list) > 1) {
			while (listcount(list) > ripng->ecmp) {
				struct ripng_info *from_highest = NULL;

				for (ALL_LIST_ELEMENTS(list, node, nextnode,
						       rinfo)) {
					if (!from_highest ||
					    (from_highest &&
					     IPV6_ADDR_CMP(
						     &rinfo->from,
						     &from_highest->from) > 0))
						from_highest = rinfo;
				}

				ripng_ecmp_delete(ripng, from_highest);
			}
		}
	}
}

/* Replace the ECMP list with the new route.
 * RETURN: the new entry added in the list
 */
struct ripng_info *ripng_ecmp_replace(struct ripng *ripng,
				      struct ripng_info *rinfo_new)
{
	struct agg_node *rp = rinfo_new->rp;
	struct list *list = (struct list *)rp->info;
	struct ripng_info *rinfo = NULL, *tmp_rinfo = NULL;
	struct listnode *node = NULL, *nextnode = NULL;

	if (list == NULL || listcount(list) == 0)
		return ripng_ecmp_add(ripng, rinfo_new);

	/* Get the first entry */
	rinfo = listgetdata(listhead(list));

	/* Learnt route replaced by a local one. Delete it from zebra. */
	if (ripng_route_rte(rinfo) && !ripng_route_rte(rinfo_new))
		if (CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
			ripng_zebra_ipv6_delete(ripng, rp);

	if (rinfo->metric != RIPNG_METRIC_INFINITY)
		ripng_aggregate_decrement_list(rp, list);

	/* Re-use the first entry, and delete the others. */
	for (ALL_LIST_ELEMENTS(list, node, nextnode, tmp_rinfo))
		if (tmp_rinfo != rinfo) {
			EVENT_OFF(tmp_rinfo->t_timeout);
			EVENT_OFF(tmp_rinfo->t_garbage_collect);
			list_delete_node(list, node);
			ripng_info_free(tmp_rinfo);
		}

	EVENT_OFF(rinfo->t_timeout);
	EVENT_OFF(rinfo->t_garbage_collect);
	memcpy(rinfo, rinfo_new, sizeof(struct ripng_info));

	if (ripng_route_rte(rinfo)) {
		ripng_timeout_update(ripng, rinfo);
		/* The ADD message implies an update. */
		ripng_zebra_ipv6_add(ripng, rp);
	}

	ripng_aggregate_increment(rp, rinfo);

	/* Set the route change flag. */
	SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

	/* Signal the output process to trigger an update. */
	ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Delete one route from the ECMP list.
 * RETURN:
 *  null - the entry is freed, and other entries exist in the list
 *  the entry - the entry is the last one in the list; its metric is set
 *              to INFINITY, and the garbage collector is started for it
 */
struct ripng_info *ripng_ecmp_delete(struct ripng *ripng,
				     struct ripng_info *rinfo)
{
	struct agg_node *rp = rinfo->rp;
	struct list *list = (struct list *)rp->info;

	EVENT_OFF(rinfo->t_timeout);

	if (rinfo->metric != RIPNG_METRIC_INFINITY)
		ripng_aggregate_decrement(rp, rinfo);

	if (listcount(list) > 1) {
		/* Some other ECMP entries still exist. Just delete this entry.
		 */
		EVENT_OFF(rinfo->t_garbage_collect);
		listnode_delete(list, rinfo);
		if (ripng_route_rte(rinfo) &&
		    CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
			/* The ADD message implies the update. */
			ripng_zebra_ipv6_add(ripng, rp);
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

		if (ripng_route_rte(rinfo) &&
		    CHECK_FLAG(rinfo->flags, RIPNG_RTF_FIB))
			ripng_zebra_ipv6_delete(ripng, rp);
	}

	/* Set the route change flag on the first entry. */
	rinfo = listgetdata(listhead(list));
	SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

	/* Signal the output process to trigger an update. */
	ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Timeout RIPng routes. */
static void ripng_timeout(struct event *t)
{
	struct ripng_info *rinfo = EVENT_ARG(t);
	struct ripng *ripng = ripng_info_get_instance(rinfo);

	ripng_ecmp_delete(ripng, rinfo);
}

static void ripng_timeout_update(struct ripng *ripng, struct ripng_info *rinfo)
{
	if (rinfo->metric != RIPNG_METRIC_INFINITY) {
		EVENT_OFF(rinfo->t_timeout);
		event_add_timer(master, ripng_timeout, rinfo,
				ripng->timeout_time, &rinfo->t_timeout);
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
				      (struct prefix *)p) == FILTER_DENY) {
			if (IS_RIPNG_DEBUG_PACKET)
				zlog_debug("%pFX filtered by distribute %s", p,
					   inout);
			return -1;
		}
	}
	if (ri->prefix[ripng_distribute]) {
		if (prefix_list_apply(ri->prefix[ripng_distribute],
				      (struct prefix *)p) == PREFIX_DENY) {
			if (IS_RIPNG_DEBUG_PACKET)
				zlog_debug("%pFX filtered by prefix-list %s", p,
					   inout);
			return -1;
		}
	}

	/* All interface filter check. */
	dist = distribute_lookup(ri->ripng->distribute_ctx, NULL);
	if (dist) {
		if (dist->list[distribute]) {
			alist = access_list_lookup(AFI_IP6,
						   dist->list[distribute]);

			if (alist) {
				if (access_list_apply(alist, (struct prefix *)p)
				    == FILTER_DENY) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"%pFX filtered by distribute %s",
							p, inout);
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
							"%pFX filtered by prefix-list %s",
							p, inout);
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
	struct agg_node *rp;
	struct ripng_info *rinfo = NULL, newinfo;
	struct ripng_interface *ri;
	struct ripng *ripng;
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

	ri = ifp->info;
	ripng = ri->ripng;

	/* Apply input filters. */
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
		ret = route_map_apply(ri->routemap[RIPNG_FILTER_IN],
				      (struct prefix *)&p, &newinfo);

		if (ret == RMAP_DENYMATCH) {
			if (IS_RIPNG_DEBUG_PACKET)
				zlog_debug(
					"RIPng %pFX is filtered by route-map in",
					&p);
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
		rte->metric = newinfo.metric_out;  /* XXX: the routemap uses the
			 metric_out field */
	}

	/* Once the entry has been validated, update the metric by
	 * adding the cost of the network on wich the message
	 * arrived. If the result is greater than infinity, use infinity
	 * (RFC2453 Sec. 3.9.2)
	 **/

	/* Zebra ripngd can handle offset-list in. */
	ret = ripng_offset_list_apply_in(ripng, &p, ifp, &rte->metric);

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
	rp = agg_node_get(ripng->table, (struct prefix *)&p);

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
					agg_unlock_node(rp);
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
			agg_unlock_node(rp);
			return;
		}

		/* Local static route. */
		if (rinfo->type == ZEBRA_ROUTE_RIPNG
		    && ((rinfo->sub_type == RIPNG_ROUTE_STATIC)
			|| (rinfo->sub_type == RIPNG_ROUTE_DEFAULT))
		    && rinfo->metric != RIPNG_METRIC_INFINITY) {
			agg_unlock_node(rp);
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
			ripng_ecmp_add(ripng, &newinfo);
		else
			agg_unlock_node(rp);
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
		if (!ripng->ecmp && !same && rinfo->metric == rte->metric &&
		    rinfo->t_timeout &&
		    (event_timer_remain_second(rinfo->t_timeout) <
		     (ripng->timeout_time / 2))) {
			ripng_ecmp_replace(ripng, &newinfo);
		}
		/* Next, compare the metrics.  If the datagram is from the same
		   router as the existing route, and the new metric is different
		   than the old one; or, if the new metric is lower than the old
		   one; do the following actions: */
		else if ((same && rinfo->metric != rte->metric) ||
			 rte->metric < rinfo->metric) {
			if (listcount(list) == 1) {
				if (newinfo.metric != RIPNG_METRIC_INFINITY)
					ripng_ecmp_replace(ripng, &newinfo);
				else
					ripng_ecmp_delete(ripng, rinfo);
			} else {
				if (newinfo.metric < rinfo->metric)
					ripng_ecmp_replace(ripng, &newinfo);
				else /* newinfo.metric > rinfo->metric */
					ripng_ecmp_delete(ripng, rinfo);
			}
		} else /* same & no change */
			ripng_timeout_update(ripng, rinfo);

		/* Unlock tempolary lock of the route. */
		agg_unlock_node(rp);
	}
}

/* Add redistributed route to RIPng table. */
void ripng_redistribute_add(struct ripng *ripng, int type, int sub_type,
			    struct prefix_ipv6 *p, ifindex_t ifindex,
			    struct in6_addr *nexthop, route_tag_t tag)
{
	struct agg_node *rp;
	struct ripng_info *rinfo = NULL, newinfo;
	struct list *list = NULL;

	/* Redistribute route  */
	if (IN6_IS_ADDR_LINKLOCAL(&p->prefix))
		return;
	if (IN6_IS_ADDR_LOOPBACK(&p->prefix))
		return;

	rp = agg_node_get(ripng->table, (struct prefix *)p);

	memset(&newinfo, 0, sizeof(newinfo));
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
			agg_unlock_node(rp);
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
				agg_unlock_node(rp);
				return;
			}
		}

		ripng_ecmp_replace(ripng, &newinfo);
		agg_unlock_node(rp);
	} else
		ripng_ecmp_add(ripng, &newinfo);

	if (IS_RIPNG_DEBUG_EVENT) {
		if (!nexthop)
			zlog_debug(
				"Redistribute new prefix %pFX on the interface %s",
				p, ifindex2ifname(ifindex, ripng->vrf->vrf_id));
		else
			zlog_debug(
				"Redistribute new prefix %pFX with nexthop %pI6 on the interface %s",
				p, nexthop,
				ifindex2ifname(ifindex, ripng->vrf->vrf_id));
	}

	ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);
}

/* Delete redistributed route to RIPng table. */
void ripng_redistribute_delete(struct ripng *ripng, int type, int sub_type,
			       struct prefix_ipv6 *p, ifindex_t ifindex)
{
	struct agg_node *rp;
	struct ripng_info *rinfo;

	if (IN6_IS_ADDR_LINKLOCAL(&p->prefix))
		return;
	if (IN6_IS_ADDR_LOOPBACK(&p->prefix))
		return;

	rp = agg_node_lookup(ripng->table, (struct prefix *)p);

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
				EVENT_OFF(rinfo->t_timeout);

				/* Aggregate count decrement. */
				ripng_aggregate_decrement(rp, rinfo);

				SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

				if (IS_RIPNG_DEBUG_EVENT)
					zlog_debug(
						"Poisone %pFX on the interface %s with an infinity metric [delete]",
						p,
						ifindex2ifname(
							ifindex,
							ripng->vrf->vrf_id));

				ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);
			}
		}
		agg_unlock_node(rp);
	}
}

/* Withdraw redistributed route. */
void ripng_redistribute_withdraw(struct ripng *ripng, int type)
{
	struct agg_node *rp;
	struct ripng_info *rinfo = NULL;
	struct list *list = NULL;

	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp))
		if ((list = rp->info) != NULL) {
			rinfo = listgetdata(listhead(list));
			if ((rinfo->type == type)
			    && (rinfo->sub_type != RIPNG_ROUTE_INTERFACE)) {
				/* Perform poisoned reverse. */
				rinfo->metric = RIPNG_METRIC_INFINITY;
				RIPNG_TIMER_ON(rinfo->t_garbage_collect,
					       ripng_garbage_collect,
					       ripng->garbage_time);
				EVENT_OFF(rinfo->t_timeout);

				/* Aggregate count decrement. */
				ripng_aggregate_decrement(rp, rinfo);

				SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

				if (IS_RIPNG_DEBUG_EVENT) {
					struct prefix_ipv6 *p =
						(struct prefix_ipv6 *)
							agg_node_get_prefix(rp);

					zlog_debug(
						"Poisone %pFX on the interface %s [withdraw]",
						p,
						ifindex2ifname(
							rinfo->ifindex,
							ripng->vrf->vrf_id));
				}

				ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);
			}
		}
}

/* RIP routing information. */
static void ripng_response_process(struct ripng_packet *packet, int size,
				   struct sockaddr_in6 *from,
				   struct interface *ifp, int hoplimit)
{
	struct ripng_interface *ri = ifp->info;
	struct ripng *ripng = ri->ripng;
	caddr_t lim;
	struct rte *rte;
	struct ripng_nexthop nexthop;

	/* RFC2080 2.4.2  Response Messages:
	 The Response must be ignored if it is not from the RIPng port.  */
	if (ntohs(from->sin6_port) != RIPNG_PORT_DEFAULT) {
		zlog_warn("RIPng packet comes from non RIPng port %d from %pI6",
			  ntohs(from->sin6_port), &from->sin6_addr);
		ripng_peer_bad_packet(ripng, from);
		return;
	}

	/* The datagram's IPv6 source address should be checked to see
	 whether the datagram is from a valid neighbor; the source of the
	 datagram must be a link-local address.  */
	if (!IN6_IS_ADDR_LINKLOCAL(&from->sin6_addr)) {
		zlog_warn("RIPng packet comes from non link local address %pI6",
			  &from->sin6_addr);
		ripng_peer_bad_packet(ripng, from);
		return;
	}

	/* It is also worth checking to see whether the response is from one
	 of the router's own addresses.  Interfaces on broadcast networks
	 may receive copies of their own multicasts immediately.  If a
	 router processes its own output as new input, confusion is likely,
	 and such datagrams must be ignored. */
	if (ripng_lladdr_check(ifp, &from->sin6_addr)) {
		zlog_warn(
			"RIPng packet comes from my own link local address %pI6",
			&from->sin6_addr);
		ripng_peer_bad_packet(ripng, from);
		return;
	}

	/* As an additional check, periodic advertisements must have their
	 hop counts set to 255, and inbound, multicast packets sent from the
	 RIPng port (i.e. periodic advertisement or triggered update
	 packets) must be examined to ensure that the hop count is 255. */
	if (hoplimit >= 0 && hoplimit != 255) {
		zlog_warn(
			"RIPng packet comes with non 255 hop count %d from %pI6",
			hoplimit, &from->sin6_addr);
		ripng_peer_bad_packet(ripng, from);
		return;
	}

	/* Update RIPng peer. */
	ripng_peer_update(ripng, from, packet->version);

	/* Reset nexthop. */
	memset(&nexthop, 0, sizeof(nexthop));
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
				"Destination prefix is a multicast address %pI6/%d [%d]",
				&rte->addr, rte->prefixlen, rte->metric);
			ripng_peer_bad_route(ripng, from);
			continue;
		}
		if (IN6_IS_ADDR_LINKLOCAL(&rte->addr)) {
			zlog_warn(
				"Destination prefix is a link-local address %pI6/%d [%d]",
				&rte->addr, rte->prefixlen, rte->metric);
			ripng_peer_bad_route(ripng, from);
			continue;
		}
		if (IN6_IS_ADDR_LOOPBACK(&rte->addr)) {
			zlog_warn(
				"Destination prefix is a loopback address %pI6/%d [%d]",
				&rte->addr, rte->prefixlen, rte->metric);
			ripng_peer_bad_route(ripng, from);
			continue;
		}

		/* - is the prefix length valid (i.e., between 0 and 128,
		   inclusive) */
		if (rte->prefixlen > IPV6_MAX_BITLEN) {
			zlog_warn("Invalid prefix length %pI6/%d from %pI6%%%s",
				  &rte->addr, rte->prefixlen,
				  &from->sin6_addr, ifp->name);
			ripng_peer_bad_route(ripng, from);
			continue;
		}

		/* - is the metric valid (i.e., between 1 and 16, inclusive) */
		if (!(rte->metric >= 1 && rte->metric <= 16)) {
			zlog_warn("Invalid metric %d from %pI6%%%s",
				  rte->metric, &from->sin6_addr, ifp->name);
			ripng_peer_bad_route(ripng, from);
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
	struct ripng *ripng;
	caddr_t lim;
	struct rte *rte;
	struct prefix_ipv6 p;
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct ripng_interface *ri;

	/* Does not reponse to the requests on the loopback interfaces */
	if (if_is_loopback(ifp))
		return;

	/* Check RIPng process is enabled on this interface. */
	ri = ifp->info;
	if (!ri->running)
		return;
	ripng = ri->ripng;

	/* When passive interface is specified, suppress responses */
	if (ri->passive)
		return;

	/* RIPng peer update. */
	ripng_peer_update(ripng, from, packet->version);

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
		memset(&p, 0, sizeof(p));
		p.family = AF_INET6;

		for (; ((caddr_t)rte) < lim; rte++) {
			p.prefix = rte->addr;
			p.prefixlen = rte->prefixlen;
			apply_mask_ipv6(&p);

			rp = agg_node_lookup(ripng->table, (struct prefix *)&p);

			if (rp) {
				rinfo = listgetdata(
					listhead((struct list *)rp->info));
				rte->metric = rinfo->metric;
				agg_unlock_node(rp);
			} else
				rte->metric = RIPNG_METRIC_INFINITY;
		}
		packet->command = RIPNG_RESPONSE;

		ripng_send_packet((caddr_t)packet, size, from, ifp);
	}
}

/* First entry point of reading RIPng packet. */
static void ripng_read(struct event *thread)
{
	struct ripng *ripng = EVENT_ARG(thread);
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
	sock = EVENT_FD(thread);

	/* Add myself to the next event. */
	ripng_event(ripng, RIPNG_READ, sock);

	/* Read RIPng packet. */
	len = ripng_recv_packet(sock, STREAM_DATA(ripng->ibuf),
				STREAM_SIZE(ripng->ibuf), &from, &ifindex,
				&hoplimit);
	if (len < 0) {
		zlog_warn("RIPng recvfrom failed (VRF %s): %s.",
			  ripng->vrf_name, safe_strerror(errno));
		return;
	}

	/* Check RTE boundary.  RTE size (Packet length - RIPng header size
	   (4)) must be multiple size of one RTE size (20). */
	if (((len - 4) % 20) != 0) {
		zlog_warn("RIPng invalid packet size %d from %pI6 (VRF %s)",
			  len, &from.sin6_addr, ripng->vrf_name);
		ripng_peer_bad_packet(ripng, &from);
		return;
	}

	packet = (struct ripng_packet *)STREAM_DATA(ripng->ibuf);
	ifp = if_lookup_by_index(ifindex, ripng->vrf->vrf_id);

	/* RIPng packet received. */
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug(
			"RIPng packet received from %pI6 port %d on %s (VRF %s)",
			&from.sin6_addr, ntohs(from.sin6_port),
			ifp ? ifp->name : "unknown", ripng->vrf_name);

	/* Logging before packet checking. */
	if (IS_RIPNG_DEBUG_RECV)
		ripng_packet_dump(packet, len, "RECV");

	/* Packet comes from unknown interface. */
	if (ifp == NULL) {
		zlog_warn(
			"RIPng packet comes from unknown interface %d (VRF %s)",
			ifindex, ripng->vrf_name);
		return;
	}

	/* Packet version mismatch checking. */
	if (packet->version != ripng->version) {
		zlog_warn(
			"RIPng packet version %d doesn't fit to my version %d (VRF %s)",
			packet->version, ripng->version, ripng->vrf_name);
		ripng_peer_bad_packet(ripng, &from);
		return;
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
		zlog_warn("Invalid RIPng command %d (VRF %s)", packet->command,
			  ripng->vrf_name);
		ripng_peer_bad_packet(ripng, &from);
		break;
	}
}

/* Walk down the RIPng routing table then clear changed flag. */
static void ripng_clear_changed_flag(struct ripng *ripng)
{
	struct agg_node *rp;
	struct ripng_info *rinfo = NULL;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp))
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
static void ripng_update(struct event *t)
{
	struct ripng *ripng = EVENT_ARG(t);
	struct interface *ifp;
	struct ripng_interface *ri;

	/* Logging update event. */
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("RIPng update timer expired!");

	/* Supply routes to each interface. */
	FOR_ALL_INTERFACES (ripng->vrf, ifp) {
		ri = ifp->info;

		if (if_is_loopback(ifp) || !if_is_up(ifp))
			continue;

		if (!ri->running)
			continue;

		/* When passive interface is specified, suppress announce to the
		   interface. */
		if (ri->passive)
			continue;

#ifdef RIPNG_ADVANCED
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
	EVENT_OFF(ripng->t_triggered_interval);
	ripng->trigger = 0;

	/* Reset flush event. */
	ripng_event(ripng, RIPNG_UPDATE_EVENT, 0);
}

/* Triggered update interval timer. */
static void ripng_triggered_interval(struct event *t)
{
	struct ripng *ripng = EVENT_ARG(t);

	if (ripng->trigger) {
		ripng->trigger = 0;
		ripng_triggered_update(t);
	}
}

/* Execute triggered update. */
void ripng_triggered_update(struct event *t)
{
	struct ripng *ripng = EVENT_ARG(t);
	struct interface *ifp;
	struct ripng_interface *ri;
	int interval;

	/* Cancel interval timer. */
	EVENT_OFF(ripng->t_triggered_interval);
	ripng->trigger = 0;

	/* Logging triggered update. */
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("RIPng triggered update!");

	/* Split Horizon processing is done when generating triggered
	   updates as well as normal updates (see section 2.6). */
	FOR_ALL_INTERFACES (ripng->vrf, ifp) {
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
	ripng_clear_changed_flag(ripng);

	/* After a triggered update is sent, a timer should be set for a
	   random interval between 1 and 5 seconds.  If other changes that
	   would trigger updates occur before the timer expires, a single
	   update is triggered when the timer expires. */
	interval = (frr_weak_random() % 5) + 1;

	event_add_timer(master, ripng_triggered_interval, ripng, interval,
			&ripng->t_triggered_interval);
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
	struct ripng *ripng;
	int ret;
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct ripng_interface *ri;
	struct ripng_aggregate *aggregate;
	struct prefix_ipv6 *p;
	struct list *ripng_rte_list;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	if (IS_RIPNG_DEBUG_EVENT) {
		if (to)
			zlog_debug("RIPng update routes to neighbor %pI6",
				   &to->sin6_addr);
		else
			zlog_debug("RIPng update routes on interface %s",
				   ifp->name);
	}

	/* Get RIPng interface and instance. */
	ri = ifp->info;
	ripng = ri->ripng;

	ripng_rte_list = ripng_rte_new();

	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp)) {
		if ((list = rp->info) != NULL
		    && (rinfo = listgetdata(listhead(list))) != NULL
		    && rinfo->suppress == 0) {
			/* If no route-map are applied, the RTE will be these
			 * following
			 * information.
			 */
			p = (struct prefix_ipv6 *)agg_node_get_prefix(rp);
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
			if (route_type == ripng_changed_route &&
			    (!CHECK_FLAG(rinfo->flags, RIPNG_RTF_CHANGED)))
				continue;

			/* Split horizon. */
			if (ri->split_horizon == RIPNG_SPLIT_HORIZON) {
				/* We perform split horizon for RIPng routes. */
				int suppress = 0;
				struct ripng_info *tmp_rinfo = NULL;

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  tmp_rinfo))
					if (tmp_rinfo->type ==
						    ZEBRA_ROUTE_RIPNG &&
					    tmp_rinfo->ifindex ==
						    ifp->ifindex) {
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
				ret = route_map_apply(
					ri->routemap[RIPNG_FILTER_OUT],
					(struct prefix *)p, rinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"RIPng %pFX is filtered by route-map out",
							p);
					continue;
				}
			}

			/* Redistribute route-map. */
			if (ripng->redist[rinfo->type].route_map.name) {
				ret = route_map_apply(ripng->redist[rinfo->type]
							      .route_map.map,
						      (struct prefix *)p,
						      rinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"RIPng %pFX is filtered by route-map",
							p);
					continue;
				}
			}

			/* When the route-map does not set metric. */
			if (!rinfo->metric_set) {
				/* If the redistribute metric is set. */
				if (ripng->redist[rinfo->type].metric_config
				    && rinfo->metric != RIPNG_METRIC_INFINITY) {
					rinfo->metric_out =
						ripng->redist[rinfo->type]
							.metric;
				} else {
					/* If the route is not connected or
					   localy generated
					   one, use default-metric value */
					if (rinfo->type != ZEBRA_ROUTE_RIPNG &&
					    rinfo->type !=
						    ZEBRA_ROUTE_CONNECT &&
					    rinfo->metric !=
						    RIPNG_METRIC_INFINITY)
						rinfo->metric_out =
							ripng->default_metric;
				}
			}

			/* Apply offset-list */
			if (rinfo->metric_out != RIPNG_METRIC_INFINITY)
				ripng_offset_list_apply_out(ripng, p, ifp,
							    &rinfo->metric_out);

			if (rinfo->metric_out > RIPNG_METRIC_INFINITY)
				rinfo->metric_out = RIPNG_METRIC_INFINITY;

			/* Perform split-horizon with poisoned reverse
			 * for RIPng routes.
			 **/
			if (ri->split_horizon ==
			    RIPNG_SPLIT_HORIZON_POISONED_REVERSE) {
				struct ripng_info *tmp_rinfo = NULL;

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  tmp_rinfo))
					if ((tmp_rinfo->type ==
					     ZEBRA_ROUTE_RIPNG) &&
					    tmp_rinfo->ifindex == ifp->ifindex)
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
			 * information.
			 */
			p = (struct prefix_ipv6 *)agg_node_get_prefix(rp);
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
					(struct prefix *)p, &newinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIPNG_DEBUG_PACKET)
						zlog_debug(
							"RIPng %pFX is filtered by route-map out",
							p);
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
					ripng, p, ifp, &aggregate->metric_out);

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

struct ripng *ripng_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	return vrf->info;
}

struct ripng *ripng_lookup_by_vrf_name(const char *vrf_name)
{
	struct ripng ripng;

	ripng.vrf_name = (char *)vrf_name;

	return RB_FIND(ripng_instance_head, &ripng_instances, &ripng);
}

/* Create new RIPng instance and set it to global variable. */
struct ripng *ripng_create(const char *vrf_name, struct vrf *vrf, int socket)
{
	struct ripng *ripng;

	/* Allocaste RIPng instance. */
	ripng = XCALLOC(MTYPE_RIPNG, sizeof(struct ripng));
	ripng->vrf_name = XSTRDUP(MTYPE_RIPNG_VRF_NAME, vrf_name);

	/* Default version and timer values. */
	ripng->version = RIPNG_V1;
	ripng->update_time = yang_get_default_uint32(
		"%s/timers/update-interval", RIPNG_INSTANCE);
	ripng->timeout_time = yang_get_default_uint32(
		"%s/timers/holddown-interval", RIPNG_INSTANCE);
	ripng->garbage_time = yang_get_default_uint32(
		"%s/timers/flush-interval", RIPNG_INSTANCE);
	ripng->default_metric =
		yang_get_default_uint8("%s/default-metric", RIPNG_INSTANCE);
	ripng->ecmp = yang_get_default_uint8("%s/allow-ecmp", RIPNG_INSTANCE);

	/* Make buffer.  */
	ripng->ibuf = stream_new(RIPNG_MAX_PACKET_SIZE * 5);
	ripng->obuf = stream_new(RIPNG_MAX_PACKET_SIZE);

	/* Initialize RIPng data structures. */
	ripng->table = agg_table_init();
	agg_set_table_info(ripng->table, ripng);
	ripng->peer_list = list_new();
	ripng->peer_list->cmp = (int (*)(void *, void *))ripng_peer_list_cmp;
	ripng->peer_list->del = ripng_peer_list_del;
	ripng->enable_if = vector_init(1);
	ripng->enable_network = agg_table_init();
	ripng->passive_interface = vector_init(1);
	ripng->offset_list_master = list_new();
	ripng->offset_list_master->cmp =
		(int (*)(void *, void *))offset_list_cmp;
	ripng->offset_list_master->del =
		(void (*)(void *))ripng_offset_list_free;
	ripng->distribute_ctx = distribute_list_ctx_create(vrf);
	distribute_list_add_hook(ripng->distribute_ctx,
				 ripng_distribute_update);
	distribute_list_delete_hook(ripng->distribute_ctx,
				    ripng_distribute_update);

	/* if rmap install. */
	ripng->if_rmap_ctx = if_rmap_ctx_create(vrf_name);
	if_rmap_hook_add(ripng->if_rmap_ctx, ripng_if_rmap_update);
	if_rmap_hook_delete(ripng->if_rmap_ctx, ripng_if_rmap_update);

	/* Enable the routing instance if possible. */
	if (vrf && vrf_is_enabled(vrf))
		ripng_instance_enable(ripng, vrf, socket);
	else {
		ripng->vrf = NULL;
		ripng->sock = -1;
	}

	RB_INSERT(ripng_instance_head, &ripng_instances, ripng);

	return ripng;
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
	return ((frr_weak_random() % (time + 1)) - (time / 2));
}

void ripng_event(struct ripng *ripng, enum ripng_event event, int sock)
{
	int jitter = 0;

	switch (event) {
	case RIPNG_READ:
		event_add_read(master, ripng_read, ripng, sock, &ripng->t_read);
		break;
	case RIPNG_UPDATE_EVENT:
		EVENT_OFF(ripng->t_update);

		/* Update timer jitter. */
		jitter = ripng_update_jitter(ripng->update_time);

		event_add_timer(master, ripng_update, ripng,
				sock ? 2 : ripng->update_time + jitter,
				&ripng->t_update);
		break;
	case RIPNG_TRIGGERED_UPDATE:
		if (ripng->t_triggered_interval)
			ripng->trigger = 1;
		else
			event_add_event(master, ripng_triggered_update, ripng,
					0, &ripng->t_triggered_update);
		break;
	case RIPNG_ZEBRA:
	case RIPNG_REQUEST_EVENT:
		break;
	}
}


/* Print out routes update time. */
static void ripng_vty_out_uptime(struct vty *vty, struct ripng_info *rinfo)
{
	time_t clock;
	struct tm tm;
#define TIME_BUF 25
	char timebuf[TIME_BUF];
	struct event *thread;

	if ((thread = rinfo->t_timeout) != NULL) {
		clock = event_timer_remain_second(thread);
		gmtime_r(&clock, &tm);
		strftime(timebuf, TIME_BUF, "%M:%S", &tm);
		vty_out(vty, "%5s", timebuf);
	} else if ((thread = rinfo->t_garbage_collect) != NULL) {
		clock = event_timer_remain_second(thread);
		gmtime_r(&clock, &tm);
		strftime(timebuf, TIME_BUF, "%M:%S", &tm);
		vty_out(vty, "%5s", timebuf);
	}
}

static char *ripng_route_subtype_print(struct ripng_info *rinfo)
{
	static char str[3];
	memset(str, 0, 3);

	if (rinfo->suppress)
		strlcat(str, "S", sizeof(str));

	switch (rinfo->sub_type) {
	case RIPNG_ROUTE_RTE:
		strlcat(str, "n", sizeof(str));
		break;
	case RIPNG_ROUTE_STATIC:
		strlcat(str, "s", sizeof(str));
		break;
	case RIPNG_ROUTE_DEFAULT:
		strlcat(str, "d", sizeof(str));
		break;
	case RIPNG_ROUTE_REDISTRIBUTE:
		strlcat(str, "r", sizeof(str));
		break;
	case RIPNG_ROUTE_INTERFACE:
		strlcat(str, "i", sizeof(str));
		break;
	default:
		strlcat(str, "?", sizeof(str));
		break;
	}

	return str;
}

DEFUN (show_ipv6_ripng,
       show_ipv6_ripng_cmd,
       "show ipv6 ripng [vrf NAME]",
       SHOW_STR
       IPV6_STR
       "Show RIPng routes\n"
       VRF_CMD_HELP_STR)
{
	struct ripng *ripng;
	struct agg_node *rp;
	struct ripng_info *rinfo;
	struct ripng_aggregate *aggregate;
	struct list *list = NULL;
	struct listnode *listnode = NULL;
	int len;
	const char *vrf_name;
	int idx = 0;

	if (argv_find(argv, argc, "vrf", &idx))
		vrf_name = argv[idx + 1]->arg;
	else
		vrf_name = VRF_DEFAULT_NAME;

	ripng = ripng_lookup_by_vrf_name(vrf_name);
	if (!ripng) {
		vty_out(vty, "%% RIPng instance not found\n");
		return CMD_SUCCESS;
	}
	if (!ripng->enabled) {
		vty_out(vty, "%% RIPng instance is disabled\n");
		return CMD_SUCCESS;
	}

	/* Header of display. */
	vty_out(vty,
		"Codes: R - RIPng, C - connected, S - Static, O - OSPF, B - BGP\n"
		"Sub-codes:\n"
		"      (n) - normal, (s) - static, (d) - default, (r) - redistribute,\n"
		"      (i) - interface, (a/S) - aggregated/Suppressed\n\n"
		"   Network      Next Hop                      Via     Metric Tag Time\n");

	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp)) {
		if ((aggregate = rp->aggregate) != NULL) {
#ifdef DEBUG
			vty_out(vty, "R(a) %d/%d %pRN ", aggregate->count,
				aggregate->suppress, rp);
#else
			vty_out(vty, "R(a) %pRN ", rp);
#endif /* DEBUG */
			vty_out(vty, "\n");
			vty_out(vty, "%*s", 18, " ");

			vty_out(vty, "%*s", 28, " ");
			vty_out(vty, "self      %2d  %3" ROUTE_TAG_PRI "\n",
				aggregate->metric, (route_tag_t)aggregate->tag);
		}

		if ((list = rp->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
#ifdef DEBUG
				vty_out(vty, "%c(%s) 0/%d %pRN ",
					zebra_route_char(rinfo->type),
					ripng_route_subtype_print(rinfo),
					rinfo->suppress, rp);
#else
				vty_out(vty, "%c(%s) %pRN ",
					zebra_route_char(rinfo->type),
					ripng_route_subtype_print(rinfo), rp);
#endif /* DEBUG */
				vty_out(vty, "\n");
				vty_out(vty, "%*s", 18, " ");
				len = vty_out(vty, "%pI6",
					      &rinfo->nexthop);

				len = 28 - len;
				if (len > 0)
					vty_out(vty, "%*s", len, " ");

				/* from */
				if ((rinfo->type == ZEBRA_ROUTE_RIPNG)
				    && (rinfo->sub_type == RIPNG_ROUTE_RTE)) {
					len = vty_out(
						vty, "%s",
						ifindex2ifname(
							rinfo->ifindex,
							ripng->vrf->vrf_id));
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
       "show ipv6 ripng [vrf NAME] status",
       SHOW_STR
       IPV6_STR
       "Show RIPng routes\n"
       VRF_CMD_HELP_STR
       "IPv6 routing protocol process parameters and statistics\n")
{
	struct ripng *ripng;
	struct interface *ifp;
	const char *vrf_name;
	int idx = 0;

	if (argv_find(argv, argc, "vrf", &idx))
		vrf_name = argv[idx + 1]->arg;
	else
		vrf_name = VRF_DEFAULT_NAME;

	ripng = ripng_lookup_by_vrf_name(vrf_name);
	if (!ripng) {
		vty_out(vty, "%% RIPng instance not found\n");
		return CMD_SUCCESS;
	}
	if (!ripng->enabled) {
		vty_out(vty, "%% RIPng instance is disabled\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Routing Protocol is \"RIPng\"\n");
	vty_out(vty, "  Sending updates every %u seconds with +/-50%%,",
		ripng->update_time);
	vty_out(vty, " next due in %lu seconds\n",
		event_timer_remain_second(ripng->t_update));
	vty_out(vty, "  Timeout after %u seconds,", ripng->timeout_time);
	vty_out(vty, " garbage collect after %u seconds\n",
		ripng->garbage_time);

	/* Filtering status show. */
	config_show_distribute(vty, ripng->distribute_ctx);

	/* Default metric information. */
	vty_out(vty, "  Default redistribution metric is %d\n",
		ripng->default_metric);

	/* Redistribute information. */
	vty_out(vty, "  Redistributing:");
	ripng_redistribute_write(vty, ripng);
	vty_out(vty, "\n");

	vty_out(vty, "  Default version control: send version %d,",
		ripng->version);
	vty_out(vty, " receive version %d \n", ripng->version);

	vty_out(vty, "    Interface        Send  Recv\n");

	FOR_ALL_INTERFACES (ripng->vrf, ifp) {
		struct ripng_interface *ri;

		ri = ifp->info;

		if (ri->enable_network || ri->enable_interface) {

			vty_out(vty, "    %-17s%-3d   %-3d\n", ifp->name,
				ripng->version, ripng->version);
		}
	}

	vty_out(vty, "  Routing for Networks:\n");
	ripng_network_write(vty, ripng);

	vty_out(vty, "  Routing Information Sources:\n");
	vty_out(vty,
		"    Gateway          BadPackets BadRoutes  Distance Last Update\n");
	ripng_peer_display(vty, ripng);

	return CMD_SUCCESS;
}

#include "ripngd/ripngd_clippy.c"

/*
 * XPath: /frr-ripngd:clear-ripng-route
 */
DEFPY_YANG (clear_ipv6_rip,
       clear_ipv6_rip_cmd,
       "clear ipv6 ripng [vrf WORD]",
       CLEAR_STR
       IPV6_STR
       "Clear IPv6 RIP database\n"
       VRF_CMD_HELP_STR)
{
	struct list *input;
	int ret;

	input = list_new();
	if (vrf) {
		struct yang_data *yang_vrf;

		yang_vrf = yang_data_new(
			"/frr-ripngd:clear-ripng-route/input/vrf", vrf);
		listnode_add(input, yang_vrf);
	}

	ret = nb_cli_rpc(vty, "/frr-ripngd:clear-ripng-route", input, NULL);

	list_delete(&input);

	return ret;
}

/* Update ECMP routes to zebra when ECMP is disabled. */
void ripng_ecmp_disable(struct ripng *ripng)
{
	struct agg_node *rp;
	struct ripng_info *rinfo, *tmp_rinfo;
	struct list *list;
	struct listnode *node, *nextnode;

	if (!ripng)
		return;

	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp))
		if ((list = rp->info) != NULL && listcount(list) > 1) {
			rinfo = listgetdata(listhead(list));
			if (!ripng_route_rte(rinfo))
				continue;

			/* Drop all other entries, except the first one. */
			for (ALL_LIST_ELEMENTS(list, node, nextnode, tmp_rinfo))
				if (tmp_rinfo != rinfo) {
					EVENT_OFF(tmp_rinfo->t_timeout);
					EVENT_OFF(tmp_rinfo->t_garbage_collect);
					list_delete_node(list, node);
					ripng_info_free(tmp_rinfo);
				}

			/* Update zebra. */
			ripng_zebra_ipv6_add(ripng, rp);

			/* Set the route change flag. */
			SET_FLAG(rinfo->flags, RIPNG_RTF_CHANGED);

			/* Signal the output process to trigger an update. */
			ripng_event(ripng, RIPNG_TRIGGERED_UPDATE, 0);
		}
}

static void ripng_distribute_update(struct distribute_ctx *ctx,
				    struct distribute *dist)
{
	struct interface *ifp;
	struct ripng_interface *ri;
	struct access_list *alist;
	struct prefix_list *plist;

	if (!ctx->vrf || !dist->ifname)
		return;

	ifp = if_lookup_by_name(dist->ifname, ctx->vrf->vrf_id);
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
	struct ripng_interface *ri = ifp->info;
	struct ripng *ripng = ri->ripng;
	struct distribute *dist;

	if (!ripng)
		return;
	dist = distribute_lookup(ripng->distribute_ctx, ifp->name);
	if (dist)
		ripng_distribute_update(ripng->distribute_ctx, dist);
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
void ripng_clean(struct ripng *ripng)
{
	ripng_interface_clean(ripng);

	if (ripng->enabled)
		ripng_instance_disable(ripng);

	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++)
		if (ripng->redist[i].route_map.name)
			free(ripng->redist[i].route_map.name);

	agg_table_finish(ripng->table);
	list_delete(&ripng->peer_list);
	distribute_list_delete(&ripng->distribute_ctx);
	if_rmap_ctx_delete(ripng->if_rmap_ctx);

	stream_free(ripng->ibuf);
	stream_free(ripng->obuf);

	ripng_clean_network(ripng);
	ripng_passive_interface_clean(ripng);
	vector_free(ripng->enable_if);
	agg_table_finish(ripng->enable_network);
	vector_free(ripng->passive_interface);
	list_delete(&ripng->offset_list_master);

	RB_REMOVE(ripng_instance_head, &ripng_instances, ripng);
	XFREE(MTYPE_RIPNG_VRF_NAME, ripng->vrf_name);
	XFREE(MTYPE_RIPNG, ripng);
}

static void ripng_if_rmap_update(struct if_rmap_ctx *ctx,
				 struct if_rmap *if_rmap)
{
	struct interface *ifp = NULL;
	struct ripng_interface *ri;
	struct route_map *rmap;
	struct vrf *vrf = NULL;

	if (ctx->name)
		vrf = vrf_lookup_by_name(ctx->name);
	if (vrf)
		ifp = if_lookup_by_name(if_rmap->ifname, vrf->vrf_id);
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
	struct ripng_interface *ri = ifp->info;
	struct ripng *ripng = ri->ripng;
	struct if_rmap *if_rmap;
	struct if_rmap_ctx *ctx;

	if (!ripng)
		return;
	ctx = ripng->if_rmap_ctx;
	if (!ctx)
		return;
	if_rmap = if_rmap_lookup(ctx, ifp->name);
	if (if_rmap)
		ripng_if_rmap_update(ctx, if_rmap);
}

static void ripng_routemap_update_redistribute(struct ripng *ripng)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (ripng->redist[i].route_map.name) {
			ripng->redist[i].route_map.map =
				route_map_lookup_by_name(
					ripng->redist[i].route_map.name);
			route_map_counter_increment(
				ripng->redist[i].route_map.map);
		}
	}
}

static void ripng_routemap_update(const char *unused)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct ripng *ripng;
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		ripng_if_rmap_update_interface(ifp);

	ripng = vrf->info;
	if (ripng)
		ripng_routemap_update_redistribute(ripng);
}

/* Link RIPng instance to VRF. */
static void ripng_vrf_link(struct ripng *ripng, struct vrf *vrf)
{
	struct interface *ifp;

	ripng->vrf = vrf;
	ripng->distribute_ctx->vrf = vrf;
	vrf->info = ripng;

	FOR_ALL_INTERFACES (vrf, ifp)
		ripng_interface_sync(ifp);
}

/* Unlink RIPng instance from VRF. */
static void ripng_vrf_unlink(struct ripng *ripng, struct vrf *vrf)
{
	struct interface *ifp;

	ripng->vrf = NULL;
	ripng->distribute_ctx->vrf = NULL;
	vrf->info = NULL;

	FOR_ALL_INTERFACES (vrf, ifp)
		ripng_interface_sync(ifp);
}

static void ripng_instance_enable(struct ripng *ripng, struct vrf *vrf,
				  int sock)
{
	ripng->sock = sock;

	ripng_vrf_link(ripng, vrf);
	ripng->enabled = true;

	/* Resend all redistribute requests. */
	ripng_redistribute_enable(ripng);

	/* Create read and timer thread. */
	ripng_event(ripng, RIPNG_READ, ripng->sock);
	ripng_event(ripng, RIPNG_UPDATE_EVENT, 1);

	ripng_zebra_vrf_register(vrf);
}

static void ripng_instance_disable(struct ripng *ripng)
{
	struct vrf *vrf = ripng->vrf;
	struct agg_node *rp;

	/* Clear RIPng routes */
	for (rp = agg_route_top(ripng->table); rp; rp = agg_route_next(rp)) {
		struct ripng_aggregate *aggregate;
		struct list *list;

		if ((list = rp->info) != NULL) {
			struct ripng_info *rinfo;
			struct listnode *listnode;

			rinfo = listgetdata(listhead(list));
			if (ripng_route_rte(rinfo))
				ripng_zebra_ipv6_delete(ripng, rp);

			for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
				EVENT_OFF(rinfo->t_timeout);
				EVENT_OFF(rinfo->t_garbage_collect);
				ripng_info_free(rinfo);
			}
			list_delete(&list);
			rp->info = NULL;
			agg_unlock_node(rp);
		}

		if ((aggregate = rp->aggregate) != NULL) {
			ripng_aggregate_free(aggregate);
			rp->aggregate = NULL;
			agg_unlock_node(rp);
		}
	}

	/* Flush all redistribute requests. */
	ripng_redistribute_disable(ripng);

	/* Cancel the RIPng timers */
	EVENT_OFF(ripng->t_update);
	EVENT_OFF(ripng->t_triggered_update);
	EVENT_OFF(ripng->t_triggered_interval);

	/* Cancel the read thread */
	EVENT_OFF(ripng->t_read);

	/* Close the RIPng socket */
	if (ripng->sock >= 0) {
		close(ripng->sock);
		ripng->sock = -1;
	}

	/* Clear existing peers. */
	list_delete_all_node(ripng->peer_list);

	ripng_zebra_vrf_deregister(vrf);

	ripng_vrf_unlink(ripng, vrf);
	ripng->enabled = false;
}

static int ripng_vrf_new(struct vrf *vrf)
{
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("%s: VRF created: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

static int ripng_vrf_delete(struct vrf *vrf)
{
	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("%s: VRF deleted: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

static int ripng_vrf_enable(struct vrf *vrf)
{
	struct ripng *ripng;
	int socket;

	ripng = ripng_lookup_by_vrf_name(vrf->name);
	if (!ripng || ripng->enabled)
		return 0;

	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("%s: VRF %s(%u) enabled", __func__, vrf->name,
			   vrf->vrf_id);

	/* Activate the VRF RIPng instance. */
	socket = ripng_make_socket(vrf);
	if (socket < 0)
		return -1;

	ripng_instance_enable(ripng, vrf, socket);

	return 0;
}

static int ripng_vrf_disable(struct vrf *vrf)
{
	struct ripng *ripng;

	ripng = ripng_lookup_by_vrf_name(vrf->name);
	if (!ripng || !ripng->enabled)
		return 0;

	if (IS_RIPNG_DEBUG_EVENT)
		zlog_debug("%s: VRF %s(%u) disabled", __func__, vrf->name,
			   vrf->vrf_id);

	/* Deactivate the VRF RIPng instance. */
	if (ripng->enabled)
		ripng_instance_disable(ripng);

	return 0;
}

void ripng_vrf_init(void)
{
	vrf_init(ripng_vrf_new, ripng_vrf_enable, ripng_vrf_disable,
		 ripng_vrf_delete);
}

void ripng_vrf_terminate(void)
{
	vrf_terminate();
}

/* Initialize ripng structure and set commands. */
void ripng_init(void)
{
	/* Install ripng commands. */
	install_element(VIEW_NODE, &show_ipv6_ripng_cmd);
	install_element(VIEW_NODE, &show_ipv6_ripng_status_cmd);
	install_element(ENABLE_NODE, &clear_ipv6_rip_cmd);

	ripng_if_init();
	ripng_debug_init();

	/* Enable mgmt be debug */
	mgmt_be_client_lib_vty_init();

	/* Access list install. */
	access_list_init_new(true);
	access_list_add_hook(ripng_distribute_update_all_wrapper);
	access_list_delete_hook(ripng_distribute_update_all_wrapper);

	/* Prefix list initialize.*/
	prefix_list_init();
	prefix_list_add_hook(ripng_distribute_update_all);
	prefix_list_delete_hook(ripng_distribute_update_all);

	/* Route-map for interface. */
	ripng_route_map_init();

	route_map_add_hook(ripng_routemap_update);
	route_map_delete_hook(ripng_routemap_update);
}
