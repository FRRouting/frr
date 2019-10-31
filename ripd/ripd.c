/* RIP version 1 and 2.
 * Copyright (C) 2005 6WIND <alain.ritoux@6wind.com>
 * Copyright (C) 1997, 98, 99 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "vrf.h"
#include "if.h"
#include "command.h"
#include "prefix.h"
#include "table.h"
#include "thread.h"
#include "memory.h"
#include "log.h"
#include "stream.h"
#include "filter.h"
#include "sockunion.h"
#include "sockopt.h"
#include "routemap.h"
#include "if_rmap.h"
#include "plist.h"
#include "distribute.h"
#ifdef CRYPTO_INTERNAL
#include "md5.h"
#endif
#include "keychain.h"
#include "privs.h"
#include "lib_errors.h"
#include "northbound_cli.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_errors.h"
#include "ripd/rip_interface.h"

/* UDP receive buffer size */
#define RIP_UDP_RCV_BUF 41600

DEFINE_MGROUP(RIPD, "ripd")
DEFINE_MTYPE_STATIC(RIPD, RIP, "RIP structure")
DEFINE_MTYPE_STATIC(RIPD, RIP_VRF_NAME, "RIP VRF name")
DEFINE_MTYPE_STATIC(RIPD, RIP_INFO, "RIP route info")
DEFINE_MTYPE_STATIC(RIPD, RIP_DISTANCE, "RIP distance")

/* Prototypes. */
static void rip_output_process(struct connected *, struct sockaddr_in *, int,
			       uint8_t);
static int rip_triggered_update(struct thread *);
static int rip_update_jitter(unsigned long);
static void rip_distance_table_node_cleanup(struct route_table *table,
					    struct route_node *node);
static void rip_instance_enable(struct rip *rip, struct vrf *vrf, int sock);
static void rip_instance_disable(struct rip *rip);

static void rip_distribute_update(struct distribute_ctx *ctx,
				  struct distribute *dist);

static void rip_if_rmap_update(struct if_rmap_ctx *ctx,
			       struct if_rmap *if_rmap);

/* RIP output routes type. */
enum { rip_all_route, rip_changed_route };

/* RIP command strings. */
static const struct message rip_msg[] = {{RIP_REQUEST, "REQUEST"},
					 {RIP_RESPONSE, "RESPONSE"},
					 {RIP_TRACEON, "TRACEON"},
					 {RIP_TRACEOFF, "TRACEOFF"},
					 {RIP_POLL, "POLL"},
					 {RIP_POLL_ENTRY, "POLL ENTRY"},
					 {0}};

/* Generate rb-tree of RIP instances. */
static inline int rip_instance_compare(const struct rip *a, const struct rip *b)
{
	return strcmp(a->vrf_name, b->vrf_name);
}
RB_GENERATE(rip_instance_head, rip, entry, rip_instance_compare)

struct rip_instance_head rip_instances = RB_INITIALIZER(&rip_instances);

/* Utility function to set boradcast option to the socket. */
static int sockopt_broadcast(int sock)
{
	int ret;
	int on = 1;

	ret = setsockopt(sock, SOL_SOCKET, SO_BROADCAST, (char *)&on,
			 sizeof on);
	if (ret < 0) {
		zlog_warn("can't set sockopt SO_BROADCAST to socket %d", sock);
		return -1;
	}
	return 0;
}

int rip_route_rte(struct rip_info *rinfo)
{
	return (rinfo->type == ZEBRA_ROUTE_RIP
		&& rinfo->sub_type == RIP_ROUTE_RTE);
}

static struct rip_info *rip_info_new(void)
{
	return XCALLOC(MTYPE_RIP_INFO, sizeof(struct rip_info));
}

void rip_info_free(struct rip_info *rinfo)
{
	XFREE(MTYPE_RIP_INFO, rinfo);
}

struct rip *rip_info_get_instance(const struct rip_info *rinfo)
{
	return route_table_get_info(rinfo->rp->table);
}

/* RIP route garbage collect timer. */
static int rip_garbage_collect(struct thread *t)
{
	struct rip_info *rinfo;
	struct route_node *rp;

	rinfo = THREAD_ARG(t);
	rinfo->t_garbage_collect = NULL;

	/* Off timeout timer. */
	RIP_TIMER_OFF(rinfo->t_timeout);

	/* Get route_node pointer. */
	rp = rinfo->rp;

	/* Unlock route_node. */
	listnode_delete(rp->info, rinfo);
	if (list_isempty((struct list *)rp->info)) {
		list_delete((struct list **)&rp->info);
		route_unlock_node(rp);
	}

	/* Free RIP routing information. */
	rip_info_free(rinfo);

	return 0;
}

static void rip_timeout_update(struct rip *rip, struct rip_info *rinfo);

/* Add new route to the ECMP list.
 * RETURN: the new entry added in the list, or NULL if it is not the first
 *         entry and ECMP is not allowed.
 */
struct rip_info *rip_ecmp_add(struct rip *rip, struct rip_info *rinfo_new)
{
	struct route_node *rp = rinfo_new->rp;
	struct rip_info *rinfo = NULL;
	struct list *list = NULL;

	if (rp->info == NULL)
		rp->info = list_new();
	list = (struct list *)rp->info;

	/* If ECMP is not allowed and some entry already exists in the list,
	 * do nothing. */
	if (listcount(list) && !rip->ecmp)
		return NULL;

	rinfo = rip_info_new();
	memcpy(rinfo, rinfo_new, sizeof(struct rip_info));
	listnode_add(list, rinfo);

	if (rip_route_rte(rinfo)) {
		rip_timeout_update(rip, rinfo);
		rip_zebra_ipv4_add(rip, rp);
	}

	/* Set the route change flag on the first entry. */
	rinfo = listgetdata(listhead(list));
	SET_FLAG(rinfo->flags, RIP_RTF_CHANGED);

	/* Signal the output process to trigger an update (see section 2.5). */
	rip_event(rip, RIP_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Replace the ECMP list with the new route.
 * RETURN: the new entry added in the list
 */
struct rip_info *rip_ecmp_replace(struct rip *rip, struct rip_info *rinfo_new)
{
	struct route_node *rp = rinfo_new->rp;
	struct list *list = (struct list *)rp->info;
	struct rip_info *rinfo = NULL, *tmp_rinfo = NULL;
	struct listnode *node = NULL, *nextnode = NULL;

	if (list == NULL || listcount(list) == 0)
		return rip_ecmp_add(rip, rinfo_new);

	/* Get the first entry */
	rinfo = listgetdata(listhead(list));

	/* Learnt route replaced by a local one. Delete it from zebra. */
	if (rip_route_rte(rinfo) && !rip_route_rte(rinfo_new))
		if (CHECK_FLAG(rinfo->flags, RIP_RTF_FIB))
			rip_zebra_ipv4_delete(rip, rp);

	/* Re-use the first entry, and delete the others. */
	for (ALL_LIST_ELEMENTS(list, node, nextnode, tmp_rinfo))
		if (tmp_rinfo != rinfo) {
			RIP_TIMER_OFF(tmp_rinfo->t_timeout);
			RIP_TIMER_OFF(tmp_rinfo->t_garbage_collect);
			list_delete_node(list, node);
			rip_info_free(tmp_rinfo);
		}

	RIP_TIMER_OFF(rinfo->t_timeout);
	RIP_TIMER_OFF(rinfo->t_garbage_collect);
	memcpy(rinfo, rinfo_new, sizeof(struct rip_info));

	if (rip_route_rte(rinfo)) {
		rip_timeout_update(rip, rinfo);
		/* The ADD message implies an update. */
		rip_zebra_ipv4_add(rip, rp);
	}

	/* Set the route change flag. */
	SET_FLAG(rinfo->flags, RIP_RTF_CHANGED);

	/* Signal the output process to trigger an update (see section 2.5). */
	rip_event(rip, RIP_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Delete one route from the ECMP list.
 * RETURN:
 *  null - the entry is freed, and other entries exist in the list
 *  the entry - the entry is the last one in the list; its metric is set
 *              to INFINITY, and the garbage collector is started for it
 */
struct rip_info *rip_ecmp_delete(struct rip *rip, struct rip_info *rinfo)
{
	struct route_node *rp = rinfo->rp;
	struct list *list = (struct list *)rp->info;

	RIP_TIMER_OFF(rinfo->t_timeout);

	if (listcount(list) > 1) {
		/* Some other ECMP entries still exist. Just delete this entry.
		 */
		RIP_TIMER_OFF(rinfo->t_garbage_collect);
		listnode_delete(list, rinfo);
		if (rip_route_rte(rinfo)
		    && CHECK_FLAG(rinfo->flags, RIP_RTF_FIB))
			/* The ADD message implies the update. */
			rip_zebra_ipv4_add(rip, rp);
		rip_info_free(rinfo);
		rinfo = NULL;
	} else {
		assert(rinfo == listgetdata(listhead(list)));

		/* This is the only entry left in the list. We must keep it in
		 * the list for garbage collection time, with INFINITY metric.
		 */

		rinfo->metric = RIP_METRIC_INFINITY;
		RIP_TIMER_ON(rinfo->t_garbage_collect, rip_garbage_collect,
			     rip->garbage_time);

		if (rip_route_rte(rinfo)
		    && CHECK_FLAG(rinfo->flags, RIP_RTF_FIB))
			rip_zebra_ipv4_delete(rip, rp);
	}

	/* Set the route change flag on the first entry. */
	rinfo = listgetdata(listhead(list));
	SET_FLAG(rinfo->flags, RIP_RTF_CHANGED);

	/* Signal the output process to trigger an update (see section 2.5). */
	rip_event(rip, RIP_TRIGGERED_UPDATE, 0);

	return rinfo;
}

/* Timeout RIP routes. */
static int rip_timeout(struct thread *t)
{
	struct rip_info *rinfo = THREAD_ARG(t);
	struct rip *rip = rip_info_get_instance(rinfo);

	rip_ecmp_delete(rip, rinfo);

	return 0;
}

static void rip_timeout_update(struct rip *rip, struct rip_info *rinfo)
{
	if (rinfo->metric != RIP_METRIC_INFINITY) {
		RIP_TIMER_OFF(rinfo->t_timeout);
		thread_add_timer(master, rip_timeout, rinfo, rip->timeout_time,
				 &rinfo->t_timeout);
	}
}

static int rip_filter(int rip_distribute, struct prefix_ipv4 *p,
		      struct rip_interface *ri)
{
	struct distribute *dist;
	struct access_list *alist;
	struct prefix_list *plist;
	int distribute = rip_distribute == RIP_FILTER_OUT ? DISTRIBUTE_V4_OUT
							  : DISTRIBUTE_V4_IN;
	const char *inout = rip_distribute == RIP_FILTER_OUT ? "out" : "in";

	/* Input distribute-list filtering. */
	if (ri->list[rip_distribute]) {
		if (access_list_apply(ri->list[rip_distribute],
				      (struct prefix *)p)
		    == FILTER_DENY) {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug("%s/%d filtered by distribute %s",
					   inet_ntoa(p->prefix), p->prefixlen,
					   inout);
			return -1;
		}
	}
	if (ri->prefix[rip_distribute]) {
		if (prefix_list_apply(ri->prefix[rip_distribute],
				      (struct prefix *)p)
		    == PREFIX_DENY) {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug("%s/%d filtered by prefix-list %s",
					   inet_ntoa(p->prefix), p->prefixlen,
					   inout);
			return -1;
		}
	}

	/* All interface filter check. */
	dist = distribute_lookup(ri->rip->distribute_ctx, NULL);
	if (dist) {
		if (dist->list[distribute]) {
			alist = access_list_lookup(AFI_IP,
						   dist->list[distribute]);

			if (alist) {
				if (access_list_apply(alist, (struct prefix *)p)
				    == FILTER_DENY) {
					if (IS_RIP_DEBUG_PACKET)
						zlog_debug(
							"%s/%d filtered by distribute %s",
							inet_ntoa(p->prefix),
							p->prefixlen, inout);
					return -1;
				}
			}
		}
		if (dist->prefix[distribute]) {
			plist = prefix_list_lookup(AFI_IP,
						   dist->prefix[distribute]);

			if (plist) {
				if (prefix_list_apply(plist, (struct prefix *)p)
				    == PREFIX_DENY) {
					if (IS_RIP_DEBUG_PACKET)
						zlog_debug(
							"%s/%d filtered by prefix-list %s",
							inet_ntoa(p->prefix),
							p->prefixlen, inout);
					return -1;
				}
			}
		}
	}
	return 0;
}

/* Check nexthop address validity. */
static int rip_nexthop_check(struct rip *rip, struct in_addr *addr)
{
	struct interface *ifp;
	struct listnode *cnode;
	struct connected *ifc;
	struct prefix *p;

	/* If nexthop address matches local configured address then it is
	   invalid nexthop. */

	FOR_ALL_INTERFACES (rip->vrf, ifp) {
		for (ALL_LIST_ELEMENTS_RO(ifp->connected, cnode, ifc)) {
			p = ifc->address;

			if (p->family == AF_INET
			    && IPV4_ADDR_SAME(&p->u.prefix4, addr))
				return -1;
		}
	}
	return 0;
}

/* RIP add route to routing table. */
static void rip_rte_process(struct rte *rte, struct sockaddr_in *from,
			    struct interface *ifp)
{
	struct rip *rip;
	int ret;
	struct prefix_ipv4 p;
	struct route_node *rp;
	struct rip_info *rinfo = NULL, newinfo;
	struct rip_interface *ri;
	struct in_addr *nexthop;
	int same = 0;
	unsigned char old_dist, new_dist;
	struct list *list = NULL;
	struct listnode *node = NULL;

	/* Make prefix structure. */
	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefix = rte->prefix;
	p.prefixlen = ip_masklen(rte->mask);

	/* Make sure mask is applied. */
	apply_mask_ipv4(&p);

	ri = ifp->info;
	rip = ri->rip;

	/* Apply input filters. */
	ret = rip_filter(RIP_FILTER_IN, &p, ri);
	if (ret < 0)
		return;

	memset(&newinfo, 0, sizeof(newinfo));
	newinfo.type = ZEBRA_ROUTE_RIP;
	newinfo.sub_type = RIP_ROUTE_RTE;
	newinfo.nh.gate.ipv4 = rte->nexthop;
	newinfo.from = from->sin_addr;
	newinfo.nh.ifindex = ifp->ifindex;
	newinfo.nh.type = NEXTHOP_TYPE_IPV4_IFINDEX;
	newinfo.metric = rte->metric;
	newinfo.metric_out = rte->metric; /* XXX */
	newinfo.tag = ntohs(rte->tag);    /* XXX */

	/* Modify entry according to the interface routemap. */
	if (ri->routemap[RIP_FILTER_IN]) {
		/* The object should be of the type of rip_info */
		ret = route_map_apply(ri->routemap[RIP_FILTER_IN],
				      (struct prefix *)&p, RMAP_RIP, &newinfo);

		if (ret == RMAP_DENYMATCH) {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug(
					"RIP %s/%d is filtered by route-map in",
					inet_ntoa(p.prefix), p.prefixlen);
			return;
		}

		/* Get back the object */
		rte->nexthop = newinfo.nexthop_out;
		rte->tag = htons(newinfo.tag_out); /* XXX */
		rte->metric = newinfo.metric_out;  /* XXX: the routemap uses the
						      metric_out field */
	}

	/* Once the entry has been validated, update the metric by
	   adding the cost of the network on wich the message
	   arrived. If the result is greater than infinity, use infinity
	   (RFC2453 Sec. 3.9.2) */
	/* Zebra ripd can handle offset-list in. */
	ret = rip_offset_list_apply_in(&p, ifp, &rte->metric);

	/* If offset-list does not modify the metric use interface's
	   metric. */
	if (!ret)
		rte->metric += ifp->metric ? ifp->metric : 1;

	if (rte->metric > RIP_METRIC_INFINITY)
		rte->metric = RIP_METRIC_INFINITY;

	/* Set nexthop pointer. */
	if (rte->nexthop.s_addr == 0)
		nexthop = &from->sin_addr;
	else
		nexthop = &rte->nexthop;

	/* Check if nexthop address is myself, then do nothing. */
	if (rip_nexthop_check(rip, nexthop) < 0) {
		if (IS_RIP_DEBUG_PACKET)
			zlog_debug("Nexthop address %s is myself",
				   inet_ntoa(*nexthop));
		return;
	}

	/* Get index for the prefix. */
	rp = route_node_get(rip->table, (struct prefix *)&p);

	newinfo.rp = rp;
	newinfo.nh.gate.ipv4 = *nexthop;
	newinfo.nh.type = NEXTHOP_TYPE_IPV4;
	newinfo.metric = rte->metric;
	newinfo.tag = ntohs(rte->tag);
	newinfo.distance = rip_distance_apply(rip, &newinfo);

	new_dist = newinfo.distance ? newinfo.distance
				    : ZEBRA_RIP_DISTANCE_DEFAULT;

	/* Check to see whether there is already RIP route on the table. */
	if ((list = rp->info) != NULL)
		for (ALL_LIST_ELEMENTS_RO(list, node, rinfo)) {
			/* Need to compare with redistributed entry or local
			 * entry */
			if (!rip_route_rte(rinfo))
				break;

			if (IPV4_ADDR_SAME(&rinfo->from, &from->sin_addr)
			    && IPV4_ADDR_SAME(&rinfo->nh.gate.ipv4, nexthop))
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

				/* Metrics are same. We compare the distances.
				 */
				old_dist = rinfo->distance
						   ? rinfo->distance
						   : ZEBRA_RIP_DISTANCE_DEFAULT;

				if (new_dist > old_dist) {
					/* New route has a greater distance.
					 * Discard it. */
					route_unlock_node(rp);
					return;
				}

				if (new_dist < old_dist)
					/* New route has a smaller distance.
					 * Replace the ECMP list
					 * with the new one in below. */
					break;

				/* Metrics and distances are both same. Keep
				 * "rinfo" null and
				 * the new route is added in the ECMP list in
				 * below. */
			}
		}

	if (rinfo) {
		/* Local static route. */
		if (rinfo->type == ZEBRA_ROUTE_RIP
		    && ((rinfo->sub_type == RIP_ROUTE_STATIC)
			|| (rinfo->sub_type == RIP_ROUTE_DEFAULT))
		    && rinfo->metric != RIP_METRIC_INFINITY) {
			route_unlock_node(rp);
			return;
		}

		/* Redistributed route check. */
		if (rinfo->type != ZEBRA_ROUTE_RIP
		    && rinfo->metric != RIP_METRIC_INFINITY) {
			old_dist = rinfo->distance;
			/* Only routes directly connected to an interface
			 * (nexthop == 0)
			 * may have a valid NULL distance */
			if (rinfo->nh.gate.ipv4.s_addr != 0)
				old_dist = old_dist
						   ? old_dist
						   : ZEBRA_RIP_DISTANCE_DEFAULT;
			/* If imported route does not have STRICT precedence,
			   mark it as a ghost */
			if (new_dist <= old_dist
			    && rte->metric != RIP_METRIC_INFINITY)
				rip_ecmp_replace(rip, &newinfo);

			route_unlock_node(rp);
			return;
		}
	}

	if (!rinfo) {
		if (rp->info)
			route_unlock_node(rp);

		/* Now, check to see whether there is already an explicit route
		   for the destination prefix.  If there is no such route, add
		   this route to the routing table, unless the metric is
		   infinity (there is no point in adding a route which
		   unusable). */
		if (rte->metric != RIP_METRIC_INFINITY)
			rip_ecmp_add(rip, &newinfo);
	} else {
		/* Route is there but we are not sure the route is RIP or not.
		 */

		/* If there is an existing route, compare the next hop address
		   to the address of the router from which the datagram came.
		   If this datagram is from the same router as the existing
		   route, reinitialize the timeout.  */
		same = (IPV4_ADDR_SAME(&rinfo->from, &from->sin_addr)
			&& (rinfo->nh.ifindex == ifp->ifindex));

		old_dist = rinfo->distance ? rinfo->distance
					   : ZEBRA_RIP_DISTANCE_DEFAULT;

		/* Next, compare the metrics.  If the datagram is from the same
		   router as the existing route, and the new metric is different
		   than the old one; or, if the new metric is lower than the old
		   one, or if the tag has been changed; or if there is a route
		   with a lower administrave distance; or an update of the
		   distance on the actual route; do the following actions: */
		if ((same && rinfo->metric != rte->metric)
		    || (rte->metric < rinfo->metric)
		    || ((same) && (rinfo->metric == rte->metric)
			&& (newinfo.tag != rinfo->tag))
		    || (old_dist > new_dist)
		    || ((old_dist != new_dist) && same)) {
			if (listcount(list) == 1) {
				if (newinfo.metric != RIP_METRIC_INFINITY)
					rip_ecmp_replace(rip, &newinfo);
				else
					rip_ecmp_delete(rip, rinfo);
			} else {
				if (newinfo.metric < rinfo->metric)
					rip_ecmp_replace(rip, &newinfo);
				else if (newinfo.metric > rinfo->metric)
					rip_ecmp_delete(rip, rinfo);
				else if (new_dist < old_dist)
					rip_ecmp_replace(rip, &newinfo);
				else if (new_dist > old_dist)
					rip_ecmp_delete(rip, rinfo);
				else {
					int update = CHECK_FLAG(rinfo->flags,
								RIP_RTF_FIB)
							     ? 1
							     : 0;

					assert(newinfo.metric
					       != RIP_METRIC_INFINITY);

					RIP_TIMER_OFF(rinfo->t_timeout);
					RIP_TIMER_OFF(rinfo->t_garbage_collect);
					memcpy(rinfo, &newinfo,
					       sizeof(struct rip_info));
					rip_timeout_update(rip, rinfo);

					if (update)
						rip_zebra_ipv4_add(rip, rp);

					/* - Set the route change flag on the
					 * first entry. */
					rinfo = listgetdata(listhead(list));
					SET_FLAG(rinfo->flags, RIP_RTF_CHANGED);
					rip_event(rip, RIP_TRIGGERED_UPDATE, 0);
				}
			}
		} else /* same & no change */
			rip_timeout_update(rip, rinfo);

		/* Unlock tempolary lock of the route. */
		route_unlock_node(rp);
	}
}

/* Dump RIP packet */
static void rip_packet_dump(struct rip_packet *packet, int size,
			    const char *sndrcv)
{
	caddr_t lim;
	struct rte *rte;
	const char *command_str;
	char pbuf[BUFSIZ], nbuf[BUFSIZ];
	uint8_t netmask = 0;
	uint8_t *p;

	/* Set command string. */
	if (packet->command > 0 && packet->command < RIP_COMMAND_MAX)
		command_str = lookup_msg(rip_msg, packet->command, NULL);
	else
		command_str = "unknown";

	/* Dump packet header. */
	zlog_debug("%s %s version %d packet size %d", sndrcv, command_str,
		   packet->version, size);

	/* Dump each routing table entry. */
	rte = packet->rte;

	for (lim = (caddr_t)packet + size; (caddr_t)rte < lim; rte++) {
		if (packet->version == RIPv2) {
			netmask = ip_masklen(rte->mask);

			if (rte->family == htons(RIP_FAMILY_AUTH)) {
				if (rte->tag
				    == htons(RIP_AUTH_SIMPLE_PASSWORD)) {
					p = (uint8_t *)&rte->prefix;

					zlog_debug(
						"  family 0x%X type %d auth string: %s",
						ntohs(rte->family),
						ntohs(rte->tag), p);
				} else if (rte->tag == htons(RIP_AUTH_MD5)) {
					struct rip_md5_info *md5;

					md5 = (struct rip_md5_info *)&packet
						      ->rte;

					zlog_debug(
						"  family 0x%X type %d (MD5 authentication)",
						ntohs(md5->family),
						ntohs(md5->type));
					zlog_debug(
						"    RIP-2 packet len %d Key ID %d"
						" Auth Data len %d",
						ntohs(md5->packet_len),
						md5->keyid, md5->auth_len);
					zlog_debug("    Sequence Number %ld",
						   (unsigned long)ntohl(
							   md5->sequence));
				} else if (rte->tag == htons(RIP_AUTH_DATA)) {
					p = (uint8_t *)&rte->prefix;

					zlog_debug(
						"  family 0x%X type %d (MD5 data)",
						ntohs(rte->family),
						ntohs(rte->tag));
					zlog_debug(
						"    MD5: %02X%02X%02X%02X%02X%02X%02X%02X"
						"%02X%02X%02X%02X%02X%02X%02X%02X",
						p[0], p[1], p[2], p[3], p[4],
						p[5], p[6], p[7], p[8], p[9],
						p[10], p[11], p[12], p[13],
						p[14], p[15]);
				} else {
					zlog_debug(
						"  family 0x%X type %d (Unknown auth type)",
						ntohs(rte->family),
						ntohs(rte->tag));
				}
			} else
				zlog_debug(
					"  %s/%d -> %s family %d tag %" ROUTE_TAG_PRI
					" metric %ld",
					inet_ntop(AF_INET, &rte->prefix, pbuf,
						  BUFSIZ),
					netmask,
					inet_ntop(AF_INET, &rte->nexthop, nbuf,
						  BUFSIZ),
					ntohs(rte->family),
					(route_tag_t)ntohs(rte->tag),
					(unsigned long)ntohl(rte->metric));
		} else {
			zlog_debug(
				"  %s family %d tag %" ROUTE_TAG_PRI
				" metric %ld",
				inet_ntop(AF_INET, &rte->prefix, pbuf, BUFSIZ),
				ntohs(rte->family),
				(route_tag_t)ntohs(rte->tag),
				(unsigned long)ntohl(rte->metric));
		}
	}
}

/* Check if the destination address is valid (unicast; not net 0
   or 127) (RFC2453 Section 3.9.2 - Page 26).  But we don't
   check net 0 because we accept default route. */
static int rip_destination_check(struct in_addr addr)
{
	uint32_t destination;

	/* Convert to host byte order. */
	destination = ntohl(addr.s_addr);

	if (IPV4_NET127(destination))
		return 0;

	/* Net 0 may match to the default route. */
	if (IPV4_NET0(destination) && destination != 0)
		return 0;

	/* Unicast address must belong to class A, B, C. */
	if (IN_CLASSA(destination))
		return 1;
	if (IN_CLASSB(destination))
		return 1;
	if (IN_CLASSC(destination))
		return 1;

	return 0;
}

/* RIP version 2 authentication. */
static int rip_auth_simple_password(struct rte *rte, struct sockaddr_in *from,
				    struct interface *ifp)
{
	struct rip_interface *ri;
	char *auth_str = (char *)rte + offsetof(struct rte, prefix);
	int i;

	/* reject passwords with zeros in the middle of the string */
	for (i = strnlen(auth_str, 16); i < 16; i++) {
		if (auth_str[i] != '\0')
			return 0;
	}

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("RIPv2 simple password authentication from %s",
			   inet_ntoa(from->sin_addr));

	ri = ifp->info;

	if (ri->auth_type != RIP_AUTH_SIMPLE_PASSWORD
	    || rte->tag != htons(RIP_AUTH_SIMPLE_PASSWORD))
		return 0;

	/* Simple password authentication. */
	if (ri->auth_str) {
		if (strncmp(auth_str, ri->auth_str, 16) == 0)
			return 1;
	}
	if (ri->key_chain) {
		struct keychain *keychain;
		struct key *key;

		keychain = keychain_lookup(ri->key_chain);
		if (keychain == NULL || keychain->key == NULL)
			return 0;

		key = key_match_for_accept(keychain, auth_str);
		if (key)
			return 1;
	}
	return 0;
}

/* RIP version 2 authentication with MD5. */
static int rip_auth_md5(struct rip_packet *packet, struct sockaddr_in *from,
			int length, struct interface *ifp)
{
	struct rip_interface *ri;
	struct rip_md5_info *md5;
	struct rip_md5_data *md5data;
	struct keychain *keychain;
	struct key *key;
#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	MD5_CTX ctx;
#endif
	uint8_t digest[RIP_AUTH_MD5_SIZE];
	uint16_t packet_len;
	char auth_str[RIP_AUTH_MD5_SIZE] = {};

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("RIPv2 MD5 authentication from %s",
			   inet_ntoa(from->sin_addr));

	ri = ifp->info;
	md5 = (struct rip_md5_info *)&packet->rte;

	/* Check auth type. */
	if (ri->auth_type != RIP_AUTH_MD5 || md5->type != htons(RIP_AUTH_MD5))
		return 0;

	/* If the authentication length is less than 16, then it must be wrong
	 * for
	 * any interpretation of rfc2082. Some implementations also interpret
	 * this as RIP_HEADER_SIZE+ RIP_AUTH_MD5_SIZE, aka
	 * RIP_AUTH_MD5_COMPAT_SIZE.
	 */
	if (!((md5->auth_len == RIP_AUTH_MD5_SIZE)
	      || (md5->auth_len == RIP_AUTH_MD5_COMPAT_SIZE))) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug(
				"RIPv2 MD5 authentication, strange authentication "
				"length field %d",
				md5->auth_len);
		return 0;
	}

	/* grab and verify check packet length */
	packet_len = ntohs(md5->packet_len);

	if (packet_len > (length - RIP_HEADER_SIZE - RIP_AUTH_MD5_SIZE)) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug(
				"RIPv2 MD5 authentication, packet length field %d "
				"greater than received length %d!",
				md5->packet_len, length);
		return 0;
	}

	/* retrieve authentication data */
	md5data = (struct rip_md5_data *)(((uint8_t *)packet) + packet_len);

	if (ri->key_chain) {
		keychain = keychain_lookup(ri->key_chain);
		if (keychain == NULL)
			return 0;

		key = key_lookup_for_accept(keychain, md5->keyid);
		if (key == NULL || key->string == NULL)
			return 0;

		strlcpy(auth_str, key->string, sizeof(auth_str));
	} else if (ri->auth_str)
		strlcpy(auth_str, ri->auth_str, sizeof(auth_str));

	if (auth_str[0] == 0)
		return 0;

	/* MD5 digest authentication. */
#ifdef CRYPTO_OPENSSL
	unsigned int md5_size = RIP_AUTH_MD5_SIZE;
	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_md5());
	EVP_DigestUpdate(ctx, packet, packet_len + RIP_HEADER_SIZE);
	EVP_DigestUpdate(ctx, auth_str, RIP_AUTH_MD5_SIZE);
	EVP_DigestFinal(ctx, digest, &md5_size);
	EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, packet, packet_len + RIP_HEADER_SIZE);
	MD5Update(&ctx, auth_str, RIP_AUTH_MD5_SIZE);
	MD5Final(digest, &ctx);
#endif

	if (memcmp(md5data->digest, digest, RIP_AUTH_MD5_SIZE) == 0)
		return packet_len;
	else
		return 0;
}

/* Pick correct auth string for sends, prepare auth_str buffer for use.
 * (left justified and padded).
 *
 * presumes one of ri or key is valid, and that the auth strings they point
 * to are nul terminated. If neither are present, auth_str will be fully
 * zero padded.
 *
 */
static void rip_auth_prepare_str_send(struct rip_interface *ri, struct key *key,
				      char *auth_str, int len)
{
	assert(ri || key);

	memset(auth_str, 0, len);
	if (key && key->string)
		strlcpy(auth_str, key->string, len);
	else if (ri->auth_str)
		strlcpy(auth_str, ri->auth_str, len);

	return;
}

/* Write RIPv2 simple password authentication information
 *
 * auth_str is presumed to be 2 bytes and correctly prepared
 * (left justified and zero padded).
 */
static void rip_auth_simple_write(struct stream *s, char *auth_str, int len)
{
	assert(s && len == RIP_AUTH_SIMPLE_SIZE);

	stream_putw(s, RIP_FAMILY_AUTH);
	stream_putw(s, RIP_AUTH_SIMPLE_PASSWORD);
	stream_put(s, auth_str, RIP_AUTH_SIMPLE_SIZE);

	return;
}

/* write RIPv2 MD5 "authentication header"
 * (uses the auth key data field)
 *
 * Digest offset field is set to 0.
 *
 * returns: offset of the digest offset field, which must be set when
 * length to the auth-data MD5 digest is known.
 */
static size_t rip_auth_md5_ah_write(struct stream *s, struct rip_interface *ri,
				    struct key *key)
{
	size_t doff = 0;

	assert(s && ri && ri->auth_type == RIP_AUTH_MD5);

	/* MD5 authentication. */
	stream_putw(s, RIP_FAMILY_AUTH);
	stream_putw(s, RIP_AUTH_MD5);

	/* MD5 AH digest offset field.
	 *
	 * Set to placeholder value here, to true value when RIP-2 Packet length
	 * is known.  Actual value is set in .....().
	 */
	doff = stream_get_endp(s);
	stream_putw(s, 0);

	/* Key ID. */
	if (key)
		stream_putc(s, key->index % 256);
	else
		stream_putc(s, 1);

	/* Auth Data Len.  Set 16 for MD5 authentication data. Older ripds
	 * however expect RIP_HEADER_SIZE + RIP_AUTH_MD5_SIZE so we allow for
	 * this
	 * to be configurable.
	 */
	stream_putc(s, ri->md5_auth_len);

	/* Sequence Number (non-decreasing). */
	/* RFC2080: The value used in the sequence number is
	   arbitrary, but two suggestions are the time of the
	   message's creation or a simple message counter. */
	stream_putl(s, time(NULL));

	/* Reserved field must be zero. */
	stream_putl(s, 0);
	stream_putl(s, 0);

	return doff;
}

/* If authentication is in used, write the appropriate header
 * returns stream offset to which length must later be written
 * or 0 if this is not required
 */
static size_t rip_auth_header_write(struct stream *s, struct rip_interface *ri,
				    struct key *key, char *auth_str, int len)
{
	assert(ri->auth_type != RIP_NO_AUTH);

	switch (ri->auth_type) {
	case RIP_AUTH_SIMPLE_PASSWORD:
		rip_auth_prepare_str_send(ri, key, auth_str, len);
		rip_auth_simple_write(s, auth_str, len);
		return 0;
	case RIP_AUTH_MD5:
		return rip_auth_md5_ah_write(s, ri, key);
	}
	assert(1);
	return 0;
}

/* Write RIPv2 MD5 authentication data trailer */
static void rip_auth_md5_set(struct stream *s, struct rip_interface *ri,
			     size_t doff, char *auth_str, int authlen)
{
	unsigned long len;
#ifdef CRYPTO_OPENSSL
	EVP_MD_CTX *ctx;
#elif CRYPTO_INTERNAL
	MD5_CTX ctx;
#endif
	unsigned char digest[RIP_AUTH_MD5_SIZE];

	/* Make it sure this interface is configured as MD5
	   authentication. */
	assert((ri->auth_type == RIP_AUTH_MD5)
	       && (authlen == RIP_AUTH_MD5_SIZE));
	assert(doff > 0);

	/* Get packet length. */
	len = stream_get_endp(s);

	/* Check packet length. */
	if (len < (RIP_HEADER_SIZE + RIP_RTE_SIZE)) {
		flog_err(
			EC_RIP_PACKET,
			"rip_auth_md5_set(): packet length %ld is less than minimum length.",
			len);
		return;
	}

	/* Set the digest offset length in the header */
	stream_putw_at(s, doff, len);

	/* Set authentication data. */
	stream_putw(s, RIP_FAMILY_AUTH);
	stream_putw(s, RIP_AUTH_DATA);

	/* Generate a digest for the RIP packet. */
#ifdef CRYPTO_OPENSSL
	unsigned int md5_size = RIP_AUTH_MD5_SIZE;
	ctx = EVP_MD_CTX_new();
	EVP_DigestInit(ctx, EVP_md5());
	EVP_DigestUpdate(ctx, STREAM_DATA(s), stream_get_endp(s));
	EVP_DigestUpdate(ctx, auth_str, RIP_AUTH_MD5_SIZE);
	EVP_DigestFinal(ctx, digest, &md5_size);
	EVP_MD_CTX_free(ctx);
#elif CRYPTO_INTERNAL
	memset(&ctx, 0, sizeof(ctx));
	MD5Init(&ctx);
	MD5Update(&ctx, STREAM_DATA(s), stream_get_endp(s));
	MD5Update(&ctx, auth_str, RIP_AUTH_MD5_SIZE);
	MD5Final(digest, &ctx);
#endif

	/* Copy the digest to the packet. */
	stream_write(s, digest, RIP_AUTH_MD5_SIZE);
}

/* RIP routing information. */
static void rip_response_process(struct rip_packet *packet, int size,
				 struct sockaddr_in *from,
				 struct connected *ifc)
{
	struct rip_interface *ri = ifc->ifp->info;
	struct rip *rip = ri->rip;
	caddr_t lim;
	struct rte *rte;
	struct prefix_ipv4 ifaddr;
	struct prefix_ipv4 ifaddrclass;
	int subnetted;

	memset(&ifaddr, 0, sizeof(ifaddr));
	/* We don't know yet. */
	subnetted = -1;

	/* The Response must be ignored if it is not from the RIP
	   port. (RFC2453 - Sec. 3.9.2)*/
	if (from->sin_port != htons(RIP_PORT_DEFAULT)) {
		zlog_info("response doesn't come from RIP port: %d",
			  from->sin_port);
		rip_peer_bad_packet(rip, from);
		return;
	}

	/* The datagram's IPv4 source address should be checked to see
	   whether the datagram is from a valid neighbor; the source of the
	   datagram must be on a directly connected network (RFC2453 - Sec.
	   3.9.2) */
	if (if_lookup_address((void *)&from->sin_addr, AF_INET,
			      rip->vrf->vrf_id)
	    == NULL) {
		zlog_info(
			"This datagram doesn't came from a valid neighbor: %s",
			inet_ntoa(from->sin_addr));
		rip_peer_bad_packet(rip, from);
		return;
	}

	/* It is also worth checking to see whether the response is from one
	   of the router's own addresses. */

	; /* Alredy done in rip_read () */

	/* Update RIP peer. */
	rip_peer_update(rip, from, packet->version);

	/* Set RTE pointer. */
	rte = packet->rte;

	for (lim = (caddr_t)packet + size; (caddr_t)rte < lim; rte++) {
		/* RIPv2 authentication check. */
		/* If the Address Family Identifier of the first (and only the
		   first) entry in the message is 0xFFFF, then the remainder of
		   the entry contains the authentication. */
		/* If the packet gets here it means authentication enabled */
		/* Check is done in rip_read(). So, just skipping it */
		if (packet->version == RIPv2 && rte == packet->rte
		    && rte->family == htons(RIP_FAMILY_AUTH))
			continue;

		if (rte->family != htons(AF_INET)) {
			/* Address family check.  RIP only supports AF_INET. */
			zlog_info("Unsupported family %d from %s.",
				  ntohs(rte->family),
				  inet_ntoa(from->sin_addr));
			continue;
		}

		/* - is the destination address valid (e.g., unicast; not net 0
		   or 127) */
		if (!rip_destination_check(rte->prefix)) {
			zlog_info(
				"Network is net 0 or net 127 or it is not unicast network");
			rip_peer_bad_route(rip, from);
			continue;
		}

		/* Convert metric value to host byte order. */
		rte->metric = ntohl(rte->metric);

		/* - is the metric valid (i.e., between 1 and 16, inclusive) */
		if (!(rte->metric >= 1 && rte->metric <= 16)) {
			zlog_info("Route's metric is not in the 1-16 range.");
			rip_peer_bad_route(rip, from);
			continue;
		}

		/* RIPv1 does not have nexthop value. */
		if (packet->version == RIPv1 && rte->nexthop.s_addr != 0) {
			zlog_info("RIPv1 packet with nexthop value %s",
				  inet_ntoa(rte->nexthop));
			rip_peer_bad_route(rip, from);
			continue;
		}

		/* That is, if the provided information is ignored, a possibly
		   sub-optimal, but absolutely valid, route may be taken.  If
		   the received Next Hop is not directly reachable, it should be
		   treated as 0.0.0.0. */
		if (packet->version == RIPv2 && rte->nexthop.s_addr != 0) {
			uint32_t addrval;

			/* Multicast address check. */
			addrval = ntohl(rte->nexthop.s_addr);
			if (IN_CLASSD(addrval)) {
				zlog_info(
					"Nexthop %s is multicast address, skip this rte",
					inet_ntoa(rte->nexthop));
				continue;
			}

			if (!if_lookup_address((void *)&rte->nexthop, AF_INET,
					       rip->vrf->vrf_id)) {
				struct route_node *rn;
				struct rip_info *rinfo;

				rn = route_node_match_ipv4(rip->table,
							   &rte->nexthop);

				if (rn) {
					rinfo = rn->info;

					if (rinfo->type == ZEBRA_ROUTE_RIP
					    && rinfo->sub_type
						       == RIP_ROUTE_RTE) {
						if (IS_RIP_DEBUG_EVENT)
							zlog_debug(
								"Next hop %s is on RIP network.  Set nexthop to the packet's originator",
								inet_ntoa(
									rte->nexthop));
						rte->nexthop = rinfo->from;
					} else {
						if (IS_RIP_DEBUG_EVENT)
							zlog_debug(
								"Next hop %s is not directly reachable. Treat it as 0.0.0.0",
								inet_ntoa(
									rte->nexthop));
						rte->nexthop.s_addr = 0;
					}

					route_unlock_node(rn);
				} else {
					if (IS_RIP_DEBUG_EVENT)
						zlog_debug(
							"Next hop %s is not directly reachable. Treat it as 0.0.0.0",
							inet_ntoa(
								rte->nexthop));
					rte->nexthop.s_addr = 0;
				}
			}
		}

		/* For RIPv1, there won't be a valid netmask.

		   This is a best guess at the masks.  If everyone was using old
		   Ciscos before the 'ip subnet zero' option, it would be almost
		   right too :-)

		   Cisco summarize ripv1 advertisements to the classful boundary
		   (/16 for class B's) except when the RIP packet does to inside
		   the classful network in question.  */

		if ((packet->version == RIPv1 && rte->prefix.s_addr != 0)
		    || (packet->version == RIPv2
			&& (rte->prefix.s_addr != 0
			    && rte->mask.s_addr == 0))) {
			uint32_t destination;

			if (subnetted == -1) {
				memcpy(&ifaddr, ifc->address,
				       sizeof(struct prefix_ipv4));
				memcpy(&ifaddrclass, &ifaddr,
				       sizeof(struct prefix_ipv4));
				apply_classful_mask_ipv4(&ifaddrclass);
				subnetted = 0;
				if (ifaddr.prefixlen > ifaddrclass.prefixlen)
					subnetted = 1;
			}

			destination = ntohl(rte->prefix.s_addr);

			if (IN_CLASSA(destination))
				masklen2ip(8, &rte->mask);
			else if (IN_CLASSB(destination))
				masklen2ip(16, &rte->mask);
			else if (IN_CLASSC(destination))
				masklen2ip(24, &rte->mask);

			if (subnetted == 1)
				masklen2ip(ifaddrclass.prefixlen,
					   (struct in_addr *)&destination);
			if ((subnetted == 1)
			    && ((rte->prefix.s_addr & destination)
				== ifaddrclass.prefix.s_addr)) {
				masklen2ip(ifaddr.prefixlen, &rte->mask);
				if ((rte->prefix.s_addr & rte->mask.s_addr)
				    != rte->prefix.s_addr)
					masklen2ip(32, &rte->mask);
				if (IS_RIP_DEBUG_EVENT)
					zlog_debug("Subnetted route %s",
						   inet_ntoa(rte->prefix));
			} else {
				if ((rte->prefix.s_addr & rte->mask.s_addr)
				    != rte->prefix.s_addr)
					continue;
			}

			if (IS_RIP_DEBUG_EVENT) {
				zlog_debug("Resultant route %s",
					   inet_ntoa(rte->prefix));
				zlog_debug("Resultant mask %s",
					   inet_ntoa(rte->mask));
			}
		}

		/* In case of RIPv2, if prefix in RTE is not netmask applied one
		   ignore the entry.  */
		if ((packet->version == RIPv2) && (rte->mask.s_addr != 0)
		    && ((rte->prefix.s_addr & rte->mask.s_addr)
			!= rte->prefix.s_addr)) {
			zlog_warn(
				"RIPv2 address %s is not mask /%d applied one",
				inet_ntoa(rte->prefix), ip_masklen(rte->mask));
			rip_peer_bad_route(rip, from);
			continue;
		}

		/* Default route's netmask is ignored. */
		if (packet->version == RIPv2 && (rte->prefix.s_addr == 0)
		    && (rte->mask.s_addr != 0)) {
			if (IS_RIP_DEBUG_EVENT)
				zlog_debug(
					"Default route with non-zero netmask.  Set zero to netmask");
			rte->mask.s_addr = 0;
		}

		/* Routing table updates. */
		rip_rte_process(rte, from, ifc->ifp);
	}
}

/* Make socket for RIP protocol. */
int rip_create_socket(struct vrf *vrf)
{
	int ret;
	int sock;
	struct sockaddr_in addr;
	const char *vrf_dev = NULL;

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	addr.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */
	/* sending port must always be the RIP port */
	addr.sin_port = htons(RIP_PORT_DEFAULT);

	/* Make datagram socket. */
	if (vrf->vrf_id != VRF_DEFAULT)
		vrf_dev = vrf->name;
	frr_with_privs(&ripd_privs) {
		sock = vrf_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, vrf->vrf_id,
				  vrf_dev);
		if (sock < 0) {
			flog_err_sys(EC_LIB_SOCKET,
				     "Cannot create UDP socket: %s",
				     safe_strerror(errno));
			return -1;
		}
	}

	sockopt_broadcast(sock);
	sockopt_reuseaddr(sock);
	sockopt_reuseport(sock);
	setsockopt_ipv4_multicast_loop(sock, 0);
#ifdef IPTOS_PREC_INTERNETCONTROL
	setsockopt_ipv4_tos(sock, IPTOS_PREC_INTERNETCONTROL);
#endif
	setsockopt_so_recvbuf(sock, RIP_UDP_RCV_BUF);

	frr_with_privs(&ripd_privs) {
		if ((ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr)))
		    < 0) {
			zlog_err("%s: Can't bind socket %d to %s port %d: %s",
				 __func__, sock, inet_ntoa(addr.sin_addr),
				 (int)ntohs(addr.sin_port),
				 safe_strerror(errno));

			close(sock);
			return ret;
		}
	}

	return sock;
}

/* RIP packet send to destination address, on interface denoted by
 * by connected argument. NULL to argument denotes destination should be
 * should be RIP multicast group
 */
static int rip_send_packet(uint8_t *buf, int size, struct sockaddr_in *to,
			   struct connected *ifc)
{
	struct rip_interface *ri;
	struct rip *rip;
	int ret;
	struct sockaddr_in sin;
	struct msghdr msg;
	struct iovec iov;
#ifdef GNU_LINUX
	struct cmsghdr *cmsgptr;
	char adata[256] = {};
	struct in_pktinfo *pkt;
#endif /* GNU_LINUX */

	assert(ifc != NULL);
	ri = ifc->ifp->info;
	rip = ri->rip;

	if (IS_RIP_DEBUG_PACKET) {
#define ADDRESS_SIZE 20
		char dst[ADDRESS_SIZE];

		if (to) {
			strlcpy(dst, inet_ntoa(to->sin_addr), sizeof(dst));
		} else {
			sin.sin_addr.s_addr = htonl(INADDR_RIP_GROUP);
			strlcpy(dst, inet_ntoa(sin.sin_addr), sizeof(dst));
		}
#undef ADDRESS_SIZE
		zlog_debug("rip_send_packet %s > %s (%s)",
			   inet_ntoa(ifc->address->u.prefix4), dst,
			   ifc->ifp->name);
	}

	if (CHECK_FLAG(ifc->flags, ZEBRA_IFA_SECONDARY)) {
		/*
		 * ZEBRA_IFA_SECONDARY is set on linux when an interface is
		 * configured
		 * with multiple addresses on the same subnet: the first address
		 * on the subnet is configured "primary", and all subsequent
		 * addresses
		 * on that subnet are treated as "secondary" addresses.
		 * In order to avoid routing-table bloat on other rip listeners,
		 * we do not send out RIP packets with ZEBRA_IFA_SECONDARY
		 * source addrs.
		 * XXX Since Linux is the only system for which the
		 * ZEBRA_IFA_SECONDARY
		 * flag is set, we would end up sending a packet for a
		 * "secondary"
		 * source address on non-linux systems.
		 */
		if (IS_RIP_DEBUG_PACKET)
			zlog_debug("duplicate dropped");
		return 0;
	}

	/* Make destination address. */
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
#ifdef HAVE_STRUCT_SOCKADDR_IN_SIN_LEN
	sin.sin_len = sizeof(struct sockaddr_in);
#endif /* HAVE_STRUCT_SOCKADDR_IN_SIN_LEN */

	/* When destination is specified, use it's port and address. */
	if (to) {
		sin.sin_port = to->sin_port;
		sin.sin_addr = to->sin_addr;
	} else {
		sin.sin_port = htons(RIP_PORT_DEFAULT);
		sin.sin_addr.s_addr = htonl(INADDR_RIP_GROUP);

		rip_interface_multicast_set(rip->sock, ifc);
	}

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&sin;
	msg.msg_namelen = sizeof(struct sockaddr_in);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	iov.iov_base = buf;
	iov.iov_len = size;

#ifdef GNU_LINUX
	msg.msg_control = (void *)adata;
	msg.msg_controllen = CMSG_SPACE(sizeof(struct in_pktinfo));

	cmsgptr = (struct cmsghdr *)adata;
	cmsgptr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
	cmsgptr->cmsg_level = IPPROTO_IP;
	cmsgptr->cmsg_type = IP_PKTINFO;
	pkt = (struct in_pktinfo *)CMSG_DATA(cmsgptr);
	pkt->ipi_ifindex = ifc->ifp->ifindex;
#endif /* GNU_LINUX */

	ret = sendmsg(rip->sock, &msg, 0);

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("SEND to  %s.%d", inet_ntoa(sin.sin_addr),
			   ntohs(sin.sin_port));

	if (ret < 0)
		zlog_warn("can't send packet : %s", safe_strerror(errno));

	return ret;
}

/* Add redistributed route to RIP table. */
void rip_redistribute_add(struct rip *rip, int type, int sub_type,
			  struct prefix_ipv4 *p, struct nexthop *nh,
			  unsigned int metric, unsigned char distance,
			  route_tag_t tag)
{
	int ret;
	struct route_node *rp = NULL;
	struct rip_info *rinfo = NULL, newinfo;
	struct list *list = NULL;

	/* Redistribute route  */
	ret = rip_destination_check(p->prefix);
	if (!ret)
		return;

	rp = route_node_get(rip->table, (struct prefix *)p);

	memset(&newinfo, 0, sizeof(struct rip_info));
	newinfo.type = type;
	newinfo.sub_type = sub_type;
	newinfo.metric = 1;
	newinfo.external_metric = metric;
	newinfo.distance = distance;
	if (tag <= UINT16_MAX) /* RIP only supports 16 bit tags */
		newinfo.tag = tag;
	newinfo.rp = rp;
	newinfo.nh = *nh;

	if ((list = rp->info) != NULL && listcount(list) != 0) {
		rinfo = listgetdata(listhead(list));

		if (rinfo->type == ZEBRA_ROUTE_CONNECT
		    && rinfo->sub_type == RIP_ROUTE_INTERFACE
		    && rinfo->metric != RIP_METRIC_INFINITY) {
			route_unlock_node(rp);
			return;
		}

		/* Manually configured RIP route check. */
		if (rinfo->type == ZEBRA_ROUTE_RIP
		    && ((rinfo->sub_type == RIP_ROUTE_STATIC)
			|| (rinfo->sub_type == RIP_ROUTE_DEFAULT))) {
			if (type != ZEBRA_ROUTE_RIP
			    || ((sub_type != RIP_ROUTE_STATIC)
				&& (sub_type != RIP_ROUTE_DEFAULT))) {
				route_unlock_node(rp);
				return;
			}
		}

		(void)rip_ecmp_replace(rip, &newinfo);
		route_unlock_node(rp);
	} else
		(void)rip_ecmp_add(rip, &newinfo);

	if (IS_RIP_DEBUG_EVENT) {
		zlog_debug("Redistribute new prefix %s/%d",
			   inet_ntoa(p->prefix), p->prefixlen);
	}

	rip_event(rip, RIP_TRIGGERED_UPDATE, 0);
}

/* Delete redistributed route from RIP table. */
void rip_redistribute_delete(struct rip *rip, int type, int sub_type,
			     struct prefix_ipv4 *p, ifindex_t ifindex)
{
	int ret;
	struct route_node *rp;
	struct rip_info *rinfo;

	ret = rip_destination_check(p->prefix);
	if (!ret)
		return;

	rp = route_node_lookup(rip->table, (struct prefix *)p);
	if (rp) {
		struct list *list = rp->info;

		if (list != NULL && listcount(list) != 0) {
			rinfo = listgetdata(listhead(list));
			if (rinfo != NULL && rinfo->type == type
			    && rinfo->sub_type == sub_type
			    && rinfo->nh.ifindex == ifindex) {
				/* Perform poisoned reverse. */
				rinfo->metric = RIP_METRIC_INFINITY;
				RIP_TIMER_ON(rinfo->t_garbage_collect,
					     rip_garbage_collect,
					     rip->garbage_time);
				RIP_TIMER_OFF(rinfo->t_timeout);
				rinfo->flags |= RIP_RTF_CHANGED;

				if (IS_RIP_DEBUG_EVENT)
					zlog_debug(
						"Poison %s/%d on the interface %s with an "
						"infinity metric [delete]",
						inet_ntoa(p->prefix),
						p->prefixlen,
						ifindex2ifname(
							ifindex,
							rip->vrf->vrf_id));

				rip_event(rip, RIP_TRIGGERED_UPDATE, 0);
			}
		}
		route_unlock_node(rp);
	}
}

/* Response to request called from rip_read ().*/
static void rip_request_process(struct rip_packet *packet, int size,
				struct sockaddr_in *from, struct connected *ifc)
{
	struct rip *rip;
	caddr_t lim;
	struct rte *rte;
	struct prefix_ipv4 p;
	struct route_node *rp;
	struct rip_info *rinfo;
	struct rip_interface *ri;

	/* Does not reponse to the requests on the loopback interfaces */
	if (if_is_loopback(ifc->ifp))
		return;

	/* Check RIP process is enabled on this interface. */
	ri = ifc->ifp->info;
	if (!ri->running)
		return;
	rip = ri->rip;

	/* When passive interface is specified, suppress responses */
	if (ri->passive)
		return;

	/* RIP peer update. */
	rip_peer_update(rip, from, packet->version);

	lim = ((caddr_t)packet) + size;
	rte = packet->rte;

	/* The Request is processed entry by entry.  If there are no
	   entries, no response is given. */
	if (lim == (caddr_t)rte)
		return;

	/* There is one special case.  If there is exactly one entry in the
	   request, and it has an address family identifier of zero and a
	   metric of infinity (i.e., 16), then this is a request to send the
	   entire routing table. */
	if (lim == ((caddr_t)(rte + 1)) && ntohs(rte->family) == 0
	    && ntohl(rte->metric) == RIP_METRIC_INFINITY) {
		/* All route with split horizon */
		rip_output_process(ifc, from, rip_all_route, packet->version);
	} else {
		if (ntohs(rte->family) != AF_INET)
			return;

		/* Examine the list of RTEs in the Request one by one.  For each
		   entry, look up the destination in the router's routing
		   database and, if there is a route, put that route's metric in
		   the metric field of the RTE.  If there is no explicit route
		   to the specified destination, put infinity in the metric
		   field.  Once all the entries have been filled in, change the
		   command from Request to Response and send the datagram back
		   to the requestor. */
		p.family = AF_INET;

		for (; ((caddr_t)rte) < lim; rte++) {
			p.prefix = rte->prefix;
			p.prefixlen = ip_masklen(rte->mask);
			apply_mask_ipv4(&p);

			rp = route_node_lookup(rip->table, (struct prefix *)&p);
			if (rp) {
				rinfo = listgetdata(
					listhead((struct list *)rp->info));
				rte->metric = htonl(rinfo->metric);
				route_unlock_node(rp);
			} else
				rte->metric = htonl(RIP_METRIC_INFINITY);
		}
		packet->command = RIP_RESPONSE;

		(void)rip_send_packet((uint8_t *)packet, size, from, ifc);
	}
	rip->counters.queries++;
}

/* First entry point of RIP packet. */
static int rip_read(struct thread *t)
{
	struct rip *rip = THREAD_ARG(t);
	int sock;
	int ret;
	int rtenum;
	union rip_buf rip_buf;
	struct rip_packet *packet;
	struct sockaddr_in from;
	int len;
	int vrecv;
	socklen_t fromlen;
	struct interface *ifp = NULL;
	struct connected *ifc;
	struct rip_interface *ri;
	struct prefix p;

	/* Fetch socket then register myself. */
	sock = THREAD_FD(t);
	rip->t_read = NULL;

	/* Add myself to tne next event */
	rip_event(rip, RIP_READ, sock);

	/* RIPd manages only IPv4. */
	memset(&from, 0, sizeof(struct sockaddr_in));
	fromlen = sizeof(struct sockaddr_in);

	len = recvfrom(sock, (char *)&rip_buf.buf, sizeof(rip_buf.buf), 0,
		       (struct sockaddr *)&from, &fromlen);
	if (len < 0) {
		zlog_info("recvfrom failed (VRF %s): %s", rip->vrf_name,
			  safe_strerror(errno));
		return len;
	}

	/* Check is this packet comming from myself? */
	if (if_check_address(rip, from.sin_addr)) {
		if (IS_RIP_DEBUG_PACKET)
			zlog_debug("ignore packet comes from myself (VRF %s)",
				   rip->vrf_name);
		return -1;
	}

	/* Which interface is this packet comes from. */
	ifc = if_lookup_address((void *)&from.sin_addr, AF_INET,
				rip->vrf->vrf_id);
	if (ifc)
		ifp = ifc->ifp;

	/* RIP packet received */
	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("RECV packet from %s port %d on %s (VRF %s)",
			   inet_ntoa(from.sin_addr), ntohs(from.sin_port),
			   ifp ? ifp->name : "unknown", rip->vrf_name);

	/* If this packet come from unknown interface, ignore it. */
	if (ifp == NULL) {
		zlog_info(
			"rip_read: cannot find interface for packet from %s port %d (VRF %s)",
			inet_ntoa(from.sin_addr), ntohs(from.sin_port),
			rip->vrf_name);
		return -1;
	}

	p.family = AF_INET;
	p.u.prefix4 = from.sin_addr;
	p.prefixlen = IPV4_MAX_BITLEN;

	ifc = connected_lookup_prefix(ifp, &p);

	if (ifc == NULL) {
		zlog_info(
			"rip_read: cannot find connected address for packet from %s "
			"port %d on interface %s (VRF %s)",
			inet_ntoa(from.sin_addr), ntohs(from.sin_port),
			ifp->name, rip->vrf_name);
		return -1;
	}

	/* Packet length check. */
	if (len < RIP_PACKET_MINSIZ) {
		zlog_warn("packet size %d is smaller than minimum size %d", len,
			  RIP_PACKET_MINSIZ);
		rip_peer_bad_packet(rip, &from);
		return len;
	}
	if (len > RIP_PACKET_MAXSIZ) {
		zlog_warn("packet size %d is larger than max size %d", len,
			  RIP_PACKET_MAXSIZ);
		rip_peer_bad_packet(rip, &from);
		return len;
	}

	/* Packet alignment check. */
	if ((len - RIP_PACKET_MINSIZ) % 20) {
		zlog_warn("packet size %d is wrong for RIP packet alignment",
			  len);
		rip_peer_bad_packet(rip, &from);
		return len;
	}

	/* Set RTE number. */
	rtenum = ((len - RIP_PACKET_MINSIZ) / 20);

	/* For easy to handle. */
	packet = &rip_buf.rip_packet;

	/* RIP version check. */
	if (packet->version == 0) {
		zlog_info("version 0 with command %d received.",
			  packet->command);
		rip_peer_bad_packet(rip, &from);
		return -1;
	}

	/* Dump RIP packet. */
	if (IS_RIP_DEBUG_RECV)
		rip_packet_dump(packet, len, "RECV");

	/* RIP version adjust.  This code should rethink now.  RFC1058 says
	   that "Version 1 implementations are to ignore this extra data and
	   process only the fields specified in this document.". So RIPv3
	   packet should be treated as RIPv1 ignoring must be zero field. */
	if (packet->version > RIPv2)
		packet->version = RIPv2;

	/* Is RIP running or is this RIP neighbor ?*/
	ri = ifp->info;
	if (!ri->running && !rip_neighbor_lookup(rip, &from)) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("RIP is not enabled on interface %s.",
				   ifp->name);
		rip_peer_bad_packet(rip, &from);
		return -1;
	}

	/* RIP Version check. RFC2453, 4.6 and 5.1 */
	vrecv = ((ri->ri_receive == RI_RIP_UNSPEC) ? rip->version_recv
						   : ri->ri_receive);
	if (vrecv == RI_RIP_VERSION_NONE
	    || ((packet->version == RIPv1) && !(vrecv & RIPv1))
	    || ((packet->version == RIPv2) && !(vrecv & RIPv2))) {
		if (IS_RIP_DEBUG_PACKET)
			zlog_debug(
				"  packet's v%d doesn't fit to if version spec",
				packet->version);
		rip_peer_bad_packet(rip, &from);
		return -1;
	}

	/* RFC2453 5.2 If the router is not configured to authenticate RIP-2
	   messages, then RIP-1 and unauthenticated RIP-2 messages will be
	   accepted; authenticated RIP-2 messages shall be discarded.  */
	if ((ri->auth_type == RIP_NO_AUTH) && rtenum
	    && (packet->version == RIPv2)
	    && (packet->rte->family == htons(RIP_FAMILY_AUTH))) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug(
				"packet RIPv%d is dropped because authentication disabled",
				packet->version);
		ripd_notif_send_auth_type_failure(ifp->name);
		rip_peer_bad_packet(rip, &from);
		return -1;
	}

	/* RFC:
	   If the router is configured to authenticate RIP-2 messages, then
	   RIP-1 messages and RIP-2 messages which pass authentication
	   testing shall be accepted; unauthenticated and failed
	   authentication RIP-2 messages shall be discarded.  For maximum
	   security, RIP-1 messages should be ignored when authentication is
	   in use (see section 4.1); otherwise, the routing information from
	   authenticated messages will be propagated by RIP-1 routers in an
	   unauthenticated manner.
	*/
	/* We make an exception for RIPv1 REQUEST packets, to which we'll
	 * always reply regardless of authentication settings, because:
	 *
	 * - if there other authorised routers on-link, the REQUESTor can
	 *   passively obtain the routing updates anyway
	 * - if there are no other authorised routers on-link, RIP can
	 *   easily be disabled for the link to prevent giving out information
	 *   on state of this routers RIP routing table..
	 *
	 * I.e. if RIPv1 has any place anymore these days, it's as a very
	 * simple way to distribute routing information (e.g. to embedded
	 * hosts / appliances) and the ability to give out RIPv1
	 * routing-information freely, while still requiring RIPv2
	 * authentication for any RESPONSEs might be vaguely useful.
	 */
	if (ri->auth_type != RIP_NO_AUTH && packet->version == RIPv1) {
		/* Discard RIPv1 messages other than REQUESTs */
		if (packet->command != RIP_REQUEST) {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug(
					"RIPv1"
					" dropped because authentication enabled");
			ripd_notif_send_auth_type_failure(ifp->name);
			rip_peer_bad_packet(rip, &from);
			return -1;
		}
	} else if (ri->auth_type != RIP_NO_AUTH) {
		const char *auth_desc;

		if (rtenum == 0) {
			/* There definitely is no authentication in the packet.
			 */
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug(
					"RIPv2 authentication failed: no auth RTE in packet");
			ripd_notif_send_auth_type_failure(ifp->name);
			rip_peer_bad_packet(rip, &from);
			return -1;
		}

		/* First RTE must be an Authentication Family RTE */
		if (packet->rte->family != htons(RIP_FAMILY_AUTH)) {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug(
					"RIPv2"
					" dropped because authentication enabled");
			ripd_notif_send_auth_type_failure(ifp->name);
			rip_peer_bad_packet(rip, &from);
			return -1;
		}

		/* Check RIPv2 authentication. */
		switch (ntohs(packet->rte->tag)) {
		case RIP_AUTH_SIMPLE_PASSWORD:
			auth_desc = "simple";
			ret = rip_auth_simple_password(packet->rte, &from, ifp);
			break;

		case RIP_AUTH_MD5:
			auth_desc = "MD5";
			ret = rip_auth_md5(packet, &from, len, ifp);
			/* Reset RIP packet length to trim MD5 data. */
			len = ret;
			break;

		default:
			ret = 0;
			auth_desc = "unknown type";
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug(
					"RIPv2 Unknown authentication type %d",
					ntohs(packet->rte->tag));
		}

		if (ret) {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug("RIPv2 %s authentication success",
					   auth_desc);
		} else {
			if (IS_RIP_DEBUG_PACKET)
				zlog_debug("RIPv2 %s authentication failure",
					   auth_desc);
			ripd_notif_send_auth_failure(ifp->name);
			rip_peer_bad_packet(rip, &from);
			return -1;
		}
	}

	/* Process each command. */
	switch (packet->command) {
	case RIP_RESPONSE:
		rip_response_process(packet, len, &from, ifc);
		break;
	case RIP_REQUEST:
	case RIP_POLL:
		rip_request_process(packet, len, &from, ifc);
		break;
	case RIP_TRACEON:
	case RIP_TRACEOFF:
		zlog_info(
			"Obsolete command %s received, please sent it to routed",
			lookup_msg(rip_msg, packet->command, NULL));
		rip_peer_bad_packet(rip, &from);
		break;
	case RIP_POLL_ENTRY:
		zlog_info("Obsolete command %s received",
			  lookup_msg(rip_msg, packet->command, NULL));
		rip_peer_bad_packet(rip, &from);
		break;
	default:
		zlog_info("Unknown RIP command %d received", packet->command);
		rip_peer_bad_packet(rip, &from);
		break;
	}

	return len;
}

/* Write routing table entry to the stream and return next index of
   the routing table entry in the stream. */
static int rip_write_rte(int num, struct stream *s, struct prefix_ipv4 *p,
			 uint8_t version, struct rip_info *rinfo)
{
	struct in_addr mask;

	/* Write routing table entry. */
	if (version == RIPv1) {
		stream_putw(s, AF_INET);
		stream_putw(s, 0);
		stream_put_ipv4(s, p->prefix.s_addr);
		stream_put_ipv4(s, 0);
		stream_put_ipv4(s, 0);
		stream_putl(s, rinfo->metric_out);
	} else {
		masklen2ip(p->prefixlen, &mask);

		stream_putw(s, AF_INET);
		stream_putw(s, rinfo->tag_out);
		stream_put_ipv4(s, p->prefix.s_addr);
		stream_put_ipv4(s, mask.s_addr);
		stream_put_ipv4(s, rinfo->nexthop_out.s_addr);
		stream_putl(s, rinfo->metric_out);
	}

	return ++num;
}

/* Send update to the ifp or spcified neighbor. */
void rip_output_process(struct connected *ifc, struct sockaddr_in *to,
			int route_type, uint8_t version)
{
	struct rip *rip;
	int ret;
	struct stream *s;
	struct route_node *rp;
	struct rip_info *rinfo;
	struct rip_interface *ri;
	struct prefix_ipv4 *p;
	struct prefix_ipv4 classfull;
	struct prefix_ipv4 ifaddrclass;
	struct key *key = NULL;
	/* this might need to made dynamic if RIP ever supported auth methods
	   with larger key string sizes */
	char auth_str[RIP_AUTH_SIMPLE_SIZE];
	size_t doff = 0; /* offset of digest offset field */
	int num = 0;
	int rtemax;
	int subnetted = 0;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	/* Logging output event. */
	if (IS_RIP_DEBUG_EVENT) {
		if (to)
			zlog_debug("update routes to neighbor %s",
				   inet_ntoa(to->sin_addr));
		else
			zlog_debug("update routes on interface %s ifindex %d",
				   ifc->ifp->name, ifc->ifp->ifindex);
	}

	/* Get RIP interface. */
	ri = ifc->ifp->info;
	rip = ri->rip;

	/* Set output stream. */
	s = rip->obuf;

	/* Reset stream and RTE counter. */
	stream_reset(s);
	rtemax = RIP_MAX_RTE;

	/* If output interface is in simple password authentication mode, we
	   need space for authentication data.  */
	if (ri->auth_type == RIP_AUTH_SIMPLE_PASSWORD)
		rtemax -= 1;

	/* If output interface is in MD5 authentication mode, we need space
	   for authentication header and data. */
	if (ri->auth_type == RIP_AUTH_MD5)
		rtemax -= 2;

	/* If output interface is in simple password authentication mode
	   and string or keychain is specified we need space for auth. data */
	if (ri->auth_type != RIP_NO_AUTH) {
		if (ri->key_chain) {
			struct keychain *keychain;

			keychain = keychain_lookup(ri->key_chain);
			if (keychain)
				key = key_lookup_for_send(keychain);
		}
		/* to be passed to auth functions later */
		rip_auth_prepare_str_send(ri, key, auth_str, sizeof(auth_str));
		if (strlen(auth_str) == 0)
			return;
	}

	if (version == RIPv1) {
		memcpy(&ifaddrclass, ifc->address, sizeof(struct prefix_ipv4));
		apply_classful_mask_ipv4(&ifaddrclass);
		subnetted = 0;
		if (ifc->address->prefixlen > ifaddrclass.prefixlen)
			subnetted = 1;
	}

	for (rp = route_top(rip->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL && listcount(list) != 0) {
			rinfo = listgetdata(listhead(list));
			/* For RIPv1, if we are subnetted, output subnets in our
			 * network    */
			/* that have the same mask as the output "interface".
			 * For other     */
			/* networks, only the classfull version is output. */

			if (version == RIPv1) {
				p = (struct prefix_ipv4 *)&rp->p;

				if (IS_RIP_DEBUG_PACKET)
					zlog_debug(
						"RIPv1 mask check, %s/%d considered for output",
						inet_ntoa(rp->p.u.prefix4),
						rp->p.prefixlen);

				if (subnetted
				    && prefix_match(
					       (struct prefix *)&ifaddrclass,
					       &rp->p)) {
					if ((ifc->address->prefixlen
					     != rp->p.prefixlen)
					    && (rp->p.prefixlen != 32))
						continue;
				} else {
					memcpy(&classfull, &rp->p,
					       sizeof(struct prefix_ipv4));
					apply_classful_mask_ipv4(&classfull);
					if (rp->p.u.prefix4.s_addr != 0
					    && classfull.prefixlen
						       != rp->p.prefixlen)
						continue;
				}
				if (IS_RIP_DEBUG_PACKET)
					zlog_debug(
						"RIPv1 mask check, %s/%d made it through",
						inet_ntoa(rp->p.u.prefix4),
						rp->p.prefixlen);
			} else
				p = (struct prefix_ipv4 *)&rp->p;

			/* Apply output filters. */
			ret = rip_filter(RIP_FILTER_OUT, p, ri);
			if (ret < 0)
				continue;

			/* Changed route only output. */
			if (route_type == rip_changed_route
			    && (!(rinfo->flags & RIP_RTF_CHANGED)))
				continue;

			/* Split horizon. */
			/* if (split_horizon == rip_split_horizon) */
			if (ri->split_horizon == RIP_SPLIT_HORIZON) {
				/*
				 * We perform split horizon for RIP and
				 * connected route.
				 * For rip routes, we want to suppress the route
				 * if we would
				 * end up sending the route back on the
				 * interface that we
				 * learned it from, with a higher metric. For
				 * connected routes,
				 * we suppress the route if the prefix is a
				 * subset of the
				 * source address that we are going to use for
				 * the packet
				 * (in order to handle the case when multiple
				 * subnets are
				 * configured on the same interface).
				 */
				int suppress = 0;
				struct rip_info *tmp_rinfo = NULL;
				struct connected *tmp_ifc = NULL;

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  tmp_rinfo))
					if (tmp_rinfo->type == ZEBRA_ROUTE_RIP
					    && tmp_rinfo->nh.ifindex
						       == ifc->ifp->ifindex) {
						suppress = 1;
						break;
					}

				if (!suppress
				    && rinfo->type == ZEBRA_ROUTE_CONNECT) {
					for (ALL_LIST_ELEMENTS_RO(
						     ifc->ifp->connected,
						     listnode, tmp_ifc))
						if (prefix_match(
							    (struct prefix *)p,
							    tmp_ifc->address)) {
							suppress = 1;
							break;
						}
				}

				if (suppress)
					continue;
			}

			/* Preparation for route-map. */
			rinfo->metric_set = 0;
			rinfo->nexthop_out.s_addr = 0;
			rinfo->metric_out = rinfo->metric;
			rinfo->tag_out = rinfo->tag;
			rinfo->ifindex_out = ifc->ifp->ifindex;

			/* In order to avoid some local loops,
			 * if the RIP route has a nexthop via this interface,
			 * keep the nexthop,
			 * otherwise set it to 0. The nexthop should not be
			 * propagated
			 * beyond the local broadcast/multicast area in order
			 * to avoid an IGP multi-level recursive look-up.
			 * see (4.4)
			 */
			if (rinfo->nh.ifindex == ifc->ifp->ifindex)
				rinfo->nexthop_out = rinfo->nh.gate.ipv4;

			/* Interface route-map */
			if (ri->routemap[RIP_FILTER_OUT]) {
				ret = route_map_apply(
					ri->routemap[RIP_FILTER_OUT],
					(struct prefix *)p, RMAP_RIP, rinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIP_DEBUG_PACKET)
						zlog_debug(
							"RIP %s/%d is filtered by route-map out",
							inet_ntoa(p->prefix),
							p->prefixlen);
					continue;
				}
			}

			/* Apply redistribute route map - continue, if deny */
			if (rip->redist[rinfo->type].route_map.name
			    && rinfo->sub_type != RIP_ROUTE_INTERFACE) {
				ret = route_map_apply(
					rip->redist[rinfo->type].route_map.map,
					(struct prefix *)p, RMAP_RIP, rinfo);

				if (ret == RMAP_DENYMATCH) {
					if (IS_RIP_DEBUG_PACKET)
						zlog_debug(
							"%s/%d is filtered by route-map",
							inet_ntoa(p->prefix),
							p->prefixlen);
					continue;
				}
			}

			/* When route-map does not set metric. */
			if (!rinfo->metric_set) {
				/* If redistribute metric is set. */
				if (rip->redist[rinfo->type].metric_config
				    && rinfo->metric != RIP_METRIC_INFINITY) {
					rinfo->metric_out =
						rip->redist[rinfo->type].metric;
				} else {
					/* If the route is not connected or
					   localy generated
					   one, use default-metric value*/
					if (rinfo->type != ZEBRA_ROUTE_RIP
					    && rinfo->type
						       != ZEBRA_ROUTE_CONNECT
					    && rinfo->metric
						       != RIP_METRIC_INFINITY)
						rinfo->metric_out =
							rip->default_metric;
				}
			}

			/* Apply offset-list */
			if (rinfo->metric != RIP_METRIC_INFINITY)
				rip_offset_list_apply_out(p, ifc->ifp,
							  &rinfo->metric_out);

			if (rinfo->metric_out > RIP_METRIC_INFINITY)
				rinfo->metric_out = RIP_METRIC_INFINITY;

			/* Perform split-horizon with poisoned reverse
			 * for RIP and connected routes.
			 **/
			if (ri->split_horizon
			    == RIP_SPLIT_HORIZON_POISONED_REVERSE) {
				/*
				 * We perform split horizon for RIP and
				 * connected route.
				 * For rip routes, we want to suppress the route
				 * if we would
				 * end up sending the route back on the
				 * interface that we
				 * learned it from, with a higher metric. For
				 * connected routes,
				 * we suppress the route if the prefix is a
				 * subset of the
				 * source address that we are going to use for
				 * the packet
				 * (in order to handle the case when multiple
				 * subnets are
				 * configured on the same interface).
				 */
				struct rip_info *tmp_rinfo = NULL;
				struct connected *tmp_ifc = NULL;

				for (ALL_LIST_ELEMENTS_RO(list, listnode,
							  tmp_rinfo))
					if (tmp_rinfo->type == ZEBRA_ROUTE_RIP
					    && tmp_rinfo->nh.ifindex
						       == ifc->ifp->ifindex)
						rinfo->metric_out =
							RIP_METRIC_INFINITY;

				if (rinfo->metric_out != RIP_METRIC_INFINITY
				    && rinfo->type == ZEBRA_ROUTE_CONNECT) {
					for (ALL_LIST_ELEMENTS_RO(
						     ifc->ifp->connected,
						     listnode, tmp_ifc))
						if (prefix_match(
							    (struct prefix *)p,
							    tmp_ifc->address)) {
							rinfo->metric_out =
								RIP_METRIC_INFINITY;
							break;
						}
				}
			}

			/* Prepare preamble, auth headers, if needs be */
			if (num == 0) {
				stream_putc(s, RIP_RESPONSE);
				stream_putc(s, version);
				stream_putw(s, 0);

				/* auth header for !v1 && !no_auth */
				if ((ri->auth_type != RIP_NO_AUTH)
				    && (version != RIPv1))
					doff = rip_auth_header_write(
						s, ri, key, auth_str,
						RIP_AUTH_SIMPLE_SIZE);
			}

			/* Write RTE to the stream. */
			num = rip_write_rte(num, s, p, version, rinfo);
			if (num == rtemax) {
				if (version == RIPv2
				    && ri->auth_type == RIP_AUTH_MD5)
					rip_auth_md5_set(s, ri, doff, auth_str,
							 RIP_AUTH_SIMPLE_SIZE);

				ret = rip_send_packet(STREAM_DATA(s),
						      stream_get_endp(s), to,
						      ifc);

				if (ret >= 0 && IS_RIP_DEBUG_SEND)
					rip_packet_dump((struct rip_packet *)
								STREAM_DATA(s),
							stream_get_endp(s),
							"SEND");
				num = 0;
				stream_reset(s);
			}
		}

	/* Flush unwritten RTE. */
	if (num != 0) {
		if (version == RIPv2 && ri->auth_type == RIP_AUTH_MD5)
			rip_auth_md5_set(s, ri, doff, auth_str,
					 RIP_AUTH_SIMPLE_SIZE);

		ret = rip_send_packet(STREAM_DATA(s), stream_get_endp(s), to,
				      ifc);

		if (ret >= 0 && IS_RIP_DEBUG_SEND)
			rip_packet_dump((struct rip_packet *)STREAM_DATA(s),
					stream_get_endp(s), "SEND");
		stream_reset(s);
	}

	/* Statistics updates. */
	ri->sent_updates++;
}

/* Send RIP packet to the interface. */
static void rip_update_interface(struct connected *ifc, uint8_t version,
				 int route_type)
{
	struct interface *ifp = ifc->ifp;
	struct rip_interface *ri = ifp->info;
	struct sockaddr_in to;

	/* When RIP version is 2 and multicast enable interface. */
	if (version == RIPv2 && !ri->v2_broadcast && if_is_multicast(ifp)) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("multicast announce on %s ", ifp->name);

		rip_output_process(ifc, NULL, route_type, version);
		return;
	}

	/* If we can't send multicast packet, send it with unicast. */
	if (if_is_broadcast(ifp) || if_is_pointopoint(ifp)) {
		if (ifc->address->family == AF_INET) {
			/* Destination address and port setting. */
			memset(&to, 0, sizeof(struct sockaddr_in));
			if (ifc->destination)
				/* use specified broadcast or peer destination
				 * addr */
				to.sin_addr = ifc->destination->u.prefix4;
			else if (ifc->address->prefixlen < IPV4_MAX_PREFIXLEN)
				/* calculate the appropriate broadcast address
				 */
				to.sin_addr.s_addr = ipv4_broadcast_addr(
					ifc->address->u.prefix4.s_addr,
					ifc->address->prefixlen);
			else
				/* do not know where to send the packet */
				return;
			to.sin_port = htons(RIP_PORT_DEFAULT);

			if (IS_RIP_DEBUG_EVENT)
				zlog_debug("%s announce to %s on %s",
					   CONNECTED_PEER(ifc) ? "unicast"
							       : "broadcast",
					   inet_ntoa(to.sin_addr), ifp->name);

			rip_output_process(ifc, &to, route_type, version);
		}
	}
}

/* Update send to all interface and neighbor. */
static void rip_update_process(struct rip *rip, int route_type)
{
	struct listnode *ifnode, *ifnnode;
	struct connected *connected;
	struct interface *ifp;
	struct rip_interface *ri;
	struct route_node *rp;
	struct sockaddr_in to;
	struct prefix *p;

	/* Send RIP update to each interface. */
	FOR_ALL_INTERFACES (rip->vrf, ifp) {
		if (if_is_loopback(ifp))
			continue;

		if (!if_is_operative(ifp))
			continue;

		/* Fetch RIP interface information. */
		ri = ifp->info;

		/* When passive interface is specified, suppress announce to the
		   interface. */
		if (ri->passive)
			continue;

		if (ri->running) {
			/*
			 * If there is no version configuration in the
			 * interface,
			 * use rip's version setting.
			 */
			int vsend = ((ri->ri_send == RI_RIP_UNSPEC)
					     ? rip->version_send
					     : ri->ri_send);

			if (IS_RIP_DEBUG_EVENT)
				zlog_debug("SEND UPDATE to %s ifindex %d",
					   ifp->name, ifp->ifindex);

			/* send update on each connected network */
			for (ALL_LIST_ELEMENTS(ifp->connected, ifnode, ifnnode,
					       connected)) {
				if (connected->address->family == AF_INET) {
					if (vsend & RIPv1)
						rip_update_interface(
							connected, RIPv1,
							route_type);
					if ((vsend & RIPv2)
					    && if_is_multicast(ifp))
						rip_update_interface(
							connected, RIPv2,
							route_type);
				}
			}
		}
	}

	/* RIP send updates to each neighbor. */
	for (rp = route_top(rip->neighbor); rp; rp = route_next(rp))
		if (rp->info != NULL) {
			p = &rp->p;

			connected = if_lookup_address(&p->u.prefix4, AF_INET,
						      rip->vrf->vrf_id);
			if (!connected) {
				zlog_warn(
					"Neighbor %s doesn't have connected interface!",
					inet_ntoa(p->u.prefix4));
				continue;
			}

			/* Set destination address and port */
			memset(&to, 0, sizeof(struct sockaddr_in));
			to.sin_addr = p->u.prefix4;
			to.sin_port = htons(RIP_PORT_DEFAULT);

			/* RIP version is rip's configuration. */
			rip_output_process(connected, &to, route_type,
					   rip->version_send);
		}
}

/* RIP's periodical timer. */
static int rip_update(struct thread *t)
{
	struct rip *rip = THREAD_ARG(t);

	/* Clear timer pointer. */
	rip->t_update = NULL;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("update timer fire!");

	/* Process update output. */
	rip_update_process(rip, rip_all_route);

	/* Triggered updates may be suppressed if a regular update is due by
	   the time the triggered update would be sent. */
	RIP_TIMER_OFF(rip->t_triggered_interval);
	rip->trigger = 0;

	/* Register myself. */
	rip_event(rip, RIP_UPDATE_EVENT, 0);

	return 0;
}

/* Walk down the RIP routing table then clear changed flag. */
static void rip_clear_changed_flag(struct rip *rip)
{
	struct route_node *rp;
	struct rip_info *rinfo = NULL;
	struct list *list = NULL;
	struct listnode *listnode = NULL;

	for (rp = route_top(rip->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
				UNSET_FLAG(rinfo->flags, RIP_RTF_CHANGED);
				/* This flag can be set only on the first entry.
				 */
				break;
			}
}

/* Triggered update interval timer. */
static int rip_triggered_interval(struct thread *t)
{
	struct rip *rip = THREAD_ARG(t);

	rip->t_triggered_interval = NULL;

	if (rip->trigger) {
		rip->trigger = 0;
		rip_triggered_update(t);
	}
	return 0;
}

/* Execute triggered update. */
static int rip_triggered_update(struct thread *t)
{
	struct rip *rip = THREAD_ARG(t);
	int interval;

	/* Clear thred pointer. */
	rip->t_triggered_update = NULL;

	/* Cancel interval timer. */
	RIP_TIMER_OFF(rip->t_triggered_interval);
	rip->trigger = 0;

	/* Logging triggered update. */
	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("triggered update!");

	/* Split Horizon processing is done when generating triggered
	   updates as well as normal updates (see section 2.6). */
	rip_update_process(rip, rip_changed_route);

	/* Once all of the triggered updates have been generated, the route
	   change flags should be cleared. */
	rip_clear_changed_flag(rip);

	/* After a triggered update is sent, a timer should be set for a
	 random interval between 1 and 5 seconds.  If other changes that
	 would trigger updates occur before the timer expires, a single
	 update is triggered when the timer expires. */
	interval = (random() % 5) + 1;

	rip->t_triggered_interval = NULL;
	thread_add_timer(master, rip_triggered_interval, rip, interval,
			 &rip->t_triggered_interval);

	return 0;
}

/* Withdraw redistributed route. */
void rip_redistribute_withdraw(struct rip *rip, int type)
{
	struct route_node *rp;
	struct rip_info *rinfo = NULL;
	struct list *list = NULL;

	for (rp = route_top(rip->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL) {
			rinfo = listgetdata(listhead(list));
			if (rinfo->type == type
			    && rinfo->sub_type != RIP_ROUTE_INTERFACE) {
				/* Perform poisoned reverse. */
				rinfo->metric = RIP_METRIC_INFINITY;
				RIP_TIMER_ON(rinfo->t_garbage_collect,
					     rip_garbage_collect,
					     rip->garbage_time);
				RIP_TIMER_OFF(rinfo->t_timeout);
				rinfo->flags |= RIP_RTF_CHANGED;

				if (IS_RIP_DEBUG_EVENT) {
					struct prefix_ipv4 *p =
						(struct prefix_ipv4 *)&rp->p;

					zlog_debug(
						"Poisone %s/%d on the interface %s with an infinity metric [withdraw]",
						inet_ntoa(p->prefix),
						p->prefixlen,
						ifindex2ifname(
							rinfo->nh.ifindex,
							rip->vrf->vrf_id));
				}

				rip_event(rip, RIP_TRIGGERED_UPDATE, 0);
			}
		}
}

struct rip *rip_lookup_by_vrf_id(vrf_id_t vrf_id)
{
	struct vrf *vrf;

	vrf = vrf_lookup_by_id(vrf_id);
	if (!vrf)
		return NULL;

	return vrf->info;
}

struct rip *rip_lookup_by_vrf_name(const char *vrf_name)
{
	struct rip rip;

	rip.vrf_name = (char *)vrf_name;

	return RB_FIND(rip_instance_head, &rip_instances, &rip);
}

/* Create new RIP instance and set it to global variable. */
struct rip *rip_create(const char *vrf_name, struct vrf *vrf, int socket)
{
	struct rip *rip;

	rip = XCALLOC(MTYPE_RIP, sizeof(struct rip));
	rip->vrf_name = XSTRDUP(MTYPE_RIP_VRF_NAME, vrf_name);

	/* Set initial value. */
	rip->ecmp = yang_get_default_bool("%s/allow-ecmp", RIP_INSTANCE);
	rip->default_metric =
		yang_get_default_uint8("%s/default-metric", RIP_INSTANCE);
	rip->distance =
		yang_get_default_uint8("%s/distance/default", RIP_INSTANCE);
	rip->passive_default =
		yang_get_default_bool("%s/passive-default", RIP_INSTANCE);
	rip->garbage_time = yang_get_default_uint32("%s/timers/flush-interval",
						    RIP_INSTANCE);
	rip->timeout_time = yang_get_default_uint32(
		"%s/timers/holddown-interval", RIP_INSTANCE);
	rip->update_time = yang_get_default_uint32("%s/timers/update-interval",
						   RIP_INSTANCE);
	rip->version_send =
		yang_get_default_enum("%s/version/send", RIP_INSTANCE);
	rip->version_recv =
		yang_get_default_enum("%s/version/receive", RIP_INSTANCE);

	/* Initialize RIP data structures. */
	rip->table = route_table_init();
	route_table_set_info(rip->table, rip);
	rip->neighbor = route_table_init();
	rip->peer_list = list_new();
	rip->peer_list->cmp = (int (*)(void *, void *))rip_peer_list_cmp;
	rip->peer_list->del = rip_peer_list_del;
	rip->distance_table = route_table_init();
	rip->distance_table->cleanup = rip_distance_table_node_cleanup;
	rip->enable_interface = vector_init(1);
	rip->enable_network = route_table_init();
	rip->passive_nondefault = vector_init(1);
	rip->offset_list_master = list_new();
	rip->offset_list_master->cmp = (int (*)(void *, void *))offset_list_cmp;
	rip->offset_list_master->del = (void (*)(void *))offset_list_free;

	/* Distribute list install. */
	rip->distribute_ctx = distribute_list_ctx_create(vrf);
	distribute_list_add_hook(rip->distribute_ctx, rip_distribute_update);
	distribute_list_delete_hook(rip->distribute_ctx, rip_distribute_update);

	/* if rmap install. */
	rip->if_rmap_ctx = if_rmap_ctx_create(vrf_name);
	if_rmap_hook_add(rip->if_rmap_ctx, rip_if_rmap_update);
	if_rmap_hook_delete(rip->if_rmap_ctx, rip_if_rmap_update);

	/* Make output stream. */
	rip->obuf = stream_new(1500);

	/* Enable the routing instance if possible. */
	if (vrf && vrf_is_enabled(vrf))
		rip_instance_enable(rip, vrf, socket);
	else {
		rip->vrf = NULL;
		rip->sock = -1;
	}

	RB_INSERT(rip_instance_head, &rip_instances, rip);

	return rip;
}

/* Sned RIP request to the destination. */
int rip_request_send(struct sockaddr_in *to, struct interface *ifp,
		     uint8_t version, struct connected *connected)
{
	struct rte *rte;
	struct rip_packet rip_packet;
	struct listnode *node, *nnode;

	memset(&rip_packet, 0, sizeof(rip_packet));

	rip_packet.command = RIP_REQUEST;
	rip_packet.version = version;
	rte = rip_packet.rte;
	rte->metric = htonl(RIP_METRIC_INFINITY);

	if (connected) {
		/*
		 * connected is only sent for ripv1 case, or when
		 * interface does not support multicast.  Caller loops
		 * over each connected address for this case.
		 */
		if (rip_send_packet((uint8_t *)&rip_packet, sizeof(rip_packet),
				    to, connected)
		    != sizeof(rip_packet))
			return -1;
		else
			return sizeof(rip_packet);
	}

	/* send request on each connected network */
	for (ALL_LIST_ELEMENTS(ifp->connected, node, nnode, connected)) {
		struct prefix_ipv4 *p;

		p = (struct prefix_ipv4 *)connected->address;

		if (p->family != AF_INET)
			continue;

		if (rip_send_packet((uint8_t *)&rip_packet, sizeof(rip_packet),
				    to, connected)
		    != sizeof(rip_packet))
			return -1;
	}
	return sizeof(rip_packet);
}

static int rip_update_jitter(unsigned long time)
{
#define JITTER_BOUND 4
	/* We want to get the jitter to +/- 1/JITTER_BOUND the interval.
	   Given that, we cannot let time be less than JITTER_BOUND seconds.
	   The RIPv2 RFC says jitter should be small compared to
	   update_time.  We consider 1/JITTER_BOUND to be small.
	*/

	int jitter_input = time;
	int jitter;

	if (jitter_input < JITTER_BOUND)
		jitter_input = JITTER_BOUND;

	jitter = (((random() % ((jitter_input * 2) + 1)) - jitter_input));

	return jitter / JITTER_BOUND;
}

void rip_event(struct rip *rip, enum rip_event event, int sock)
{
	int jitter = 0;

	switch (event) {
	case RIP_READ:
		rip->t_read = NULL;
		thread_add_read(master, rip_read, rip, sock, &rip->t_read);
		break;
	case RIP_UPDATE_EVENT:
		RIP_TIMER_OFF(rip->t_update);
		jitter = rip_update_jitter(rip->update_time);
		thread_add_timer(master, rip_update, rip,
				 sock ? 2 : rip->update_time + jitter,
				 &rip->t_update);
		break;
	case RIP_TRIGGERED_UPDATE:
		if (rip->t_triggered_interval)
			rip->trigger = 1;
		else
			thread_add_event(master, rip_triggered_update, rip, 0,
					 &rip->t_triggered_update);
		break;
	default:
		break;
	}
}

#if 0
static void
rip_update_default_metric (void)
{
  struct route_node *np;
  struct rip_info *rinfo = NULL;
  struct list *list = NULL;
  struct listnode *listnode = NULL;

  for (np = route_top (rip->table); np; np = route_next (np))
    if ((list = np->info) != NULL)
      for (ALL_LIST_ELEMENTS_RO (list, listnode, rinfo))
        if (rinfo->type != ZEBRA_ROUTE_RIP && rinfo->type != ZEBRA_ROUTE_CONNECT)
          rinfo->metric = rip->default_metric;
}
#endif

struct rip_distance *rip_distance_new(void)
{
	return XCALLOC(MTYPE_RIP_DISTANCE, sizeof(struct rip_distance));
}

void rip_distance_free(struct rip_distance *rdistance)
{
	if (rdistance->access_list)
		free(rdistance->access_list);
	XFREE(MTYPE_RIP_DISTANCE, rdistance);
}

static void rip_distance_table_node_cleanup(struct route_table *table,
					    struct route_node *node)
{
	struct rip_distance *rdistance;

	rdistance = node->info;
	if (rdistance)
		rip_distance_free(rdistance);
}

/* Apply RIP information to distance method. */
uint8_t rip_distance_apply(struct rip *rip, struct rip_info *rinfo)
{
	struct route_node *rn;
	struct prefix_ipv4 p;
	struct rip_distance *rdistance;
	struct access_list *alist;

	memset(&p, 0, sizeof(struct prefix_ipv4));
	p.family = AF_INET;
	p.prefix = rinfo->from;
	p.prefixlen = IPV4_MAX_BITLEN;

	/* Check source address. */
	rn = route_node_match(rip->distance_table, (struct prefix *)&p);
	if (rn) {
		rdistance = rn->info;
		route_unlock_node(rn);

		if (rdistance->access_list) {
			alist = access_list_lookup(AFI_IP,
						   rdistance->access_list);
			if (alist == NULL)
				return 0;
			if (access_list_apply(alist, &rinfo->rp->p)
			    == FILTER_DENY)
				return 0;

			return rdistance->distance;
		} else
			return rdistance->distance;
	}

	if (rip->distance)
		return rip->distance;

	return 0;
}

static void rip_distance_show(struct vty *vty, struct rip *rip)
{
	struct route_node *rn;
	struct rip_distance *rdistance;
	int header = 1;
	char buf[BUFSIZ];

	vty_out(vty, "  Distance: (default is %u)\n",
		rip->distance ? rip->distance : ZEBRA_RIP_DISTANCE_DEFAULT);

	for (rn = route_top(rip->distance_table); rn; rn = route_next(rn))
		if ((rdistance = rn->info) != NULL) {
			if (header) {
				vty_out(vty,
					"    Address           Distance  List\n");
				header = 0;
			}
			sprintf(buf, "%s/%d", inet_ntoa(rn->p.u.prefix4),
				rn->p.prefixlen);
			vty_out(vty, "    %-20s  %4d  %s\n", buf,
				rdistance->distance,
				rdistance->access_list ? rdistance->access_list
						       : "");
		}
}

/* Update ECMP routes to zebra when ECMP is disabled. */
void rip_ecmp_disable(struct rip *rip)
{
	struct route_node *rp;
	struct rip_info *rinfo, *tmp_rinfo;
	struct list *list;
	struct listnode *node, *nextnode;

	for (rp = route_top(rip->table); rp; rp = route_next(rp))
		if ((list = rp->info) != NULL && listcount(list) > 1) {
			rinfo = listgetdata(listhead(list));
			if (!rip_route_rte(rinfo))
				continue;

			/* Drop all other entries, except the first one. */
			for (ALL_LIST_ELEMENTS(list, node, nextnode, tmp_rinfo))
				if (tmp_rinfo != rinfo) {
					RIP_TIMER_OFF(tmp_rinfo->t_timeout);
					RIP_TIMER_OFF(
						tmp_rinfo->t_garbage_collect);
					list_delete_node(list, node);
					rip_info_free(tmp_rinfo);
				}

			/* Update zebra. */
			rip_zebra_ipv4_add(rip, rp);

			/* Set the route change flag. */
			SET_FLAG(rinfo->flags, RIP_RTF_CHANGED);

			/* Signal the output process to trigger an update. */
			rip_event(rip, RIP_TRIGGERED_UPDATE, 0);
		}
}

/* Print out routes update time. */
static void rip_vty_out_uptime(struct vty *vty, struct rip_info *rinfo)
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

static const char *rip_route_type_print(int sub_type)
{
	switch (sub_type) {
	case RIP_ROUTE_RTE:
		return "n";
	case RIP_ROUTE_STATIC:
		return "s";
	case RIP_ROUTE_DEFAULT:
		return "d";
	case RIP_ROUTE_REDISTRIBUTE:
		return "r";
	case RIP_ROUTE_INTERFACE:
		return "i";
	default:
		return "?";
	}
}

DEFUN (show_ip_rip,
       show_ip_rip_cmd,
       "show ip rip [vrf NAME]",
       SHOW_STR
       IP_STR
       "Show RIP routes\n"
       VRF_CMD_HELP_STR)
{
	struct rip *rip;
	struct route_node *np;
	struct rip_info *rinfo = NULL;
	struct list *list = NULL;
	struct listnode *listnode = NULL;
	const char *vrf_name;
	int idx = 0;

	if (argv_find(argv, argc, "vrf", &idx))
		vrf_name = argv[idx + 1]->arg;
	else
		vrf_name = VRF_DEFAULT_NAME;

	rip = rip_lookup_by_vrf_name(vrf_name);
	if (!rip) {
		vty_out(vty, "%% RIP instance not found\n");
		return CMD_SUCCESS;
	}
	if (!rip->enabled) {
		vty_out(vty, "%% RIP instance is disabled\n");
		return CMD_SUCCESS;
	}

	vty_out(vty,
		"Codes: R - RIP, C - connected, S - Static, O - OSPF, B - BGP\n"
		"Sub-codes:\n"
		"      (n) - normal, (s) - static, (d) - default, (r) - redistribute,\n"
		"      (i) - interface\n\n"
		"     Network            Next Hop         Metric From            Tag Time\n");

	for (np = route_top(rip->table); np; np = route_next(np))
		if ((list = np->info) != NULL)
			for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
				int len;

				len = vty_out(
					vty, "%c(%s) %s/%d",
					/* np->lock, For debugging. */
					zebra_route_char(rinfo->type),
					rip_route_type_print(rinfo->sub_type),
					inet_ntoa(np->p.u.prefix4),
					np->p.prefixlen);

				len = 24 - len;

				if (len > 0)
					vty_out(vty, "%*s", len, " ");

				switch (rinfo->nh.type) {
				case NEXTHOP_TYPE_IPV4:
				case NEXTHOP_TYPE_IPV4_IFINDEX:
					vty_out(vty, "%-20s %2d ",
						inet_ntoa(rinfo->nh.gate.ipv4),
						rinfo->metric);
					break;
				case NEXTHOP_TYPE_IFINDEX:
					vty_out(vty,
						"0.0.0.0              %2d ",
						rinfo->metric);
					break;
				case NEXTHOP_TYPE_BLACKHOLE:
					vty_out(vty,
						"blackhole            %2d ",
						rinfo->metric);
					break;
				case NEXTHOP_TYPE_IPV6:
				case NEXTHOP_TYPE_IPV6_IFINDEX:
					vty_out(vty,
						"V6 Address Hidden    %2d ",
						rinfo->metric);
					break;
				}

				/* Route which exist in kernel routing table. */
				if ((rinfo->type == ZEBRA_ROUTE_RIP)
				    && (rinfo->sub_type == RIP_ROUTE_RTE)) {
					vty_out(vty, "%-15s ",
						inet_ntoa(rinfo->from));
					vty_out(vty, "%3" ROUTE_TAG_PRI " ",
						(route_tag_t)rinfo->tag);
					rip_vty_out_uptime(vty, rinfo);
				} else if (rinfo->metric
					   == RIP_METRIC_INFINITY) {
					vty_out(vty, "self            ");
					vty_out(vty, "%3" ROUTE_TAG_PRI " ",
						(route_tag_t)rinfo->tag);
					rip_vty_out_uptime(vty, rinfo);
				} else {
					if (rinfo->external_metric) {
						len = vty_out(
							vty, "self (%s:%d)",
							zebra_route_string(
								rinfo->type),
							rinfo->external_metric);
						len = 16 - len;
						if (len > 0)
							vty_out(vty, "%*s", len,
								" ");
					} else
						vty_out(vty,
							"self            ");
					vty_out(vty, "%3" ROUTE_TAG_PRI,
						(route_tag_t)rinfo->tag);
				}

				vty_out(vty, "\n");
			}
	return CMD_SUCCESS;
}

/* Vincent: formerly, it was show_ip_protocols_rip: "show ip protocols" */
DEFUN (show_ip_rip_status,
       show_ip_rip_status_cmd,
       "show ip rip [vrf NAME] status",
       SHOW_STR
       IP_STR
       "Show RIP routes\n"
       VRF_CMD_HELP_STR
       "IP routing protocol process parameters and statistics\n")
{
	struct rip *rip;
	struct interface *ifp;
	struct rip_interface *ri;
	extern const struct message ri_version_msg[];
	const char *send_version;
	const char *receive_version;
	const char *vrf_name;
	int idx = 0;

	if (argv_find(argv, argc, "vrf", &idx))
		vrf_name = argv[idx + 1]->arg;
	else
		vrf_name = VRF_DEFAULT_NAME;

	rip = rip_lookup_by_vrf_name(vrf_name);
	if (!rip) {
		vty_out(vty, "%% RIP instance not found\n");
		return CMD_SUCCESS;
	}
	if (!rip->enabled) {
		vty_out(vty, "%% RIP instance is disabled\n");
		return CMD_SUCCESS;
	}

	vty_out(vty, "Routing Protocol is \"rip\"\n");
	vty_out(vty, "  Sending updates every %u seconds with +/-50%%,",
		rip->update_time);
	vty_out(vty, " next due in %lu seconds\n",
		thread_timer_remain_second(rip->t_update));
	vty_out(vty, "  Timeout after %u seconds,", rip->timeout_time);
	vty_out(vty, " garbage collect after %u seconds\n", rip->garbage_time);

	/* Filtering status show. */
	config_show_distribute(vty, rip->distribute_ctx);

	/* Default metric information. */
	vty_out(vty, "  Default redistribution metric is %u\n",
		rip->default_metric);

	/* Redistribute information. */
	vty_out(vty, "  Redistributing:");
	rip_show_redistribute_config(vty, rip);
	vty_out(vty, "\n");

	vty_out(vty, "  Default version control: send version %s,",
		lookup_msg(ri_version_msg, rip->version_send, NULL));
	if (rip->version_recv == RI_RIP_VERSION_1_AND_2)
		vty_out(vty, " receive any version \n");
	else
		vty_out(vty, " receive version %s \n",
			lookup_msg(ri_version_msg, rip->version_recv, NULL));

	vty_out(vty, "    Interface        Send  Recv   Key-chain\n");

	FOR_ALL_INTERFACES (rip->vrf, ifp) {
		ri = ifp->info;

		if (!ri->running)
			continue;

		if (ri->enable_network || ri->enable_interface) {
			if (ri->ri_send == RI_RIP_UNSPEC)
				send_version =
					lookup_msg(ri_version_msg,
						   rip->version_send, NULL);
			else
				send_version = lookup_msg(ri_version_msg,
							  ri->ri_send, NULL);

			if (ri->ri_receive == RI_RIP_UNSPEC)
				receive_version =
					lookup_msg(ri_version_msg,
						   rip->version_recv, NULL);
			else
				receive_version = lookup_msg(
					ri_version_msg, ri->ri_receive, NULL);

			vty_out(vty, "    %-17s%-3s   %-3s    %s\n", ifp->name,
				send_version, receive_version,
				ri->key_chain ? ri->key_chain : "");
		}
	}

	vty_out(vty, "  Routing for Networks:\n");
	rip_show_network_config(vty, rip);

	{
		int found_passive = 0;
		FOR_ALL_INTERFACES (rip->vrf, ifp) {
			ri = ifp->info;

			if ((ri->enable_network || ri->enable_interface)
			    && ri->passive) {
				if (!found_passive) {
					vty_out(vty,
						"  Passive Interface(s):\n");
					found_passive = 1;
				}
				vty_out(vty, "    %s\n", ifp->name);
			}
		}
	}

	vty_out(vty, "  Routing Information Sources:\n");
	vty_out(vty,
		"    Gateway          BadPackets BadRoutes  Distance Last Update\n");
	rip_peer_display(vty, rip);

	rip_distance_show(vty, rip);

	return CMD_SUCCESS;
}

/* RIP configuration write function. */
static int config_write_rip(struct vty *vty)
{
	struct rip *rip;
	int write = 0;

	RB_FOREACH(rip, rip_instance_head, &rip_instances) {
		char xpath[XPATH_MAXLEN];
		struct lyd_node *dnode;

		snprintf(xpath, sizeof(xpath),
			 "/frr-ripd:ripd/instance[vrf='%s']", rip->vrf_name);

		dnode = yang_dnode_get(running_config->dnode, xpath);
		assert(dnode);

		nb_cli_show_dnode_cmds(vty, dnode, false);

		/* Distribute configuration. */
		config_write_distribute(vty, rip->distribute_ctx);

		/* Interface routemap configuration */
		config_write_if_rmap(vty, rip->if_rmap_ctx);

		write = 1;
	}

	return write;
}

/* RIP node structure. */
static struct cmd_node rip_node = {RIP_NODE, "%s(config-router)# ", 1};

/* Distribute-list update functions. */
static void rip_distribute_update(struct distribute_ctx *ctx,
				  struct distribute *dist)
{
	struct interface *ifp;
	struct rip_interface *ri;
	struct access_list *alist;
	struct prefix_list *plist;

	if (!ctx->vrf || !dist->ifname)
		return;

	ifp = if_lookup_by_name(dist->ifname, ctx->vrf->vrf_id);
	if (ifp == NULL)
		return;

	ri = ifp->info;

	if (dist->list[DISTRIBUTE_V4_IN]) {
		alist = access_list_lookup(AFI_IP,
					   dist->list[DISTRIBUTE_V4_IN]);
		if (alist)
			ri->list[RIP_FILTER_IN] = alist;
		else
			ri->list[RIP_FILTER_IN] = NULL;
	} else
		ri->list[RIP_FILTER_IN] = NULL;

	if (dist->list[DISTRIBUTE_V4_OUT]) {
		alist = access_list_lookup(AFI_IP,
					   dist->list[DISTRIBUTE_V4_OUT]);
		if (alist)
			ri->list[RIP_FILTER_OUT] = alist;
		else
			ri->list[RIP_FILTER_OUT] = NULL;
	} else
		ri->list[RIP_FILTER_OUT] = NULL;

	if (dist->prefix[DISTRIBUTE_V4_IN]) {
		plist = prefix_list_lookup(AFI_IP,
					   dist->prefix[DISTRIBUTE_V4_IN]);
		if (plist)
			ri->prefix[RIP_FILTER_IN] = plist;
		else
			ri->prefix[RIP_FILTER_IN] = NULL;
	} else
		ri->prefix[RIP_FILTER_IN] = NULL;

	if (dist->prefix[DISTRIBUTE_V4_OUT]) {
		plist = prefix_list_lookup(AFI_IP,
					   dist->prefix[DISTRIBUTE_V4_OUT]);
		if (plist)
			ri->prefix[RIP_FILTER_OUT] = plist;
		else
			ri->prefix[RIP_FILTER_OUT] = NULL;
	} else
		ri->prefix[RIP_FILTER_OUT] = NULL;
}

void rip_distribute_update_interface(struct interface *ifp)
{
	struct rip_interface *ri = ifp->info;
	struct rip *rip = ri->rip;
	struct distribute *dist;

	if (!rip)
		return;
	dist = distribute_lookup(rip->distribute_ctx, ifp->name);
	if (dist)
		rip_distribute_update(rip->distribute_ctx, dist);
}

/* Update all interface's distribute list. */
/* ARGSUSED */
static void rip_distribute_update_all(struct prefix_list *notused)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		rip_distribute_update_interface(ifp);
}
/* ARGSUSED */
static void rip_distribute_update_all_wrapper(struct access_list *notused)
{
	rip_distribute_update_all(NULL);
}

/* Delete all added rip route. */
void rip_clean(struct rip *rip)
{
	if (rip->enabled)
		rip_instance_disable(rip);

	stream_free(rip->obuf);

	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++)
		if (rip->redist[i].route_map.name)
			free(rip->redist[i].route_map.name);

	route_table_finish(rip->table);
	route_table_finish(rip->neighbor);
	list_delete(&rip->peer_list);
	distribute_list_delete(&rip->distribute_ctx);
	if_rmap_ctx_delete(rip->if_rmap_ctx);

	rip_clean_network(rip);
	rip_passive_nondefault_clean(rip);
	vector_free(rip->enable_interface);
	route_table_finish(rip->enable_network);
	vector_free(rip->passive_nondefault);
	list_delete(&rip->offset_list_master);
	rip_interfaces_clean(rip);
	route_table_finish(rip->distance_table);

	RB_REMOVE(rip_instance_head, &rip_instances, rip);
	XFREE(MTYPE_RIP_VRF_NAME, rip->vrf_name);
	XFREE(MTYPE_RIP, rip);
}

static void rip_if_rmap_update(struct if_rmap_ctx *ctx,
			       struct if_rmap *if_rmap)
{
	struct interface *ifp = NULL;
	struct rip_interface *ri;
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
		ri->routemap[RIP_FILTER_IN] = NULL;

	if (if_rmap->routemap[IF_RMAP_OUT]) {
		rmap = route_map_lookup_by_name(if_rmap->routemap[IF_RMAP_OUT]);
		if (rmap)
			ri->routemap[IF_RMAP_OUT] = rmap;
		else
			ri->routemap[IF_RMAP_OUT] = NULL;
	} else
		ri->routemap[RIP_FILTER_OUT] = NULL;
}

void rip_if_rmap_update_interface(struct interface *ifp)
{
	struct rip_interface *ri = ifp->info;
	struct rip *rip = ri->rip;
	struct if_rmap *if_rmap;
	struct if_rmap_ctx *ctx;

	if (!rip)
		return;
	ctx = rip->if_rmap_ctx;
	if (!ctx)
		return;
	if_rmap = if_rmap_lookup(ctx, ifp->name);
	if (if_rmap)
		rip_if_rmap_update(ctx, if_rmap);
}

static void rip_routemap_update_redistribute(struct rip *rip)
{
	for (int i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (rip->redist[i].route_map.name) {
			rip->redist[i].route_map.map = route_map_lookup_by_name(
				rip->redist[i].route_map.name);
			route_map_counter_increment(
				rip->redist[i].route_map.map);
		}
	}
}

/* ARGSUSED */
static void rip_routemap_update(const char *notused)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct rip *rip;
	struct interface *ifp;

	FOR_ALL_INTERFACES (vrf, ifp)
		rip_if_rmap_update_interface(ifp);

	rip = vrf->info;
	if (rip)
		rip_routemap_update_redistribute(rip);
}

/* Link RIP instance to VRF. */
static void rip_vrf_link(struct rip *rip, struct vrf *vrf)
{
	struct interface *ifp;

	rip->vrf = vrf;
	rip->distribute_ctx->vrf = vrf;
	vrf->info = rip;

	FOR_ALL_INTERFACES (vrf, ifp)
		rip_interface_sync(ifp);
}

/* Unlink RIP instance from VRF. */
static void rip_vrf_unlink(struct rip *rip, struct vrf *vrf)
{
	struct interface *ifp;

	rip->vrf = NULL;
	rip->distribute_ctx->vrf = NULL;
	vrf->info = NULL;

	FOR_ALL_INTERFACES (vrf, ifp)
		rip_interface_sync(ifp);
}

static void rip_instance_enable(struct rip *rip, struct vrf *vrf, int sock)
{
	rip->sock = sock;

	rip_vrf_link(rip, vrf);
	rip->enabled = true;

	/* Resend all redistribute requests. */
	rip_redistribute_enable(rip);

	/* Create read and timer thread. */
	rip_event(rip, RIP_READ, rip->sock);
	rip_event(rip, RIP_UPDATE_EVENT, 1);

	rip_zebra_vrf_register(vrf);
}

static void rip_instance_disable(struct rip *rip)
{
	struct vrf *vrf = rip->vrf;
	struct route_node *rp;

	/* Clear RIP routes */
	for (rp = route_top(rip->table); rp; rp = route_next(rp)) {
		struct rip_info *rinfo;
		struct list *list;
		struct listnode *listnode;

		if ((list = rp->info) == NULL)
			continue;

		rinfo = listgetdata(listhead(list));
		if (rip_route_rte(rinfo))
			rip_zebra_ipv4_delete(rip, rp);

		for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
			RIP_TIMER_OFF(rinfo->t_timeout);
			RIP_TIMER_OFF(rinfo->t_garbage_collect);
			rip_info_free(rinfo);
		}
		list_delete(&list);
		rp->info = NULL;
		route_unlock_node(rp);
	}

	/* Flush all redistribute requests. */
	rip_redistribute_disable(rip);

	/* Cancel RIP related timers. */
	RIP_TIMER_OFF(rip->t_update);
	RIP_TIMER_OFF(rip->t_triggered_update);
	RIP_TIMER_OFF(rip->t_triggered_interval);

	/* Cancel read thread. */
	THREAD_READ_OFF(rip->t_read);

	/* Close RIP socket. */
	close(rip->sock);
	rip->sock = -1;

	/* Clear existing peers. */
	list_delete_all_node(rip->peer_list);

	rip_zebra_vrf_deregister(vrf);

	rip_vrf_unlink(rip, vrf);
	rip->enabled = false;
}

static int rip_vrf_new(struct vrf *vrf)
{
	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: VRF created: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

static int rip_vrf_delete(struct vrf *vrf)
{
	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: VRF deleted: %s(%u)", __func__, vrf->name,
			   vrf->vrf_id);

	return 0;
}

static int rip_vrf_enable(struct vrf *vrf)
{
	struct rip *rip;
	int socket;

	rip = rip_lookup_by_vrf_name(vrf->name);
	if (!rip) {
		char *old_vrf_name = NULL;

		rip = (struct rip *)vrf->info;
		if (!rip)
			return 0;
		/* update vrf name */
		if (rip->vrf_name)
			old_vrf_name = rip->vrf_name;
		rip->vrf_name = XSTRDUP(MTYPE_RIP_VRF_NAME, vrf->name);
		/*
		 * HACK: Change the RIP VRF in the running configuration directly,
		 * bypassing the northbound layer. This is necessary to avoid deleting
		 * the RIP and readding it in the new VRF, which would have
		 * several implications.
		 */
		if (yang_module_find("frr-ripd") && old_vrf_name) {
			struct lyd_node *rip_dnode;

			rip_dnode = yang_dnode_get(
				running_config->dnode,
				"/frr-ripd:ripd/instance[vrf='%s']/vrf",
				old_vrf_name);
			if (rip_dnode) {
				yang_dnode_change_leaf(rip_dnode, vrf->name);
				running_config->version++;
			}
		}
		if (old_vrf_name)
			XFREE(MTYPE_RIP_VRF_NAME, old_vrf_name);
	}
	if (!rip || rip->enabled)
		return 0;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: VRF %s(%u) enabled", __func__, vrf->name,
			   vrf->vrf_id);

	/* Activate the VRF RIP instance. */
	if (!rip->enabled) {
		socket = rip_create_socket(vrf);
		if (socket < 0)
			return -1;

		rip_instance_enable(rip, vrf, socket);
	}

	return 0;
}

static int rip_vrf_disable(struct vrf *vrf)
{
	struct rip *rip;

	rip = rip_lookup_by_vrf_name(vrf->name);
	if (!rip || !rip->enabled)
		return 0;

	if (IS_RIP_DEBUG_EVENT)
		zlog_debug("%s: VRF %s(%u) disabled", __func__, vrf->name,
			   vrf->vrf_id);

	/* Deactivate the VRF RIP instance. */
	if (rip->enabled)
		rip_instance_disable(rip);

	return 0;
}

void rip_vrf_init(void)
{
	vrf_init(rip_vrf_new, rip_vrf_enable, rip_vrf_disable, rip_vrf_delete,
		 rip_vrf_enable);
}

void rip_vrf_terminate(void)
{
	vrf_terminate();
}

/* Allocate new rip structure and set default value. */
void rip_init(void)
{
	/* Install top nodes. */
	install_node(&rip_node, config_write_rip);

	/* Install rip commands. */
	install_element(VIEW_NODE, &show_ip_rip_cmd);
	install_element(VIEW_NODE, &show_ip_rip_status_cmd);

	install_default(RIP_NODE);

	/* Debug related init. */
	rip_debug_init();

	/* Access list install. */
	access_list_init();
	access_list_add_hook(rip_distribute_update_all_wrapper);
	access_list_delete_hook(rip_distribute_update_all_wrapper);

	/* Prefix list initialize.*/
	prefix_list_init();
	prefix_list_add_hook(rip_distribute_update_all);
	prefix_list_delete_hook(rip_distribute_update_all);

	/* Distribute list install. */
	distribute_list_init(RIP_NODE);

	/* Route-map */
	rip_route_map_init();

	route_map_add_hook(rip_routemap_update);
	route_map_delete_hook(rip_routemap_update);

	if_rmap_init(RIP_NODE);
}
