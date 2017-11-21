/*
 * OSPF AS Boundary Router functions.
 * Copyright (C) 1999, 2000 Kunihiro Ishiguro, Toshiaki Takada
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

#include "thread.h"
#include "memory.h"
#include "linklist.h"
#include "prefix.h"
#include "if.h"
#include "table.h"
#include "vty.h"
#include "filter.h"
#include "log.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_dump.h"


/* Remove external route. */
void ospf_external_route_remove(struct ospf *ospf, struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct ospf_route * or ;

	rn = route_node_lookup(ospf->old_external_route, (struct prefix *)p);
	if (rn)
		if ((or = rn->info)) {
			zlog_info("Route[%s/%d]: external path deleted",
				  inet_ntoa(p->prefix), p->prefixlen);

			/* Remove route from zebra. */
			if (or->type == OSPF_DESTINATION_NETWORK)
				ospf_zebra_delete(ospf,
						  (struct prefix_ipv4 *)&rn->p,
						  or);

			ospf_route_free(or);
			rn->info = NULL;

			route_unlock_node(rn);
			route_unlock_node(rn);
			return;
		}

	zlog_info("Route[%s/%d]: no such external path", inet_ntoa(p->prefix),
		  p->prefixlen);
}

/* Lookup external route. */
struct ospf_route *ospf_external_route_lookup(struct ospf *ospf,
					      struct prefix_ipv4 *p)
{
	struct route_node *rn;

	rn = route_node_lookup(ospf->old_external_route, (struct prefix *)p);
	if (rn) {
		route_unlock_node(rn);
		if (rn->info)
			return rn->info;
	}

	zlog_warn("Route[%s/%d]: lookup, no such prefix", inet_ntoa(p->prefix),
		  p->prefixlen);

	return NULL;
}


/* Add an External info for AS-external-LSA. */
struct external_info *ospf_external_info_new(u_char type, u_short instance)
{
	struct external_info *new;

	new = (struct external_info *)XCALLOC(MTYPE_OSPF_EXTERNAL_INFO,
					      sizeof(struct external_info));
	new->type = type;
	new->instance = instance;

	ospf_reset_route_map_set_values(&new->route_map_set);
	return new;
}

static void ospf_external_info_free(struct external_info *ei)
{
	XFREE(MTYPE_OSPF_EXTERNAL_INFO, ei);
}

void ospf_reset_route_map_set_values(struct route_map_set_values *values)
{
	values->metric = -1;
	values->metric_type = -1;
}

int ospf_route_map_set_compare(struct route_map_set_values *values1,
			       struct route_map_set_values *values2)
{
	return values1->metric == values2->metric
	       && values1->metric_type == values2->metric_type;
}

/* Add an External info for AS-external-LSA. */
struct external_info *ospf_external_info_add(struct ospf *ospf, u_char type,
					     u_short instance,
					     struct prefix_ipv4 p,
					     ifindex_t ifindex,
					     struct in_addr nexthop,
					     route_tag_t tag)
{
	struct external_info *new;
	struct route_node *rn;
	struct ospf_external *ext;
	char inetbuf[INET6_BUFSIZ];

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		ext = ospf_external_add(ospf, type, instance);

	rn = route_node_get(EXTERNAL_INFO(ext), (struct prefix *)&p);
	/* If old info exists, -- discard new one or overwrite with new one? */
	if (rn)
		if (rn->info) {
			new = rn->info;
			if ((new->ifindex == ifindex)
			    && (new->nexthop.s_addr == nexthop.s_addr)
			    && (new->tag == tag)) {
				route_unlock_node(rn);
				return NULL; /* NULL => no LSA to refresh */
			}

			inet_ntop(AF_INET, (void *)&nexthop.s_addr, inetbuf,
				  INET6_BUFSIZ);
			zlog_warn(
				"Redistribute[%s][%d][%u]: %s/%d discarding old info with NH %s.",
				ospf_redist_string(type), instance,
				ospf->vrf_id, inet_ntoa(p.prefix),
				p.prefixlen, inetbuf);
			XFREE(MTYPE_OSPF_EXTERNAL_INFO, rn->info);
			rn->info = NULL;
		}

	/* Create new External info instance. */
	new = ospf_external_info_new(type, instance);
	new->p = p;
	new->ifindex = ifindex;
	new->nexthop = nexthop;
	new->tag = tag;

	/* we don't unlock rn from the get() because we're attaching the info */
	if (rn)
		rn->info = new;

	if (IS_DEBUG_OSPF(lsa, LSA_GENERATE)) {
		inet_ntop(AF_INET, (void *)&nexthop.s_addr, inetbuf,
			  INET6_BUFSIZ);
		zlog_debug(
			"Redistribute[%s][%u]: %s/%d external info created, with NH %s",
			ospf_redist_string(type), ospf->vrf_id,
			inet_ntoa(p.prefix), p.prefixlen, inetbuf);
	}
	return new;
}

void ospf_external_info_delete(struct ospf *ospf, u_char type, u_short instance,
			       struct prefix_ipv4 p)
{
	struct route_node *rn;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		return;

	rn = route_node_lookup(EXTERNAL_INFO(ext), (struct prefix *)&p);
	if (rn) {
		ospf_external_info_free(rn->info);
		rn->info = NULL;
		route_unlock_node(rn);
		route_unlock_node(rn);
	}
}

struct external_info *ospf_external_info_lookup(struct ospf *ospf, u_char type,
						u_short instance,
						struct prefix_ipv4 *p)
{
	struct route_node *rn;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		return NULL;

	rn = route_node_lookup(EXTERNAL_INFO(ext), (struct prefix *)p);
	if (rn) {
		route_unlock_node(rn);
		if (rn->info)
			return rn->info;
	}

	return NULL;
}

struct ospf_lsa *ospf_external_info_find_lsa(struct ospf *ospf,
					     struct prefix_ipv4 *p)
{
	struct ospf_lsa *lsa;
	struct as_external_lsa *al;
	struct in_addr mask, id;

	lsa = ospf_lsdb_lookup_by_id(ospf->lsdb, OSPF_AS_EXTERNAL_LSA,
				     p->prefix, ospf->router_id);

	if (!lsa)
		return NULL;

	al = (struct as_external_lsa *)lsa->data;

	masklen2ip(p->prefixlen, &mask);

	if (mask.s_addr != al->mask.s_addr) {
		id.s_addr = p->prefix.s_addr | (~mask.s_addr);
		lsa = ospf_lsdb_lookup_by_id(ospf->lsdb, OSPF_AS_EXTERNAL_LSA,
					     id, ospf->router_id);
		if (!lsa)
			return NULL;
	}

	return lsa;
}


/* Update ASBR status. */
void ospf_asbr_status_update(struct ospf *ospf, u_char status)
{
	zlog_info("ASBR[Status:%d]: Update", status);

	/* ASBR on. */
	if (status) {
		/* Already ASBR. */
		if (IS_OSPF_ASBR(ospf)) {
			zlog_info("ASBR[Status:%d]: Already ASBR", status);
			return;
		}
		SET_FLAG(ospf->flags, OSPF_FLAG_ASBR);
	} else {
		/* Already non ASBR. */
		if (!IS_OSPF_ASBR(ospf)) {
			zlog_info("ASBR[Status:%d]: Already non ASBR", status);
			return;
		}
		UNSET_FLAG(ospf->flags, OSPF_FLAG_ASBR);
	}

	/* Transition from/to status ASBR, schedule timer. */
	ospf_spf_calculate_schedule(ospf, SPF_FLAG_ASBR_STATUS_CHANGE);
	ospf_router_lsa_update(ospf);
}

void ospf_redistribute_withdraw(struct ospf *ospf, u_char type,
				u_short instance)
{
	struct route_node *rn;
	struct external_info *ei;
	struct ospf_external *ext;

	ext = ospf_external_lookup(ospf, type, instance);
	if (!ext)
		return;

	/* Delete external info for specified type. */
	if (EXTERNAL_INFO(ext))
		for (rn = route_top(EXTERNAL_INFO(ext)); rn;
		     rn = route_next(rn))
			if ((ei = rn->info))
				if (ospf_external_info_find_lsa(ospf, &ei->p)) {
					if (is_prefix_default(&ei->p)
					    && ospf->default_originate
						       != DEFAULT_ORIGINATE_NONE)
						continue;
					ospf_external_lsa_flush(
						ospf, type, &ei->p,
						ei->ifindex /*, ei->nexthop */);

					ospf_external_info_free(ei);
					route_unlock_node(rn);
					rn->info = NULL;
				}
}
