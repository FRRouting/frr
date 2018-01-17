/*
 * Copyright (C) 2003 Yasuhiro Ohara
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

/* Shortest Path First calculation for OSPFv3 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "pqueue.h"
#include "linklist.h"
#include "thread.h"

#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_area.h"
#include "ospf6_proto.h"
#include "ospf6_abr.h"
#include "ospf6_spf.h"
#include "ospf6_intra.h"
#include "ospf6_interface.h"
#include "ospf6d.h"
#include "ospf6_abr.h"

unsigned char conf_debug_ospf6_spf = 0;

static void ospf6_spf_copy_nexthops_to_route(struct ospf6_route *rt,
					     struct ospf6_vertex *v)
{
	if (rt && v)
		ospf6_copy_nexthops(rt->nh_list, v->nh_list);
}

static void ospf6_spf_merge_nexthops_to_route(struct ospf6_route *rt,
					      struct ospf6_vertex *v)
{
	if (rt && v)
		ospf6_merge_nexthops(rt->nh_list, v->nh_list);
}

static unsigned int ospf6_spf_get_ifindex_from_nh(struct ospf6_vertex *v)
{
	struct ospf6_nexthop *nh;
	struct listnode *node;

	if (v) {
		node = listhead(v->nh_list);
		if (node) {
			nh = listgetdata(node);
			if (nh)
				return (nh->ifindex);
		}
	}
	return 0;
}

static int ospf6_vertex_cmp(void *a, void *b)
{
	struct ospf6_vertex *va = (struct ospf6_vertex *)a;
	struct ospf6_vertex *vb = (struct ospf6_vertex *)b;

	/* ascending order */
	if (va->cost != vb->cost)
		return (va->cost - vb->cost);
	return (va->hops - vb->hops);
}

static int ospf6_vertex_id_cmp(void *a, void *b)
{
	struct ospf6_vertex *va = (struct ospf6_vertex *)a;
	struct ospf6_vertex *vb = (struct ospf6_vertex *)b;
	int ret = 0;

	ret = ntohl(ospf6_linkstate_prefix_adv_router(&va->vertex_id))
	      - ntohl(ospf6_linkstate_prefix_adv_router(&vb->vertex_id));
	if (ret)
		return ret;

	ret = ntohl(ospf6_linkstate_prefix_id(&va->vertex_id))
	      - ntohl(ospf6_linkstate_prefix_id(&vb->vertex_id));
	return ret;
}

static struct ospf6_vertex *ospf6_vertex_create(struct ospf6_lsa *lsa)
{
	struct ospf6_vertex *v;

	v = (struct ospf6_vertex *)XMALLOC(MTYPE_OSPF6_VERTEX,
					   sizeof(struct ospf6_vertex));

	/* type */
	if (ntohs(lsa->header->type) == OSPF6_LSTYPE_ROUTER) {
		v->type = OSPF6_VERTEX_TYPE_ROUTER;
		/* Router LSA use Link ID 0 as base in vertex_id */
		ospf6_linkstate_prefix(lsa->header->adv_router, htonl(0),
			       &v->vertex_id);
	} else if (ntohs(lsa->header->type) == OSPF6_LSTYPE_NETWORK) {
		v->type = OSPF6_VERTEX_TYPE_NETWORK;
		/* vertex_id */
		ospf6_linkstate_prefix(lsa->header->adv_router, lsa->header->id,
			       &v->vertex_id);
	} else
		assert(0);

	/* name */
	ospf6_linkstate_prefix2str(&v->vertex_id, v->name, sizeof(v->name));

	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("%s: Creating vertex %s of type %s (0x%04hx) lsa %s",
			   __func__, v->name,
			   ((ntohs(lsa->header->type) == OSPF6_LSTYPE_ROUTER)
				    ? "Router"
				    : "N/W"), ntohs(lsa->header->type),
			   lsa->name);


	/* Associated LSA */
	v->lsa = lsa;

	/* capability bits + options */
	v->capability = *(u_char *)(OSPF6_LSA_HEADER_END(lsa->header));
	v->options[0] = *(u_char *)(OSPF6_LSA_HEADER_END(lsa->header) + 1);
	v->options[1] = *(u_char *)(OSPF6_LSA_HEADER_END(lsa->header) + 2);
	v->options[2] = *(u_char *)(OSPF6_LSA_HEADER_END(lsa->header) + 3);

	v->nh_list = list_new();
	v->nh_list->cmp = (int (*)(void *, void *))ospf6_nexthop_cmp;
	v->nh_list->del = (void (*) (void *))ospf6_nexthop_delete;

	v->parent = NULL;
	v->child_list = list_new();
	v->child_list->cmp = ospf6_vertex_id_cmp;

	return v;
}

static void ospf6_vertex_delete(struct ospf6_vertex *v)
{
	list_delete_and_null(&v->nh_list);
	list_delete_and_null(&v->child_list);
	XFREE(MTYPE_OSPF6_VERTEX, v);
}

static struct ospf6_lsa *ospf6_lsdesc_lsa(caddr_t lsdesc,
					  struct ospf6_vertex *v)
{
	struct ospf6_lsa *lsa = NULL;
	u_int16_t type = 0;
	u_int32_t id = 0, adv_router = 0;

	if (VERTEX_IS_TYPE(NETWORK, v)) {
		type = htons(OSPF6_LSTYPE_ROUTER);
		id = htonl(0);
		adv_router = NETWORK_LSDESC_GET_NBR_ROUTERID(lsdesc);
	} else {
		if (ROUTER_LSDESC_IS_TYPE(POINTTOPOINT, lsdesc)) {
			type = htons(OSPF6_LSTYPE_ROUTER);
			id = htonl(0);
			adv_router = ROUTER_LSDESC_GET_NBR_ROUTERID(lsdesc);
		} else if (ROUTER_LSDESC_IS_TYPE(TRANSIT_NETWORK, lsdesc)) {
			type = htons(OSPF6_LSTYPE_NETWORK);
			id = htonl(ROUTER_LSDESC_GET_NBR_IFID(lsdesc));
			adv_router = ROUTER_LSDESC_GET_NBR_ROUTERID(lsdesc);
		}
	}

	if (type == htons(OSPF6_LSTYPE_NETWORK))
		lsa = ospf6_lsdb_lookup(type, id, adv_router, v->area->lsdb);
	else
		lsa = ospf6_create_single_router_lsa(v->area, v->area->lsdb,
						     adv_router);
	if (IS_OSPF6_DEBUG_SPF(PROCESS)) {
		char ibuf[16], abuf[16];
		inet_ntop(AF_INET, &id, ibuf, sizeof(ibuf));
		inet_ntop(AF_INET, &adv_router, abuf, sizeof(abuf));
		if (lsa)
			zlog_debug("  Link to: %s len %u, V %s", lsa->name,
				   ntohs(lsa->header->length), v->name);
		else
			zlog_debug("  Link to: [%s Id:%s Adv:%s] No LSA , V %s",
				   ospf6_lstype_name(type), ibuf, abuf,
				   v->name);
	}

	return lsa;
}

static char *ospf6_lsdesc_backlink(struct ospf6_lsa *lsa, caddr_t lsdesc,
				   struct ospf6_vertex *v)
{
	caddr_t backlink, found = NULL;
	int size;

	size = (OSPF6_LSA_IS_TYPE(ROUTER, lsa)
			? sizeof(struct ospf6_router_lsdesc)
			: sizeof(struct ospf6_network_lsdesc));
	for (backlink = OSPF6_LSA_HEADER_END(lsa->header) + 4;
	     backlink + size <= OSPF6_LSA_END(lsa->header); backlink += size) {
		assert(!(OSPF6_LSA_IS_TYPE(NETWORK, lsa)
			 && VERTEX_IS_TYPE(NETWORK, v)));

		if (OSPF6_LSA_IS_TYPE(NETWORK, lsa)
		    && NETWORK_LSDESC_GET_NBR_ROUTERID(backlink)
			       == v->lsa->header->adv_router)
			found = backlink;
		else if (VERTEX_IS_TYPE(NETWORK, v)
			 && ROUTER_LSDESC_IS_TYPE(TRANSIT_NETWORK, backlink)
			 && ROUTER_LSDESC_GET_NBR_ROUTERID(backlink)
				    == v->lsa->header->adv_router
			 && ROUTER_LSDESC_GET_NBR_IFID(backlink)
				    == ntohl(v->lsa->header->id))
			found = backlink;
		else {
			if (!ROUTER_LSDESC_IS_TYPE(POINTTOPOINT, backlink)
			    || !ROUTER_LSDESC_IS_TYPE(POINTTOPOINT, lsdesc))
				continue;
			if (ROUTER_LSDESC_GET_NBR_IFID(backlink)
				    != ROUTER_LSDESC_GET_IFID(lsdesc)
			    || ROUTER_LSDESC_GET_NBR_IFID(lsdesc)
				       != ROUTER_LSDESC_GET_IFID(backlink))
				continue;
			if (ROUTER_LSDESC_GET_NBR_ROUTERID(backlink)
				    != v->lsa->header->adv_router
			    || ROUTER_LSDESC_GET_NBR_ROUTERID(lsdesc)
				       != lsa->header->adv_router)
				continue;
			found = backlink;
		}
	}

	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("Vertex %s Lsa %s Backlink %s", v->name, lsa->name,
			   (found ? "OK" : "FAIL"));

	return found;
}

static void ospf6_nexthop_calc(struct ospf6_vertex *w, struct ospf6_vertex *v,
			       caddr_t lsdesc)
{
	int i;
	ifindex_t ifindex;
	struct ospf6_interface *oi;
	u_int16_t type;
	u_int32_t adv_router;
	struct ospf6_lsa *lsa;
	struct ospf6_link_lsa *link_lsa;
	char buf[64];

	assert(VERTEX_IS_TYPE(ROUTER, w));
	ifindex = (VERTEX_IS_TYPE(NETWORK, v) ? ospf6_spf_get_ifindex_from_nh(v)
					      : ROUTER_LSDESC_GET_IFID(lsdesc));
	if (ifindex == 0) {
		zlog_err("No nexthop ifindex at vertex %s", v->name);
		return;
	}

	oi = ospf6_interface_lookup_by_ifindex(ifindex);
	if (oi == NULL) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("Can't find interface in SPF: ifindex %d",
				   ifindex);
		return;
	}

	type = htons(OSPF6_LSTYPE_LINK);
	adv_router = (VERTEX_IS_TYPE(NETWORK, v)
			      ? NETWORK_LSDESC_GET_NBR_ROUTERID(lsdesc)
			      : ROUTER_LSDESC_GET_NBR_ROUTERID(lsdesc));

	i = 0;
	for (ALL_LSDB_TYPED_ADVRTR(oi->lsdb, type, adv_router, lsa)) {
		if (VERTEX_IS_TYPE(ROUTER, v)
		    && htonl(ROUTER_LSDESC_GET_NBR_IFID(lsdesc))
			       != lsa->header->id)
			continue;

		link_lsa = (struct ospf6_link_lsa *)OSPF6_LSA_HEADER_END(
			lsa->header);
		if (IS_OSPF6_DEBUG_SPF(PROCESS)) {
			inet_ntop(AF_INET6, &link_lsa->linklocal_addr, buf,
				  sizeof(buf));
			zlog_debug("  nexthop %s from %s", buf, lsa->name);
		}

		ospf6_add_nexthop(w->nh_list, ifindex,
				  &link_lsa->linklocal_addr);
		i++;
	}

	if (i == 0 && IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("No nexthop for %s found", w->name);
}

static int ospf6_spf_install(struct ospf6_vertex *v,
			     struct ospf6_route_table *result_table)
{
	struct ospf6_route *route, *parent_route;
	struct ospf6_vertex *prev;
	char pbuf[PREFIX2STR_BUFFER];

	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("SPF install %s (lsa %s) hops %d cost %d", v->name,
			   v->lsa->name, v->hops, v->cost);

	route = ospf6_route_lookup(&v->vertex_id, result_table);
	if (route && route->path.cost < v->cost) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug(
				"  already installed with lower cost (%d), ignore",
				route->path.cost);
		ospf6_vertex_delete(v);
		return -1;
	} else if (route && route->path.cost == v->cost) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS)) {
			prefix2str(&route->prefix, pbuf, sizeof(pbuf));
			zlog_debug("  another path found to route %s lsa %s, merge",
				   pbuf, v->lsa->name);
		}
		ospf6_spf_merge_nexthops_to_route(route, v);

		prev = (struct ospf6_vertex *)route->route_option;
		assert(prev->hops <= v->hops);

		if ((VERTEX_IS_TYPE(ROUTER, v) &&
		    route->path.origin.id != v->lsa->header->id)) {
			if (IS_OSPF6_DEBUG_SPF(PROCESS)) {
				zlog_debug("%s: V lsa %s id %u, route id %u are different",
				   __PRETTY_FUNCTION__, v->lsa->name,
				   ntohl(v->lsa->header->id),
				   ntohl(route->path.origin.id));
			}
			return 0;
		}

		ospf6_vertex_delete(v);
		return -1;

	}

	/* There should be no case where candidate being installed (variable
	   "v") is closer than the one in the SPF tree (variable "route").
	   In the case something has gone wrong with the behavior of
	   Priority-Queue. */

	/* the case where the route exists already is handled and returned
	   up to here. */
	assert(route == NULL);

	route = ospf6_route_create();
	memcpy(&route->prefix, &v->vertex_id, sizeof(struct prefix));
	route->type = OSPF6_DEST_TYPE_LINKSTATE;
	route->path.type = OSPF6_PATH_TYPE_INTRA;
	route->path.origin.type = v->lsa->header->type;
	route->path.origin.id = v->lsa->header->id;
	route->path.origin.adv_router = v->lsa->header->adv_router;
	route->path.metric_type = 1;
	route->path.cost = v->cost;
	route->path.u.cost_e2 = v->hops;
	route->path.router_bits = v->capability;
	route->path.options[0] = v->options[0];
	route->path.options[1] = v->options[1];
	route->path.options[2] = v->options[2];

	ospf6_spf_copy_nexthops_to_route(route, v);

	/*
	 * The SPF logic implementation does not transfer the multipathing
	 * properties
	 * of a parent to a child node. Thus if there was a 3-way multipath to a
	 * node's parent and a single hop from the parent to the child, the
	 * logic of
	 * creating new vertices and computing next hops prevents there from
	 * being 3
	 * paths to the child node. This is primarily because the resolution of
	 * multipath is done in this routine, not in the main spf loop.
	 *
	 * The following logic addresses that problem by merging the parent's
	 * nexthop
	 * information with the child's, if the parent is not the root of the
	 * tree.
	 * This is based on the assumption that before a node's route is
	 * installed,
	 * its parent's route's nexthops have already been installed.
	 */
	if (v->parent && v->parent->hops) {
		parent_route =
			ospf6_route_lookup(&v->parent->vertex_id, result_table);
		if (parent_route) {
			ospf6_route_merge_nexthops(route, parent_route);
		}
	}

	if (v->parent)
		listnode_add_sort(v->parent->child_list, v);
	route->route_option = v;

	ospf6_route_add(route, result_table);
	return 0;
}

void ospf6_spf_table_finish(struct ospf6_route_table *result_table)
{
	struct ospf6_route *route, *nroute;
	struct ospf6_vertex *v;
	for (route = ospf6_route_head(result_table); route; route = nroute) {
		nroute = ospf6_route_next(route);
		v = (struct ospf6_vertex *)route->route_option;
		ospf6_vertex_delete(v);
		ospf6_route_remove(route, result_table);
	}
}

static const char *ospf6_spf_reason_str[] = {
	"R+", "R-", "N+", "N-", "L+", "L-", "R*", "N*",
};

void ospf6_spf_reason_string(unsigned int reason, char *buf, int size)
{
	unsigned int bit;
	int len = 0;

	if (!buf)
		return;

	for (bit = 0; bit < array_size(ospf6_spf_reason_str); bit++) {
		if ((reason & (1 << bit)) && (len < size)) {
			len += snprintf((buf + len), (size - len), "%s%s",
					(len > 0) ? ", " : "",
					ospf6_spf_reason_str[bit]);
		}
	}
}

/* RFC2328 16.1.  Calculating the shortest-path tree for an area */
/* RFC2740 3.8.1.  Calculating the shortest path tree for an area */
void ospf6_spf_calculation(u_int32_t router_id,
			   struct ospf6_route_table *result_table,
			   struct ospf6_area *oa)
{
	struct pqueue *candidate_list;
	struct ospf6_vertex *root, *v, *w;
	int size;
	caddr_t lsdesc;
	struct ospf6_lsa *lsa;
	struct in6_addr address;

	ospf6_spf_table_finish(result_table);

	/* Install the calculating router itself as the root of the SPF tree */
	/* construct root vertex */
	lsa = ospf6_create_single_router_lsa(oa, oa->lsdb_self, router_id);
	if (lsa == NULL) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("%s: No router LSA for area %s\n", __func__,
				   oa->name);
		return;
	}

	/* initialize */
	candidate_list = pqueue_create();
	candidate_list->cmp = ospf6_vertex_cmp;

	root = ospf6_vertex_create(lsa);
	root->area = oa;
	root->cost = 0;
	root->hops = 0;
	root->link_id = lsa->header->id;
	inet_pton(AF_INET6, "::1", &address);

	/* Actually insert root to the candidate-list as the only candidate */
	pqueue_enqueue(root, candidate_list);

	/* Iterate until candidate-list becomes empty */
	while (candidate_list->size) {
		/* get closest candidate from priority queue */
		v = pqueue_dequeue(candidate_list);

		/* installing may result in merging or rejecting of the vertex
		 */
		if (ospf6_spf_install(v, result_table) < 0)
			continue;

		/* Skip overloaded routers */
		if ((OSPF6_LSA_IS_TYPE(ROUTER, v->lsa)
		     && ospf6_router_is_stub_router(v->lsa)))
			continue;

		/* For each LS description in the just-added vertex V's LSA */
		size = (VERTEX_IS_TYPE(ROUTER, v)
				? sizeof(struct ospf6_router_lsdesc)
				: sizeof(struct ospf6_network_lsdesc));
		for (lsdesc = OSPF6_LSA_HEADER_END(v->lsa->header) + 4;
		     lsdesc + size <= OSPF6_LSA_END(v->lsa->header);
		     lsdesc += size) {
			lsa = ospf6_lsdesc_lsa(lsdesc, v);
			if (lsa == NULL)
				continue;

			if (OSPF6_LSA_IS_MAXAGE(lsa))
				continue;

			if (!ospf6_lsdesc_backlink(lsa, lsdesc, v))
				continue;

			w = ospf6_vertex_create(lsa);
			w->area = oa;
			w->parent = v;
			if (VERTEX_IS_TYPE(ROUTER, v)) {
				w->cost = v->cost
					  + ROUTER_LSDESC_GET_METRIC(lsdesc);
				w->hops =
					v->hops
					+ (VERTEX_IS_TYPE(NETWORK, w) ? 0 : 1);
			} else {
				/* NETWORK */
				w->cost = v->cost;
				w->hops = v->hops + 1;
			}

			/* nexthop calculation */
			if (w->hops == 0)
				ospf6_add_nexthop(
					w->nh_list,
					ROUTER_LSDESC_GET_IFID(lsdesc), NULL);
			else if (w->hops == 1 && v->hops == 0)
				ospf6_nexthop_calc(w, v, lsdesc);
			else
				ospf6_copy_nexthops(w->nh_list, v->nh_list);


			/* add new candidate to the candidate_list */
			if (IS_OSPF6_DEBUG_SPF(PROCESS))
				zlog_debug(
					"  New candidate: %s hops %d cost %d",
						w->name, w->hops, w->cost);
			pqueue_enqueue(w, candidate_list);
		}
	}


	pqueue_delete(candidate_list);

	ospf6_remove_temp_router_lsa(oa);

	oa->spf_calculation++;
}

static void ospf6_spf_log_database(struct ospf6_area *oa)
{
	char *p, *end, buffer[256];
	struct listnode *node;
	struct ospf6_interface *oi;

	p = buffer;
	end = buffer + sizeof(buffer);

	snprintf(p, end - p, "SPF on DB (#LSAs):");
	p = (buffer + strlen(buffer) < end ? buffer + strlen(buffer) : end);
	snprintf(p, end - p, " Area %s: %d", oa->name, oa->lsdb->count);
	p = (buffer + strlen(buffer) < end ? buffer + strlen(buffer) : end);

	for (ALL_LIST_ELEMENTS_RO(oa->if_list, node, oi)) {
		snprintf(p, end - p, " I/F %s: %d", oi->interface->name,
			 oi->lsdb->count);
		p = (buffer + strlen(buffer) < end ? buffer + strlen(buffer)
						   : end);
	}

	zlog_debug("%s", buffer);
}

static int ospf6_spf_calculation_thread(struct thread *t)
{
	struct ospf6_area *oa;
	struct ospf6 *ospf6;
	struct timeval start, end, runtime;
	struct listnode *node;
	int areas_processed = 0;
	char rbuf[32];

	ospf6 = (struct ospf6 *)THREAD_ARG(t);
	ospf6->t_spf_calc = NULL;

	/* execute SPF calculation */
	monotime(&start);
	ospf6->ts_spf = start;

	if (ospf6_is_router_abr(ospf6))
		ospf6_abr_range_reset_cost(ospf6);

	for (ALL_LIST_ELEMENTS_RO(ospf6->area_list, node, oa)) {

		if (oa == ospf6->backbone)
			continue;

		monotime(&oa->ts_spf);
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("SPF calculation for Area %s", oa->name);
		if (IS_OSPF6_DEBUG_SPF(DATABASE))
			ospf6_spf_log_database(oa);

		ospf6_spf_calculation(ospf6->router_id, oa->spf_table, oa);
		ospf6_intra_route_calculation(oa);
		ospf6_intra_brouter_calculation(oa);

		areas_processed++;
	}

	if (ospf6->backbone) {
		monotime(&ospf6->backbone->ts_spf);
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("SPF calculation for Backbone area %s",
				   ospf6->backbone->name);
		if (IS_OSPF6_DEBUG_SPF(DATABASE))
			ospf6_spf_log_database(ospf6->backbone);

		ospf6_spf_calculation(ospf6->router_id,
				      ospf6->backbone->spf_table,
				      ospf6->backbone);
		ospf6_intra_route_calculation(ospf6->backbone);
		ospf6_intra_brouter_calculation(ospf6->backbone);
		areas_processed++;
	}

	if (ospf6_is_router_abr(ospf6))
		ospf6_abr_defaults_to_stub(ospf6);

	monotime(&end);
	timersub(&end, &start, &runtime);

	ospf6->ts_spf_duration = runtime;

	ospf6_spf_reason_string(ospf6->spf_reason, rbuf, sizeof(rbuf));

	if (IS_OSPF6_DEBUG_SPF(PROCESS) || IS_OSPF6_DEBUG_SPF(TIME))
		zlog_debug("SPF runtime: %lld sec %lld usec",
			   (long long)runtime.tv_sec,
			   (long long)runtime.tv_usec);

	zlog_info(
		"SPF processing: # Areas: %d, SPF runtime: %lld sec %lld usec, "
		"Reason: %s\n",
		areas_processed, (long long)runtime.tv_sec,
		(long long)runtime.tv_usec, rbuf);

	ospf6->last_spf_reason = ospf6->spf_reason;
	ospf6_reset_spf_reason(ospf6);
	return 0;
}

/* Add schedule for SPF calculation.  To avoid frequenst SPF calc, we
   set timer for SPF calc. */
void ospf6_spf_schedule(struct ospf6 *ospf6, unsigned int reason)
{
	unsigned long delay, elapsed, ht;

	ospf6_set_spf_reason(ospf6, reason);

	if (IS_OSPF6_DEBUG_SPF(PROCESS) || IS_OSPF6_DEBUG_SPF(TIME)) {
		char rbuf[32];
		ospf6_spf_reason_string(reason, rbuf, sizeof(rbuf));
		zlog_debug("SPF: calculation timer scheduled (reason %s)",
			   rbuf);
	}

	/* OSPF instance does not exist. */
	if (ospf6 == NULL)
		return;

	/* SPF calculation timer is already scheduled. */
	if (ospf6->t_spf_calc) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS) || IS_OSPF6_DEBUG_SPF(TIME))
			zlog_debug(
				"SPF: calculation timer is already scheduled: %p",
				(void *)ospf6->t_spf_calc);
		return;
	}

	elapsed = monotime_since(&ospf6->ts_spf, NULL) / 1000LL;
	ht = ospf6->spf_holdtime * ospf6->spf_hold_multiplier;

	if (ht > ospf6->spf_max_holdtime)
		ht = ospf6->spf_max_holdtime;

	/* Get SPF calculation delay time. */
	if (elapsed < ht) {
		/* Got an event within the hold time of last SPF. We need to
		 * increase the hold_multiplier, if it's not already at/past
		 * maximum value, and wasn't already increased..
		 */
		if (ht < ospf6->spf_max_holdtime)
			ospf6->spf_hold_multiplier++;

		/* always honour the SPF initial delay */
		if ((ht - elapsed) < ospf6->spf_delay)
			delay = ospf6->spf_delay;
		else
			delay = ht - elapsed;
	} else {
		/* Event is past required hold-time of last SPF */
		delay = ospf6->spf_delay;
		ospf6->spf_hold_multiplier = 1;
	}

	if (IS_OSPF6_DEBUG_SPF(PROCESS) || IS_OSPF6_DEBUG_SPF(TIME))
		zlog_debug("SPF: calculation timer delay = %ld", delay);

	zlog_info("SPF: Scheduled in %ld msec", delay);

	ospf6->t_spf_calc = NULL;
	thread_add_timer_msec(master, ospf6_spf_calculation_thread, ospf6,
			      delay, &ospf6->t_spf_calc);
}

void ospf6_spf_display_subtree(struct vty *vty, const char *prefix, int rest,
			       struct ospf6_vertex *v)
{
	struct listnode *node, *nnode;
	struct ospf6_vertex *c;
	char *next_prefix;
	int len;
	int restnum;

	/* "prefix" is the space prefix of the display line */
	vty_out(vty, "%s+-%s [%d]\n", prefix, v->name, v->cost);

	len = strlen(prefix) + 4;
	next_prefix = (char *)malloc(len);
	if (next_prefix == NULL) {
		vty_out(vty, "malloc failed\n");
		return;
	}
	snprintf(next_prefix, len, "%s%s", prefix, (rest ? "|  " : "   "));

	restnum = listcount(v->child_list);
	for (ALL_LIST_ELEMENTS(v->child_list, node, nnode, c)) {
		restnum--;
		ospf6_spf_display_subtree(vty, next_prefix, restnum, c);
	}

	free(next_prefix);
}

DEFUN (debug_ospf6_spf_process,
       debug_ospf6_spf_process_cmd,
       "debug ospf6 spf process",
       DEBUG_STR
       OSPF6_STR
       "Debug SPF Calculation\n"
       "Debug Detailed SPF Process\n"
      )
{
	unsigned char level = 0;
	level = OSPF6_DEBUG_SPF_PROCESS;
	OSPF6_DEBUG_SPF_ON(level);
	return CMD_SUCCESS;
}

DEFUN (debug_ospf6_spf_time,
       debug_ospf6_spf_time_cmd,
       "debug ospf6 spf time",
       DEBUG_STR
       OSPF6_STR
       "Debug SPF Calculation\n"
       "Measure time taken by SPF Calculation\n"
      )
{
	unsigned char level = 0;
	level = OSPF6_DEBUG_SPF_TIME;
	OSPF6_DEBUG_SPF_ON(level);
	return CMD_SUCCESS;
}

DEFUN (debug_ospf6_spf_database,
       debug_ospf6_spf_database_cmd,
       "debug ospf6 spf database",
       DEBUG_STR
       OSPF6_STR
       "Debug SPF Calculation\n"
       "Log number of LSAs at SPF Calculation time\n"
      )
{
	unsigned char level = 0;
	level = OSPF6_DEBUG_SPF_DATABASE;
	OSPF6_DEBUG_SPF_ON(level);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_spf_process,
       no_debug_ospf6_spf_process_cmd,
       "no debug ospf6 spf process",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Quit Debugging SPF Calculation\n"
       "Quit Debugging Detailed SPF Process\n"
      )
{
	unsigned char level = 0;
	level = OSPF6_DEBUG_SPF_PROCESS;
	OSPF6_DEBUG_SPF_OFF(level);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_spf_time,
       no_debug_ospf6_spf_time_cmd,
       "no debug ospf6 spf time",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Quit Debugging SPF Calculation\n"
       "Quit Measuring time taken by SPF Calculation\n"
      )
{
	unsigned char level = 0;
	level = OSPF6_DEBUG_SPF_TIME;
	OSPF6_DEBUG_SPF_OFF(level);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_spf_database,
       no_debug_ospf6_spf_database_cmd,
       "no debug ospf6 spf database",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug SPF Calculation\n"
       "Quit Logging number of LSAs at SPF Calculation time\n"
      )
{
	unsigned char level = 0;
	level = OSPF6_DEBUG_SPF_DATABASE;
	OSPF6_DEBUG_SPF_OFF(level);
	return CMD_SUCCESS;
}

static int ospf6_timers_spf_set(struct vty *vty, unsigned int delay,
				unsigned int hold, unsigned int max)
{
	VTY_DECLVAR_CONTEXT(ospf6, ospf);

	ospf->spf_delay = delay;
	ospf->spf_holdtime = hold;
	ospf->spf_max_holdtime = max;

	return CMD_SUCCESS;
}

DEFUN (ospf6_timers_throttle_spf,
       ospf6_timers_throttle_spf_cmd,
       "timers throttle spf (0-600000) (0-600000) (0-600000)",
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "OSPF6 SPF timers\n"
       "Delay (msec) from first change received till SPF calculation\n"
       "Initial hold time (msec) between consecutive SPF calculations\n"
       "Maximum hold time (msec)\n")
{
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	unsigned int delay, hold, max;

	delay = strtoul(argv[idx_number]->arg, NULL, 10);
	hold = strtoul(argv[idx_number_2]->arg, NULL, 10);
	max = strtoul(argv[idx_number_3]->arg, NULL, 10);

	return ospf6_timers_spf_set(vty, delay, hold, max);
}

DEFUN (no_ospf6_timers_throttle_spf,
       no_ospf6_timers_throttle_spf_cmd,
       "no timers throttle spf [(0-600000) (0-600000) (0-600000)]",
       NO_STR
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "OSPF6 SPF timers\n"
       "Delay (msec) from first change received till SPF calculation\n"
       "Initial hold time (msec) between consecutive SPF calculations\n"
       "Maximum hold time (msec)\n")
{
	return ospf6_timers_spf_set(vty, OSPF_SPF_DELAY_DEFAULT,
				    OSPF_SPF_HOLDTIME_DEFAULT,
				    OSPF_SPF_MAX_HOLDTIME_DEFAULT);
}


int config_write_ospf6_debug_spf(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		vty_out(vty, "debug ospf6 spf process\n");
	if (IS_OSPF6_DEBUG_SPF(TIME))
		vty_out(vty, "debug ospf6 spf time\n");
	if (IS_OSPF6_DEBUG_SPF(DATABASE))
		vty_out(vty, "debug ospf6 spf database\n");
	return 0;
}

void ospf6_spf_config_write(struct vty *vty)
{

	if (ospf6->spf_delay != OSPF_SPF_DELAY_DEFAULT
	    || ospf6->spf_holdtime != OSPF_SPF_HOLDTIME_DEFAULT
	    || ospf6->spf_max_holdtime != OSPF_SPF_MAX_HOLDTIME_DEFAULT)
		vty_out(vty, " timers throttle spf %d %d %d\n",
			ospf6->spf_delay, ospf6->spf_holdtime,
			ospf6->spf_max_holdtime);
}

void install_element_ospf6_debug_spf(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_spf_process_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_spf_time_cmd);
	install_element(ENABLE_NODE, &debug_ospf6_spf_database_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_spf_process_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_spf_time_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_spf_database_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_spf_process_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_spf_time_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_spf_database_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_spf_process_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_spf_time_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_spf_database_cmd);
}

void ospf6_spf_init(void)
{
	install_element(OSPF6_NODE, &ospf6_timers_throttle_spf_cmd);
	install_element(OSPF6_NODE, &no_ospf6_timers_throttle_spf_cmd);
}

/* Create Aggregated Large Router-LSA from multiple Link-State IDs
 * RFC 5340 A 4.3:
 * When more than one router-LSA is received from a single router,
 * the links are processed as if concatenated into a single LSA.*/
struct ospf6_lsa *ospf6_create_single_router_lsa(struct ospf6_area *area,
						 struct ospf6_lsdb *lsdb,
						 uint32_t adv_router)
{
	struct ospf6_lsa *lsa = NULL;
	struct ospf6_lsa *rtr_lsa = NULL;
	struct ospf6_lsa_header *lsa_header = NULL;
	uint8_t *new_header = NULL;
	const struct route_node *end = NULL;
	uint16_t lsa_length, total_lsa_length = 0, num_lsa = 0;
	u_int16_t type = 0;
	char ifbuf[16];
	uint32_t interface_id;
	caddr_t lsd;

	lsa_length = sizeof(struct ospf6_lsa_header) +
				sizeof(struct ospf6_router_lsa);
	total_lsa_length = lsa_length;
	type = htons(OSPF6_LSTYPE_ROUTER);

	/* First check Aggregated LSA formed earlier in Cache */
	lsa = ospf6_lsdb_lookup(type, htonl(0), adv_router,
				area->temp_router_lsa_lsdb);
	if (lsa)
		return lsa;

	inet_ntop(AF_INET, &adv_router, ifbuf, sizeof(ifbuf));

	/* Determine total LSA length from all link state ids */
	end = ospf6_lsdb_head(lsdb, 2, type, adv_router, &rtr_lsa);
	while (rtr_lsa) {
		lsa = rtr_lsa;
		if (OSPF6_LSA_IS_MAXAGE(rtr_lsa)) {
			rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
			continue;
		}
		lsa_header = (struct ospf6_lsa_header *) rtr_lsa->header;
		total_lsa_length += (ntohs(lsa_header->length)
				     - lsa_length);
		num_lsa++;
		rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
	}
	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("%s: adv_router %s num_lsa %u to convert.",
			__PRETTY_FUNCTION__, ifbuf, num_lsa);
	if (num_lsa == 1)
		return lsa;

	if (num_lsa == 0) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("%s: adv_router %s not found in LSDB.",
				   __PRETTY_FUNCTION__, ifbuf);
		return NULL;
	}

	/* Allocate memory for this LSA */
	new_header = XMALLOC(MTYPE_OSPF6_LSA_HEADER, total_lsa_length);
	if (!new_header)
		return NULL;

	/* LSA information structure */
	lsa = (struct ospf6_lsa *)XCALLOC(MTYPE_OSPF6_LSA,
					  sizeof(struct ospf6_lsa));
	if (!lsa) {
		free(new_header);
		return NULL;
	}

	lsa->header = (struct ospf6_lsa_header *)new_header;

	lsa->lsdb = area->temp_router_lsa_lsdb;

	/* Fill Larger LSA Payload */
	end = ospf6_lsdb_head(lsdb, 2, type, adv_router, &rtr_lsa);
	if (rtr_lsa) {
		if (!OSPF6_LSA_IS_MAXAGE(rtr_lsa)) {
			/* Append first Link State ID LSA */
			lsa_header = (struct ospf6_lsa_header *)rtr_lsa->header;
			memcpy(new_header, lsa_header,
				ntohs(lsa_header->length));
			/* Assign new lsa length as aggregated length. */
			((struct ospf6_lsa_header *)new_header)->length =
					htons(total_lsa_length);
			new_header += ntohs(lsa_header->length);
			num_lsa--;
		}
	}

	/* Print LSA Name */
	ospf6_lsa_printbuf(lsa, lsa->name, sizeof(lsa->name));

	rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
	while (rtr_lsa) {
		if (OSPF6_LSA_IS_MAXAGE(rtr_lsa)) {
			rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
			continue;
		}

		if (IS_OSPF6_DEBUG_SPF(PROCESS)) {
			lsd = OSPF6_LSA_HEADER_END(rtr_lsa->header) + 4;
			interface_id = ROUTER_LSDESC_GET_IFID(lsd);
			inet_ntop(AF_INET, &interface_id, ifbuf, sizeof(ifbuf));
			zlog_debug("%s: Next Router LSA %s to aggreat with len %u interface_id %s",
				   __PRETTY_FUNCTION__, rtr_lsa->name,
				   ntohs(lsa_header->length), ifbuf);
		}

		/* Append Next Link State ID LSA */
		lsa_header = (struct ospf6_lsa_header *) rtr_lsa->header;
		memcpy(new_header, (OSPF6_LSA_HEADER_END(rtr_lsa->header) + 4),
		       (ntohs(lsa_header->length) - lsa_length));
		new_header += (ntohs(lsa_header->length) - lsa_length);
		num_lsa--;

		rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
	}

	/* Calculate birth of this lsa */
	ospf6_lsa_age_set(lsa);

	/* Store Aggregated LSA into area temp lsdb */
	ospf6_lsdb_add(lsa, area->temp_router_lsa_lsdb);

	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("%s: LSA %s id %u type 0%x len %u num_lsa %u",
			   __PRETTY_FUNCTION__, lsa->name,
			   ntohl(lsa->header->id), ntohs(lsa->header->type),
			   ntohs(lsa->header->length), num_lsa);

	return lsa;
}

void ospf6_remove_temp_router_lsa(struct ospf6_area *area)
{
	struct ospf6_lsa *lsa = NULL;

	for (ALL_LSDB(area->temp_router_lsa_lsdb, lsa)) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("%s Remove LSA %s lsa->lock %u lsdb count %u",
				   __PRETTY_FUNCTION__,
				   lsa->name, lsa->lock,
				   area->temp_router_lsa_lsdb->count);
		ospf6_lsdb_remove(lsa, area->temp_router_lsa_lsdb);
	}
}
