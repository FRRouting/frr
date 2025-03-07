// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2003 Yasuhiro Ohara
 */

/* Shortest Path First calculation for OSPFv3 */

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "command.h"
#include "vty.h"
#include "prefix.h"
#include "linklist.h"
#include "frrevent.h"
#include "lib_errors.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_area.h"
#include "ospf6_abr.h"
#include "ospf6_asbr.h"
#include "ospf6_spf.h"
#include "ospf6_intra.h"
#include "ospf6_interface.h"
#include "ospf6d.h"
#include "ospf6_abr.h"
#include "ospf6_nssa.h"
#include "ospf6_zebra.h"

DEFINE_MTYPE_STATIC(OSPF6D, OSPF6_VERTEX, "OSPF6 vertex");

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

static int ospf6_vertex_cmp(const struct ospf6_vertex *va,
		const struct ospf6_vertex *vb)
{
	/* ascending order */
	if (va->cost != vb->cost)
		return (va->cost - vb->cost);
	if (va->hops != vb->hops)
		return (va->hops - vb->hops);
	return 0;
}
DECLARE_SKIPLIST_NONUNIQ(vertex_pqueue, struct ospf6_vertex, pqi,
		ospf6_vertex_cmp);

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

	v = XMALLOC(MTYPE_OSPF6_VERTEX, sizeof(struct ospf6_vertex));

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
				    : "N/W"),
			   ntohs(lsa->header->type), lsa->name);


	/* Associated LSA */
	v->lsa = lsa;

	/* capability bits + options */
	v->capability = *(uint8_t *)(ospf6_lsa_header_end(lsa->header));
	v->options[0] = *(uint8_t *)(ospf6_lsa_header_end(lsa->header) + 1);
	v->options[1] = *(uint8_t *)(ospf6_lsa_header_end(lsa->header) + 2);
	v->options[2] = *(uint8_t *)(ospf6_lsa_header_end(lsa->header) + 3);

	v->nh_list = list_new();
	v->nh_list->cmp = (int (*)(void *, void *))ospf6_nexthop_cmp;
	v->nh_list->del = (void (*)(void *))ospf6_nexthop_delete;

	v->parent = NULL;
	v->child_list = list_new();
	v->child_list->cmp = ospf6_vertex_id_cmp;

	return v;
}

static void ospf6_vertex_delete(struct ospf6_vertex *v)
{
	list_delete(&v->nh_list);
	list_delete(&v->child_list);
	XFREE(MTYPE_OSPF6_VERTEX, v);
}

static struct ospf6_lsa *ospf6_lsdesc_lsa(caddr_t lsdesc,
					  struct ospf6_vertex *v)
{
	struct ospf6_lsa *lsa = NULL;
	uint16_t type = 0;
	uint32_t id = 0, adv_router = 0;

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
				   ospf6_lsa_size(lsa->header), v->name);
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
	for (backlink = ospf6_lsa_header_end(lsa->header) + 4;
	     backlink + size <= ospf6_lsa_end(lsa->header); backlink += size) {
		assert(!(OSPF6_LSA_IS_TYPE(NETWORK, lsa)
			 && VERTEX_IS_TYPE(NETWORK, v)));

		if (OSPF6_LSA_IS_TYPE(NETWORK, lsa)) {
			if (NETWORK_LSDESC_GET_NBR_ROUTERID(backlink)
			    == v->lsa->header->adv_router)
				found = backlink;
		} else if (VERTEX_IS_TYPE(NETWORK, v)) {
			if (ROUTER_LSDESC_IS_TYPE(TRANSIT_NETWORK, backlink)
			    && ROUTER_LSDESC_GET_NBR_ROUTERID(backlink)
				       == v->lsa->header->adv_router
			    && ROUTER_LSDESC_GET_NBR_IFID(backlink)
				       == ntohl(v->lsa->header->id))
				found = backlink;
		} else {
			assert(OSPF6_LSA_IS_TYPE(ROUTER, lsa)
			       && VERTEX_IS_TYPE(ROUTER, v));

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
			       caddr_t lsdesc, struct ospf6 *ospf6)
{
	int i;
	ifindex_t ifindex;
	struct ospf6_interface *oi;
	uint16_t type;
	uint32_t adv_router;
	struct ospf6_lsa *lsa;
	struct ospf6_link_lsa *link_lsa;
	char buf[64];

	assert(VERTEX_IS_TYPE(ROUTER, w));
	ifindex = (VERTEX_IS_TYPE(NETWORK, v) ? ospf6_spf_get_ifindex_from_nh(v)
					      : ROUTER_LSDESC_GET_IFID(lsdesc));
	if (ifindex == 0) {
		flog_err(EC_LIB_DEVELOPMENT, "No nexthop ifindex at vertex %s",
			 v->name);
		return;
	}

	oi = ospf6_interface_lookup_by_ifindex(ifindex, ospf6->vrf_id);
	if (oi == NULL) {
		zlog_warn("Can't find interface in SPF: ifindex %d", ifindex);
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

		link_lsa = lsa_after_header(lsa->header);
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
	struct ospf6_route *route;
	struct ospf6_vertex *prev;

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
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug(
				"  another path found to route %pFX lsa %s, merge",
				&route->prefix, v->lsa->name);

		/* merging the parent's nexthop information to the child's
		 * if the parent is not the root of the tree.
		 */
		if (!ospf6_merge_parents_nh_to_child(v, route, result_table))
			ospf6_spf_merge_nexthops_to_route(route, v);

		prev = (struct ospf6_vertex *)route->route_option;
		assert(prev->hops <= v->hops);

		if ((VERTEX_IS_TYPE(ROUTER, v)
		     && route->path.origin.id != v->lsa->header->id)) {
			if (IS_OSPF6_DEBUG_SPF(PROCESS)) {
				zlog_debug(
					"%s: V lsa %s id %u, route id %u are different",
					__func__, v->lsa->name,
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

	route = ospf6_route_create(v->area->ospf6);
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
	ospf6_merge_parents_nh_to_child(v, route, result_table);

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

static const char *const ospf6_spf_reason_str[] = {
	"R+", /* OSPF6_SPF_FLAGS_ROUTER_LSA_ADDED */
	"R-", /* OSPF6_SPF_FLAGS_ROUTER_LSA_REMOVED */
	"N+", /* OSPF6_SPF_FLAGS_NETWORK_LSA_ADDED */
	"N-", /* OSPF6_SPF_FLAGS_NETWORK_LSA_REMOVED */
	"L+", /* OSPF6_SPF_FLAGS_NETWORK_LINK_LSA_ADDED */
	"L-", /* OSPF6_SPF_FLAGS_NETWORK_LINK_LSA_REMOVED */
	"R*", /* OSPF6_SPF_FLAGS_ROUTER_LSA_ORIGINATED */
	"N*", /* OSPF6_SPF_FLAGS_NETWORK_LSA_ORIGINATED */
	"C",  /* OSPF6_SPF_FLAGS_CONFIG_CHANGE */
	"A",  /* OSPF6_SPF_FLAGS_ASBR_STATUS_CHANGE */
	"GR", /* OSPF6_SPF_FLAGS_GR_FINISH */
};

void ospf6_spf_reason_string(uint32_t reason, char *buf, int size)
{
	uint32_t bit;
	int len = 0;

	if (!buf)
		return;

	if (!reason) {
		buf[0] = '\0';
		return;
	}
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
void ospf6_spf_calculation(uint32_t router_id,
			   struct ospf6_route_table *result_table,
			   struct ospf6_area *oa)
{
	struct vertex_pqueue_head candidate_list;
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
		zlog_warn("%s: No router LSA for area %s", __func__, oa->name);
		return;
	}

	/* initialize */
	vertex_pqueue_init(&candidate_list);

	root = ospf6_vertex_create(lsa);
	root->area = oa;
	root->cost = 0;
	root->hops = 0;
	root->link_id = lsa->header->id;
	inet_pton(AF_INET6, "::1", &address);

	/* Actually insert root to the candidate-list as the only candidate */
	vertex_pqueue_add(&candidate_list, root);

	/* Iterate until candidate-list becomes empty */
	while ((v = vertex_pqueue_pop(&candidate_list))) {
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
		for (lsdesc = ospf6_lsa_header_end(v->lsa->header) + 4;
		     lsdesc + size <= ospf6_lsa_end(v->lsa->header);
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
				ospf6_nexthop_calc(w, v, lsdesc, oa->ospf6);
			else
				ospf6_copy_nexthops(w->nh_list, v->nh_list);


			/* add new candidate to the candidate_list */
			if (IS_OSPF6_DEBUG_SPF(PROCESS))
				zlog_debug(
					"  New candidate: %s hops %d cost %d",
					w->name, w->hops, w->cost);
			vertex_pqueue_add(&candidate_list, w);
		}
	}

	//vertex_pqueue_fini(&candidate_list);

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

static void ospf6_spf_calculation_thread(struct event *t)
{
	struct ospf6_area *oa;
	struct ospf6 *ospf6;
	struct timeval start, end, runtime;
	struct listnode *node;
	int areas_processed = 0;
	char rbuf[32];

	ospf6 = (struct ospf6 *)EVENT_ARG(t);

	/* execute SPF calculation */
	monotime(&start);
	ospf6->ts_spf = start;

	if (ospf6_check_and_set_router_abr(ospf6))
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

	/* External LSA calculation */
	ospf6_ase_calculate_timer_add(ospf6);

	if (ospf6_check_and_set_router_abr(ospf6)) {
		ospf6_abr_defaults_to_stub(ospf6);
		ospf6_abr_nssa_type_7_defaults(ospf6);
	}

	monotime(&end);
	timersub(&end, &start, &runtime);

	ospf6->ts_spf_duration = runtime;

	ospf6_spf_reason_string(ospf6->spf_reason, rbuf, sizeof(rbuf));

	if (IS_OSPF6_DEBUG_SPF(PROCESS) || IS_OSPF6_DEBUG_SPF(TIME))
		zlog_debug(
			"SPF processing: # Areas: %d, SPF runtime: %lld sec %lld usec, Reason: %s",
			areas_processed, (long long)runtime.tv_sec,
			(long long)runtime.tv_usec, rbuf);

	ospf6->last_spf_reason = ospf6->spf_reason;
	ospf6_reset_spf_reason(ospf6);
}

/* Add schedule for SPF calculation.  To avoid frequenst SPF calc, we
   set timer for SPF calc. */
void ospf6_spf_schedule(struct ospf6 *ospf6, unsigned int reason)
{
	unsigned long delay, elapsed, ht;

	/* OSPF instance does not exist. */
	if (ospf6 == NULL)
		return;

	ospf6_set_spf_reason(ospf6, reason);

	if (IS_OSPF6_DEBUG_SPF(PROCESS) || IS_OSPF6_DEBUG_SPF(TIME)) {
		char rbuf[32];
		ospf6_spf_reason_string(reason, rbuf, sizeof(rbuf));
		zlog_debug("SPF: calculation timer scheduled (reason %s)",
			   rbuf);
	}

	/* SPF calculation timer is already scheduled. */
	if (event_is_scheduled(ospf6->t_spf_calc)) {
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
		zlog_debug("SPF: Rescheduling in %ld msec", delay);

	EVENT_OFF(ospf6->t_spf_calc);
	event_add_timer_msec(master, ospf6_spf_calculation_thread, ospf6, delay,
			     &ospf6->t_spf_calc);
}

void ospf6_spf_display_subtree(struct vty *vty, const char *prefix, int rest,
			       struct ospf6_vertex *v, json_object *json_obj,
			       bool use_json)
{
	struct listnode *node, *nnode;
	struct ospf6_vertex *c;
	char *next_prefix;
	int len;
	int restnum;
	json_object *json_childs = NULL;
	json_object *json_child = NULL;

	if (use_json) {
		json_childs = json_object_new_object();
		json_object_int_add(json_obj, "cost", v->cost);
	} else {
		/* "prefix" is the space prefix of the display line */
		vty_out(vty, "%s+-%s [%d]\n", prefix, v->name, v->cost);
	}

	len = strlen(prefix) + 4;
	next_prefix = (char *)malloc(len);
	if (next_prefix == NULL) {
		vty_out(vty, "malloc failed\n");
		return;
	}
	snprintf(next_prefix, len, "%s%s", prefix, (rest ? "|  " : "   "));

	restnum = listcount(v->child_list);
	for (ALL_LIST_ELEMENTS(v->child_list, node, nnode, c)) {
		if (use_json)
			json_child = json_object_new_object();
		else
			restnum--;

		ospf6_spf_display_subtree(vty, next_prefix, restnum, c,
					  json_child, use_json);

		if (use_json)
			json_object_object_add(json_childs, c->name,
					       json_child);
	}
	if (use_json) {
		json_object_boolean_add(json_obj, "isLeafNode",
					!listcount(v->child_list));
		if (listcount(v->child_list))
			json_object_object_add(json_obj, "children",
					       json_childs);
		else
			json_object_free(json_childs);
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

void ospf6_spf_config_write(struct vty *vty, struct ospf6 *ospf6)
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
	uint16_t type = 0;
	char ifbuf[16];
	uint32_t interface_id;
	caddr_t lsd;

	lsa_length = sizeof(struct ospf6_lsa_header)
		     + sizeof(struct ospf6_router_lsa);
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
		lsa_header = rtr_lsa->header;
		total_lsa_length += (ospf6_lsa_size(lsa_header) - lsa_length);
		num_lsa++;
		rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
	}
	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("%s: adv_router %s num_lsa %u to convert.", __func__,
			   ifbuf, num_lsa);
	if (num_lsa == 1)
		return lsa;

	if (num_lsa == 0) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("%s: adv_router %s not found in LSDB.",
				   __func__, ifbuf);
		return NULL;
	}

	lsa = ospf6_lsa_alloc(total_lsa_length);
	new_header = (uint8_t *)lsa->header;

	lsa->lsdb = area->temp_router_lsa_lsdb;

	/* Fill Larger LSA Payload */
	end = ospf6_lsdb_head(lsdb, 2, type, adv_router, &rtr_lsa);

	/*
	 * We assume at this point in time that rtr_lsa is
	 * a valid pointer.
	 */
	assert(rtr_lsa);
	if (!OSPF6_LSA_IS_MAXAGE(rtr_lsa)) {
		/* Append first Link State ID LSA */
		lsa_header = rtr_lsa->header;
		memcpy(new_header, lsa_header, ospf6_lsa_size(lsa_header));
		/* Assign new lsa length as aggregated length. */
		((struct ospf6_lsa_header *)new_header)->length =
			htons(total_lsa_length);
		new_header += ospf6_lsa_size(lsa_header);
		num_lsa--;
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
			lsd = ospf6_lsa_header_end(rtr_lsa->header) + 4;
			interface_id = ROUTER_LSDESC_GET_IFID(lsd);
			inet_ntop(AF_INET, &interface_id, ifbuf, sizeof(ifbuf));
			zlog_debug("%s: Next Router LSA %s to aggreat with len %u interface_id %s",
				   __func__, rtr_lsa->name,
				   ospf6_lsa_size(lsa_header), ifbuf);
		}

		/* Append Next Link State ID LSA */
		lsa_header = rtr_lsa->header;
		memcpy(new_header, (ospf6_lsa_header_end(rtr_lsa->header) + 4),
		       (ospf6_lsa_size(lsa_header) - lsa_length));
		new_header += (ospf6_lsa_size(lsa_header) - lsa_length);
		num_lsa--;

		rtr_lsa = ospf6_lsdb_next(end, rtr_lsa);
	}

	/* Calculate birth of this lsa */
	ospf6_lsa_age_set(lsa);

	/* Store Aggregated LSA into area temp lsdb */
	ospf6_lsdb_add(lsa, area->temp_router_lsa_lsdb);

	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("%s: LSA %s id %u type 0%x len %u num_lsa %u",
			   __func__, lsa->name, ntohl(lsa->header->id),
			   ntohs(lsa->header->type),
			   ospf6_lsa_size(lsa->header), num_lsa);

	return lsa;
}

void ospf6_remove_temp_router_lsa(struct ospf6_area *area)
{
	struct ospf6_lsa *lsa = NULL, *lsanext;

	for (ALL_LSDB(area->temp_router_lsa_lsdb, lsa, lsanext)) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug(
				"%s Remove LSA %s lsa->lock %u lsdb count %u",
				__func__, lsa->name, lsa->lock,
				area->temp_router_lsa_lsdb->count);
		ospf6_lsdb_remove(lsa, area->temp_router_lsa_lsdb);
	}
}

int ospf6_ase_calculate_route(struct ospf6 *ospf6, struct ospf6_lsa *lsa,
			      struct ospf6_area *area)
{
	struct ospf6_route *route;
	struct ospf6_as_external_lsa *external;
	struct prefix prefix;
	void (*hook_add)(struct ospf6_route *) = NULL;
	void (*hook_remove)(struct ospf6_route *) = NULL;

	assert(lsa);

	if (IS_OSPF6_DEBUG_SPF(PROCESS))
		zlog_debug("%s :  start", __func__);

	if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7)
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("%s: Processing Type-7", __func__);

	/* Stay away from any Local Translated Type-7 LSAs */
	if (CHECK_FLAG(lsa->flag, OSPF6_LSA_LOCAL_XLT)) {
		if (IS_OSPF6_DEBUG_SPF(PROCESS))
			zlog_debug("%s: Rejecting Local translated LSA",
				   __func__);
		return 0;
	}

	external = lsa_after_header(lsa->header);
	prefix.family = AF_INET6;
	prefix.prefixlen = external->prefix.prefix_length;
	ospf6_prefix_in6_addr(&prefix.u.prefix6, external, &external->prefix);

	if (ntohs(lsa->header->type) == OSPF6_LSTYPE_AS_EXTERNAL) {
		hook_add = ospf6->route_table->hook_add;
		hook_remove = ospf6->route_table->hook_remove;
		ospf6->route_table->hook_add = NULL;
		ospf6->route_table->hook_remove = NULL;

		if (!OSPF6_LSA_IS_MAXAGE(lsa))
			ospf6_asbr_lsa_add(lsa);

		ospf6->route_table->hook_add = hook_add;
		ospf6->route_table->hook_remove = hook_remove;

		route = ospf6_route_lookup(&prefix, ospf6->route_table);
		if (route == NULL) {
			if (IS_OSPF6_DEBUG_SPF(PROCESS))
				zlog_debug("%s: no external route %pFX",
					   __func__, &prefix);
			return 0;
		}

		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE)
		    && CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD)) {
			UNSET_FLAG(route->flag, OSPF6_ROUTE_REMOVE);
			UNSET_FLAG(route->flag, OSPF6_ROUTE_ADD);
		}

		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE))
			ospf6_route_remove(route, ospf6->route_table);
		else if (CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD)
			 || CHECK_FLAG(route->flag, OSPF6_ROUTE_CHANGE)) {
			if (hook_add) {
				if (IS_OSPF6_DEBUG_SPF(PROCESS))
					zlog_debug(
						"%s: add external route %pFX",
						__func__, &prefix);
				(*hook_add)(route);
			}
		}
	} else if (ntohs(lsa->header->type) == OSPF6_LSTYPE_TYPE_7) {
		hook_add = area->route_table->hook_add;
		hook_remove = area->route_table->hook_remove;
		area->route_table->hook_add = NULL;
		area->route_table->hook_remove = NULL;

		if (!OSPF6_LSA_IS_MAXAGE(lsa))
			ospf6_asbr_lsa_add(lsa);

		area->route_table->hook_add = hook_add;
		area->route_table->hook_remove = hook_remove;

		route = ospf6_route_lookup(&prefix, area->route_table);
		if (route == NULL) {
			if (IS_OSPF6_DEBUG_SPF(PROCESS))
				zlog_debug("%s: no route %pFX, area %s",
					   __func__, &prefix, area->name);
			return 0;
		}

		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE)
		    && CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD)) {
			UNSET_FLAG(route->flag, OSPF6_ROUTE_REMOVE);
			UNSET_FLAG(route->flag, OSPF6_ROUTE_ADD);
		}

		if (CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE)) {
			if (IS_OSPF6_DEBUG_SPF(PROCESS))
				zlog_debug("%s : remove route %pFX, area %s",
					   __func__, &prefix, area->name);
			ospf6_route_remove(route, area->route_table);
		} else if (CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD)
			   || CHECK_FLAG(route->flag, OSPF6_ROUTE_CHANGE)) {
			if (hook_add) {
				if (IS_OSPF6_DEBUG_SPF(PROCESS))
					zlog_debug(
						"%s: add nssa route %pFX, area %s",
						__func__, &prefix, area->name);
				(*hook_add)(route);
			}
			ospf6_abr_check_translate_nssa(area, lsa);
		}
	}
	return 0;
}

static void ospf6_ase_calculate_timer(struct event *t)
{
	struct ospf6 *ospf6;
	struct ospf6_lsa *lsa;
	struct listnode *node, *nnode;
	struct ospf6_area *area;
	uint16_t type;

	ospf6 = EVENT_ARG(t);

	/* Calculate external route for each AS-external-LSA */
	type = htons(OSPF6_LSTYPE_AS_EXTERNAL);
	for (ALL_LSDB_TYPED(ospf6->lsdb, type, lsa))
		ospf6_ase_calculate_route(ospf6, lsa, NULL);

	/*  This version simple adds to the table all NSSA areas  */
	if (ospf6->anyNSSA) {
		for (ALL_LIST_ELEMENTS(ospf6->area_list, node, nnode, area)) {
			if (IS_OSPF6_DEBUG_SPF(PROCESS))
				zlog_debug("%s : looking at area %s", __func__,
					   area->name);

			type = htons(OSPF6_LSTYPE_TYPE_7);
			for (ALL_LSDB_TYPED(area->lsdb, type, lsa))
				ospf6_ase_calculate_route(ospf6, lsa, area);
		}
	}

	if (ospf6->gr_info.finishing_restart) {
		/*
		 * The routing table computation is complete. Uninstall remnant
		 * routes that were installed before the restart, but that are
		 * no longer valid.
		 */
		ospf6_zebra_gr_disable(ospf6);
		ospf6_zebra_gr_enable(ospf6, ospf6->gr_info.grace_period);
		ospf6->gr_info.finishing_restart = false;
	}
}

void ospf6_ase_calculate_timer_add(struct ospf6 *ospf6)
{
	if (ospf6 == NULL)
		return;

	event_add_timer(master, ospf6_ase_calculate_timer, ospf6,
			OSPF6_ASE_CALC_INTERVAL, &ospf6->t_ase_calc);
}

bool ospf6_merge_parents_nh_to_child(struct ospf6_vertex *v,
				     struct ospf6_route *route,
				     struct ospf6_route_table *result_table)
{
	struct ospf6_route *parent_route;

	if (v->parent && v->parent->hops) {
		parent_route =
			ospf6_route_lookup(&v->parent->vertex_id, result_table);
		if (parent_route) {
			ospf6_route_merge_nexthops(route, parent_route);
			return true;
		}
	}
	return false;
}
