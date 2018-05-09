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

#include <zebra.h>

#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "linklist.h"

#include "ospf6_proto.h"
#include "ospf6_lsa.h"
#include "ospf6_lsdb.h"
#include "ospf6_route.h"
#include "ospf6_top.h"
#include "ospf6_area.h"
#include "ospf6_interface.h"
#include "ospf6d.h"
#include "ospf6_zebra.h"

unsigned char conf_debug_ospf6_route = 0;

static char *ospf6_route_table_name(struct ospf6_route_table *table)
{
	static char name[64];
	switch (table->scope_type) {
	case OSPF6_SCOPE_TYPE_GLOBAL: {
		switch (table->table_type) {
		case OSPF6_TABLE_TYPE_ROUTES:
			snprintf(name, sizeof(name), "global route table");
			break;
		case OSPF6_TABLE_TYPE_BORDER_ROUTERS:
			snprintf(name, sizeof(name), "global brouter table");
			break;
		case OSPF6_TABLE_TYPE_EXTERNAL_ROUTES:
			snprintf(name, sizeof(name), "global external table");
			break;
		default:
			snprintf(name, sizeof(name), "global unknown table");
			break;
		}
	} break;

	case OSPF6_SCOPE_TYPE_AREA: {
		struct ospf6_area *oa = (struct ospf6_area *)table->scope;
		switch (table->table_type) {
		case OSPF6_TABLE_TYPE_SPF_RESULTS:
			snprintf(name, sizeof(name), "area %s spf table",
				 oa->name);
			break;
		case OSPF6_TABLE_TYPE_ROUTES:
			snprintf(name, sizeof(name), "area %s route table",
				 oa->name);
			break;
		case OSPF6_TABLE_TYPE_PREFIX_RANGES:
			snprintf(name, sizeof(name), "area %s range table",
				 oa->name);
			break;
		case OSPF6_TABLE_TYPE_SUMMARY_PREFIXES:
			snprintf(name, sizeof(name),
				 "area %s summary prefix table", oa->name);
			break;
		case OSPF6_TABLE_TYPE_SUMMARY_ROUTERS:
			snprintf(name, sizeof(name),
				 "area %s summary router table", oa->name);
			break;
		default:
			snprintf(name, sizeof(name), "area %s unknown table",
				 oa->name);
			break;
		}
	} break;

	case OSPF6_SCOPE_TYPE_INTERFACE: {
		struct ospf6_interface *oi =
			(struct ospf6_interface *)table->scope;
		switch (table->table_type) {
		case OSPF6_TABLE_TYPE_CONNECTED_ROUTES:
			snprintf(name, sizeof(name),
				 "interface %s connected table",
				 oi->interface->name);
			break;
		default:
			snprintf(name, sizeof(name),
				 "interface %s unknown table",
				 oi->interface->name);
			break;
		}
	} break;

	default: {
		switch (table->table_type) {
		case OSPF6_TABLE_TYPE_SPF_RESULTS:
			snprintf(name, sizeof(name), "temporary spf table");
			break;
		default:
			snprintf(name, sizeof(name), "temporary unknown table");
			break;
		}
	} break;
	}
	return name;
}

void ospf6_linkstate_prefix(uint32_t adv_router, uint32_t id,
			    struct prefix *prefix)
{
	memset(prefix, 0, sizeof(struct prefix));
	prefix->family = AF_INET6;
	prefix->prefixlen = 64;
	memcpy(&prefix->u.prefix6.s6_addr[0], &adv_router, 4);
	memcpy(&prefix->u.prefix6.s6_addr[4], &id, 4);
}

void ospf6_linkstate_prefix2str(struct prefix *prefix, char *buf, int size)
{
	uint32_t adv_router, id;
	char adv_router_str[16], id_str[16];
	memcpy(&adv_router, &prefix->u.prefix6.s6_addr[0], 4);
	memcpy(&id, &prefix->u.prefix6.s6_addr[4], 4);
	inet_ntop(AF_INET, &adv_router, adv_router_str, sizeof(adv_router_str));
	inet_ntop(AF_INET, &id, id_str, sizeof(id_str));
	if (ntohl(id))
		snprintf(buf, size, "%s Net-ID: %s", adv_router_str, id_str);
	else
		snprintf(buf, size, "%s", adv_router_str);
}

/* Global strings for logging */
const char *ospf6_dest_type_str[OSPF6_DEST_TYPE_MAX] = {
	"Unknown", "Router", "Network", "Discard", "Linkstate", "AddressRange",
};

const char *ospf6_dest_type_substr[OSPF6_DEST_TYPE_MAX] = {
	"?", "R", "N", "D", "L", "A",
};

const char *ospf6_path_type_str[OSPF6_PATH_TYPE_MAX] = {
	"Unknown", "Intra-Area", "Inter-Area", "External-1", "External-2",
};

const char *ospf6_path_type_substr[OSPF6_PATH_TYPE_MAX] = {
	"??", "IA", "IE", "E1", "E2",
};


struct ospf6_nexthop *ospf6_nexthop_create(void)
{
	struct ospf6_nexthop *nh;

	nh = XCALLOC(MTYPE_OSPF6_NEXTHOP, sizeof(struct ospf6_nexthop));
	return nh;
}

void ospf6_nexthop_delete(struct ospf6_nexthop *nh)
{
	if (nh)
		XFREE(MTYPE_OSPF6_NEXTHOP, nh);
}

void ospf6_clear_nexthops(struct list *nh_list)
{
	struct listnode *node;
	struct ospf6_nexthop *nh;

	if (nh_list) {
		for (ALL_LIST_ELEMENTS_RO(nh_list, node, nh))
			ospf6_nexthop_clear(nh);
	}
}

static struct ospf6_nexthop *
ospf6_route_find_nexthop(struct list *nh_list, struct ospf6_nexthop *nh_match)
{
	struct listnode *node;
	struct ospf6_nexthop *nh;

	if (nh_list && nh_match) {
		for (ALL_LIST_ELEMENTS_RO(nh_list, node, nh)) {
			if (ospf6_nexthop_is_same(nh, nh_match))
				return (nh);
		}
	}

	return (NULL);
}

void ospf6_copy_nexthops(struct list *dst, struct list *src)
{
	struct ospf6_nexthop *nh_new, *nh;
	struct listnode *node;

	if (dst && src) {
		for (ALL_LIST_ELEMENTS_RO(src, node, nh)) {
			if (ospf6_nexthop_is_set(nh)) {
				nh_new = ospf6_nexthop_create();
				ospf6_nexthop_copy(nh_new, nh);
				listnode_add_sort(dst, nh_new);
			}
		}
	}
}

void ospf6_merge_nexthops(struct list *dst, struct list *src)
{
	struct listnode *node;
	struct ospf6_nexthop *nh, *nh_new;

	if (src && dst) {
		for (ALL_LIST_ELEMENTS_RO(src, node, nh)) {
			if (!ospf6_route_find_nexthop(dst, nh)) {
				nh_new = ospf6_nexthop_create();
				ospf6_nexthop_copy(nh_new, nh);
				listnode_add_sort(dst, nh_new);
			}
		}
	}
}

int ospf6_route_cmp_nexthops(struct ospf6_route *a, struct ospf6_route *b)
{
	struct listnode *anode, *bnode;
	struct ospf6_nexthop *anh, *bnh;
	bool identical = false;

	if (a && b) {
		if (listcount(a->nh_list) == listcount(b->nh_list)) {
			for (ALL_LIST_ELEMENTS_RO(a->nh_list, anode, anh)) {
				identical = false;
				for (ALL_LIST_ELEMENTS_RO(b->nh_list, bnode,
							  bnh)) {
					if (ospf6_nexthop_is_same(anh, bnh))
						identical = true;
				}
				/* Currnet List A element not found List B
				 * Non-Identical lists return */
				if (identical == false)
					return 1;
			}
			return 0;
		} else
			return 1;
	}
	/* One of the routes doesn't exist ? */
	return (1);
}

int ospf6_num_nexthops(struct list *nh_list)
{
	return (listcount(nh_list));
}

void ospf6_add_nexthop(struct list *nh_list, int ifindex, struct in6_addr *addr)
{
	struct ospf6_nexthop *nh;
	struct ospf6_nexthop nh_match;

	if (nh_list) {
		nh_match.ifindex = ifindex;
		if (addr != NULL)
			memcpy(&nh_match.address, addr,
			       sizeof(struct in6_addr));
		else
			memset(&nh_match.address, 0, sizeof(struct in6_addr));

		if (!ospf6_route_find_nexthop(nh_list, &nh_match)) {
			nh = ospf6_nexthop_create();
			ospf6_nexthop_copy(nh, &nh_match);
			listnode_add(nh_list, nh);
		}
	}
}

void ospf6_route_zebra_copy_nexthops(struct ospf6_route *route,
				     struct zapi_nexthop nexthops[],
				     int entries)
{
	struct ospf6_nexthop *nh;
	struct listnode *node;
	char buf[64];
	int i;

	if (route) {
		i = 0;
		for (ALL_LIST_ELEMENTS_RO(route->nh_list, node, nh)) {
			if (IS_OSPF6_DEBUG_ZEBRA(SEND)) {
				const char *ifname;
				inet_ntop(AF_INET6, &nh->address, buf,
					  sizeof(buf));
				ifname = ifindex2ifname(nh->ifindex,
							VRF_DEFAULT);
				zlog_debug("  nexthop: %s%%%.*s(%d)", buf,
					   IFNAMSIZ, ifname, nh->ifindex);
			}
			if (i >= entries)
				return;

			nexthops[i].vrf_id = VRF_DEFAULT;
			nexthops[i].ifindex = nh->ifindex;
			if (!IN6_IS_ADDR_UNSPECIFIED(&nh->address)) {
				nexthops[i].gate.ipv6 = nh->address;
				nexthops[i].type = NEXTHOP_TYPE_IPV6_IFINDEX;
			} else
				nexthops[i].type = NEXTHOP_TYPE_IFINDEX;
			i++;
		}
	}
}

int ospf6_route_get_first_nh_index(struct ospf6_route *route)
{
	struct ospf6_nexthop *nh;

	if (route) {
		if ((nh = (struct ospf6_nexthop *)listhead(route->nh_list)))
			return (nh->ifindex);
	}

	return (-1);
}

int ospf6_nexthop_cmp(struct ospf6_nexthop *a, struct ospf6_nexthop *b)
{
	if (a->ifindex < b->ifindex)
		return -1;
	else if (a->ifindex > b->ifindex)
		return 1;
	else
		return memcmp(&a->address, &b->address,
			      sizeof(struct in6_addr));

	return 0;
}

static int ospf6_path_cmp(struct ospf6_path *a, struct ospf6_path *b)
{
	if (a->origin.adv_router < b->origin.adv_router)
		return -1;
	else if (a->origin.adv_router > b->origin.adv_router)
		return 1;
	else
		return 0;
}

void ospf6_path_free(struct ospf6_path *op)
{
	if (op->nh_list)
		list_delete_and_null(&op->nh_list);
	XFREE(MTYPE_OSPF6_PATH, op);
}

struct ospf6_path *ospf6_path_dup(struct ospf6_path *path)
{
	struct ospf6_path *new;

	new = XCALLOC(MTYPE_OSPF6_PATH, sizeof(struct ospf6_path));
	memcpy(new, path, sizeof(struct ospf6_path));
	new->nh_list = list_new();
	new->nh_list->cmp = (int (*)(void *, void *))ospf6_nexthop_cmp;
	new->nh_list->del = (void (*)(void *))ospf6_nexthop_delete;

	return new;
}

void ospf6_copy_paths(struct list *dst, struct list *src)
{
	struct ospf6_path *path_new, *path;
	struct listnode *node;

	if (dst && src) {
		for (ALL_LIST_ELEMENTS_RO(src, node, path)) {
			path_new = ospf6_path_dup(path);
			ospf6_copy_nexthops(path_new->nh_list, path->nh_list);
			listnode_add_sort(dst, path_new);
		}
	}
}

struct ospf6_route *ospf6_route_create(void)
{
	struct ospf6_route *route;
	route = XCALLOC(MTYPE_OSPF6_ROUTE, sizeof(struct ospf6_route));
	route->nh_list = list_new();
	route->nh_list->cmp = (int (*)(void *, void *))ospf6_nexthop_cmp;
	route->nh_list->del = (void (*)(void *))ospf6_nexthop_delete;
	route->paths = list_new();
	route->paths->cmp = (int (*)(void *, void *))ospf6_path_cmp;
	route->paths->del = (void (*)(void *))ospf6_path_free;
	return route;
}

void ospf6_route_delete(struct ospf6_route *route)
{
	if (route) {
		if (route->nh_list)
			list_delete_and_null(&route->nh_list);
		if (route->paths)
			list_delete_and_null(&route->paths);
		XFREE(MTYPE_OSPF6_ROUTE, route);
	}
}

struct ospf6_route *ospf6_route_copy(struct ospf6_route *route)
{
	struct ospf6_route *new;

	new = ospf6_route_create();
	new->type = route->type;
	memcpy(&new->prefix, &route->prefix, sizeof(struct prefix));
	new->installed = route->installed;
	new->changed = route->changed;
	new->flag = route->flag;
	new->route_option = route->route_option;
	new->linkstate_id = route->linkstate_id;
	new->path = route->path;
	ospf6_copy_nexthops(new->nh_list, route->nh_list);
	ospf6_copy_paths(new->paths, route->paths);
	new->rnode = NULL;
	new->prev = NULL;
	new->next = NULL;
	new->table = NULL;
	new->lock = 0;
	return new;
}

void ospf6_route_lock(struct ospf6_route *route)
{
	route->lock++;
}

void ospf6_route_unlock(struct ospf6_route *route)
{
	assert(route->lock > 0);
	route->lock--;
	if (route->lock == 0) {
		/* Can't detach from the table until here
		   because ospf6_route_next () will use
		   the 'route->table' pointer for logging */
		route->table = NULL;
		ospf6_route_delete(route);
	}
}

/* Route compare function. If ra is more preferred, it returns
   less than 0. If rb is more preferred returns greater than 0.
   Otherwise (neither one is preferred), returns 0 */
int ospf6_route_cmp(struct ospf6_route *ra, struct ospf6_route *rb)
{
	assert(ospf6_route_is_same(ra, rb));
	assert(OSPF6_PATH_TYPE_NONE < ra->path.type
	       && ra->path.type < OSPF6_PATH_TYPE_MAX);
	assert(OSPF6_PATH_TYPE_NONE < rb->path.type
	       && rb->path.type < OSPF6_PATH_TYPE_MAX);

	if (ra->type != rb->type)
		return (ra->type - rb->type);

	if (ra->path.type != rb->path.type)
		return (ra->path.type - rb->path.type);

	if (ra->path.type == OSPF6_PATH_TYPE_EXTERNAL2) {
		if (ra->path.u.cost_e2 != rb->path.u.cost_e2)
			return (ra->path.u.cost_e2 - rb->path.u.cost_e2);
		else
			return (ra->path.cost - rb->path.cost);
	} else {
		if (ra->path.cost != rb->path.cost)
			return (ra->path.cost - rb->path.cost);
	}

	if (ra->path.area_id != rb->path.area_id)
		return (ntohl(ra->path.area_id) - ntohl(rb->path.area_id));

	return 0;
}

struct ospf6_route *ospf6_route_lookup(struct prefix *prefix,
				       struct ospf6_route_table *table)
{
	struct route_node *node;
	struct ospf6_route *route;

	node = route_node_lookup(table->table, prefix);
	if (node == NULL)
		return NULL;

	route = (struct ospf6_route *)node->info;
	route_unlock_node(node); /* to free the lookup lock */
	return route;
}

struct ospf6_route *
ospf6_route_lookup_identical(struct ospf6_route *route,
			     struct ospf6_route_table *table)
{
	struct ospf6_route *target;

	for (target = ospf6_route_lookup(&route->prefix, table); target;
	     target = target->next) {
		if (target->type == route->type
		    && (memcmp(&target->prefix, &route->prefix,
			       sizeof(struct prefix))
			== 0)
		    && target->path.type == route->path.type
		    && target->path.cost == route->path.cost
		    && target->path.u.cost_e2 == route->path.u.cost_e2
		    && ospf6_route_cmp_nexthops(target, route) == 0)
			return target;
	}
	return NULL;
}

struct ospf6_route *
ospf6_route_lookup_bestmatch(struct prefix *prefix,
			     struct ospf6_route_table *table)
{
	struct route_node *node;
	struct ospf6_route *route;

	node = route_node_match(table->table, prefix);
	if (node == NULL)
		return NULL;
	route_unlock_node(node);

	route = (struct ospf6_route *)node->info;
	return route;
}

#ifdef DEBUG
static void route_table_assert(struct ospf6_route_table *table)
{
	struct ospf6_route *prev, *r, *next;
	char buf[PREFIX2STR_BUFFER];
	unsigned int link_error = 0, num = 0;

	r = ospf6_route_head(table);
	prev = NULL;
	while (r) {
		if (r->prev != prev)
			link_error++;

		next = ospf6_route_next(r);

		if (r->next != next)
			link_error++;

		prev = r;
		r = next;
	}

	for (r = ospf6_route_head(table); r; r = ospf6_route_next(r))
		num++;

	if (link_error == 0 && num == table->count)
		return;

	zlog_err("PANIC !!");
	zlog_err("Something has gone wrong with ospf6_route_table[%p]", table);
	zlog_debug("table count = %d, real number = %d", table->count, num);
	zlog_debug("DUMP START");
	for (r = ospf6_route_head(table); r; r = ospf6_route_next(r)) {
		prefix2str(&r->prefix, buf, sizeof(buf));
		zlog_info("%p<-[%p]->%p : %s", r->prev, r, r->next, buf);
	}
	zlog_debug("DUMP END");

	assert(link_error == 0 && num == table->count);
}
#define ospf6_route_table_assert(t) (route_table_assert (t))
#else
#define ospf6_route_table_assert(t) ((void) 0)
#endif /*DEBUG*/

struct ospf6_route *ospf6_route_add(struct ospf6_route *route,
				    struct ospf6_route_table *table)
{
	struct route_node *node, *nextnode, *prevnode;
	struct ospf6_route *current = NULL;
	struct ospf6_route *prev = NULL, *old = NULL, *next = NULL;
	char buf[PREFIX2STR_BUFFER];
	struct timeval now;

	assert(route->rnode == NULL);
	assert(route->lock == 0);
	assert(route->next == NULL);
	assert(route->prev == NULL);

	if (route->type == OSPF6_DEST_TYPE_LINKSTATE)
		ospf6_linkstate_prefix2str(&route->prefix, buf, sizeof(buf));
	else
		prefix2str(&route->prefix, buf, sizeof(buf));

	if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_debug("%s %p: route add %p: %s paths %u nh %u",
			   ospf6_route_table_name(table), (void *)table,
			   (void *)route, buf, listcount(route->paths),
			   listcount(route->nh_list));
	else if (IS_OSPF6_DEBUG_ROUTE(TABLE))
		zlog_debug("%s: route add: %s", ospf6_route_table_name(table),
			   buf);

	monotime(&now);

	node = route_node_get(table->table, &route->prefix);
	route->rnode = node;

	/* find place to insert */
	for (current = node->info; current; current = current->next) {
		if (!ospf6_route_is_same(current, route))
			next = current;
		else if (current->type != route->type)
			prev = current;
		else if (ospf6_route_is_same_origin(current, route))
			old = current;
		else if (ospf6_route_cmp(current, route) > 0)
			next = current;
		else
			prev = current;

		if (old || next)
			break;
	}

	if (old) {
		/* if route does not actually change, return unchanged */
		if (ospf6_route_is_identical(old, route)) {
			if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
				zlog_debug(
					"%s %p: route add %p: needless update of %p old cost %u",
					ospf6_route_table_name(table),
					(void *)table, (void *)route,
					(void *)old, old->path.cost);
			else if (IS_OSPF6_DEBUG_ROUTE(TABLE))
				zlog_debug("%s: route add: needless update",
					   ospf6_route_table_name(table));

			ospf6_route_delete(route);
			SET_FLAG(old->flag, OSPF6_ROUTE_ADD);
			ospf6_route_table_assert(table);

			/* to free the lookup lock */
			route_unlock_node(node);
			return old;
		}

		if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
			zlog_debug(
				"%s %p: route add %p cost %u paths %u nh %u: update of %p cost %u paths %u nh %u",
				ospf6_route_table_name(table), (void *)table,
				(void *)route, route->path.cost,
				listcount(route->paths),
				listcount(route->nh_list), (void *)old,
				old->path.cost, listcount(old->paths),
				listcount(old->nh_list));
		else if (IS_OSPF6_DEBUG_ROUTE(TABLE))
			zlog_debug("%s: route add: update",
				   ospf6_route_table_name(table));

		/* replace old one if exists */
		if (node->info == old) {
			node->info = route;
			SET_FLAG(route->flag, OSPF6_ROUTE_BEST);
		}

		if (old->prev)
			old->prev->next = route;
		route->prev = old->prev;
		if (old->next)
			old->next->prev = route;
		route->next = old->next;

		route->installed = old->installed;
		route->changed = now;
		assert(route->table == NULL);
		route->table = table;

		ospf6_route_unlock(old); /* will be deleted later */
		ospf6_route_lock(route);

		SET_FLAG(route->flag, OSPF6_ROUTE_CHANGE);
		ospf6_route_table_assert(table);

		if (table->hook_add)
			(*table->hook_add)(route);

		return route;
	}

	/* insert if previous or next node found */
	if (prev || next) {
		if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
			zlog_debug(
				"%s %p: route add %p cost %u: another path: prev %p, next %p node ref %u",
				ospf6_route_table_name(table), (void *)table,
				(void *)route, route->path.cost, (void *)prev,
				(void *)next, node->lock);
		else if (IS_OSPF6_DEBUG_ROUTE(TABLE))
			zlog_debug("%s: route add cost %u: another path found",
				   ospf6_route_table_name(table),
				   route->path.cost);

		if (prev == NULL)
			prev = next->prev;
		if (next == NULL)
			next = prev->next;

		if (prev)
			prev->next = route;
		route->prev = prev;
		if (next)
			next->prev = route;
		route->next = next;

		if (node->info == next) {
			assert(next->rnode == node);
			node->info = route;
			UNSET_FLAG(next->flag, OSPF6_ROUTE_BEST);
			SET_FLAG(route->flag, OSPF6_ROUTE_BEST);
			if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
				zlog_info(
					"%s %p: route add %p cost %u: replacing previous best: %p cost %u",
					ospf6_route_table_name(table),
					(void *)table, (void *)route,
					route->path.cost,
					(void *)next, next->path.cost);
		}

		route->installed = now;
		route->changed = now;
		assert(route->table == NULL);
		route->table = table;

		ospf6_route_lock(route);
		table->count++;
		ospf6_route_table_assert(table);

		SET_FLAG(route->flag, OSPF6_ROUTE_ADD);
		if (table->hook_add)
			(*table->hook_add)(route);

		return route;
	}

	/* Else, this is the brand new route regarding to the prefix */
	if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_debug("%s %p: route add %p %s cost %u: brand new route",
			   ospf6_route_table_name(table), (void *)table,
			   (void *)route, buf, route->path.cost);
	else if (IS_OSPF6_DEBUG_ROUTE(TABLE))
		zlog_debug("%s: route add: brand new route",
			   ospf6_route_table_name(table));

	assert(node->info == NULL);
	node->info = route;
	SET_FLAG(route->flag, OSPF6_ROUTE_BEST);
	ospf6_route_lock(route);
	route->installed = now;
	route->changed = now;
	assert(route->table == NULL);
	route->table = table;

	/* lookup real existing next route */
	nextnode = node;
	route_lock_node(nextnode);
	do {
		nextnode = route_next(nextnode);
	} while (nextnode && nextnode->info == NULL);

	/* set next link */
	if (nextnode == NULL)
		route->next = NULL;
	else {
		route_unlock_node(nextnode);

		next = nextnode->info;
		route->next = next;
		next->prev = route;
	}

	/* lookup real existing prev route */
	prevnode = node;
	route_lock_node(prevnode);
	do {
		prevnode = route_prev(prevnode);
	} while (prevnode && prevnode->info == NULL);

	/* set prev link */
	if (prevnode == NULL)
		route->prev = NULL;
	else {
		route_unlock_node(prevnode);

		prev = prevnode->info;
		while (prev->next && ospf6_route_is_same(prev, prev->next))
			prev = prev->next;
		route->prev = prev;
		prev->next = route;
	}

	table->count++;
	ospf6_route_table_assert(table);

	SET_FLAG(route->flag, OSPF6_ROUTE_ADD);
	if (table->hook_add)
		(*table->hook_add)(route);

	return route;
}

void ospf6_route_remove(struct ospf6_route *route,
			struct ospf6_route_table *table)
{
	struct route_node *node;
	struct ospf6_route *current;
	char buf[PREFIX2STR_BUFFER];

	if (route->type == OSPF6_DEST_TYPE_LINKSTATE)
		ospf6_linkstate_prefix2str(&route->prefix, buf, sizeof(buf));
	else
		prefix2str(&route->prefix, buf, sizeof(buf));

	if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_debug("%s %p: route remove %p: %s cost %u refcount %u",
			   ospf6_route_table_name(table), (void *)table,
			   (void *)route, buf, route->path.cost, route->lock);
	else if (IS_OSPF6_DEBUG_ROUTE(TABLE))
		zlog_debug("%s: route remove: %s",
			   ospf6_route_table_name(table), buf);

	node = route_node_lookup(table->table, &route->prefix);
	assert(node);

	/* find the route to remove, making sure that the route pointer
	   is from the route table. */
	current = node->info;
	while (current && current != route)
		current = current->next;

	assert(current == route);

	/* adjust doubly linked list */
	if (route->prev)
		route->prev->next = route->next;
	if (route->next)
		route->next->prev = route->prev;

	if (node->info == route) {
		if (route->next && route->next->rnode == node) {
			node->info = route->next;
			SET_FLAG(route->next->flag, OSPF6_ROUTE_BEST);
		} else {
			node->info = NULL;
			route->rnode = NULL;
			route_unlock_node(node); /* to free the original lock */
		}
	}

	route_unlock_node(node); /* to free the lookup lock */
	table->count--;
	ospf6_route_table_assert(table);

	SET_FLAG(route->flag, OSPF6_ROUTE_WAS_REMOVED);

	/* Note hook_remove may call ospf6_route_remove */
	if (table->hook_remove)
		(*table->hook_remove)(route);

	ospf6_route_unlock(route);
}

struct ospf6_route *ospf6_route_head(struct ospf6_route_table *table)
{
	struct route_node *node;
	struct ospf6_route *route;

	node = route_top(table->table);
	if (node == NULL)
		return NULL;

	/* skip to the real existing entry */
	while (node && node->info == NULL)
		node = route_next(node);
	if (node == NULL)
		return NULL;

	route_unlock_node(node);
	assert(node->info);

	route = (struct ospf6_route *)node->info;
	assert(route->prev == NULL);
	assert(route->table == table);
	ospf6_route_lock(route);

	if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_info("%s %p: route head: %p<-[%p]->%p",
			  ospf6_route_table_name(table), (void *)table,
			  (void *)route->prev, (void *)route,
			  (void *)route->next);

	return route;
}

struct ospf6_route *ospf6_route_next(struct ospf6_route *route)
{
	struct ospf6_route *next = route->next;

	if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
		zlog_info("%s %p: route next: %p<-[%p]->%p , route ref count %u",
			  ospf6_route_table_name(route->table),
			  (void *)route->table, (void *)route->prev,
			  (void *)route, (void *)route->next,
			  route->lock);

	ospf6_route_unlock(route);
	if (next)
		ospf6_route_lock(next);

	return next;
}

struct ospf6_route *ospf6_route_best_next(struct ospf6_route *route)
{
	struct route_node *rnode;
	struct ospf6_route *next;

	ospf6_route_unlock(route);

	rnode = route->rnode;
	route_lock_node(rnode);
	rnode = route_next(rnode);
	while (rnode && rnode->info == NULL)
		rnode = route_next(rnode);
	if (rnode == NULL)
		return NULL;
	route_unlock_node(rnode);

	assert(rnode->info);
	next = (struct ospf6_route *)rnode->info;
	ospf6_route_lock(next);
	return next;
}

struct ospf6_route *ospf6_route_match_head(struct prefix *prefix,
					   struct ospf6_route_table *table)
{
	struct route_node *node;
	struct ospf6_route *route;

	/* Walk down tree. */
	node = table->table->top;
	while (node && node->p.prefixlen < prefix->prefixlen
	       && prefix_match(&node->p, prefix))
		node = node->link[prefix_bit(&prefix->u.prefix,
					     node->p.prefixlen)];

	if (node)
		route_lock_node(node);
	while (node && node->info == NULL)
		node = route_next(node);
	if (node == NULL)
		return NULL;
	route_unlock_node(node);

	if (!prefix_match(prefix, &node->p))
		return NULL;

	route = node->info;
	ospf6_route_lock(route);
	return route;
}

struct ospf6_route *ospf6_route_match_next(struct prefix *prefix,
					   struct ospf6_route *route)
{
	struct ospf6_route *next;

	next = ospf6_route_next(route);
	if (next && !prefix_match(prefix, &next->prefix)) {
		ospf6_route_unlock(next);
		next = NULL;
	}

	return next;
}

void ospf6_route_remove_all(struct ospf6_route_table *table)
{
	struct ospf6_route *route;
	for (route = ospf6_route_head(table); route;
	     route = ospf6_route_next(route))
		ospf6_route_remove(route, table);
}

struct ospf6_route_table *ospf6_route_table_create(int s, int t)
{
	struct ospf6_route_table *new;
	new = XCALLOC(MTYPE_OSPF6_ROUTE, sizeof(struct ospf6_route_table));
	new->table = route_table_init();
	new->scope_type = s;
	new->table_type = t;
	return new;
}

void ospf6_route_table_delete(struct ospf6_route_table *table)
{
	ospf6_route_remove_all(table);
	bf_free(table->idspace);
	route_table_finish(table->table);
	XFREE(MTYPE_OSPF6_ROUTE, table);
}


/* VTY commands */
void ospf6_route_show(struct vty *vty, struct ospf6_route *route)
{
	int i;
	char destination[PREFIX2STR_BUFFER], nexthop[64];
	char duration[64];
	const char *ifname;
	struct timeval now, res;
	struct listnode *node;
	struct ospf6_nexthop *nh;

	monotime(&now);
	timersub(&now, &route->changed, &res);
	timerstring(&res, duration, sizeof(duration));

	/* destination */
	if (route->type == OSPF6_DEST_TYPE_LINKSTATE)
		ospf6_linkstate_prefix2str(&route->prefix, destination,
					   sizeof(destination));
	else if (route->type == OSPF6_DEST_TYPE_ROUTER)
		inet_ntop(route->prefix.family, &route->prefix.u.prefix,
			  destination, sizeof(destination));
	else
		prefix2str(&route->prefix, destination, sizeof(destination));

	i = 0;
	for (ALL_LIST_ELEMENTS_RO(route->nh_list, node, nh)) {
		/* nexthop */
		inet_ntop(AF_INET6, &nh->address, nexthop, sizeof(nexthop));
		ifname = ifindex2ifname(nh->ifindex, VRF_DEFAULT);

		if (!i) {
			vty_out(vty, "%c%1s %2s %-30s %-25s %6.*s %s\n",
				(ospf6_route_is_best(route) ? '*' : ' '),
				OSPF6_DEST_TYPE_SUBSTR(route->type),
				OSPF6_PATH_TYPE_SUBSTR(route->path.type),
				destination, nexthop, IFNAMSIZ, ifname,
				duration);
			i++;
		} else
			vty_out(vty, "%c%1s %2s %-30s %-25s %6.*s %s\n", ' ',
				"", "", "", nexthop, IFNAMSIZ, ifname, "");
	}
}

void ospf6_route_show_detail(struct vty *vty, struct ospf6_route *route)
{
	const char *ifname;
	char destination[PREFIX2STR_BUFFER], nexthop[64];
	char area_id[16], id[16], adv_router[16], capa[16], options[16];
	struct timeval now, res;
	char duration[64];
	struct listnode *node;
	struct ospf6_nexthop *nh;

	monotime(&now);

	/* destination */
	if (route->type == OSPF6_DEST_TYPE_LINKSTATE)
		ospf6_linkstate_prefix2str(&route->prefix, destination,
					   sizeof(destination));
	else if (route->type == OSPF6_DEST_TYPE_ROUTER)
		inet_ntop(route->prefix.family, &route->prefix.u.prefix,
			  destination, sizeof(destination));
	else
		prefix2str(&route->prefix, destination, sizeof(destination));
	vty_out(vty, "Destination: %s\n", destination);

	/* destination type */
	vty_out(vty, "Destination type: %s\n",
		OSPF6_DEST_TYPE_NAME(route->type));

	/* Time */
	timersub(&now, &route->installed, &res);
	timerstring(&res, duration, sizeof(duration));
	vty_out(vty, "Installed Time: %s ago\n", duration);

	timersub(&now, &route->changed, &res);
	timerstring(&res, duration, sizeof(duration));
	vty_out(vty, "  Changed Time: %s ago\n", duration);

	/* Debugging info */
	vty_out(vty, "Lock: %d Flags: %s%s%s%s\n", route->lock,
		(CHECK_FLAG(route->flag, OSPF6_ROUTE_BEST) ? "B" : "-"),
		(CHECK_FLAG(route->flag, OSPF6_ROUTE_ADD) ? "A" : "-"),
		(CHECK_FLAG(route->flag, OSPF6_ROUTE_REMOVE) ? "R" : "-"),
		(CHECK_FLAG(route->flag, OSPF6_ROUTE_CHANGE) ? "C" : "-"));
	vty_out(vty, "Memory: prev: %p this: %p next: %p\n",
		(void *)route->prev, (void *)route, (void *)route->next);

	/* Path section */

	/* Area-ID */
	inet_ntop(AF_INET, &route->path.area_id, area_id, sizeof(area_id));
	vty_out(vty, "Associated Area: %s\n", area_id);

	/* Path type */
	vty_out(vty, "Path Type: %s\n", OSPF6_PATH_TYPE_NAME(route->path.type));

	/* LS Origin */
	inet_ntop(AF_INET, &route->path.origin.id, id, sizeof(id));
	inet_ntop(AF_INET, &route->path.origin.adv_router, adv_router,
		  sizeof(adv_router));
	vty_out(vty, "LS Origin: %s Id: %s Adv: %s\n",
		ospf6_lstype_name(route->path.origin.type), id, adv_router);

	/* Options */
	ospf6_options_printbuf(route->path.options, options, sizeof(options));
	vty_out(vty, "Options: %s\n", options);

	/* Router Bits */
	ospf6_capability_printbuf(route->path.router_bits, capa, sizeof(capa));
	vty_out(vty, "Router Bits: %s\n", capa);

	/* Prefix Options */
	vty_out(vty, "Prefix Options: xxx\n");

	/* Metrics */
	vty_out(vty, "Metric Type: %d\n", route->path.metric_type);
	vty_out(vty, "Metric: %d (%d)\n", route->path.cost,
		route->path.u.cost_e2);

	vty_out(vty, "Paths count: %u\n", route->paths->count);
	vty_out(vty, "Nexthop count: %u\n", route->nh_list->count);
	/* Nexthops */
	vty_out(vty, "Nexthop:\n");
	for (ALL_LIST_ELEMENTS_RO(route->nh_list, node, nh)) {
		/* nexthop */
		inet_ntop(AF_INET6, &nh->address, nexthop, sizeof(nexthop));
		ifname = ifindex2ifname(nh->ifindex, VRF_DEFAULT);
		vty_out(vty, "  %s %.*s\n", nexthop, IFNAMSIZ, ifname);
	}
	vty_out(vty, "\n");
}

static void ospf6_route_show_table_summary(struct vty *vty,
					   struct ospf6_route_table *table)
{
	struct ospf6_route *route, *prev = NULL;
	int i, pathtype[OSPF6_PATH_TYPE_MAX];
	unsigned int number = 0;
	int nh_count = 0, nhinval = 0, ecmp = 0;
	int alternative = 0, destination = 0;

	for (i = 0; i < OSPF6_PATH_TYPE_MAX; i++)
		pathtype[i] = 0;

	for (route = ospf6_route_head(table); route;
	     route = ospf6_route_next(route)) {
		if (prev == NULL || !ospf6_route_is_same(prev, route))
			destination++;
		else
			alternative++;
		nh_count = ospf6_num_nexthops(route->nh_list);
		if (!nh_count)
			nhinval++;
		else if (nh_count > 1)
			ecmp++;
		pathtype[route->path.type]++;
		number++;

		prev = route;
	}

	assert(number == table->count);

	vty_out(vty, "Number of OSPFv3 routes: %d\n", number);
	vty_out(vty, "Number of Destination: %d\n", destination);
	vty_out(vty, "Number of Alternative routes: %d\n", alternative);
	vty_out(vty, "Number of Equal Cost Multi Path: %d\n", ecmp);
	for (i = OSPF6_PATH_TYPE_INTRA; i <= OSPF6_PATH_TYPE_EXTERNAL2; i++) {
		vty_out(vty, "Number of %s routes: %d\n",
			OSPF6_PATH_TYPE_NAME(i), pathtype[i]);
	}
}

static void ospf6_route_show_table_prefix(struct vty *vty,
					  struct prefix *prefix,
					  struct ospf6_route_table *table)
{
	struct ospf6_route *route;

	route = ospf6_route_lookup(prefix, table);
	if (route == NULL)
		return;

	ospf6_route_lock(route);
	while (route && ospf6_route_is_prefix(prefix, route)) {
		/* Specifying a prefix will always display details */
		ospf6_route_show_detail(vty, route);
		route = ospf6_route_next(route);
	}
	if (route)
		ospf6_route_unlock(route);
}

static void ospf6_route_show_table_address(struct vty *vty,
					   struct prefix *prefix,
					   struct ospf6_route_table *table)
{
	struct ospf6_route *route;

	route = ospf6_route_lookup_bestmatch(prefix, table);
	if (route == NULL)
		return;

	prefix = &route->prefix;
	ospf6_route_lock(route);
	while (route && ospf6_route_is_prefix(prefix, route)) {
		/* Specifying a prefix will always display details */
		ospf6_route_show_detail(vty, route);
		route = ospf6_route_next(route);
	}
	if (route)
		ospf6_route_unlock(route);
}

static void ospf6_route_show_table_match(struct vty *vty, int detail,
					 struct prefix *prefix,
					 struct ospf6_route_table *table)
{
	struct ospf6_route *route;
	assert(prefix->family);

	route = ospf6_route_match_head(prefix, table);
	while (route) {
		if (detail)
			ospf6_route_show_detail(vty, route);
		else
			ospf6_route_show(vty, route);
		route = ospf6_route_match_next(prefix, route);
	}
}

static void ospf6_route_show_table_type(struct vty *vty, int detail,
					uint8_t type,
					struct ospf6_route_table *table)
{
	struct ospf6_route *route;

	route = ospf6_route_head(table);
	while (route) {
		if (route->path.type == type) {
			if (detail)
				ospf6_route_show_detail(vty, route);
			else
				ospf6_route_show(vty, route);
		}
		route = ospf6_route_next(route);
	}
}

static void ospf6_route_show_table(struct vty *vty, int detail,
				   struct ospf6_route_table *table)
{
	struct ospf6_route *route;

	route = ospf6_route_head(table);
	while (route) {
		if (detail)
			ospf6_route_show_detail(vty, route);
		else
			ospf6_route_show(vty, route);
		route = ospf6_route_next(route);
	}
}

int ospf6_route_table_show(struct vty *vty, int argc_start, int argc,
			   struct cmd_token **argv,
			   struct ospf6_route_table *table)
{
	int summary = 0;
	int match = 0;
	int detail = 0;
	int slash = 0;
	int isprefix = 0;
	int i, ret;
	struct prefix prefix;
	uint8_t type = 0;

	memset(&prefix, 0, sizeof(struct prefix));

	for (i = argc_start; i < argc; i++) {
		if (strmatch(argv[i]->text, "summary")) {
			summary++;
			continue;
		}

		if (strmatch(argv[i]->text, "intra-area")) {
			type = OSPF6_PATH_TYPE_INTRA;
			continue;
		}

		if (strmatch(argv[i]->text, "inter-area")) {
			type = OSPF6_PATH_TYPE_INTER;
			continue;
		}

		if (strmatch(argv[i]->text, "external-1")) {
			type = OSPF6_PATH_TYPE_EXTERNAL1;
			continue;
		}

		if (strmatch(argv[i]->text, "external-2")) {
			type = OSPF6_PATH_TYPE_EXTERNAL2;
			continue;
		}

		if (strmatch(argv[i]->text, "detail")) {
			detail++;
			continue;
		}

		if (strmatch(argv[i]->text, "match")) {
			match++;
			continue;
		}

		ret = str2prefix(argv[i]->arg, &prefix);
		if (ret == 1 && prefix.family == AF_INET6) {
			isprefix++;
			if (strchr(argv[i]->arg, '/'))
				slash++;
			continue;
		}

		vty_out(vty, "Malformed argument: %s\n", argv[i]->arg);
		return CMD_SUCCESS;
	}

	/* Give summary of this route table */
	if (summary) {
		ospf6_route_show_table_summary(vty, table);
		return CMD_SUCCESS;
	}

	/* Give exact prefix-match route */
	if (isprefix && !match) {
		/* If exact address, give best matching route */
		if (!slash)
			ospf6_route_show_table_address(vty, &prefix, table);
		else
			ospf6_route_show_table_prefix(vty, &prefix, table);

		return CMD_SUCCESS;
	}

	if (match)
		ospf6_route_show_table_match(vty, detail, &prefix, table);
	else if (type)
		ospf6_route_show_table_type(vty, detail, type, table);
	else
		ospf6_route_show_table(vty, detail, table);

	return CMD_SUCCESS;
}

static void ospf6_linkstate_show_header(struct vty *vty)
{
	vty_out(vty, "%-7s %-15s %-15s %-8s %-14s %s\n", "Type", "Router-ID",
		"Net-ID", "Rtr-Bits", "Options", "Cost");
}

static void ospf6_linkstate_show(struct vty *vty, struct ospf6_route *route)
{
	uint32_t router, id;
	char routername[16], idname[16], rbits[16], options[16];

	router = ospf6_linkstate_prefix_adv_router(&route->prefix);
	inet_ntop(AF_INET, &router, routername, sizeof(routername));
	id = ospf6_linkstate_prefix_id(&route->prefix);
	inet_ntop(AF_INET, &id, idname, sizeof(idname));

	ospf6_capability_printbuf(route->path.router_bits, rbits,
				  sizeof(rbits));
	ospf6_options_printbuf(route->path.options, options, sizeof(options));

	if (ntohl(id))
		vty_out(vty, "%-7s %-15s %-15s %-8s %-14s %lu\n", "Network",
			routername, idname, rbits, options,
			(unsigned long)route->path.cost);
	else
		vty_out(vty, "%-7s %-15s %-15s %-8s %-14s %lu\n", "Router",
			routername, idname, rbits, options,
			(unsigned long)route->path.cost);
}


static void ospf6_linkstate_show_table_exact(struct vty *vty,
					     struct prefix *prefix,
					     struct ospf6_route_table *table)
{
	struct ospf6_route *route;

	route = ospf6_route_lookup(prefix, table);
	if (route == NULL)
		return;

	ospf6_route_lock(route);
	while (route && ospf6_route_is_prefix(prefix, route)) {
		/* Specifying a prefix will always display details */
		ospf6_route_show_detail(vty, route);
		route = ospf6_route_next(route);
	}
	if (route)
		ospf6_route_unlock(route);
}

static void ospf6_linkstate_show_table(struct vty *vty, int detail,
				       struct ospf6_route_table *table)
{
	struct ospf6_route *route;

	if (!detail)
		ospf6_linkstate_show_header(vty);

	route = ospf6_route_head(table);
	while (route) {
		if (detail)
			ospf6_route_show_detail(vty, route);
		else
			ospf6_linkstate_show(vty, route);
		route = ospf6_route_next(route);
	}
}

int ospf6_linkstate_table_show(struct vty *vty, int idx_ipv4, int argc,
			       struct cmd_token **argv,
			       struct ospf6_route_table *table)
{
	int detail = 0;
	int is_id = 0;
	int is_router = 0;
	int i, ret;
	struct prefix router, id, prefix;

	memset(&router, 0, sizeof(struct prefix));
	memset(&id, 0, sizeof(struct prefix));
	memset(&prefix, 0, sizeof(struct prefix));

	for (i = idx_ipv4; i < argc; i++) {
		if (strmatch(argv[i]->text, "detail")) {
			detail++;
			continue;
		}

		if (!is_router) {
			ret = str2prefix(argv[i]->arg, &router);
			if (ret == 1 && router.family == AF_INET) {
				is_router++;
				continue;
			}
			vty_out(vty, "Malformed argument: %s\n", argv[i]->arg);
			return CMD_SUCCESS;
		}

		if (!is_id) {
			ret = str2prefix(argv[i]->arg, &id);
			if (ret == 1 && id.family == AF_INET) {
				is_id++;
				continue;
			}
			vty_out(vty, "Malformed argument: %s\n", argv[i]->arg);
			return CMD_SUCCESS;
		}

		vty_out(vty, "Malformed argument: %s\n", argv[i]->arg);
		return CMD_SUCCESS;
	}

	if (is_router)
		ospf6_linkstate_prefix(router.u.prefix4.s_addr,
				       id.u.prefix4.s_addr, &prefix);

	if (prefix.family)
		ospf6_linkstate_show_table_exact(vty, &prefix, table);
	else
		ospf6_linkstate_show_table(vty, detail, table);

	return CMD_SUCCESS;
}


void ospf6_brouter_show_header(struct vty *vty)
{
	vty_out(vty, "%-15s %-8s %-14s %-10s %-15s\n", "Router-ID", "Rtr-Bits",
		"Options", "Path-Type", "Area");
}

void ospf6_brouter_show(struct vty *vty, struct ospf6_route *route)
{
	uint32_t adv_router;
	char adv[16], rbits[16], options[16], area[16];

	adv_router = ospf6_linkstate_prefix_adv_router(&route->prefix);
	inet_ntop(AF_INET, &adv_router, adv, sizeof(adv));
	ospf6_capability_printbuf(route->path.router_bits, rbits,
				  sizeof(rbits));
	ospf6_options_printbuf(route->path.options, options, sizeof(options));
	inet_ntop(AF_INET, &route->path.area_id, area, sizeof(area));

	/* vty_out (vty, "%-15s %-8s %-14s %-10s %-15s\n",
		 "Router-ID", "Rtr-Bits", "Options", "Path-Type", "Area"); */
	vty_out(vty, "%-15s %-8s %-14s %-10s %-15s\n", adv, rbits, options,
		OSPF6_PATH_TYPE_NAME(route->path.type), area);
}

DEFUN (debug_ospf6_route,
       debug_ospf6_route_cmd,
       "debug ospf6 route <table|intra-area|inter-area|memory>",
       DEBUG_STR
       OSPF6_STR
       "Debug routes\n"
       "Debug route table calculation\n"
       "Debug intra-area route calculation\n"
       "Debug inter-area route calculation\n"
       "Debug route memory use\n"
       )
{
	int idx_type = 3;
	unsigned char level = 0;

	if (!strcmp(argv[idx_type]->text, "table"))
		level = OSPF6_DEBUG_ROUTE_TABLE;
	else if (!strcmp(argv[idx_type]->text, "intra-area"))
		level = OSPF6_DEBUG_ROUTE_INTRA;
	else if (!strcmp(argv[idx_type]->text, "inter-area"))
		level = OSPF6_DEBUG_ROUTE_INTER;
	else if (!strcmp(argv[idx_type]->text, "memory"))
		level = OSPF6_DEBUG_ROUTE_MEMORY;
	OSPF6_DEBUG_ROUTE_ON(level);
	return CMD_SUCCESS;
}

DEFUN (no_debug_ospf6_route,
       no_debug_ospf6_route_cmd,
       "no debug ospf6 route <table|intra-area|inter-area|memory>",
       NO_STR
       DEBUG_STR
       OSPF6_STR
       "Debug routes\n"
       "Debug route table calculation\n"
       "Debug intra-area route calculation\n"
       "Debug inter-area route calculation\n"
       "Debug route memory use\n")
{
	int idx_type = 4;
	unsigned char level = 0;

	if (!strcmp(argv[idx_type]->text, "table"))
		level = OSPF6_DEBUG_ROUTE_TABLE;
	else if (!strcmp(argv[idx_type]->text, "intra-area"))
		level = OSPF6_DEBUG_ROUTE_INTRA;
	else if (!strcmp(argv[idx_type]->text, "inter-area"))
		level = OSPF6_DEBUG_ROUTE_INTER;
	else if (!strcmp(argv[idx_type]->text, "memory"))
		level = OSPF6_DEBUG_ROUTE_MEMORY;
	OSPF6_DEBUG_ROUTE_OFF(level);
	return CMD_SUCCESS;
}

int config_write_ospf6_debug_route(struct vty *vty)
{
	if (IS_OSPF6_DEBUG_ROUTE(TABLE))
		vty_out(vty, "debug ospf6 route table\n");
	if (IS_OSPF6_DEBUG_ROUTE(INTRA))
		vty_out(vty, "debug ospf6 route intra-area\n");
	if (IS_OSPF6_DEBUG_ROUTE(INTER))
		vty_out(vty, "debug ospf6 route inter-area\n");
	if (IS_OSPF6_DEBUG_ROUTE(MEMORY))
		vty_out(vty, "debug ospf6 route memory\n");

	return 0;
}

void install_element_ospf6_debug_route(void)
{
	install_element(ENABLE_NODE, &debug_ospf6_route_cmd);
	install_element(ENABLE_NODE, &no_debug_ospf6_route_cmd);
	install_element(CONFIG_NODE, &debug_ospf6_route_cmd);
	install_element(CONFIG_NODE, &no_debug_ospf6_route_cmd);
}
