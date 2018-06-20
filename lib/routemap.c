/* Route map function.
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

#include "linklist.h"
#include "memory.h"
#include "vector.h"
#include "prefix.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "log.h"
#include "hash.h"
#include "libfrr.h"

DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP, "Route map")
DEFINE_MTYPE(LIB, ROUTE_MAP_NAME, "Route map name")
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_INDEX, "Route map index")
DEFINE_MTYPE(LIB, ROUTE_MAP_RULE, "Route map rule")
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_RULE_STR, "Route map rule str")
DEFINE_MTYPE(LIB, ROUTE_MAP_COMPILED, "Route map compiled")
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_DEP, "Route map dependency")

DEFINE_QOBJ_TYPE(route_map_index)
DEFINE_QOBJ_TYPE(route_map)

/* Vector for route match rules. */
static vector route_match_vec;

/* Vector for route set rules. */
static vector route_set_vec;

struct route_map_match_set_hooks {
	/* match interface */
	int (*match_interface)(struct vty *vty, struct route_map_index *index,
			       const char *command, const char *arg,
			       route_map_event_t type);

	/* no match interface */
	int (*no_match_interface)(struct vty *vty,
				  struct route_map_index *index,
				  const char *command, const char *arg,
				  route_map_event_t type);

	/* match ip address */
	int (*match_ip_address)(struct vty *vty, struct route_map_index *index,
				const char *command, const char *arg,
				route_map_event_t type);

	/* no match ip address */
	int (*no_match_ip_address)(struct vty *vty,
				   struct route_map_index *index,
				   const char *command, const char *arg,
				   route_map_event_t type);

	/* match ip address prefix list */
	int (*match_ip_address_prefix_list)(struct vty *vty,
					    struct route_map_index *index,
					    const char *command,
					    const char *arg,
					    route_map_event_t type);

	/* no match ip address prefix list */
	int (*no_match_ip_address_prefix_list)(struct vty *vty,
					       struct route_map_index *index,
					       const char *command,
					       const char *arg,
					       route_map_event_t type);

	/* match ip next hop */
	int (*match_ip_next_hop)(struct vty *vty, struct route_map_index *index,
				 const char *command, const char *arg,
				 route_map_event_t type);

	/* no match ip next hop */
	int (*no_match_ip_next_hop)(struct vty *vty,
				    struct route_map_index *index,
				    const char *command, const char *arg,
				    route_map_event_t type);

	/* match ip next hop prefix list */
	int (*match_ip_next_hop_prefix_list)(struct vty *vty,
					     struct route_map_index *index,
					     const char *command,
					     const char *arg,
					     route_map_event_t type);

	/* no match ip next hop prefix list */
	int (*no_match_ip_next_hop_prefix_list)(struct vty *vty,
						struct route_map_index *index,
						const char *command,
						const char *arg,
						route_map_event_t type);

	/* match ipv6 address */
	int (*match_ipv6_address)(struct vty *vty,
				  struct route_map_index *index,
				  const char *command, const char *arg,
				  route_map_event_t type);

	/* no match ipv6 address */
	int (*no_match_ipv6_address)(struct vty *vty,
				     struct route_map_index *index,
				     const char *command, const char *arg,
				     route_map_event_t type);


	/* match ipv6 address prefix list */
	int (*match_ipv6_address_prefix_list)(struct vty *vty,
					      struct route_map_index *index,
					      const char *command,
					      const char *arg,
					      route_map_event_t type);

	/* no match ipv6 address prefix list */
	int (*no_match_ipv6_address_prefix_list)(struct vty *vty,
						 struct route_map_index *index,
						 const char *command,
						 const char *arg,
						 route_map_event_t type);

	/* match metric */
	int (*match_metric)(struct vty *vty, struct route_map_index *index,
			    const char *command, const char *arg,
			    route_map_event_t type);

	/* no match metric */
	int (*no_match_metric)(struct vty *vty, struct route_map_index *index,
			       const char *command, const char *arg,
			       route_map_event_t type);

	/* match tag */
	int (*match_tag)(struct vty *vty, struct route_map_index *index,
			 const char *command, const char *arg,
			 route_map_event_t type);

	/* no match tag */
	int (*no_match_tag)(struct vty *vty, struct route_map_index *index,
			    const char *command, const char *arg,
			    route_map_event_t type);

	/* set ip nexthop */
	int (*set_ip_nexthop)(struct vty *vty, struct route_map_index *index,
			      const char *command, const char *arg);

	/* no set ip nexthop */
	int (*no_set_ip_nexthop)(struct vty *vty, struct route_map_index *index,
				 const char *command, const char *arg);

	/* set ipv6 nexthop local */
	int (*set_ipv6_nexthop_local)(struct vty *vty,
				      struct route_map_index *index,
				      const char *command, const char *arg);

	/* no set ipv6 nexthop local */
	int (*no_set_ipv6_nexthop_local)(struct vty *vty,
					 struct route_map_index *index,
					 const char *command, const char *arg);

	/* set metric */
	int (*set_metric)(struct vty *vty, struct route_map_index *index,
			  const char *command, const char *arg);

	/* no set metric */
	int (*no_set_metric)(struct vty *vty, struct route_map_index *index,
			     const char *command, const char *arg);

	/* set tag */
	int (*set_tag)(struct vty *vty, struct route_map_index *index,
		       const char *command, const char *arg);

	/* no set tag */
	int (*no_set_tag)(struct vty *vty, struct route_map_index *index,
			  const char *command, const char *arg);
};

struct route_map_match_set_hooks rmap_match_set_hook;

/* match interface */
void route_map_match_interface_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_interface = func;
}

/* no match interface */
void route_map_no_match_interface_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_interface = func;
}

/* match ip address */
void route_map_match_ip_address_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_ip_address = func;
}

/* no match ip address */
void route_map_no_match_ip_address_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_ip_address = func;
}

/* match ip address prefix list */
void route_map_match_ip_address_prefix_list_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_ip_address_prefix_list = func;
}

/* no match ip address prefix list */
void route_map_no_match_ip_address_prefix_list_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_ip_address_prefix_list = func;
}

/* match ip next hop */
void route_map_match_ip_next_hop_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_ip_next_hop = func;
}

/* no match ip next hop */
void route_map_no_match_ip_next_hop_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_ip_next_hop = func;
}

/* match ip next hop prefix list */
void route_map_match_ip_next_hop_prefix_list_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_ip_next_hop_prefix_list = func;
}

/* no match ip next hop prefix list */
void route_map_no_match_ip_next_hop_prefix_list_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_ip_next_hop_prefix_list = func;
}

/* match ipv6 address */
void route_map_match_ipv6_address_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_ipv6_address = func;
}

/* no match ipv6 address */
void route_map_no_match_ipv6_address_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_ipv6_address = func;
}


/* match ipv6 address prefix list */
void route_map_match_ipv6_address_prefix_list_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_ipv6_address_prefix_list = func;
}

/* no match ipv6 address prefix list */
void route_map_no_match_ipv6_address_prefix_list_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_ipv6_address_prefix_list = func;
}

/* match metric */
void route_map_match_metric_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.match_metric = func;
}

/* no match metric */
void route_map_no_match_metric_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_metric = func;
}

/* match tag */
void route_map_match_tag_hook(int (*func)(struct vty *vty,
					  struct route_map_index *index,
					  const char *command, const char *arg,
					  route_map_event_t type))
{
	rmap_match_set_hook.match_tag = func;
}

/* no match tag */
void route_map_no_match_tag_hook(int (*func)(
	struct vty *vty, struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type))
{
	rmap_match_set_hook.no_match_tag = func;
}

/* set ip nexthop */
void route_map_set_ip_nexthop_hook(int (*func)(struct vty *vty,
					       struct route_map_index *index,
					       const char *command,
					       const char *arg))
{
	rmap_match_set_hook.set_ip_nexthop = func;
}

/* no set ip nexthop */
void route_map_no_set_ip_nexthop_hook(int (*func)(struct vty *vty,
						  struct route_map_index *index,
						  const char *command,
						  const char *arg))
{
	rmap_match_set_hook.no_set_ip_nexthop = func;
}

/* set ipv6 nexthop local */
void route_map_set_ipv6_nexthop_local_hook(
	int (*func)(struct vty *vty, struct route_map_index *index,
		    const char *command, const char *arg))
{
	rmap_match_set_hook.set_ipv6_nexthop_local = func;
}

/* no set ipv6 nexthop local */
void route_map_no_set_ipv6_nexthop_local_hook(
	int (*func)(struct vty *vty, struct route_map_index *index,
		    const char *command, const char *arg))
{
	rmap_match_set_hook.no_set_ipv6_nexthop_local = func;
}

/* set metric */
void route_map_set_metric_hook(int (*func)(struct vty *vty,
					   struct route_map_index *index,
					   const char *command,
					   const char *arg))
{
	rmap_match_set_hook.set_metric = func;
}

/* no set metric */
void route_map_no_set_metric_hook(int (*func)(struct vty *vty,
					      struct route_map_index *index,
					      const char *command,
					      const char *arg))
{
	rmap_match_set_hook.no_set_metric = func;
}

/* set tag */
void route_map_set_tag_hook(int (*func)(struct vty *vty,
					struct route_map_index *index,
					const char *command, const char *arg))
{
	rmap_match_set_hook.set_tag = func;
}

/* no set tag */
void route_map_no_set_tag_hook(int (*func)(struct vty *vty,
					   struct route_map_index *index,
					   const char *command,
					   const char *arg))
{
	rmap_match_set_hook.no_set_tag = func;
}

int generic_match_add(struct vty *vty, struct route_map_index *index,
		      const char *command, const char *arg,
		      route_map_event_t type)
{
	int ret;

	ret = route_map_add_match(index, command, arg);
	switch (ret) {
	case RMAP_COMPILE_SUCCESS:
		if (type != RMAP_EVENT_MATCH_ADDED) {
			route_map_upd8_dependency(type, arg, index->map->name);
		}
		break;
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% [%s] Can't find rule.\n", frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty,
			"%% [%s] Argument form is unsupported or malformed.\n",
			frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	}

	return CMD_SUCCESS;
}

int generic_match_delete(struct vty *vty, struct route_map_index *index,
			 const char *command, const char *arg,
			 route_map_event_t type)
{
	int ret;
	int retval = CMD_SUCCESS;
	char *dep_name = NULL;
	const char *tmpstr;
	char *rmap_name = NULL;

	if (type != RMAP_EVENT_MATCH_DELETED) {
		/* ignore the mundane, the types without any dependency */
		if (arg == NULL) {
			if ((tmpstr = route_map_get_match_arg(index, command))
			    != NULL)
				dep_name =
					XSTRDUP(MTYPE_ROUTE_MAP_RULE, tmpstr);
		} else {
			dep_name = XSTRDUP(MTYPE_ROUTE_MAP_RULE, arg);
		}
		rmap_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, index->map->name);
	}

	ret = route_map_delete_match(index, command, dep_name);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% [%s] Can't find rule.\n", frr_protonameinst);
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty,
			"%% [%s] Argument form is unsupported or malformed.\n",
			frr_protonameinst);
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		if (type != RMAP_EVENT_MATCH_DELETED && dep_name)
			route_map_upd8_dependency(type, dep_name, rmap_name);
		break;
	}

	if (dep_name)
		XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
	if (rmap_name)
		XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

	return retval;
}

int generic_set_add(struct vty *vty, struct route_map_index *index,
		    const char *command, const char *arg)
{
	int ret;

	ret = route_map_add_set(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% [%s] Can't find rule.\n", frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty,
			"%% [%s] Argument form is unsupported or malformed.\n",
			frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		break;
	}

	return CMD_SUCCESS;
}

int generic_set_delete(struct vty *vty, struct route_map_index *index,
		       const char *command, const char *arg)
{
	int ret;

	ret = route_map_delete_set(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
		vty_out(vty, "%% [%s] Can't find rule.\n", frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		vty_out(vty,
			"%% [%s] Argument form is unsupported or malformed.\n",
			frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		break;
	}

	return CMD_SUCCESS;
}


/* Route map rule. This rule has both `match' rule and `set' rule. */
struct route_map_rule {
	/* Rule type. */
	struct route_map_rule_cmd *cmd;

	/* For pretty printing. */
	char *rule_str;

	/* Pre-compiled match rule. */
	void *value;

	/* Linked list. */
	struct route_map_rule *next;
	struct route_map_rule *prev;
};

/* Making route map list. */
struct route_map_list {
	struct route_map *head;
	struct route_map *tail;

	void (*add_hook)(const char *);
	void (*delete_hook)(const char *);
	void (*event_hook)(route_map_event_t, const char *);
};

/* Master list of route map. */
static struct route_map_list route_map_master = {NULL, NULL, NULL, NULL, NULL};
struct hash *route_map_master_hash = NULL;

static unsigned int route_map_hash_key_make(void *p)
{
	const struct route_map *map = p;
	return string_hash_make(map->name);
}

static int route_map_hash_cmp(const void *p1, const void *p2)
{
	const struct route_map *map1 = p1;
	const struct route_map *map2 = p2;

	if (map1->deleted == map2->deleted) {
		if (map1->name && map2->name) {
			if (!strcmp(map1->name, map2->name)) {
				return 1;
			}
		} else if (!map1->name && !map2->name) {
			return 1;
		}
	}

	return 0;
}

enum route_map_upd8_type {
	ROUTE_MAP_ADD = 1,
	ROUTE_MAP_DEL,
};

/* all possible route-map dependency types */
enum route_map_dep_type {
	ROUTE_MAP_DEP_RMAP = 1,
	ROUTE_MAP_DEP_CLIST,
	ROUTE_MAP_DEP_ECLIST,
	ROUTE_MAP_DEP_LCLIST,
	ROUTE_MAP_DEP_PLIST,
	ROUTE_MAP_DEP_ASPATH,
	ROUTE_MAP_DEP_FILTER,
	ROUTE_MAP_DEP_MAX,
};

struct route_map_dep {
	char *dep_name;
	struct hash *dep_rmap_hash;
	struct hash *this_hash; /* ptr to the hash structure this is part of */
};

/* Hashes maintaining dependency between various sublists used by route maps */
struct hash *route_map_dep_hash[ROUTE_MAP_DEP_MAX];

static unsigned int route_map_dep_hash_make_key(void *p);
static int route_map_dep_hash_cmp(const void *p1, const void *p2);
static void route_map_clear_all_references(char *rmap_name);
static void route_map_rule_delete(struct route_map_rule_list *,
				  struct route_map_rule *);
static int rmap_debug = 0;

static void route_map_index_delete(struct route_map_index *, int);

/* New route map allocation. Please note route map's name must be
   specified. */
static struct route_map *route_map_new(const char *name)
{
	struct route_map *new;

	new = XCALLOC(MTYPE_ROUTE_MAP, sizeof(struct route_map));
	new->name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
	QOBJ_REG(new, route_map);
	return new;
}

/* Add new name to route_map. */
static struct route_map *route_map_add(const char *name)
{
	struct route_map *map;
	struct route_map_list *list;

	map = route_map_new(name);
	list = &route_map_master;

	/* Add map to the hash */
	hash_get(route_map_master_hash, map, hash_alloc_intern);

	/* Add new entry to the head of the list to match how it is added in the
	 * hash table. This is to ensure that if the same route-map has been
	 * created more than once and then marked for deletion (which can happen
	 * if prior deletions haven't completed as BGP hasn't yet done the
	 * route-map processing), the order of the entities is the same in both
	 * the list and the hash table. Otherwise, since there is nothing to
	 * distinguish between the two entries, the wrong entry could get freed.
	 * TODO: This needs to be re-examined to handle it better - e.g., revive
	 * a deleted entry if the route-map is created again.
	 */
	map->prev = NULL;
	map->next = list->head;
	if (list->head)
		list->head->prev = map;
	list->head = map;
	if (!list->tail)
		list->tail = map;

	/* Execute hook. */
	if (route_map_master.add_hook) {
		(*route_map_master.add_hook)(name);
		route_map_notify_dependencies(name, RMAP_EVENT_CALL_ADDED);
	}
	return map;
}

/* this is supposed to be called post processing by
 * the delete hook function. Don't invoke delete_hook
 * again in this routine.
 */
static void route_map_free_map(struct route_map *map)
{
	struct route_map_list *list;
	struct route_map_index *index;

	if (map == NULL)
		return;

	while ((index = map->head) != NULL)
		route_map_index_delete(index, 0);

	list = &route_map_master;

	QOBJ_UNREG(map);

	if (map->next)
		map->next->prev = map->prev;
	else
		list->tail = map->prev;

	if (map->prev)
		map->prev->next = map->next;
	else
		list->head = map->next;

	hash_release(route_map_master_hash, map);
	XFREE(MTYPE_ROUTE_MAP_NAME, map->name);
	XFREE(MTYPE_ROUTE_MAP, map);
}

/* Route map delete from list. */
static void route_map_delete(struct route_map *map)
{
	struct route_map_index *index;
	char *name;

	while ((index = map->head) != NULL)
		route_map_index_delete(index, 0);

	name = map->name;
	map->head = NULL;

	/* Clear all dependencies */
	route_map_clear_all_references(name);
	map->deleted = true;
	/* Execute deletion hook. */
	if (route_map_master.delete_hook) {
		(*route_map_master.delete_hook)(name);
		route_map_notify_dependencies(name, RMAP_EVENT_CALL_DELETED);
	}

	if (!map->to_be_processed) {
		route_map_free_map(map);
	}
}

/* Lookup route map by route map name string. */
struct route_map *route_map_lookup_by_name(const char *name)
{
	struct route_map *map;
	struct route_map tmp_map;

	if (!name)
		return NULL;

	// map.deleted is 0 via memset
	memset(&tmp_map, 0, sizeof(struct route_map));
	tmp_map.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
	map = hash_lookup(route_map_master_hash, &tmp_map);
	XFREE(MTYPE_ROUTE_MAP_NAME, tmp_map.name);
	return map;
}

int route_map_mark_updated(const char *name)
{
	struct route_map *map;
	int ret = -1;
	struct route_map tmp_map;

	if (!name)
		return (ret);

	map = route_map_lookup_by_name(name);

	/* If we did not find the routemap with deleted=false try again
	 * with deleted=true
	 */
	if (!map) {
		memset(&tmp_map, 0, sizeof(struct route_map));
		tmp_map.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
		tmp_map.deleted = true;
		map = hash_lookup(route_map_master_hash, &tmp_map);
		XFREE(MTYPE_ROUTE_MAP_NAME, tmp_map.name);
	}

	if (map) {
		map->to_be_processed = true;
		ret = 0;
	}

	return (ret);
}

static int route_map_clear_updated(struct route_map *map)
{
	int ret = -1;

	if (map) {
		map->to_be_processed = false;
		if (map->deleted)
			route_map_free_map(map);
	}

	return (ret);
}

/* Lookup route map.  If there isn't route map create one and return
   it. */
static struct route_map *route_map_get(const char *name)
{
	struct route_map *map;

	map = route_map_lookup_by_name(name);
	if (map == NULL)
		map = route_map_add(name);

	return map;
}

void route_map_walk_update_list(void (*route_map_update_fn)(char *name))
{
	struct route_map *node;
	struct route_map *nnode = NULL;

	for (node = route_map_master.head; node; node = nnode) {
		if (node->to_be_processed) {
			/* DD: Should we add any thread yield code here */
			route_map_update_fn(node->name);
			nnode = node->next;
			route_map_clear_updated(node);
		} else
			nnode = node->next;
	}
}

/* Return route map's type string. */
static const char *route_map_type_str(enum route_map_type type)
{
	switch (type) {
	case RMAP_PERMIT:
		return "permit";
		break;
	case RMAP_DENY:
		return "deny";
		break;
	default:
		return "";
		break;
	}
}

static int route_map_empty(struct route_map *map)
{
	if (map->head == NULL && map->tail == NULL)
		return 1;
	else
		return 0;
}

/* show route-map */
static void vty_show_route_map_entry(struct vty *vty, struct route_map *map)
{
	struct route_map_index *index;
	struct route_map_rule *rule;

	vty_out(vty, "%s:\n", frr_protonameinst);

	for (index = map->head; index; index = index->next) {
		vty_out(vty, "route-map %s, %s, sequence %d\n", map->name,
			route_map_type_str(index->type), index->pref);

		/* Description */
		if (index->description)
			vty_out(vty, "  Description:\n    %s\n",
				index->description);

		/* Match clauses */
		vty_out(vty, "  Match clauses:\n");
		for (rule = index->match_list.head; rule; rule = rule->next)
			vty_out(vty, "    %s %s\n", rule->cmd->str,
				rule->rule_str);

		vty_out(vty, "  Set clauses:\n");
		for (rule = index->set_list.head; rule; rule = rule->next)
			vty_out(vty, "    %s %s\n", rule->cmd->str,
				rule->rule_str);

		/* Call clause */
		vty_out(vty, "  Call clause:\n");
		if (index->nextrm)
			vty_out(vty, "    Call %s\n", index->nextrm);

		/* Exit Policy */
		vty_out(vty, "  Action:\n");
		if (index->exitpolicy == RMAP_GOTO)
			vty_out(vty, "    Goto %d\n", index->nextpref);
		else if (index->exitpolicy == RMAP_NEXT)
			vty_out(vty, "    Continue to next entry\n");
		else if (index->exitpolicy == RMAP_EXIT)
			vty_out(vty, "    Exit routemap\n");
	}
}

static int vty_show_route_map(struct vty *vty, const char *name)
{
	struct route_map *map;

	if (name) {
		map = route_map_lookup_by_name(name);

		if (map) {
			vty_show_route_map_entry(vty, map);
			return CMD_SUCCESS;
		} else {
			vty_out(vty, "%s: 'route-map %s' not found\n",
				frr_protonameinst, name);
			return CMD_SUCCESS;
		}
	} else {
		for (map = route_map_master.head; map; map = map->next)
			if (!map->deleted)
				vty_show_route_map_entry(vty, map);
	}
	return CMD_SUCCESS;
}


/* New route map allocation. Please note route map's name must be
   specified. */
static struct route_map_index *route_map_index_new(void)
{
	struct route_map_index *new;

	new = XCALLOC(MTYPE_ROUTE_MAP_INDEX, sizeof(struct route_map_index));
	new->exitpolicy = RMAP_EXIT; /* Default to Cisco-style */
	QOBJ_REG(new, route_map_index);
	return new;
}

/* Free route map index. */
static void route_map_index_delete(struct route_map_index *index, int notify)
{
	struct route_map_rule *rule;

	QOBJ_UNREG(index);

	/* Free route match. */
	while ((rule = index->match_list.head) != NULL)
		route_map_rule_delete(&index->match_list, rule);

	/* Free route set. */
	while ((rule = index->set_list.head) != NULL)
		route_map_rule_delete(&index->set_list, rule);

	/* Remove index from route map list. */
	if (index->next)
		index->next->prev = index->prev;
	else
		index->map->tail = index->prev;

	if (index->prev)
		index->prev->next = index->next;
	else
		index->map->head = index->next;

	/* Free 'char *nextrm' if not NULL */
	if (index->nextrm)
		XFREE(MTYPE_ROUTE_MAP_NAME, index->nextrm);

	/* Execute event hook. */
	if (route_map_master.event_hook && notify) {
		(*route_map_master.event_hook)(RMAP_EVENT_INDEX_DELETED,
					       index->map->name);
		route_map_notify_dependencies(index->map->name,
					      RMAP_EVENT_CALL_ADDED);
	}
	XFREE(MTYPE_ROUTE_MAP_INDEX, index);
}

/* Lookup index from route map. */
static struct route_map_index *route_map_index_lookup(struct route_map *map,
						      enum route_map_type type,
						      int pref)
{
	struct route_map_index *index;

	for (index = map->head; index; index = index->next)
		if ((index->type == type || type == RMAP_ANY)
		    && index->pref == pref)
			return index;
	return NULL;
}

/* Add new index to route map. */
static struct route_map_index *
route_map_index_add(struct route_map *map, enum route_map_type type, int pref)
{
	struct route_map_index *index;
	struct route_map_index *point;

	/* Allocate new route map inex. */
	index = route_map_index_new();
	index->map = map;
	index->type = type;
	index->pref = pref;

	/* Compare preference. */
	for (point = map->head; point; point = point->next)
		if (point->pref >= pref)
			break;

	if (map->head == NULL) {
		map->head = map->tail = index;
	} else if (point == NULL) {
		index->prev = map->tail;
		map->tail->next = index;
		map->tail = index;
	} else if (point == map->head) {
		index->next = map->head;
		map->head->prev = index;
		map->head = index;
	} else {
		index->next = point;
		index->prev = point->prev;
		if (point->prev)
			point->prev->next = index;
		point->prev = index;
	}

	/* Execute event hook. */
	if (route_map_master.event_hook) {
		(*route_map_master.event_hook)(RMAP_EVENT_INDEX_ADDED,
					       map->name);
		route_map_notify_dependencies(map->name, RMAP_EVENT_CALL_ADDED);
	}
	return index;
}

/* Get route map index. */
static struct route_map_index *
route_map_index_get(struct route_map *map, enum route_map_type type, int pref)
{
	struct route_map_index *index;

	index = route_map_index_lookup(map, RMAP_ANY, pref);
	if (index && index->type != type) {
		/* Delete index from route map. */
		route_map_index_delete(index, 1);
		index = NULL;
	}
	if (index == NULL)
		index = route_map_index_add(map, type, pref);
	return index;
}

/* New route map rule */
static struct route_map_rule *route_map_rule_new(void)
{
	struct route_map_rule *new;

	new = XCALLOC(MTYPE_ROUTE_MAP_RULE, sizeof(struct route_map_rule));
	return new;
}

/* Install rule command to the match list. */
void route_map_install_match(struct route_map_rule_cmd *cmd)
{
	vector_set(route_match_vec, cmd);
}

/* Install rule command to the set list. */
void route_map_install_set(struct route_map_rule_cmd *cmd)
{
	vector_set(route_set_vec, cmd);
}

/* Lookup rule command from match list. */
static struct route_map_rule_cmd *route_map_lookup_match(const char *name)
{
	unsigned int i;
	struct route_map_rule_cmd *rule;

	for (i = 0; i < vector_active(route_match_vec); i++)
		if ((rule = vector_slot(route_match_vec, i)) != NULL)
			if (strcmp(rule->str, name) == 0)
				return rule;
	return NULL;
}

/* Lookup rule command from set list. */
static struct route_map_rule_cmd *route_map_lookup_set(const char *name)
{
	unsigned int i;
	struct route_map_rule_cmd *rule;

	for (i = 0; i < vector_active(route_set_vec); i++)
		if ((rule = vector_slot(route_set_vec, i)) != NULL)
			if (strcmp(rule->str, name) == 0)
				return rule;
	return NULL;
}

/* Add match and set rule to rule list. */
static void route_map_rule_add(struct route_map_rule_list *list,
			       struct route_map_rule *rule)
{
	rule->next = NULL;
	rule->prev = list->tail;
	if (list->tail)
		list->tail->next = rule;
	else
		list->head = rule;
	list->tail = rule;
}

/* Delete rule from rule list. */
static void route_map_rule_delete(struct route_map_rule_list *list,
				  struct route_map_rule *rule)
{
	if (rule->cmd->func_free)
		(*rule->cmd->func_free)(rule->value);

	if (rule->rule_str)
		XFREE(MTYPE_ROUTE_MAP_RULE_STR, rule->rule_str);

	if (rule->next)
		rule->next->prev = rule->prev;
	else
		list->tail = rule->prev;
	if (rule->prev)
		rule->prev->next = rule->next;
	else
		list->head = rule->next;

	XFREE(MTYPE_ROUTE_MAP_RULE, rule);
}

/* strcmp wrapper function which don't crush even argument is NULL. */
static int rulecmp(const char *dst, const char *src)
{
	if (dst == NULL) {
		if (src == NULL)
			return 0;
		else
			return 1;
	} else {
		if (src == NULL)
			return 1;
		else
			return strcmp(dst, src);
	}
	return 1;
}

/* Use this to return the already specified argument for this match. This is
 * useful to get the specified argument with a route map match rule when the
 * rule is being deleted and the argument is not provided.
 */
const char *route_map_get_match_arg(struct route_map_index *index,
				    const char *match_name)
{
	struct route_map_rule *rule;
	struct route_map_rule_cmd *cmd;

	/* First lookup rule for add match statement. */
	cmd = route_map_lookup_match(match_name);
	if (cmd == NULL)
		return NULL;

	for (rule = index->match_list.head; rule; rule = rule->next)
		if (rule->cmd == cmd && rule->rule_str != NULL)
			return (rule->rule_str);

	return (NULL);
}

/* Add match statement to route map. */
int route_map_add_match(struct route_map_index *index, const char *match_name,
			const char *match_arg)
{
	struct route_map_rule *rule;
	struct route_map_rule *next;
	struct route_map_rule_cmd *cmd;
	void *compile;
	int replaced = 0;

	/* First lookup rule for add match statement. */
	cmd = route_map_lookup_match(match_name);
	if (cmd == NULL)
		return RMAP_RULE_MISSING;

	/* Next call compile function for this match statement. */
	if (cmd->func_compile) {
		compile = (*cmd->func_compile)(match_arg);
		if (compile == NULL)
			return RMAP_COMPILE_ERROR;
	} else
		compile = NULL;

	/* If argument is completely same ignore it. */
	for (rule = index->match_list.head; rule; rule = next) {
		next = rule->next;
		if (rule->cmd == cmd) {
			route_map_rule_delete(&index->match_list, rule);
			replaced = 1;
		}
	}

	/* Add new route map match rule. */
	rule = route_map_rule_new();
	rule->cmd = cmd;
	rule->value = compile;
	if (match_arg)
		rule->rule_str = XSTRDUP(MTYPE_ROUTE_MAP_RULE_STR, match_arg);
	else
		rule->rule_str = NULL;

	/* Add new route match rule to linked list. */
	route_map_rule_add(&index->match_list, rule);

	/* Execute event hook. */
	if (route_map_master.event_hook) {
		(*route_map_master.event_hook)(
			replaced ? RMAP_EVENT_MATCH_REPLACED
				 : RMAP_EVENT_MATCH_ADDED,
			index->map->name);
		route_map_notify_dependencies(index->map->name,
					      RMAP_EVENT_CALL_ADDED);
	}

	return RMAP_COMPILE_SUCCESS;
}

/* Delete specified route match rule. */
int route_map_delete_match(struct route_map_index *index,
			   const char *match_name, const char *match_arg)
{
	struct route_map_rule *rule;
	struct route_map_rule_cmd *cmd;

	cmd = route_map_lookup_match(match_name);
	if (cmd == NULL)
		return 1;

	for (rule = index->match_list.head; rule; rule = rule->next)
		if (rule->cmd == cmd && (rulecmp(rule->rule_str, match_arg) == 0
					 || match_arg == NULL)) {
			route_map_rule_delete(&index->match_list, rule);
			/* Execute event hook. */
			if (route_map_master.event_hook) {
				(*route_map_master.event_hook)(
					RMAP_EVENT_MATCH_DELETED,
					index->map->name);
				route_map_notify_dependencies(
					index->map->name,
					RMAP_EVENT_CALL_ADDED);
			}
			return 0;
		}
	/* Can't find matched rule. */
	return 1;
}

/* Add route-map set statement to the route map. */
int route_map_add_set(struct route_map_index *index, const char *set_name,
		      const char *set_arg)
{
	struct route_map_rule *rule;
	struct route_map_rule *next;
	struct route_map_rule_cmd *cmd;
	void *compile;
	int replaced = 0;

	cmd = route_map_lookup_set(set_name);
	if (cmd == NULL)
		return RMAP_RULE_MISSING;

	/* Next call compile function for this match statement. */
	if (cmd->func_compile) {
		compile = (*cmd->func_compile)(set_arg);
		if (compile == NULL)
			return RMAP_COMPILE_ERROR;
	} else
		compile = NULL;

	/* Add by WJL. if old set command of same kind exist, delete it first
	   to ensure only one set command of same kind exist under a
	   route_map_index. */
	for (rule = index->set_list.head; rule; rule = next) {
		next = rule->next;
		if (rule->cmd == cmd) {
			route_map_rule_delete(&index->set_list, rule);
			replaced = 1;
		}
	}

	/* Add new route map match rule. */
	rule = route_map_rule_new();
	rule->cmd = cmd;
	rule->value = compile;
	if (set_arg)
		rule->rule_str = XSTRDUP(MTYPE_ROUTE_MAP_RULE_STR, set_arg);
	else
		rule->rule_str = NULL;

	/* Add new route match rule to linked list. */
	route_map_rule_add(&index->set_list, rule);

	/* Execute event hook. */
	if (route_map_master.event_hook) {
		(*route_map_master.event_hook)(replaced
						       ? RMAP_EVENT_SET_REPLACED
						       : RMAP_EVENT_SET_ADDED,
					       index->map->name);
		route_map_notify_dependencies(index->map->name,
					      RMAP_EVENT_CALL_ADDED);
	}
	return RMAP_COMPILE_SUCCESS;
}

/* Delete route map set rule. */
int route_map_delete_set(struct route_map_index *index, const char *set_name,
			 const char *set_arg)
{
	struct route_map_rule *rule;
	struct route_map_rule_cmd *cmd;

	cmd = route_map_lookup_set(set_name);
	if (cmd == NULL)
		return 1;

	for (rule = index->set_list.head; rule; rule = rule->next)
		if ((rule->cmd == cmd) && (rulecmp(rule->rule_str, set_arg) == 0
					   || set_arg == NULL)) {
			route_map_rule_delete(&index->set_list, rule);
			/* Execute event hook. */
			if (route_map_master.event_hook) {
				(*route_map_master.event_hook)(
					RMAP_EVENT_SET_DELETED,
					index->map->name);
				route_map_notify_dependencies(
					index->map->name,
					RMAP_EVENT_CALL_ADDED);
			}
			return 0;
		}
	/* Can't find matched rule. */
	return 1;
}

/* Apply route map's each index to the object.

   The matrix for a route-map looks like this:
   (note, this includes the description for the "NEXT"
   and "GOTO" frobs now

	      Match   |   No Match
		      |
    permit    action  |     cont
		      |
    ------------------+---------------
		      |
    deny      deny    |     cont
		      |

   action)
      -Apply Set statements, accept route
      -If Call statement is present jump to the specified route-map, if it
	 denies the route we finish.
      -If NEXT is specified, goto NEXT statement
      -If GOTO is specified, goto the first clause where pref > nextpref
      -If nothing is specified, do as Cisco and finish
   deny)
      -Route is denied by route-map.
   cont)
      -Goto Next index

   If we get no matches after we've processed all updates, then the route
   is dropped too.

   Some notes on the new "CALL", "NEXT" and "GOTO"
     call WORD        - If this clause is matched, then the set statements
			are executed and then we jump to route-map 'WORD'. If
			this route-map denies the route, we finish, in other
   case we
			do whatever the exit policy (EXIT, NEXT or GOTO) tells.
     on-match next    - If this clause is matched, then the set statements
			are executed and then we drop through to the next clause
     on-match goto n  - If this clause is matched, then the set statments
			are executed and then we goto the nth clause, or the
			first clause greater than this. In order to ensure
			route-maps *always* exit, you cannot jump backwards.
			Sorry ;)

   We need to make sure our route-map processing matches the above
*/

static route_map_result_t
route_map_apply_match(struct route_map_rule_list *match_list,
		      struct prefix *prefix, route_map_object_t type,
		      void *object)
{
	route_map_result_t ret = RMAP_NOMATCH;
	struct route_map_rule *match;


	/* Check all match rule and if there is no match rule, go to the
	   set statement. */
	if (!match_list->head)
		ret = RMAP_MATCH;
	else {
		for (match = match_list->head; match; match = match->next) {
			/* Try each match statement in turn, If any do not
			   return
			   RMAP_MATCH, return, otherwise continue on to next
			   match
			   statement. All match statements must match for
			   end-result
			   to be a match. */
			ret = (*match->cmd->func_apply)(match->value, prefix,
							type, object);
			if (ret != RMAP_MATCH)
				return ret;
		}
	}
	return ret;
}

/* Apply route map to the object. */
route_map_result_t route_map_apply(struct route_map *map, struct prefix *prefix,
				   route_map_object_t type, void *object)
{
	static int recursion = 0;
	int ret = 0;
	struct route_map_index *index;
	struct route_map_rule *set;

	if (recursion > RMAP_RECURSION_LIMIT) {
		zlog_warn(
			"route-map recursion limit (%d) reached, discarding route",
			RMAP_RECURSION_LIMIT);
		recursion = 0;
		return RMAP_DENYMATCH;
	}

	if (map == NULL)
		return RMAP_DENYMATCH;

	for (index = map->head; index; index = index->next) {
		/* Apply this index. */
		ret = route_map_apply_match(&index->match_list, prefix, type,
					    object);

		/* Now we apply the matrix from above */
		if (ret == RMAP_NOMATCH)
			/* 'cont' from matrix - continue to next route-map
			 * sequence */
			continue;
		else if (ret == RMAP_MATCH) {
			if (index->type == RMAP_PERMIT)
			/* 'action' */
			{
				/* permit+match must execute sets */
				for (set = index->set_list.head; set;
				     set = set->next)
					ret = (*set->cmd->func_apply)(
						set->value, prefix, type,
						object);

				/* Call another route-map if available */
				if (index->nextrm) {
					struct route_map *nextrm =
						route_map_lookup_by_name(
							index->nextrm);

					if (nextrm) /* Target route-map found,
						       jump to it */
					{
						recursion++;
						ret = route_map_apply(
							nextrm, prefix, type,
							object);
						recursion--;
					}

					/* If nextrm returned 'deny', finish. */
					if (ret == RMAP_DENYMATCH)
						return ret;
				}

				switch (index->exitpolicy) {
				case RMAP_EXIT:
					return ret;
				case RMAP_NEXT:
					continue;
				case RMAP_GOTO: {
					/* Find the next clause to jump to */
					struct route_map_index *next =
						index->next;
					int nextpref = index->nextpref;

					while (next && next->pref < nextpref) {
						index = next;
						next = next->next;
					}
					if (next == NULL) {
						/* No clauses match! */
						return ret;
					}
				}
				}
			} else if (index->type == RMAP_DENY)
			/* 'deny' */
			{
				return RMAP_DENYMATCH;
			}
		}
	}
	/* Finally route-map does not match at all. */
	return RMAP_DENYMATCH;
}

void route_map_add_hook(void (*func)(const char *))
{
	route_map_master.add_hook = func;
}

void route_map_delete_hook(void (*func)(const char *))
{
	route_map_master.delete_hook = func;
}

void route_map_event_hook(void (*func)(route_map_event_t, const char *))
{
	route_map_master.event_hook = func;
}

/* Routines for route map dependency lists and dependency processing */
static int route_map_rmap_hash_cmp(const void *p1, const void *p2)
{
	return (strcmp((const char *)p1, (const char *)p2) == 0);
}

static int route_map_dep_hash_cmp(const void *p1, const void *p2)
{

	return (strcmp(((const struct route_map_dep *)p1)->dep_name,
		       (const char *)p2)
		== 0);
}

static void route_map_clear_reference(struct hash_backet *backet, void *arg)
{
	struct route_map_dep *dep = (struct route_map_dep *)backet->data;
	char *rmap_name;

	if (dep && arg) {
		rmap_name =
			(char *)hash_release(dep->dep_rmap_hash, (void *)arg);
		if (rmap_name) {
			XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);
		}
		if (!dep->dep_rmap_hash->count) {
			dep = hash_release(dep->this_hash,
					   (void *)dep->dep_name);
			hash_free(dep->dep_rmap_hash);
			XFREE(MTYPE_ROUTE_MAP_NAME, dep->dep_name);
			XFREE(MTYPE_ROUTE_MAP_DEP, dep);
		}
	}
}

static void route_map_clear_all_references(char *rmap_name)
{
	int i;

	for (i = 1; i < ROUTE_MAP_DEP_MAX; i++) {
		hash_iterate(route_map_dep_hash[i], route_map_clear_reference,
			     (void *)rmap_name);
	}
}

static void *route_map_dep_hash_alloc(void *p)
{
	char *dep_name = (char *)p;
	struct route_map_dep *dep_entry;

	dep_entry = XCALLOC(MTYPE_ROUTE_MAP_DEP, sizeof(struct route_map_dep));
	dep_entry->dep_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, dep_name);
	dep_entry->dep_rmap_hash =
		hash_create_size(8, route_map_dep_hash_make_key,
				 route_map_rmap_hash_cmp, "Route Map Dep Hash");
	dep_entry->this_hash = NULL;

	return ((void *)dep_entry);
}

static void *route_map_name_hash_alloc(void *p)
{
	return ((void *)XSTRDUP(MTYPE_ROUTE_MAP_NAME, (const char *)p));
}

static unsigned int route_map_dep_hash_make_key(void *p)
{
	return (string_hash_make((char *)p));
}

static void route_map_print_dependency(struct hash_backet *backet, void *data)
{
	char *rmap_name = (char *)backet->data;
	char *dep_name = (char *)data;

	if (rmap_name)
		zlog_debug("%s: Dependency for %s: %s", __FUNCTION__, dep_name,
			   rmap_name);
}

static int route_map_dep_update(struct hash *dephash, const char *dep_name,
				const char *rmap_name, route_map_event_t type)
{
	struct route_map_dep *dep = NULL;
	char *ret_map_name;
	char *dname, *rname;
	int ret = 0;

	dname = XSTRDUP(MTYPE_ROUTE_MAP_NAME, dep_name);
	rname = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);

	switch (type) {
	case RMAP_EVENT_PLIST_ADDED:
	case RMAP_EVENT_CLIST_ADDED:
	case RMAP_EVENT_ECLIST_ADDED:
	case RMAP_EVENT_ASLIST_ADDED:
	case RMAP_EVENT_LLIST_ADDED:
	case RMAP_EVENT_CALL_ADDED:
	case RMAP_EVENT_FILTER_ADDED:
		if (rmap_debug)
			zlog_debug("%s: Adding dependency for %s in %s",
				   __FUNCTION__, dep_name, rmap_name);
		dep = (struct route_map_dep *)hash_get(
			dephash, dname, route_map_dep_hash_alloc);
		if (!dep) {
			ret = -1;
			goto out;
		}

		if (!dep->this_hash)
			dep->this_hash = dephash;

		hash_get(dep->dep_rmap_hash, rname, route_map_name_hash_alloc);
		break;
	case RMAP_EVENT_PLIST_DELETED:
	case RMAP_EVENT_CLIST_DELETED:
	case RMAP_EVENT_ECLIST_DELETED:
	case RMAP_EVENT_ASLIST_DELETED:
	case RMAP_EVENT_LLIST_DELETED:
	case RMAP_EVENT_CALL_DELETED:
	case RMAP_EVENT_FILTER_DELETED:
		if (rmap_debug)
			zlog_debug("%s: Deleting dependency for %s in %s",
				   __FUNCTION__, dep_name, rmap_name);
		dep = (struct route_map_dep *)hash_get(dephash, dname, NULL);
		if (!dep) {
			goto out;
		}

		ret_map_name = (char *)hash_release(dep->dep_rmap_hash, rname);
		if (ret_map_name)
			XFREE(MTYPE_ROUTE_MAP_NAME, ret_map_name);

		if (!dep->dep_rmap_hash->count) {
			dep = hash_release(dephash, dname);
			hash_free(dep->dep_rmap_hash);
			XFREE(MTYPE_ROUTE_MAP_NAME, dep->dep_name);
			XFREE(MTYPE_ROUTE_MAP_DEP, dep);
			dep = NULL;
		}
		break;
	default:
		break;
	}

	if (dep) {
		if (rmap_debug)
			hash_iterate(dep->dep_rmap_hash,
				     route_map_print_dependency, dname);
	}

out:
	XFREE(MTYPE_ROUTE_MAP_NAME, rname);
	XFREE(MTYPE_ROUTE_MAP_NAME, dname);
	return ret;
}

static struct hash *route_map_get_dep_hash(route_map_event_t event)
{
	struct hash *upd8_hash = NULL;

	switch (event) {
	case RMAP_EVENT_PLIST_ADDED:
	case RMAP_EVENT_PLIST_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_PLIST];
		break;
	case RMAP_EVENT_CLIST_ADDED:
	case RMAP_EVENT_CLIST_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_CLIST];
		break;
	case RMAP_EVENT_ECLIST_ADDED:
	case RMAP_EVENT_ECLIST_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_ECLIST];
		break;
	case RMAP_EVENT_ASLIST_ADDED:
	case RMAP_EVENT_ASLIST_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_ASPATH];
		break;
	case RMAP_EVENT_LLIST_ADDED:
	case RMAP_EVENT_LLIST_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_LCLIST];
		break;
	case RMAP_EVENT_CALL_ADDED:
	case RMAP_EVENT_CALL_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_RMAP];
		break;
	case RMAP_EVENT_FILTER_ADDED:
	case RMAP_EVENT_FILTER_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_FILTER];
		break;
	default:
		upd8_hash = NULL;
		break;
	}
	return (upd8_hash);
}

static void route_map_process_dependency(struct hash_backet *backet, void *data)
{
	char *rmap_name;
	route_map_event_t type = (route_map_event_t)(ptrdiff_t)data;

	rmap_name = (char *)backet->data;

	if (rmap_name) {
		if (rmap_debug)
			zlog_debug("%s: Notifying %s of dependency",
				   __FUNCTION__, rmap_name);
		if (route_map_master.event_hook)
			(*route_map_master.event_hook)(type, rmap_name);
	}
}

void route_map_upd8_dependency(route_map_event_t type, const char *arg,
			       const char *rmap_name)
{
	struct hash *upd8_hash = NULL;

	if ((upd8_hash = route_map_get_dep_hash(type)))
		route_map_dep_update(upd8_hash, arg, rmap_name, type);
}

void route_map_notify_dependencies(const char *affected_name,
				   route_map_event_t event)
{
	struct route_map_dep *dep;
	struct hash *upd8_hash;
	char *name;

	if (!affected_name)
		return;

	name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, affected_name);

	if ((upd8_hash = route_map_get_dep_hash(event)) == NULL) {
		XFREE(MTYPE_ROUTE_MAP_NAME, name);
		return;
	}

	dep = (struct route_map_dep *)hash_get(upd8_hash, name, NULL);
	if (dep) {
		if (!dep->this_hash)
			dep->this_hash = upd8_hash;

		hash_iterate(dep->dep_rmap_hash, route_map_process_dependency,
			     (void *)event);
	}

	XFREE(MTYPE_ROUTE_MAP_NAME, name);
}


/* VTY related functions. */
DEFUN (match_interface,
       match_interface_cmd,
       "match interface WORD",
       MATCH_STR
       "match first hop interface of route\n"
       "Interface name\n")
{
	int idx_word = 2;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_interface)
		return rmap_match_set_hook.match_interface(
			vty, index, "interface", argv[idx_word]->arg,
			RMAP_EVENT_MATCH_ADDED);
	return CMD_SUCCESS;
}

DEFUN (no_match_interface,
       no_match_interface_cmd,
       "no match interface [WORD]",
       NO_STR
       MATCH_STR
       "Match first hop interface of route\n"
       "Interface name\n")
{
	char *iface = (argc == 4) ? argv[3]->arg : NULL;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_interface)
		return rmap_match_set_hook.no_match_interface(
			vty, index, "interface", iface,
			RMAP_EVENT_MATCH_DELETED);
	return CMD_SUCCESS;
}


DEFUN (match_ip_address,
       match_ip_address_cmd,
       "match ip address <(1-199)|(1300-2699)|WORD>",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
	int idx_acl = 3;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_ip_address)
		return rmap_match_set_hook.match_ip_address(
			vty, index, "ip address", argv[idx_acl]->arg,
			RMAP_EVENT_FILTER_ADDED);
	return CMD_SUCCESS;
}


DEFUN (no_match_ip_address,
       no_match_ip_address_cmd,
       "no match ip address [<(1-199)|(1300-2699)|WORD>]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_ip_address) {
		if (argc <= idx_word)
			return rmap_match_set_hook.no_match_ip_address(
				vty, index, "ip address", NULL,
				RMAP_EVENT_FILTER_DELETED);
		return rmap_match_set_hook.no_match_ip_address(
			vty, index, "ip address", argv[idx_word]->arg,
			RMAP_EVENT_FILTER_DELETED);
	}
	return CMD_SUCCESS;
}


DEFUN (match_ip_address_prefix_list,
       match_ip_address_prefix_list_cmd,
       "match ip address prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_ip_address_prefix_list)
		return rmap_match_set_hook.match_ip_address_prefix_list(
			vty, index, "ip address prefix-list",
			argv[idx_word]->arg, RMAP_EVENT_PLIST_ADDED);
	return CMD_SUCCESS;
}


DEFUN (no_match_ip_address_prefix_list,
       no_match_ip_address_prefix_list_cmd,
       "no match ip address prefix-list [WORD]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 5;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_ip_address_prefix_list) {
		if (argc <= idx_word)
			return rmap_match_set_hook
				.no_match_ip_address_prefix_list(
					vty, index, "ip address prefix-list",
					NULL, RMAP_EVENT_PLIST_DELETED);
		return rmap_match_set_hook.no_match_ip_address_prefix_list(
			vty, index, "ip address prefix-list",
			argv[idx_word]->arg, RMAP_EVENT_PLIST_DELETED);
	}
	return CMD_SUCCESS;
}


DEFUN (match_ip_next_hop,
       match_ip_next_hop_cmd,
       "match ip next-hop <(1-199)|(1300-2699)|WORD>",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
	int idx_acl = 3;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_ip_next_hop)
		return rmap_match_set_hook.match_ip_next_hop(
			vty, index, "ip next-hop", argv[idx_acl]->arg,
			RMAP_EVENT_FILTER_ADDED);
	return CMD_SUCCESS;
}


DEFUN (no_match_ip_next_hop,
       no_match_ip_next_hop_cmd,
       "no match ip next-hop [<(1-199)|(1300-2699)|WORD>]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "IP access-list number\n"
       "IP access-list number (expanded range)\n"
       "IP Access-list name\n")
{
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_ip_next_hop) {
		if (argc <= idx_word)
			return rmap_match_set_hook.no_match_ip_next_hop(
				vty, index, "ip next-hop", NULL,
				RMAP_EVENT_FILTER_DELETED);
		return rmap_match_set_hook.no_match_ip_next_hop(
			vty, index, "ip next-hop", argv[idx_word]->arg,
			RMAP_EVENT_FILTER_DELETED);
	}
	return CMD_SUCCESS;
}


DEFUN (match_ip_next_hop_prefix_list,
       match_ip_next_hop_prefix_list_cmd,
       "match ip next-hop prefix-list WORD",
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_ip_next_hop_prefix_list)
		return rmap_match_set_hook.match_ip_next_hop_prefix_list(
			vty, index, "ip next-hop prefix-list",
			argv[idx_word]->arg, RMAP_EVENT_PLIST_ADDED);
	return CMD_SUCCESS;
}

DEFUN (no_match_ip_next_hop_prefix_list,
       no_match_ip_next_hop_prefix_list_cmd,
       "no match ip next-hop prefix-list [WORD]",
       NO_STR
       MATCH_STR
       IP_STR
       "Match next-hop address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 5;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_ip_next_hop) {
		if (argc <= idx_word)
			return rmap_match_set_hook.no_match_ip_next_hop(
				vty, index, "ip next-hop prefix-list", NULL,
				RMAP_EVENT_PLIST_DELETED);
		return rmap_match_set_hook.no_match_ip_next_hop(
			vty, index, "ip next-hop prefix-list",
			argv[idx_word]->arg, RMAP_EVENT_PLIST_DELETED);
	}
	return CMD_SUCCESS;
}


DEFUN (match_ipv6_address,
       match_ipv6_address_cmd,
       "match ipv6 address WORD",
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")
{
	int idx_word = 3;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_ipv6_address)
		return rmap_match_set_hook.match_ipv6_address(
			vty, index, "ipv6 address", argv[idx_word]->arg,
			RMAP_EVENT_FILTER_ADDED);
	return CMD_SUCCESS;
}

DEFUN (no_match_ipv6_address,
       no_match_ipv6_address_cmd,
       "no match ipv6 address WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match IPv6 address of route\n"
       "IPv6 access-list name\n")
{
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_ipv6_address)
		return rmap_match_set_hook.no_match_ipv6_address(
			vty, index, "ipv6 address", argv[idx_word]->arg,
			RMAP_EVENT_FILTER_DELETED);
	return CMD_SUCCESS;
}


DEFUN (match_ipv6_address_prefix_list,
       match_ipv6_address_prefix_list_cmd,
       "match ipv6 address prefix-list WORD",
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 4;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_ipv6_address_prefix_list)
		return rmap_match_set_hook.match_ipv6_address_prefix_list(
			vty, index, "ipv6 address prefix-list",
			argv[idx_word]->arg, RMAP_EVENT_PLIST_ADDED);
	return CMD_SUCCESS;
}

DEFUN (no_match_ipv6_address_prefix_list,
       no_match_ipv6_address_prefix_list_cmd,
       "no match ipv6 address prefix-list WORD",
       NO_STR
       MATCH_STR
       IPV6_STR
       "Match address of route\n"
       "Match entries of prefix-lists\n"
       "IP prefix-list name\n")
{
	int idx_word = 5;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_ipv6_address_prefix_list)
		return rmap_match_set_hook.no_match_ipv6_address_prefix_list(
			vty, index, "ipv6 address prefix-list",
			argv[idx_word]->arg, RMAP_EVENT_PLIST_DELETED);
	return CMD_SUCCESS;
}


DEFUN (match_metric,
       match_metric_cmd,
       "match metric (0-4294967295)",
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
	int idx_number = 2;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_metric)
		return rmap_match_set_hook.match_metric(vty, index, "metric",
							argv[idx_number]->arg,
							RMAP_EVENT_MATCH_ADDED);
	return CMD_SUCCESS;
}


DEFUN (no_match_metric,
       no_match_metric_cmd,
       "no match metric [(0-4294967295)]",
       NO_STR
       MATCH_STR
       "Match metric of route\n"
       "Metric value\n")
{
	int idx_number = 3;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_match_metric) {
		if (argc <= idx_number)
			return rmap_match_set_hook.no_match_metric(
				vty, index, "metric", NULL,
				RMAP_EVENT_MATCH_DELETED);
		return rmap_match_set_hook.no_match_metric(
			vty, index, "metric", argv[idx_number]->arg,
			RMAP_EVENT_MATCH_DELETED);
	}
	return CMD_SUCCESS;
}


DEFUN (match_tag,
       match_tag_cmd,
       "match tag (1-4294967295)",
       MATCH_STR
       "Match tag of route\n"
       "Tag value\n")
{
	int idx_number = 2;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.match_tag)
		return rmap_match_set_hook.match_tag(vty, index, "tag",
						     argv[idx_number]->arg,
						     RMAP_EVENT_MATCH_ADDED);
	return CMD_SUCCESS;
}


DEFUN (no_match_tag,
       no_match_tag_cmd,
       "no match tag [(1-4294967295)]",
       NO_STR
       MATCH_STR
       "Match tag of route\n"
       "Tag value\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	int idx = 0;
	char *arg = argv_find(argv, argc, "(1-4294967295)", &idx)
			    ? argv[idx]->arg
			    : NULL;

	if (rmap_match_set_hook.no_match_tag)
		return rmap_match_set_hook.no_match_tag(
			vty, index, "tag", arg, RMAP_EVENT_MATCH_DELETED);
	return CMD_SUCCESS;
}


DEFUN (set_ip_nexthop,
       set_ip_nexthop_cmd,
       "set ip next-hop A.B.C.D",
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
	int idx_ipv4 = 3;
	union sockunion su;
	int ret;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	ret = str2sockunion(argv[idx_ipv4]->arg, &su);
	if (ret < 0) {
		vty_out(vty, "%% Malformed nexthop address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (su.sin.sin_addr.s_addr == 0
	    || IPV4_CLASS_DE(ntohl(su.sin.sin_addr.s_addr))) {
		vty_out(vty,
			"%% nexthop address cannot be 0.0.0.0, multicast or reserved\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rmap_match_set_hook.set_ip_nexthop)
		return rmap_match_set_hook.set_ip_nexthop(
			vty, index, "ip next-hop", argv[idx_ipv4]->arg);
	return CMD_SUCCESS;
}


DEFUN (no_set_ip_nexthop,
       no_set_ip_nexthop_cmd,
       "no set ip next-hop [A.B.C.D]",
       NO_STR
       SET_STR
       IP_STR
       "Next hop address\n"
       "IP address of next hop\n")
{
	int idx = 0;
	VTY_DECLVAR_CONTEXT(route_map_index, index);
	const char *arg = NULL;

	if (argv_find(argv, argc, "A.B.C.D", &idx))
		arg = argv[idx]->arg;

	if (rmap_match_set_hook.no_set_ip_nexthop)
		return rmap_match_set_hook.no_set_ip_nexthop(
			vty, index, "ip next-hop", arg);

	return CMD_SUCCESS;
}


DEFUN (set_ipv6_nexthop_local,
       set_ipv6_nexthop_local_cmd,
       "set ipv6 next-hop local X:X::X:X",
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")
{
	int idx_ipv6 = 4;
	struct in6_addr addr;
	int ret;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	ret = inet_pton(AF_INET6, argv[idx_ipv6]->arg, &addr);
	if (!ret) {
		vty_out(vty, "%% Malformed nexthop address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (!IN6_IS_ADDR_LINKLOCAL(&addr)) {
		vty_out(vty, "%% Invalid link-local nexthop address\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (rmap_match_set_hook.set_ipv6_nexthop_local)
		return rmap_match_set_hook.set_ipv6_nexthop_local(
			vty, index, "ipv6 next-hop local", argv[idx_ipv6]->arg);
	return CMD_SUCCESS;
}


DEFUN (no_set_ipv6_nexthop_local,
       no_set_ipv6_nexthop_local_cmd,
       "no set ipv6 next-hop local [X:X::X:X]",
       NO_STR
       SET_STR
       IPV6_STR
       "IPv6 next-hop address\n"
       "IPv6 local address\n"
       "IPv6 address of next hop\n")
{
	int idx_ipv6 = 5;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_set_ipv6_nexthop_local) {
		if (argc <= idx_ipv6)
			return rmap_match_set_hook.no_set_ipv6_nexthop_local(
				vty, index, "ipv6 next-hop local", NULL);
		return rmap_match_set_hook.no_set_ipv6_nexthop_local(
			vty, index, "ipv6 next-hop local", argv[5]->arg);
	}
	return CMD_SUCCESS;
}

DEFUN (set_metric,
       set_metric_cmd,
       "set metric <(0-4294967295)|rtt|+rtt|-rtt|+metric|-metric>",
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n"
       "Assign round trip time\n"
       "Add round trip time\n"
       "Subtract round trip time\n"
       "Add metric\n"
       "Subtract metric\n")
{
	int idx_number = 2;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	const char *pass = (argv[idx_number]->type == RANGE_TKN)
				   ? argv[idx_number]->arg
				   : argv[idx_number]->text;

	if (rmap_match_set_hook.set_metric)
		return rmap_match_set_hook.set_metric(vty, index, "metric",
						      pass);
	return CMD_SUCCESS;
}


DEFUN (no_set_metric,
       no_set_metric_cmd,
       "no set metric [(0-4294967295)]",
       NO_STR
       SET_STR
       "Metric value for destination routing protocol\n"
       "Metric value\n")
{
	int idx_number = 3;
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	if (rmap_match_set_hook.no_set_metric) {
		if (argc <= idx_number)
			return rmap_match_set_hook.no_set_metric(
				vty, index, "metric", NULL);
		return rmap_match_set_hook.no_set_metric(vty, index, "metric",
							 argv[idx_number]->arg);
	}
	return CMD_SUCCESS;
}


DEFUN (set_tag,
       set_tag_cmd,
       "set tag (1-4294967295)",
       SET_STR
       "Tag value for routing protocol\n"
       "Tag value\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	int idx_number = 2;
	if (rmap_match_set_hook.set_tag)
		return rmap_match_set_hook.set_tag(vty, index, "tag",
						   argv[idx_number]->arg);
	return CMD_SUCCESS;
}


DEFUN (no_set_tag,
       no_set_tag_cmd,
       "no set tag [(1-4294967295)]",
       NO_STR
       SET_STR
       "Tag value for routing protocol\n"
       "Tag value\n")
{
	VTY_DECLVAR_CONTEXT(route_map_index, index);

	int idx_number = 3;
	if (rmap_match_set_hook.no_set_tag) {
		if (argc <= idx_number)
			return rmap_match_set_hook.no_set_tag(vty, index, "tag",
							      NULL);
		return rmap_match_set_hook.no_set_tag(vty, index, "tag",
						      argv[idx_number]->arg);
	}
	return CMD_SUCCESS;
}


DEFUN_NOSH (route_map,
       route_map_cmd,
       "route-map WORD <deny|permit> (1-65535)",
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n"
       "Route map denies set operations\n"
       "Route map permits set operations\n"
       "Sequence to insert to/delete from existing route-map entry\n")
{
	int idx_word = 1;
	int idx_permit_deny = 2;
	int idx_number = 3;
	struct route_map *map;
	struct route_map_index *index;
	char *endptr = NULL;
	int permit =
		argv[idx_permit_deny]->arg[0] == 'p' ? RMAP_PERMIT : RMAP_DENY;
	unsigned long pref = strtoul(argv[idx_number]->arg, &endptr, 10);
	const char *mapname = argv[idx_word]->arg;

	/* Get route map. */
	map = route_map_get(mapname);
	index = route_map_index_get(map, permit, pref);

	VTY_PUSH_CONTEXT(RMAP_NODE, index);
	return CMD_SUCCESS;
}

DEFUN (no_route_map_all,
       no_route_map_all_cmd,
       "no route-map WORD",
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n")
{
	int idx_word = 2;
	const char *mapname = argv[idx_word]->arg;
	struct route_map *map;

	map = route_map_lookup_by_name(mapname);
	if (map == NULL) {
		vty_out(vty, "%% Could not find route-map %s\n", mapname);
		return CMD_WARNING_CONFIG_FAILED;
	}

	route_map_delete(map);

	return CMD_SUCCESS;
}

DEFUN (no_route_map,
       no_route_map_cmd,
       "no route-map WORD <deny|permit> (1-65535)",
       NO_STR
       "Create route-map or enter route-map command mode\n"
       "Route map tag\n"
       "Route map denies set operations\n"
       "Route map permits set operations\n"
       "Sequence to insert to/delete from existing route-map entry\n")
{
	int idx_word = 2;
	int idx_permit_deny = 3;
	int idx_number = 4;
	struct route_map *map;
	struct route_map_index *index;
	char *endptr = NULL;
	int permit = strmatch(argv[idx_permit_deny]->text, "permit")
			     ? RMAP_PERMIT
			     : RMAP_DENY;
	const char *prefstr = argv[idx_number]->arg;
	const char *mapname = argv[idx_word]->arg;
	unsigned long pref = strtoul(prefstr, &endptr, 10);

	/* Existence check. */
	map = route_map_lookup_by_name(mapname);
	if (map == NULL) {
		vty_out(vty, "%% Could not find route-map %s\n", mapname);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Lookup route map index. */
	index = route_map_index_lookup(map, permit, pref);
	if (index == NULL) {
		vty_out(vty, "%% Could not find route-map entry %s %s\n",
			mapname, prefstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Delete index from route map. */
	route_map_index_delete(index, 1);

	/* If this route rule is the last one, delete route map itself. */
	if (route_map_empty(map))
		route_map_delete(map);

	return CMD_SUCCESS;
}

DEFUN (rmap_onmatch_next,
       rmap_onmatch_next_cmd,
       "on-match next",
       "Exit policy on matches\n"
       "Next clause\n")
{
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);

	if (index) {
		if (index->type == RMAP_DENY) {
			/* Under a deny clause, match means it's finished. No
			 * need to set next */
			vty_out(vty,
				"on-match next not supported under route-map deny\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		index->exitpolicy = RMAP_NEXT;
	}
	return CMD_SUCCESS;
}

DEFUN (no_rmap_onmatch_next,
       no_rmap_onmatch_next_cmd,
       "no on-match next",
       NO_STR
       "Exit policy on matches\n"
       "Next clause\n")
{
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);

	if (index)
		index->exitpolicy = RMAP_EXIT;

	return CMD_SUCCESS;
}

DEFUN (rmap_onmatch_goto,
       rmap_onmatch_goto_cmd,
       "on-match goto (1-65535)",
       "Exit policy on matches\n"
       "Goto Clause number\n"
       "Number\n")
{
	int idx = 0;
	char *num = argv_find(argv, argc, "(1-65535)", &idx) ? argv[idx]->arg
							     : NULL;

	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);
	int d = 0;

	if (index) {
		if (index->type == RMAP_DENY) {
			/* Under a deny clause, match means it's finished. No
			 * need to go anywhere */
			vty_out(vty,
				"on-match goto not supported under route-map deny\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		if (num)
			d = strtoul(num, NULL, 10);
		else
			d = index->pref + 1;

		if (d <= index->pref) {
			/* Can't allow you to do that, Dave */
			vty_out(vty, "can't jump backwards in route-maps\n");
			return CMD_WARNING_CONFIG_FAILED;
		} else {
			index->exitpolicy = RMAP_GOTO;
			index->nextpref = d;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (no_rmap_onmatch_goto,
       no_rmap_onmatch_goto_cmd,
       "no on-match goto",
       NO_STR
       "Exit policy on matches\n"
       "Goto Clause number\n")
{
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);

	if (index)
		index->exitpolicy = RMAP_EXIT;

	return CMD_SUCCESS;
}

/* Cisco/GNU Zebra compatibility aliases */
/* ALIAS_FIXME */
DEFUN (rmap_continue,
       rmap_continue_cmd,
       "continue (1-65535)",
       "Continue on a different entry within the route-map\n"
       "Route-map entry sequence number\n")
{
	return rmap_onmatch_goto(self, vty, argc, argv);
}

/* ALIAS_FIXME */
DEFUN (no_rmap_continue,
       no_rmap_continue_cmd,
       "no continue [(1-65535)]",
       NO_STR
       "Continue on a different entry within the route-map\n"
       "Route-map entry sequence number\n")
{
	return no_rmap_onmatch_goto(self, vty, argc, argv);
}


DEFUN (rmap_show_name,
       rmap_show_name_cmd,
       "show route-map [WORD]",
       SHOW_STR
       "route-map information\n"
       "route-map name\n")
{
	int idx_word = 2;
	const char *name = (argc == 3) ? argv[idx_word]->arg : NULL;
	return vty_show_route_map(vty, name);
}

DEFUN (rmap_call,
       rmap_call_cmd,
       "call WORD",
       "Jump to another Route-Map after match+set\n"
       "Target route-map name\n")
{
	int idx_word = 1;
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);
	const char *rmap = argv[idx_word]->arg;

	assert(index);

	if (index->nextrm) {
		route_map_upd8_dependency(RMAP_EVENT_CALL_DELETED,
					  index->nextrm, index->map->name);
		XFREE(MTYPE_ROUTE_MAP_NAME, index->nextrm);
	}
	index->nextrm = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);

	/* Execute event hook. */
	route_map_upd8_dependency(RMAP_EVENT_CALL_ADDED, index->nextrm,
				  index->map->name);
	return CMD_SUCCESS;
}

DEFUN (no_rmap_call,
       no_rmap_call_cmd,
       "no call",
       NO_STR
       "Jump to another Route-Map after match+set\n")
{
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);

	if (index->nextrm) {
		route_map_upd8_dependency(RMAP_EVENT_CALL_DELETED,
					  index->nextrm, index->map->name);
		XFREE(MTYPE_ROUTE_MAP_NAME, index->nextrm);
		index->nextrm = NULL;
	}

	return CMD_SUCCESS;
}

DEFUN (rmap_description,
       rmap_description_cmd,
       "description LINE...",
       "Route-map comment\n"
       "Comment describing this route-map rule\n")
{
	int idx_line = 1;
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);

	if (index) {
		if (index->description)
			XFREE(MTYPE_TMP, index->description);
		index->description = argv_concat(argv, argc, idx_line);
	}
	return CMD_SUCCESS;
}

DEFUN (no_rmap_description,
       no_rmap_description_cmd,
       "no description",
       NO_STR
       "Route-map comment\n")
{
	struct route_map_index *index = VTY_GET_CONTEXT(route_map_index);

	if (index) {
		if (index->description)
			XFREE(MTYPE_TMP, index->description);
		index->description = NULL;
	}
	return CMD_SUCCESS;
}

/* Configuration write function. */
static int route_map_config_write(struct vty *vty)
{
	struct route_map *map;
	struct route_map_index *index;
	struct route_map_rule *rule;
	int first = 1;
	int write = 0;

	for (map = route_map_master.head; map; map = map->next)
		for (index = map->head; index; index = index->next) {
			if (!first)
				vty_out(vty, "!\n");
			else
				first = 0;

			vty_out(vty, "route-map %s %s %d\n", map->name,
				route_map_type_str(index->type), index->pref);

			if (index->description)
				vty_out(vty, " description %s\n",
					index->description);

			for (rule = index->match_list.head; rule;
			     rule = rule->next)
				vty_out(vty, " match %s %s\n", rule->cmd->str,
					rule->rule_str ? rule->rule_str : "");

			for (rule = index->set_list.head; rule;
			     rule = rule->next)
				vty_out(vty, " set %s %s\n", rule->cmd->str,
					rule->rule_str ? rule->rule_str : "");
			if (index->nextrm)
				vty_out(vty, " call %s\n", index->nextrm);
			if (index->exitpolicy == RMAP_GOTO)
				vty_out(vty, " on-match goto %d\n",
					index->nextpref);
			if (index->exitpolicy == RMAP_NEXT)
				vty_out(vty, " on-match next\n");

			write++;
		}
	return write;
}

/* Route map node structure. */
static struct cmd_node rmap_node = {RMAP_NODE, "%s(config-route-map)# ", 1};

/* Common route map rules */

void *route_map_rule_tag_compile(const char *arg)
{
	unsigned long int tmp;
	char *endptr;
	route_tag_t *tag;

	errno = 0;
	tmp = strtoul(arg, &endptr, 0);
	if (arg[0] == '\0' || *endptr != '\0' || errno || tmp > ROUTE_TAG_MAX)
		return NULL;

	tag = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(*tag));
	*tag = tmp;

	return tag;
}

void route_map_rule_tag_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

void route_map_finish(void)
{
	int i;

	vector_free(route_match_vec);
	route_match_vec = NULL;
	vector_free(route_set_vec);
	route_set_vec = NULL;

	/* cleanup route_map */
	while (route_map_master.head) {
		struct route_map *map = route_map_master.head;
		map->to_be_processed = false;
		route_map_delete(map);
	}

	for (i = 1; i < ROUTE_MAP_DEP_MAX; i++) {
		hash_free(route_map_dep_hash[i]);
		route_map_dep_hash[i] = NULL;
	}

	hash_free(route_map_master_hash);
	route_map_master_hash = NULL;
}

static void rmap_autocomplete(vector comps, struct cmd_token *token)
{
	struct route_map *map;

	for (map = route_map_master.head; map; map = map->next)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, map->name));
}

static const struct cmd_variable_handler rmap_var_handlers[] = {
	{/* "route-map WORD" */
	 .varname = "route_map",
	 .completions = rmap_autocomplete},
	{.tokenname = "ROUTEMAP_NAME", .completions = rmap_autocomplete},
	{.tokenname = "RMAP_NAME", .completions = rmap_autocomplete},
	{.completions = NULL}};

/* Initialization of route map vector. */
void route_map_init(void)
{
	int i;

	/* Make vector for match and set. */
	route_match_vec = vector_init(1);
	route_set_vec = vector_init(1);
	route_map_master_hash =
		hash_create_size(8, route_map_hash_key_make, route_map_hash_cmp,
				 "Route Map Master Hash");

	for (i = 1; i < ROUTE_MAP_DEP_MAX; i++)
		route_map_dep_hash[i] = hash_create_size(
			8, route_map_dep_hash_make_key, route_map_dep_hash_cmp,
			"Route Map Dep Hash");

	cmd_variable_handler_register(rmap_var_handlers);

	/* Install route map top node. */
	install_node(&rmap_node, route_map_config_write);

	/* Install route map commands. */
	install_default(RMAP_NODE);
	install_element(CONFIG_NODE, &route_map_cmd);
	install_element(CONFIG_NODE, &no_route_map_cmd);
	install_element(CONFIG_NODE, &no_route_map_all_cmd);

	/* Install the on-match stuff */
	install_element(RMAP_NODE, &route_map_cmd);
	install_element(RMAP_NODE, &rmap_onmatch_next_cmd);
	install_element(RMAP_NODE, &no_rmap_onmatch_next_cmd);
	install_element(RMAP_NODE, &rmap_onmatch_goto_cmd);
	install_element(RMAP_NODE, &no_rmap_onmatch_goto_cmd);
	install_element(RMAP_NODE, &rmap_continue_cmd);
	install_element(RMAP_NODE, &no_rmap_continue_cmd);

	/* Install the continue stuff (ALIAS of on-match). */

	/* Install the call stuff. */
	install_element(RMAP_NODE, &rmap_call_cmd);
	install_element(RMAP_NODE, &no_rmap_call_cmd);

	/* Install description commands. */
	install_element(RMAP_NODE, &rmap_description_cmd);
	install_element(RMAP_NODE, &no_rmap_description_cmd);

	/* Install show command */
	install_element(ENABLE_NODE, &rmap_show_name_cmd);

	install_element(RMAP_NODE, &match_interface_cmd);
	install_element(RMAP_NODE, &no_match_interface_cmd);

	install_element(RMAP_NODE, &match_ip_address_cmd);
	install_element(RMAP_NODE, &no_match_ip_address_cmd);

	install_element(RMAP_NODE, &match_ip_address_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ip_address_prefix_list_cmd);

	install_element(RMAP_NODE, &match_ip_next_hop_cmd);
	install_element(RMAP_NODE, &no_match_ip_next_hop_cmd);

	install_element(RMAP_NODE, &match_ip_next_hop_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ip_next_hop_prefix_list_cmd);

	install_element(RMAP_NODE, &match_ipv6_address_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_address_cmd);

	install_element(RMAP_NODE, &match_ipv6_address_prefix_list_cmd);
	install_element(RMAP_NODE, &no_match_ipv6_address_prefix_list_cmd);

	install_element(RMAP_NODE, &match_metric_cmd);
	install_element(RMAP_NODE, &no_match_metric_cmd);

	install_element(RMAP_NODE, &match_tag_cmd);
	install_element(RMAP_NODE, &no_match_tag_cmd);

	install_element(RMAP_NODE, &set_ip_nexthop_cmd);
	install_element(RMAP_NODE, &no_set_ip_nexthop_cmd);

	install_element(RMAP_NODE, &set_ipv6_nexthop_local_cmd);
	install_element(RMAP_NODE, &no_set_ipv6_nexthop_local_cmd);

	install_element(RMAP_NODE, &set_metric_cmd);
	install_element(RMAP_NODE, &no_set_metric_cmd);

	install_element(RMAP_NODE, &set_tag_cmd);
	install_element(RMAP_NODE, &no_set_tag_cmd);
}
