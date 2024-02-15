// SPDX-License-Identifier: GPL-2.0-or-later
/* Route map function.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "linklist.h"
#include "memory.h"
#include "command.h"
#include "vector.h"
#include "prefix.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "log.h"
#include "hash.h"
#include "libfrr.h"
#include "lib_errors.h"
#include "table.h"
#include "json.h"
#include "jhash.h"

#include "lib/routemap_clippy.c"

DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP, "Route map");
DEFINE_MTYPE(LIB, ROUTE_MAP_NAME, "Route map name");
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_INDEX, "Route map index");
DEFINE_MTYPE(LIB, ROUTE_MAP_RULE, "Route map rule");
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_RULE_STR, "Route map rule str");
DEFINE_MTYPE(LIB, ROUTE_MAP_COMPILED, "Route map compiled");
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_DEP, "Route map dependency");
DEFINE_MTYPE_STATIC(LIB, ROUTE_MAP_DEP_DATA, "Route map dependency data");

DEFINE_QOBJ_TYPE(route_map_index);
DEFINE_QOBJ_TYPE(route_map);

static int rmap_cmd_name_cmp(const struct route_map_rule_cmd_proxy *a,
			     const struct route_map_rule_cmd_proxy *b)
{
	return strcmp(a->cmd->str, b->cmd->str);
}

static uint32_t rmap_cmd_name_hash(const struct route_map_rule_cmd_proxy *item)
{
	return jhash(item->cmd->str, strlen(item->cmd->str), 0xbfd69320);
}

DECLARE_HASH(rmap_cmd_name, struct route_map_rule_cmd_proxy, itm,
	     rmap_cmd_name_cmp, rmap_cmd_name_hash);

static struct rmap_cmd_name_head rmap_match_cmds[1] = {
	INIT_HASH(rmap_match_cmds[0]),
};
static struct rmap_cmd_name_head rmap_set_cmds[1] = {
	INIT_HASH(rmap_set_cmds[0]),
};

#define IPv4_PREFIX_LIST "ip address prefix-list"
#define IPv6_PREFIX_LIST "ipv6 address prefix-list"

#define IS_RULE_IPv4_PREFIX_LIST(S)                                            \
	(strncmp(S, IPv4_PREFIX_LIST, strlen(IPv4_PREFIX_LIST)) == 0)
#define IS_RULE_IPv6_PREFIX_LIST(S)                                            \
	(strncmp(S, IPv6_PREFIX_LIST, strlen(IPv6_PREFIX_LIST)) == 0)

struct route_map_pentry_dep {
	struct prefix_list_entry *pentry;
	const char *plist_name;
	route_map_event_t event;
};

static void route_map_pfx_tbl_update(route_map_event_t event,
				     struct route_map_index *index, afi_t afi,
				     const char *plist_name);
static void route_map_pfx_table_add_default(afi_t afi,
					    struct route_map_index *index);
static void route_map_pfx_table_del_default(afi_t afi,
					    struct route_map_index *index);
static void route_map_add_plist_entries(afi_t afi,
					struct route_map_index *index,
					const char *plist_name,
					struct prefix_list_entry *entry);
static void route_map_del_plist_entries(afi_t afi,
					struct route_map_index *index,
					const char *plist_name,
					struct prefix_list_entry *entry);

static struct hash *route_map_get_dep_hash(route_map_event_t event);
static void route_map_free_map(struct route_map *map);

struct route_map_match_set_hooks rmap_match_set_hook;

/* match interface */
void route_map_match_interface_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_interface = func;
}

/* no match interface */
void route_map_no_match_interface_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_interface = func;
}

/* match ip address */
void route_map_match_ip_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ip_address = func;
}

/* no match ip address */
void route_map_no_match_ip_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ip_address = func;
}

/* match ip address prefix list */
void route_map_match_ip_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ip_address_prefix_list = func;
}

/* no match ip address prefix list */
void route_map_no_match_ip_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ip_address_prefix_list = func;
}

/* match ip next hop */
void route_map_match_ip_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ip_next_hop = func;
}

/* no match ip next hop */
void route_map_no_match_ip_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ip_next_hop = func;
}

/* match ipv6 next-hop */
void route_map_match_ipv6_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ipv6_next_hop = func;
}

/* no match ipv6 next-hop */
void route_map_no_match_ipv6_next_hop_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ipv6_next_hop = func;
}

/* match ip next hop prefix list */
void route_map_match_ip_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ip_next_hop_prefix_list = func;
}

/* no match ip next hop prefix list */
void route_map_no_match_ip_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ip_next_hop_prefix_list = func;
}

/* match ip next-hop type */
void route_map_match_ip_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ip_next_hop_type = func;
}

/* no match ip next-hop type */
void route_map_no_match_ip_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ip_next_hop_type = func;
}

/* match ipv6 address */
void route_map_match_ipv6_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ipv6_address = func;
}

/* no match ipv6 address */
void route_map_no_match_ipv6_address_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ipv6_address = func;
}


/* match ipv6 address prefix list */
void route_map_match_ipv6_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ipv6_address_prefix_list = func;
}

/* no match ipv6 address prefix list */
void route_map_no_match_ipv6_address_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ipv6_address_prefix_list = func;
}

/* match ipv6 next-hop type */
void route_map_match_ipv6_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ipv6_next_hop_type = func;
}

/* no match ipv6 next-hop type */
void route_map_no_match_ipv6_next_hop_type_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ipv6_next_hop_type = func;
}

/* match ipv6 next-hop prefix-list */
void route_map_match_ipv6_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_ipv6_next_hop_prefix_list = func;
}

/* no match ipv6 next-hop prefix-list */
void route_map_no_match_ipv6_next_hop_prefix_list_hook(int (*func)(
	struct route_map_index *index, const char *command, const char *arg,
	route_map_event_t type, char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_ipv6_next_hop_prefix_list = func;
}

/* match metric */
void route_map_match_metric_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_metric = func;
}

/* no match metric */
void route_map_no_match_metric_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_metric = func;
}

/* match tag */
void route_map_match_tag_hook(int (*func)(struct route_map_index *index,
					  const char *command, const char *arg,
					  route_map_event_t type,
					  char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.match_tag = func;
}

/* no match tag */
void route_map_no_match_tag_hook(int (*func)(
	struct route_map_index *index, const char *command,
	const char *arg, route_map_event_t type,
	char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_match_tag = func;
}

/* set sr-te color */
void route_map_set_srte_color_hook(int (*func)(struct route_map_index *index,
					       const char *command,
					       const char *arg,
					       char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.set_srte_color = func;
}

/* no set sr-te color */
void route_map_no_set_srte_color_hook(int (*func)(struct route_map_index *index,
						  const char *command,
						  const char *arg,
						  char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_set_srte_color = func;
}

/* set ip nexthop */
void route_map_set_ip_nexthop_hook(int (*func)(struct route_map_index *index,
					       const char *command,
					       const char *arg,
					       char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.set_ip_nexthop = func;
}

/* no set ip nexthop */
void route_map_no_set_ip_nexthop_hook(int (*func)(struct route_map_index *index,
						  const char *command,
						  const char *arg,
						  char *errmsg,
						  size_t errmsg_len))
{
	rmap_match_set_hook.no_set_ip_nexthop = func;
}

/* set ipv6 nexthop local */
void route_map_set_ipv6_nexthop_local_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.set_ipv6_nexthop_local = func;
}

/* no set ipv6 nexthop local */
void route_map_no_set_ipv6_nexthop_local_hook(
	int (*func)(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_set_ipv6_nexthop_local = func;
}

/* set metric */
void route_map_set_metric_hook(int (*func)(struct route_map_index *index,
					   const char *command,
					   const char *arg,
					   char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.set_metric = func;
}

/* no set metric */
void route_map_no_set_metric_hook(int (*func)(struct route_map_index *index,
					      const char *command,
					      const char *arg,
					      char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_set_metric = func;
}
/* set min-metric */
void route_map_set_min_metric_hook(int (*func)(struct route_map_index *index,
					       const char *command,
					       const char *arg, char *errmsg,
					       size_t errmsg_len))
{
	rmap_match_set_hook.set_min_metric = func;
}

/* no set min-metric */
void route_map_no_set_min_metric_hook(int (*func)(struct route_map_index *index,
						  const char *command,
						  const char *arg, char *errmsg,
						  size_t errmsg_len))
{
	rmap_match_set_hook.no_set_min_metric = func;
}
/* set max-metric */
void route_map_set_max_metric_hook(int (*func)(struct route_map_index *index,
					       const char *command,
					       const char *arg, char *errmsg,
					       size_t errmsg_len))
{
	rmap_match_set_hook.set_max_metric = func;
}

/* no set max-metric */
void route_map_no_set_max_metric_hook(int (*func)(struct route_map_index *index,
						  const char *command,
						  const char *arg, char *errmsg,
						  size_t errmsg_len))
{
	rmap_match_set_hook.no_set_max_metric = func;
}

/* set tag */
void route_map_set_tag_hook(int (*func)(struct route_map_index *index,
					const char *command, const char *arg,
					char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.set_tag = func;
}

/* no set tag */
void route_map_no_set_tag_hook(int (*func)(struct route_map_index *index,
					   const char *command,
					   const char *arg,
					   char *errmsg, size_t errmsg_len))
{
	rmap_match_set_hook.no_set_tag = func;
}

int generic_match_add(struct route_map_index *index,
		      const char *command, const char *arg,
		      route_map_event_t type,
		      char *errmsg, size_t errmsg_len)
{
	enum rmap_compile_rets ret;

	ret = route_map_add_match(index, command, arg, type);
	switch (ret) {
	case RMAP_RULE_MISSING:
		snprintf(errmsg, errmsg_len, "%% [%s] Can't find rule.",
			 frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_ERROR:
		snprintf(errmsg, errmsg_len,
			 "%% [%s] Argument form is unsupported or malformed.",
			 frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_SUCCESS:
		/*
		 * Nothing to do here move along
		 */
		break;
	}

	return CMD_SUCCESS;
}

int generic_match_delete(struct route_map_index *index,
			 const char *command, const char *arg,
			 route_map_event_t type,
			 char *errmsg, size_t errmsg_len)
{
	enum rmap_compile_rets ret;
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

	ret = route_map_delete_match(index, command, dep_name, type);
	switch (ret) {
	case RMAP_RULE_MISSING:
		snprintf(errmsg, errmsg_len, "%% [%s] Can't find rule.",
			 frr_protonameinst);
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_ERROR:
		snprintf(errmsg, errmsg_len,
			 "%% [%s] Argument form is unsupported or malformed.",
			 frr_protonameinst);
		retval = CMD_WARNING_CONFIG_FAILED;
		break;
	case RMAP_COMPILE_SUCCESS:
		/*
		 * Nothing to do here
		 */
		break;
	}

	XFREE(MTYPE_ROUTE_MAP_RULE, dep_name);
	XFREE(MTYPE_ROUTE_MAP_NAME, rmap_name);

	return retval;
}

int generic_set_add(struct route_map_index *index,
		    const char *command, const char *arg,
		    char *errmsg, size_t errmsg_len)
{
	enum rmap_compile_rets ret;

	ret = route_map_add_set(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
		snprintf(errmsg, errmsg_len,
			 "%% [%s] Can't find rule.", frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_ERROR:
		snprintf(errmsg, errmsg_len,
			 "%% [%s] Argument form is unsupported or malformed.",
			frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_SUCCESS:
		break;
	}

	return CMD_SUCCESS;
}

int generic_set_delete(struct route_map_index *index,
		       const char *command, const char *arg,
		       char *errmsg, size_t errmsg_len)
{
	enum rmap_compile_rets ret;

	ret = route_map_delete_set(index, command, arg);
	switch (ret) {
	case RMAP_RULE_MISSING:
			snprintf(errmsg, errmsg_len, "%% [%s] Can't find rule.",
				 frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_ERROR:
			snprintf(errmsg, errmsg_len,
				 "%%  [%s] Argument form is unsupported or malformed.",
				 frr_protonameinst);
		return CMD_WARNING_CONFIG_FAILED;
	case RMAP_COMPILE_SUCCESS:
		break;
	}

	return CMD_SUCCESS;
}


/* Master list of route map. */
struct route_map_list route_map_master = {NULL, NULL, NULL, NULL, NULL};
struct hash *route_map_master_hash = NULL;

static unsigned int route_map_hash_key_make(const void *p)
{
	const struct route_map *map = p;
	return string_hash_make(map->name);
}

static bool route_map_hash_cmp(const void *p1, const void *p2)
{
	const struct route_map *map1 = p1;
	const struct route_map *map2 = p2;

	if (!strcmp(map1->name, map2->name))
		return true;

	return false;
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

struct route_map_dep_data {
	/* Route-map name.
	 */
	char *rname;
	/* Count of number of sequences of this
	 * route-map that depend on the same entity.
	 */
	uint16_t  refcnt;
};

/* Hashes maintaining dependency between various sublists used by route maps */
static struct hash *route_map_dep_hash[ROUTE_MAP_DEP_MAX];

static unsigned int route_map_dep_hash_make_key(const void *p);
static void route_map_clear_all_references(char *rmap_name);
static void route_map_rule_delete(struct route_map_rule_list *,
				  struct route_map_rule *);

uint32_t rmap_debug;

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
	struct route_map *map, *exist;
	struct route_map_list *list;

	map = route_map_new(name);
	list = &route_map_master;

	/*
	 * Add map to the hash
	 *
	 * If the map already exists in the hash, then we know that
	 * FRR is now in a sequence of delete/create.
	 * All FRR needs to do here is set the to_be_processed
	 * bit (to inherit from the old one
	 */
	exist = hash_release(route_map_master_hash, map);
	if (exist) {
		map->to_be_processed = exist->to_be_processed;
		route_map_free_map(exist);
	}
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

	if (!map->ipv4_prefix_table)
		map->ipv4_prefix_table = route_table_init();

	if (!map->ipv6_prefix_table)
		map->ipv6_prefix_table = route_table_init();

	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Add route-map %s", name);
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

	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Deleting route-map %s", map->name);

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

	route_table_finish(map->ipv4_prefix_table);
	route_table_finish(map->ipv6_prefix_table);

	hash_release(route_map_master_hash, map);
	XFREE(MTYPE_ROUTE_MAP_NAME, map->name);
	XFREE(MTYPE_ROUTE_MAP, map);
}

/* Route map delete from list. */
void route_map_delete(struct route_map *map)
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

	// map.deleted is false via memset
	memset(&tmp_map, 0, sizeof(tmp_map));
	tmp_map.name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, name);
	map = hash_lookup(route_map_master_hash, &tmp_map);
	XFREE(MTYPE_ROUTE_MAP_NAME, tmp_map.name);

	if (map && map->deleted)
		return NULL;

	return map;
}

/* Simple helper to warn if route-map does not exist. */
struct route_map *route_map_lookup_warn_noexist(struct vty *vty, const char *name)
{
	struct route_map *route_map = route_map_lookup_by_name(name);

	if (!route_map)
		if (vty_shell_serv(vty))
			vty_out(vty, "The route-map '%s' does not exist.\n", name);

	return route_map;
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
		memset(&tmp_map, 0, sizeof(tmp_map));
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

static void route_map_clear_updated(struct route_map *map)
{
	if (map) {
		map->to_be_processed = false;
		if (map->deleted)
			route_map_free_map(map);
	}
}

/* Lookup route map.  If there isn't route map create one and return
   it. */
struct route_map *route_map_get(const char *name)
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
	case RMAP_DENY:
		return "deny";
	case RMAP_ANY:
		return "";
	}

	return "";
}

static const char *route_map_cmd_result_str(enum route_map_cmd_result_t res)
{
	switch (res) {
	case RMAP_MATCH:
		return "match";
	case RMAP_NOMATCH:
		return "no match";
	case RMAP_NOOP:
		return "noop";
	case RMAP_ERROR:
		return "error";
	case RMAP_OKAY:
		return "okay";
	}

	return "invalid";
}

static const char *route_map_result_str(route_map_result_t res)
{
	switch (res) {
	case RMAP_DENYMATCH:
		return "deny";
	case RMAP_PERMITMATCH:
		return "permit";
	}

	return "invalid";
}

/* show route-map */
static void vty_show_route_map_entry(struct vty *vty, struct route_map *map,
				     json_object *json)
{
	struct route_map_index *index;
	struct route_map_rule *rule;
	json_object *json_rmap = NULL;
	json_object *json_rules = NULL;

	if (json) {
		json_rmap = json_object_new_object();
		json_object_object_add(json, map->name, json_rmap);

		json_rules = json_object_new_array();
		json_object_int_add(json_rmap, "invoked",
				    map->applied - map->applied_clear);
		json_object_boolean_add(json_rmap, "disabledOptimization",
					map->optimization_disabled);
		json_object_boolean_add(json_rmap, "processedChange",
					map->to_be_processed);
		json_object_object_add(json_rmap, "rules", json_rules);
	} else {
		vty_out(vty,
			"route-map: %s Invoked: %" PRIu64
			" Optimization: %s Processed Change: %s\n",
			map->name, map->applied - map->applied_clear,
			map->optimization_disabled ? "disabled" : "enabled",
			map->to_be_processed ? "true" : "false");
	}

	for (index = map->head; index; index = index->next) {
		if (json) {
			json_object *json_rule;
			json_object *json_matches;
			json_object *json_sets;
			char action[BUFSIZ] = {};

			json_rule = json_object_new_object();
			json_object_array_add(json_rules, json_rule);

			json_object_int_add(json_rule, "sequenceNumber",
					    index->pref);
			json_object_string_add(json_rule, "type",
					       route_map_type_str(index->type));
			json_object_int_add(json_rule, "invoked",
					    index->applied
						    - index->applied_clear);

			/* Description */
			if (index->description)
				json_object_string_add(json_rule, "description",
						       index->description);

			/* Match clauses */
			json_matches = json_object_new_array();
			json_object_object_add(json_rule, "matchClauses",
					       json_matches);
			for (rule = index->match_list.head; rule;
			     rule = rule->next) {
				char buf[BUFSIZ];

				snprintf(buf, sizeof(buf), "%s %s",
					 rule->cmd->str, rule->rule_str);
				json_array_string_add(json_matches, buf);
			}

			/* Set clauses */
			json_sets = json_object_new_array();
			json_object_object_add(json_rule, "setClauses",
					       json_sets);
			for (rule = index->set_list.head; rule;
			     rule = rule->next) {
				char buf[BUFSIZ];

				snprintf(buf, sizeof(buf), "%s %s",
					 rule->cmd->str, rule->rule_str);
				json_array_string_add(json_sets, buf);
			}

			/* Call clause */
			if (index->nextrm)
				json_object_string_add(json_rule, "callClause",
						       index->nextrm);

			/* Exit Policy */
			if (index->exitpolicy == RMAP_GOTO)
				snprintf(action, sizeof(action), "Goto %d",
					 index->nextpref);
			else if (index->exitpolicy == RMAP_NEXT)
				snprintf(action, sizeof(action),
					 "Continue to next entry");
			else if (index->exitpolicy == RMAP_EXIT)
				snprintf(action, sizeof(action),
					 "Exit routemap");
			if (action[0] != '\0')
				json_object_string_add(json_rule, "action",
						       action);
		} else {
			vty_out(vty, " %s, sequence %d Invoked %" PRIu64 "\n",
				route_map_type_str(index->type), index->pref,
				index->applied - index->applied_clear);

			/* Description */
			if (index->description)
				vty_out(vty, "  Description:\n    %s\n",
					index->description);

			/* Match clauses */
			vty_out(vty, "  Match clauses:\n");
			for (rule = index->match_list.head; rule;
			     rule = rule->next)
				vty_out(vty, "    %s %s\n", rule->cmd->str,
					rule->rule_str);

			/* Set clauses */
			vty_out(vty, "  Set clauses:\n");
			for (rule = index->set_list.head; rule;
			     rule = rule->next)
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
}

static int sort_route_map(const void **map1, const void **map2)
{
	const struct route_map *m1 = *map1;
	const struct route_map *m2 = *map2;

	return strcmp(m1->name, m2->name);
}

static int vty_show_route_map(struct vty *vty, const char *name, bool use_json)
{
	struct route_map *map;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();
	else
		vty_out(vty, "%s:\n", frr_protonameinst);

	if (name) {
		map = route_map_lookup_by_name(name);

		if (map) {
			vty_show_route_map_entry(vty, map, json);
		} else if (!use_json) {
			vty_out(vty, "%s: 'route-map %s' not found\n",
				frr_protonameinst, name);
		}
	} else {

		struct list *maplist = list_new();
		struct listnode *ln;

		for (map = route_map_master.head; map; map = map->next)
			listnode_add(maplist, map);

		list_sort(maplist, sort_route_map);

		for (ALL_LIST_ELEMENTS_RO(maplist, ln, map))
			vty_show_route_map_entry(vty, map, json);

		list_delete(&maplist);
	}

	return vty_json(vty, json);
}

/* Unused route map details */
static int vty_show_unused_route_map(struct vty *vty)
{
	struct list *maplist = list_new();
	struct listnode *ln;
	struct route_map *map;

	for (map = route_map_master.head; map; map = map->next) {
		/* If use_count is zero, No protocol is using this routemap.
		 * so adding to the list.
		 */
		if (!map->use_count)
			listnode_add(maplist, map);
	}

	if (maplist->count > 0) {
		vty_out(vty, "\n%s:\n", frr_protonameinst);
		list_sort(maplist, sort_route_map);

		for (ALL_LIST_ELEMENTS_RO(maplist, ln, map))
			vty_show_route_map_entry(vty, map, NULL);
	} else {
		vty_out(vty, "\n%s: None\n", frr_protonameinst);
	}

	list_delete(&maplist);
	return CMD_SUCCESS;
}

/* New route map allocation. Please note route map's name must be
   specified. */
static struct route_map_index *route_map_index_new(void)
{
	struct route_map_index *new;

	new = XCALLOC(MTYPE_ROUTE_MAP_INDEX, sizeof(struct route_map_index));
	new->exitpolicy = RMAP_EXIT; /* Default to Cisco-style */
	TAILQ_INIT(&new->rhclist);
	QOBJ_REG(new, route_map_index);
	return new;
}

/* Free route map index. */
void route_map_index_delete(struct route_map_index *index, int notify)
{
	struct routemap_hook_context *rhc;
	struct route_map_rule *rule;

	QOBJ_UNREG(index);

	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Deleting route-map %s sequence %d",
			   index->map->name, index->pref);

	/* Free route map entry description. */
	XFREE(MTYPE_TMP, index->description);

	/* Free route map northbound hook contexts. */
	while ((rhc = TAILQ_FIRST(&index->rhclist)) != NULL)
		routemap_hook_context_free(rhc);

	/* Free route match. */
	while ((rule = index->match_list.head) != NULL) {
		if (IS_RULE_IPv4_PREFIX_LIST(rule->cmd->str))
			route_map_pfx_tbl_update(RMAP_EVENT_PLIST_DELETED,
						 index, AFI_IP, rule->rule_str);
		else if (IS_RULE_IPv6_PREFIX_LIST(rule->cmd->str))
			route_map_pfx_tbl_update(RMAP_EVENT_PLIST_DELETED,
						 index, AFI_IP6,
						 rule->rule_str);

		route_map_rule_delete(&index->match_list, rule);
	}

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
	XFREE(MTYPE_ROUTE_MAP_NAME, index->nextrm);

	route_map_pfx_tbl_update(RMAP_EVENT_INDEX_DELETED, index, 0, NULL);

	/* Execute event hook. */
	if (route_map_master.event_hook && notify) {
		(*route_map_master.event_hook)(index->map->name);
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

	route_map_pfx_tbl_update(RMAP_EVENT_INDEX_ADDED, index, 0, NULL);

	/* Execute event hook. */
	if (route_map_master.event_hook) {
		(*route_map_master.event_hook)(map->name);
		route_map_notify_dependencies(map->name, RMAP_EVENT_CALL_ADDED);
	}

	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Route-map %s add sequence %d, type: %s",
			   map->name, pref, route_map_type_str(type));

	return index;
}

/* Get route map index. */
struct route_map_index *
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
void _route_map_install_match(struct route_map_rule_cmd_proxy *proxy)
{
	rmap_cmd_name_add(rmap_match_cmds, proxy);
}

/* Install rule command to the set list. */
void _route_map_install_set(struct route_map_rule_cmd_proxy *proxy)
{
	rmap_cmd_name_add(rmap_set_cmds, proxy);
}

/* Lookup rule command from match list. */
static const struct route_map_rule_cmd *route_map_lookup_match(const char *name)
{
	struct route_map_rule_cmd refcmd = {.str = name};
	struct route_map_rule_cmd_proxy ref = {.cmd = &refcmd};
	struct route_map_rule_cmd_proxy *res;

	res = rmap_cmd_name_find(rmap_match_cmds, &ref);
	if (res)
		return res->cmd;
	return NULL;
}

/* Lookup rule command from set list. */
static const struct route_map_rule_cmd *route_map_lookup_set(const char *name)
{
	struct route_map_rule_cmd refcmd = {.str = name};
	struct route_map_rule_cmd_proxy ref = {.cmd = &refcmd};
	struct route_map_rule_cmd_proxy *res;

	res = rmap_cmd_name_find(rmap_set_cmds, &ref);
	if (res)
		return res->cmd;
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
	const struct route_map_rule_cmd *cmd;

	/* First lookup rule for add match statement. */
	cmd = route_map_lookup_match(match_name);
	if (cmd == NULL)
		return NULL;

	for (rule = index->match_list.head; rule; rule = rule->next)
		if (rule->cmd == cmd && rule->rule_str != NULL)
			return (rule->rule_str);

	return NULL;
}

static route_map_event_t get_route_map_delete_event(route_map_event_t type)
{
	switch (type) {
	case RMAP_EVENT_CALL_ADDED:
		return RMAP_EVENT_CALL_DELETED;
	case RMAP_EVENT_PLIST_ADDED:
		return RMAP_EVENT_PLIST_DELETED;
	case RMAP_EVENT_CLIST_ADDED:
		return RMAP_EVENT_CLIST_DELETED;
	case RMAP_EVENT_ECLIST_ADDED:
		return RMAP_EVENT_ECLIST_DELETED;
	case RMAP_EVENT_LLIST_ADDED:
		return RMAP_EVENT_LLIST_DELETED;
	case RMAP_EVENT_ASLIST_ADDED:
		return RMAP_EVENT_ASLIST_DELETED;
	case RMAP_EVENT_FILTER_ADDED:
		return RMAP_EVENT_FILTER_DELETED;
	case RMAP_EVENT_SET_ADDED:
	case RMAP_EVENT_SET_DELETED:
	case RMAP_EVENT_SET_REPLACED:
	case RMAP_EVENT_MATCH_ADDED:
	case RMAP_EVENT_MATCH_DELETED:
	case RMAP_EVENT_MATCH_REPLACED:
	case RMAP_EVENT_INDEX_ADDED:
	case RMAP_EVENT_INDEX_DELETED:
	case RMAP_EVENT_CALL_DELETED:
	case RMAP_EVENT_PLIST_DELETED:
	case RMAP_EVENT_CLIST_DELETED:
	case RMAP_EVENT_ECLIST_DELETED:
	case RMAP_EVENT_LLIST_DELETED:
	case RMAP_EVENT_ASLIST_DELETED:
	case RMAP_EVENT_FILTER_DELETED:
		/* This function returns the appropriate 'deleted' event type
		 * for every 'added' event type passed to this function.
		 * This is done only for named entities used in the
		 * route-map match commands.
		 * This function is not to be invoked for any of the other event
		 * types.
		 */
		assert(0);
	}

	assert(0);
	/*
	 * Return to make c happy but if we get here something has gone
	 * terribly terribly wrong, so yes this return makes no sense.
	 */
	return RMAP_EVENT_CALL_ADDED;
}

/* Add match statement to route map. */
enum rmap_compile_rets route_map_add_match(struct route_map_index *index,
					   const char *match_name,
					   const char *match_arg,
					   route_map_event_t type)
{
	struct route_map_rule *rule;
	struct route_map_rule *next;
	const struct route_map_rule_cmd *cmd;
	void *compile;
	int8_t delete_rmap_event_type = 0;
	const char *rule_key;

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
	/* use the compiled results if applicable */
	if (compile && cmd->func_get_rmap_rule_key)
		rule_key = (*cmd->func_get_rmap_rule_key)
			   (compile);
	else
		rule_key = match_arg;

	/* If argument is completely same ignore it. */
	for (rule = index->match_list.head; rule; rule = next) {
		next = rule->next;
		if (rule->cmd == cmd) {
			/* If the configured route-map match rule is exactly
			 * the same as the existing configuration then,
			 * ignore the duplicate configuration.
			 */
			if (rulecmp(match_arg, rule->rule_str) == 0) {
				if (cmd->func_free)
					(*cmd->func_free)(compile);

				return RMAP_COMPILE_SUCCESS;
			}

			/* If IPv4 or IPv6 prefix-list match criteria
			 * has been delete to the route-map index, update
			 * the route-map's prefix table.
			 */
			if (IS_RULE_IPv4_PREFIX_LIST(match_name))
				route_map_pfx_tbl_update(
					RMAP_EVENT_PLIST_DELETED, index, AFI_IP,
					rule->rule_str);
			else if (IS_RULE_IPv6_PREFIX_LIST(match_name))
				route_map_pfx_tbl_update(
					RMAP_EVENT_PLIST_DELETED, index,
					AFI_IP6, rule->rule_str);

			/* Remove the dependency of the route-map on the rule
			 * that is being replaced.
			 */
			if (type >= RMAP_EVENT_CALL_ADDED) {
				delete_rmap_event_type =
					get_route_map_delete_event(type);
				route_map_upd8_dependency(
							delete_rmap_event_type,
							rule->rule_str,
							index->map->name);
			}

			route_map_rule_delete(&index->match_list, rule);
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

	/* If IPv4 or IPv6 prefix-list match criteria
	 * has been added to the route-map index, update
	 * the route-map's prefix table.
	 */
	if (IS_RULE_IPv4_PREFIX_LIST(match_name)) {
		route_map_pfx_tbl_update(RMAP_EVENT_PLIST_ADDED, index, AFI_IP,
					 match_arg);
	} else if (IS_RULE_IPv6_PREFIX_LIST(match_name)) {
		route_map_pfx_tbl_update(RMAP_EVENT_PLIST_ADDED, index, AFI_IP6,
					 match_arg);
	}

	/* Execute event hook. */
	if (route_map_master.event_hook) {
		(*route_map_master.event_hook)(index->map->name);
		route_map_notify_dependencies(index->map->name,
					      RMAP_EVENT_CALL_ADDED);
	}
	if (type != RMAP_EVENT_MATCH_ADDED)
		route_map_upd8_dependency(type, rule_key, index->map->name);

	return RMAP_COMPILE_SUCCESS;
}

/* Delete specified route match rule. */
enum rmap_compile_rets route_map_delete_match(struct route_map_index *index,
					      const char *match_name,
					      const char *match_arg,
					      route_map_event_t type)
{
	struct route_map_rule *rule;
	const struct route_map_rule_cmd *cmd;
	const char *rule_key;

	cmd = route_map_lookup_match(match_name);
	if (cmd == NULL)
		return RMAP_RULE_MISSING;

	for (rule = index->match_list.head; rule; rule = rule->next)
		if (rule->cmd == cmd && (rulecmp(rule->rule_str, match_arg) == 0
					 || match_arg == NULL)) {
			/* Execute event hook. */
			if (route_map_master.event_hook) {
				(*route_map_master.event_hook)(index->map->name);
				route_map_notify_dependencies(
					index->map->name,
					RMAP_EVENT_CALL_ADDED);
			}
			if (cmd->func_get_rmap_rule_key)
				rule_key = (*cmd->func_get_rmap_rule_key)
					   (rule->value);
			else
				rule_key = match_arg;

			if (type != RMAP_EVENT_MATCH_DELETED && rule_key)
				route_map_upd8_dependency(type, rule_key,
						index->map->name);

			route_map_rule_delete(&index->match_list, rule);

			/* If IPv4 or IPv6 prefix-list match criteria
			 * has been delete from the route-map index, update
			 * the route-map's prefix table.
			 */
			if (IS_RULE_IPv4_PREFIX_LIST(match_name)) {
				route_map_pfx_tbl_update(
					RMAP_EVENT_PLIST_DELETED, index, AFI_IP,
					match_arg);
			} else if (IS_RULE_IPv6_PREFIX_LIST(match_name)) {
				route_map_pfx_tbl_update(
					RMAP_EVENT_PLIST_DELETED, index,
					AFI_IP6, match_arg);
			}

			return RMAP_COMPILE_SUCCESS;
		}
	/* Can't find matched rule. */
	return RMAP_RULE_MISSING;
}

/* Add route-map set statement to the route map. */
enum rmap_compile_rets route_map_add_set(struct route_map_index *index,
					 const char *set_name,
					 const char *set_arg)
{
	struct route_map_rule *rule;
	struct route_map_rule *next;
	const struct route_map_rule_cmd *cmd;
	void *compile;

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
		if (rule->cmd == cmd)
			route_map_rule_delete(&index->set_list, rule);
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
		(*route_map_master.event_hook)(index->map->name);
		route_map_notify_dependencies(index->map->name,
					      RMAP_EVENT_CALL_ADDED);
	}
	return RMAP_COMPILE_SUCCESS;
}

/* Delete route map set rule. */
enum rmap_compile_rets route_map_delete_set(struct route_map_index *index,
					    const char *set_name,
					    const char *set_arg)
{
	struct route_map_rule *rule;
	const struct route_map_rule_cmd *cmd;

	cmd = route_map_lookup_set(set_name);
	if (cmd == NULL)
		return RMAP_RULE_MISSING;

	for (rule = index->set_list.head; rule; rule = rule->next)
		if ((rule->cmd == cmd) && (rulecmp(rule->rule_str, set_arg) == 0
					   || set_arg == NULL)) {
			route_map_rule_delete(&index->set_list, rule);
			/* Execute event hook. */
			if (route_map_master.event_hook) {
				(*route_map_master.event_hook)(index->map->name);
				route_map_notify_dependencies(
					index->map->name,
					RMAP_EVENT_CALL_ADDED);
			}
			return RMAP_COMPILE_SUCCESS;
		}
	/* Can't find matched rule. */
	return RMAP_RULE_MISSING;
}

static enum route_map_cmd_result_t
route_map_apply_match(struct route_map_rule_list *match_list,
		      const struct prefix *prefix, void *object)
{
	enum route_map_cmd_result_t ret = RMAP_NOMATCH;
	struct route_map_rule *match;
	bool is_matched = false;


	/* Check all match rule and if there is no match rule, go to the
	   set statement. */
	if (!match_list->head)
		ret = RMAP_MATCH;
	else {
		for (match = match_list->head; match; match = match->next) {
			/*
			 * Try each match statement. If any match does not
			 * return RMAP_MATCH or RMAP_NOOP, return.
			 * Otherwise continue on to next match statement.
			 * All match statements must MATCH for
			 * end-result to be a match.
			 * (Exception:If match stmts result in a mix of
			 * MATCH/NOOP, then also end-result is a match)
			 * If all result in NOOP, end-result is NOOP.
			 */
			ret = (*match->cmd->func_apply)(match->value, prefix,
							object);

			/*
			 * If the consolidated result of func_apply is:
			 *   -----------------------------------------------
			 *   |  MATCH  | NOMATCH  |  NOOP   |  Final Result |
			 *   ------------------------------------------------
			 *   |   yes   |   yes    |  yes    |     NOMATCH   |
			 *   |   no    |   no     |  yes    |     NOOP      |
			 *   |   yes   |   no     |  yes    |     MATCH     |
			 *   |   no    |   yes    |  yes    |     NOMATCH   |
			 *   |-----------------------------------------------
			 *
			 *  Traditionally, all rules within route-map
			 *  should match for it to MATCH.
			 *  If there are noops within the route-map rules,
			 *  it follows the above matrix.
			 *
			 *   Eg: route-map rm1 permit 10
			 *         match rule1
			 *         match rule2
			 *         match rule3
			 *         ....
			 *       route-map rm1 permit 20
			 *         match ruleX
			 *         match ruleY
			 *         ...
			 */

			switch (ret) {
			case RMAP_MATCH:
				is_matched = true;
				break;

			case RMAP_NOMATCH:
				return ret;

			case RMAP_NOOP:
				if (is_matched)
					ret = RMAP_MATCH;
				break;

			case RMAP_OKAY:
			case RMAP_ERROR:
				break;
			}

		}
	}
	return ret;
}

static struct list *route_map_get_index_list(struct route_node **rn,
					     const struct prefix *prefix,
					     struct route_table *table)
{
	struct route_node *tmp_rn = NULL;

	if (!(*rn)) {
		*rn = route_node_match(table, prefix);

		if (!(*rn))
			return NULL;

		if ((*rn)->info)
			return (struct list *)((*rn)->info);

		/* If rn->info is NULL, get the parent.
		 * Store the rn in tmp_rn and unlock it later.
		 */
		tmp_rn = *rn;
	}

	do {
		*rn = (*rn)->parent;
		if (tmp_rn)
			route_unlock_node(tmp_rn);

		if (!(*rn))
			break;

		if ((*rn)->info) {
			route_lock_node(*rn);
			return (struct list *)((*rn)->info);
		}
	} while (!(*rn)->info);

	return NULL;
}

/*
 * This function returns the route-map index that best matches the prefix.
 */
static struct route_map_index *
route_map_get_index(struct route_map *map, const struct prefix *prefix,
		    void *object, enum route_map_cmd_result_t *match_ret)
{
	enum route_map_cmd_result_t ret = RMAP_NOMATCH;
	struct list *candidate_rmap_list = NULL;
	struct route_node *rn = NULL;
	struct listnode *ln = NULL, *nn = NULL;
	struct route_map_index *index = NULL, *best_index = NULL;
	struct route_map_index *head_index = NULL;
	struct route_table *table = NULL;

	/* Route-map optimization relies on LPM lookups of the prefix to reduce
	 * the amount of route-map clauses a given prefix needs to be processed
	 * against. These LPM trees are IPv4/IPv6-specific and prefix->family
	 * must be AF_INET or AF_INET6 in order for the lookup to succeed. So if
	 * the AF doesn't line up with the LPM trees, skip the optimization.
	 */
	if (map->optimization_disabled) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"Skipping route-map optimization for route-map: %s, pfx: %pFX, family: %d",
				map->name, prefix, prefix->family);
		return map->head;
	}

	if (prefix->family == AF_INET)
		table = map->ipv4_prefix_table;
	else
		table = map->ipv6_prefix_table;

	do {
		candidate_rmap_list =
			route_map_get_index_list(&rn, prefix, table);
		if (!rn)
			break;

		/* If the index at the head of the list is of seq higher
		 * than that in best_index, ignore the list and get the
		 * parent node's list.
		 */
		head_index = (struct route_map_index *)(listgetdata(
			listhead(candidate_rmap_list)));
		if (best_index && head_index
		    && (best_index->pref < head_index->pref)) {
			route_unlock_node(rn);
			continue;
		}

		for (ALL_LIST_ELEMENTS(candidate_rmap_list, ln, nn, index)) {
			/* If the index is of seq higher than that in
			 * best_index, ignore the list and get the parent
			 * node's list.
			 */
			if (best_index && (best_index->pref < index->pref))
				break;

			ret = route_map_apply_match(&index->match_list, prefix,
						    object);

			if (ret == RMAP_MATCH) {
				*match_ret = ret;
				best_index = index;
				break;
			} else if (ret == RMAP_NOOP) {
				/*
				 * If match_ret is denymatch, even if we see
				 * more noops, we retain this return value and
				 * return this eventually if there are no
				 * matches.
				 * If a best match route-map index already
				 * exists, do not reset the match_ret.
				 */
				if (!best_index && (*match_ret != RMAP_NOMATCH))
					*match_ret = ret;
			} else {
				/*
				 * ret is RMAP_NOMATCH.
				 * If a best match route-map index already
				 * exists, do not reset the match_ret.
				 */
				if (!best_index)
					*match_ret = ret;
			}
		}

		route_unlock_node(rn);

	} while (rn);

	return best_index;
}

static int route_map_candidate_list_cmp(struct route_map_index *idx1,
					struct route_map_index *idx2)
{
	return idx1->pref - idx2->pref;
}

/*
 * This function adds the route-map index into the default route's
 * route-node in the route-map's IPv4/IPv6 prefix-table.
 */
static void route_map_pfx_table_add_default(afi_t afi,
					    struct route_map_index *index)
{
	struct route_node *rn = NULL;
	struct list *rmap_candidate_list = NULL;
	struct prefix p;
	bool updated_rn = false;
	struct route_table *table = NULL;

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);
	p.prefixlen = 0;

	if (p.family == AF_INET)
		table = index->map->ipv4_prefix_table;
	else
		table = index->map->ipv6_prefix_table;

	/* Add default route to table */
	rn = route_node_get(table, &p);

	if (!rn)
		return;

	if (!rn->info) {
		rmap_candidate_list = list_new();
		rmap_candidate_list->cmp =
			(int (*)(void *, void *))route_map_candidate_list_cmp;
		rn->info = rmap_candidate_list;
	} else {
		rmap_candidate_list = (struct list *)rn->info;
		updated_rn = true;
	}

	listnode_add_sort_nodup(rmap_candidate_list, index);
	if (updated_rn)
		route_unlock_node(rn);
}

/*
 * This function removes the route-map index from the default route's
 * route-node in the route-map's IPv4/IPv6 prefix-table.
 */
static void route_map_pfx_table_del_default(afi_t afi,
					    struct route_map_index *index)
{
	struct route_node *rn = NULL;
	struct list *rmap_candidate_list = NULL;
	struct prefix p;
	struct route_table *table = NULL;

	memset(&p, 0, sizeof(p));
	p.family = afi2family(afi);
	p.prefixlen = 0;

	if (p.family == AF_INET)
		table = index->map->ipv4_prefix_table;
	else
		table = index->map->ipv6_prefix_table;

	/* Remove RMAP index from default route in table */
	rn = route_node_lookup(table, &p);
	if (!rn || !rn->info)
		return;

	rmap_candidate_list = (struct list *)rn->info;

	listnode_delete(rmap_candidate_list, index);

	if (listcount(rmap_candidate_list) == 0) {
		list_delete(&rmap_candidate_list);
		rn->info = NULL;
		route_unlock_node(rn);
	}
	route_unlock_node(rn);
}

/*
 * This function adds the route-map index to the route-node for
 * the prefix-entry in the route-map's IPv4/IPv6 prefix-table.
 */
static void route_map_pfx_table_add(struct route_table *table,
				    struct route_map_index *index,
				    struct prefix_list_entry *pentry)
{
	struct route_node *rn = NULL;
	struct list *rmap_candidate_list = NULL;
	bool updated_rn = false;

	rn = route_node_get(table, &pentry->prefix);
	if (!rn)
		return;

	if (!rn->info) {
		rmap_candidate_list = list_new();
		rmap_candidate_list->cmp =
			(int (*)(void *, void *))route_map_candidate_list_cmp;
		rn->info = rmap_candidate_list;
	} else {
		rmap_candidate_list = (struct list *)rn->info;
		updated_rn = true;
	}

	listnode_add_sort_nodup(rmap_candidate_list, index);
	if (updated_rn)
		route_unlock_node(rn);
}

/*
 * This function removes the route-map index from the route-node for
 * the prefix-entry in the route-map's IPv4/IPv6 prefix-table.
 */
static void route_map_pfx_table_del(struct route_table *table,
				    struct route_map_index *index,
				    struct prefix_list_entry *pentry)
{
	struct route_node *rn = NULL;
	struct list *rmap_candidate_list = NULL;

	rn = route_node_lookup(table, &pentry->prefix);
	if (!rn || !rn->info)
		return;

	rmap_candidate_list = (struct list *)rn->info;

	listnode_delete(rmap_candidate_list, index);

	if (listcount(rmap_candidate_list) == 0) {
		list_delete(&rmap_candidate_list);
		rn->info = NULL;
		route_unlock_node(rn);
	}
	route_unlock_node(rn);
}

/* This function checks for the presence of an IPv4 prefix-list
 * match rule in the given route-map index.
 */
static bool route_map_is_ip_pfx_list_rule_present(struct route_map_index *index)
{
	struct route_map_rule_list *match_list = NULL;
	struct route_map_rule *rule = NULL;

	match_list = &index->match_list;
	for (rule = match_list->head; rule; rule = rule->next)
		if (IS_RULE_IPv4_PREFIX_LIST(rule->cmd->str))
			return true;

	return false;
}

/* This function checks for the presence of an IPv6 prefix-list
 * match rule in the given route-map index.
 */
static bool
route_map_is_ipv6_pfx_list_rule_present(struct route_map_index *index)
{
	struct route_map_rule_list *match_list = NULL;
	struct route_map_rule *rule = NULL;

	match_list = &index->match_list;
	for (rule = match_list->head; rule; rule = rule->next)
		if (IS_RULE_IPv6_PREFIX_LIST(rule->cmd->str))
			return true;

	return false;
}

/* This function does the following:
 * 1) If plist_name is not present, search for a IPv4 or IPv6 prefix-list
 *    match clause (based on the afi passed to this foo) and get the
 *    prefix-list name.
 * 2) Look up the prefix-list using the name.
 * 3) If the prefix-list is not found then, add the index to the IPv4/IPv6
 *    default-route's node in the trie (based on the afi passed to this foo).
 * 4) If the prefix-list is found then, remove the index from the IPv4/IPv6
 *    default-route's node in the trie (based on the afi passed to this foo).
 * 5) If a prefix-entry is passed then, create a route-node for this entry and
 *    add this index to the route-node.
 * 6) If prefix-entry is not passed then, for every prefix-entry in the
 *    prefix-list, create a route-node for this entry and
 *    add this index to the route-node.
 */
static void route_map_add_plist_entries(afi_t afi,
					struct route_map_index *index,
					const char *plist_name,
					struct prefix_list_entry *entry)
{
	struct route_map_rule_list *match_list = NULL;
	struct route_map_rule *match = NULL;
	struct prefix_list *plist = NULL;
	struct prefix_list_entry *pentry = NULL;
	bool plist_rule_is_present = false;

	if (!plist_name) {
		match_list = &index->match_list;

		for (match = match_list->head; match; match = match->next) {
			if (afi == AFI_IP) {
				if (IS_RULE_IPv4_PREFIX_LIST(match->cmd->str)) {
					plist_rule_is_present = true;
					break;
				}
			} else {
				if (IS_RULE_IPv6_PREFIX_LIST(match->cmd->str)) {
					plist_rule_is_present = true;
					break;
				}
			}
		}

		if (plist_rule_is_present)
			plist = prefix_list_lookup(afi, match->rule_str);
	} else {
		plist = prefix_list_lookup(afi, plist_name);
	}

	if (!plist) {
		route_map_pfx_table_add_default(afi, index);
		return;
	}

	/* Default entry should be deleted only if the first entry of the
	 * prefix-list is created.
	 */
	if (entry) {
		if (plist->count == 1)
			route_map_pfx_table_del_default(afi, index);
	} else {
		route_map_pfx_table_del_default(afi, index);
	}

	if (entry) {
		if (afi == AFI_IP) {
			route_map_pfx_table_add(index->map->ipv4_prefix_table,
						index, entry);
		} else {
			route_map_pfx_table_add(index->map->ipv6_prefix_table,
						index, entry);
		}
	} else {
		for (pentry = plist->head; pentry; pentry = pentry->next) {
			if (afi == AFI_IP) {
				route_map_pfx_table_add(
					index->map->ipv4_prefix_table, index,
					pentry);
			} else {
				route_map_pfx_table_add(
					index->map->ipv6_prefix_table, index,
					pentry);
			}
		}
	}
}

/* This function does the following:
 * 1) If plist_name is not present, search for a IPv4 or IPv6 prefix-list
 *    match clause (based on the afi passed to this foo) and get the
 *    prefix-list name.
 * 2) Look up the prefix-list using the name.
 * 3) If the prefix-list is not found then, delete the index from the IPv4/IPv6
 *    default-route's node in the trie (based on the afi passed to this foo).
 * 4) If a prefix-entry is passed then, remove this index from the route-node
 *    for the prefix in this prefix-entry.
 * 5) If prefix-entry is not passed then, for every prefix-entry in the
 *    prefix-list, remove this index from the route-node
 *    for the prefix in this prefix-entry.
 */
static void route_map_del_plist_entries(afi_t afi,
					struct route_map_index *index,
					const char *plist_name,
					struct prefix_list_entry *entry)
{
	struct route_map_rule_list *match_list = NULL;
	struct route_map_rule *match = NULL;
	struct prefix_list *plist = NULL;
	struct prefix_list_entry *pentry = NULL;
	bool plist_rule_is_present = false;

	if (!plist_name) {
		match_list = &index->match_list;

		for (match = match_list->head; match; match = match->next) {
			if (afi == AFI_IP) {
				if (IS_RULE_IPv4_PREFIX_LIST(match->cmd->str)) {
					plist_rule_is_present = true;
					break;
				}
			} else {
				if (IS_RULE_IPv6_PREFIX_LIST(match->cmd->str)) {
					plist_rule_is_present = true;
					break;
				}
			}
		}

		if (plist_rule_is_present)
			plist = prefix_list_lookup(afi, match->rule_str);
	} else {
		plist = prefix_list_lookup(afi, plist_name);
	}

	if (!plist) {
		route_map_pfx_table_del_default(afi, index);
		return;
	}

	if (entry) {
		if (afi == AFI_IP) {
			route_map_pfx_table_del(index->map->ipv4_prefix_table,
						index, entry);
		} else {
			route_map_pfx_table_del(index->map->ipv6_prefix_table,
						index, entry);
		}
	} else {
		for (pentry = plist->head; pentry; pentry = pentry->next) {
			if (afi == AFI_IP) {
				route_map_pfx_table_del(
					index->map->ipv4_prefix_table, index,
					pentry);
			} else {
				route_map_pfx_table_del(
					index->map->ipv6_prefix_table, index,
					pentry);
			}
		}
	}
}

/*
 * This function handles the cases where a prefix-list is added/removed
 * as a match command from a particular route-map index.
 * It updates the prefix-table of the route-map accordingly.
 */
static void route_map_trie_update(afi_t afi, route_map_event_t event,
				  struct route_map_index *index,
				  const char *plist_name)
{
	if (event == RMAP_EVENT_PLIST_ADDED) {
		if (afi == AFI_IP) {
			if (!route_map_is_ipv6_pfx_list_rule_present(index)) {
				route_map_pfx_table_del_default(AFI_IP6, index);
				route_map_add_plist_entries(afi, index,
							    plist_name, NULL);
			} else {
				route_map_del_plist_entries(AFI_IP6, index,
							    NULL, NULL);
			}
		} else {
			if (!route_map_is_ip_pfx_list_rule_present(index)) {
				route_map_pfx_table_del_default(AFI_IP, index);
				route_map_add_plist_entries(afi, index,
							    plist_name, NULL);
			} else {
				route_map_del_plist_entries(AFI_IP, index, NULL,
							    NULL);
			}
		}
	} else if (event == RMAP_EVENT_PLIST_DELETED) {
		if (afi == AFI_IP) {
			route_map_del_plist_entries(afi, index, plist_name,
						    NULL);

			/* If IPv6 prefix-list match rule is not present,
			 * add this index to the IPv4 default route's trie
			 * node.
			 * Also, add this index to the trie nodes created
			 * for each of the prefix-entries within the IPv6
			 * prefix-list, if the IPv6 prefix-list match rule
			 * is present. Else, add this index to the IPv6
			 * default route's trie node.
			 */
			if (!route_map_is_ipv6_pfx_list_rule_present(index))
				route_map_pfx_table_add_default(afi, index);

			route_map_add_plist_entries(AFI_IP6, index, NULL, NULL);
		} else {
			route_map_del_plist_entries(afi, index, plist_name,
						    NULL);

			/* If IPv4 prefix-list match rule is not present,
			 * add this index to the IPv6 default route's trie
			 * node.
			 * Also, add this index to the trie nodes created
			 * for each of the prefix-entries within the IPv4
			 * prefix-list, if the IPv4 prefix-list match rule
			 * is present. Else, add this index to the IPv4
			 * default route's trie node.
			 */
			if (!route_map_is_ip_pfx_list_rule_present(index))
				route_map_pfx_table_add_default(afi, index);

			route_map_add_plist_entries(AFI_IP, index, NULL, NULL);
		}
	}
}

/*
 * This function handles the cases where a route-map index and
 * prefix-list is added/removed.
 * It updates the prefix-table of the route-map accordingly.
 */
static void route_map_pfx_tbl_update(route_map_event_t event,
				     struct route_map_index *index, afi_t afi,
				     const char *plist_name)
{
	if (!index)
		return;

	if (event == RMAP_EVENT_INDEX_ADDED) {
		route_map_pfx_table_add_default(AFI_IP, index);
		route_map_pfx_table_add_default(AFI_IP6, index);
		return;
	}

	if (event == RMAP_EVENT_INDEX_DELETED) {
		route_map_pfx_table_del_default(AFI_IP, index);
		route_map_pfx_table_del_default(AFI_IP6, index);

		return;
	}

	/* Handle prefix-list match rule addition/deletion.
	 */
	route_map_trie_update(afi, event, index, plist_name);
}

/*
 * This function handles the cases where a new prefix-entry is added to
 * a prefix-list or, an existing prefix-entry is removed from the prefix-list.
 * It updates the prefix-table of the route-map accordingly.
 */
static void route_map_pentry_update(route_map_event_t event,
				    const char *plist_name,
				    struct route_map_index *index,
				    struct prefix_list_entry *pentry)
{
	struct prefix_list *plist = NULL;
	afi_t afi;
	unsigned char family = pentry->prefix.family;

	if (family == AF_INET) {
		afi = AFI_IP;
		plist = prefix_list_lookup(AFI_IP, plist_name);
	} else {
		afi = AFI_IP6;
		plist = prefix_list_lookup(AFI_IP6, plist_name);
	}

	if (event == RMAP_EVENT_PLIST_ADDED) {
		if (afi == AFI_IP) {
			if (!route_map_is_ipv6_pfx_list_rule_present(index))
				route_map_add_plist_entries(afi, index,
							    plist_name, pentry);
		} else {
			if (!route_map_is_ip_pfx_list_rule_present(index))
				route_map_add_plist_entries(afi, index,
							    plist_name, pentry);
		}
	} else if (event == RMAP_EVENT_PLIST_DELETED) {
		route_map_del_plist_entries(afi, index, plist_name, pentry);

		if (plist->count == 1) {
			if (afi == AFI_IP) {
				if (!route_map_is_ipv6_pfx_list_rule_present(
					    index))
					route_map_pfx_table_add_default(afi,
									index);
			} else {
				if (!route_map_is_ip_pfx_list_rule_present(
					    index))
					route_map_pfx_table_add_default(afi,
									index);
			}
		}
	}
}

static void route_map_pentry_process_dependency(struct hash_bucket *bucket,
						void *data)
{
	char *rmap_name = NULL;
	struct route_map *rmap = NULL;
	struct route_map_index *index = NULL;
	struct route_map_rule_list *match_list = NULL;
	struct route_map_rule *match = NULL;
	struct route_map_dep_data *dep_data = NULL;
	struct route_map_pentry_dep *pentry_dep =
		(struct route_map_pentry_dep *)data;
	unsigned char family = pentry_dep->pentry->prefix.family;

	dep_data = (struct route_map_dep_data *)bucket->data;
	if (!dep_data)
		return;

	rmap_name = dep_data->rname;
	rmap = route_map_lookup_by_name(rmap_name);
	if (!rmap || !rmap->head)
		return;

	for (index = rmap->head; index; index = index->next) {
		match_list = &index->match_list;

		if (!match_list)
			continue;

		for (match = match_list->head; match; match = match->next) {
			if (strcmp(match->rule_str, pentry_dep->plist_name)
			    == 0) {
				if (IS_RULE_IPv4_PREFIX_LIST(match->cmd->str)
				    && family == AF_INET) {
					route_map_pentry_update(
						pentry_dep->event,
						pentry_dep->plist_name, index,
						pentry_dep->pentry);
				} else if (IS_RULE_IPv6_PREFIX_LIST(
						   match->cmd->str)
					   && family == AF_INET6) {
					route_map_pentry_update(
						pentry_dep->event,
						pentry_dep->plist_name, index,
						pentry_dep->pentry);
				}
			}
		}
	}
}

void route_map_notify_pentry_dependencies(const char *affected_name,
					  struct prefix_list_entry *pentry,
					  route_map_event_t event)
{
	struct route_map_dep *dep = NULL;
	struct hash *upd8_hash = NULL;
	struct route_map_pentry_dep pentry_dep;

	if (!affected_name || !pentry)
		return;

	upd8_hash = route_map_get_dep_hash(event);
	if (!upd8_hash)
		return;

	dep = (struct route_map_dep *)hash_get(upd8_hash, (void *)affected_name,
					       NULL);
	if (dep) {
		if (!dep->this_hash)
			dep->this_hash = upd8_hash;

		memset(&pentry_dep, 0, sizeof(pentry_dep));
		pentry_dep.pentry = pentry;
		pentry_dep.plist_name = affected_name;
		pentry_dep.event = event;

		hash_iterate(dep->dep_rmap_hash,
			     route_map_pentry_process_dependency,
			     (void *)&pentry_dep);
	}
}

/* Apply route map's each index to the object.

   The matrix for a route-map looks like this:
   (note, this includes the description for the "NEXT"
   and "GOTO" frobs now

	   |   Match   |   No Match   | No op
	   |-----------|--------------|-------
    permit |   action  |     cont     | cont.
	   |           | default:deny | default:permit
    -------------------+-----------------------
	   |   deny    |     cont     | cont.
    deny   |           | default:deny | default:permit
	   |-----------|--------------|--------

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
     on-match goto n  - If this clause is matched, then the set statements
			are executed and then we goto the nth clause, or the
			first clause greater than this. In order to ensure
			route-maps *always* exit, you cannot jump backwards.
			Sorry ;)

   We need to make sure our route-map processing matches the above
*/
route_map_result_t route_map_apply_ext(struct route_map *map,
				       const struct prefix *prefix,
				       void *match_object, void *set_object,
				       int *pref)
{
	static int recursion = 0;
	enum route_map_cmd_result_t match_ret = RMAP_NOMATCH;
	route_map_result_t ret = RMAP_PERMITMATCH;
	struct route_map_index *index = NULL;
	struct route_map_rule *set = NULL;
	bool skip_match_clause = false;

	if (recursion > RMAP_RECURSION_LIMIT) {
		if (map)
			map->applied++;

		flog_warn(
			EC_LIB_RMAP_RECURSION_LIMIT,
			"route-map recursion limit (%d) reached, discarding route",
			RMAP_RECURSION_LIMIT);
		recursion = 0;
		return RMAP_DENYMATCH;
	}

	if (map == NULL || map->head == NULL) {
		if (map)
			map->applied++;
		ret = RMAP_DENYMATCH;
		goto route_map_apply_end;
	}

	map->applied++;

	if (prefix->family == AF_EVPN) {
		index = map->head;
	} else {
		skip_match_clause = true;
		index = route_map_get_index(map, prefix, match_object,
					    &match_ret);
	}

	if (index) {
		index->applied++;
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
			zlog_debug(
				"Best match route-map: %s, sequence: %d for pfx: %pFX, result: %s",
				map->name, index->pref, prefix,
				route_map_cmd_result_str(match_ret));
	} else {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
			zlog_debug(
				"No best match sequence for pfx: %pFX in route-map: %s, result: %s",
				prefix, map->name,
				route_map_cmd_result_str(match_ret));
		/*
		 * No index matches this prefix. Return deny unless,
		 * match_ret = RMAP_NOOP.
		 */
		if (match_ret == RMAP_NOOP)
			ret = RMAP_PERMITMATCH;
		else
			ret = RMAP_DENYMATCH;
		goto route_map_apply_end;
	}

	for (; index; index = index->next) {
		if (!skip_match_clause) {
			index->applied++;
			/* Apply this index. */
			match_ret = route_map_apply_match(&index->match_list,
							  prefix, match_object);
			if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP))) {
				zlog_debug(
					"Route-map: %s, sequence: %d, prefix: %pFX, result: %s",
					map->name, index->pref, prefix,
					route_map_cmd_result_str(match_ret));
			}
		} else
			skip_match_clause = false;


		/* Now we apply the matrix from above */
		if (match_ret == RMAP_NOOP)
			/*
			 * Do not change the return value. Retain the previous
			 * return value. Previous values can be:
			 * 1)permitmatch (if a nomatch was never
			 * seen before in this route-map.)
			 * 2)denymatch (if a nomatch was seen earlier in one
			 * of the previous sequences)
			 */

			/*
			 * 'cont' from matrix - continue to next route-map
			 * sequence
			 */
			continue;
		else if (match_ret == RMAP_NOMATCH) {

			/*
			 * The return value is now changed to denymatch.
			 * So from here on out, even if we see more noops,
			 * we retain this return value and return this
			 * eventually if there are no matches.
			 */
			ret = RMAP_DENYMATCH;

			/*
			 * 'cont' from matrix - continue to next route-map
			 * sequence
			 */
			continue;
		} else if (match_ret == RMAP_MATCH) {
			if (index->type == RMAP_PERMIT)
			/* 'action' */
			{
				/* Match succeeded, rmap is of type permit */
				ret = RMAP_PERMITMATCH;

				/* permit+match must execute sets */
				for (set = index->set_list.head; set;
				     set = set->next)
					/*
					 * set cmds return RMAP_OKAY or
					 * RMAP_ERROR. We do not care if
					 * set succeeded or not. So, ignore
					 * return code.
					 */
					(void)(*set->cmd->func_apply)(
						set->value, prefix, set_object);

				/* Call another route-map if available */
				if (index->nextrm) {
					struct route_map *nextrm =
						route_map_lookup_by_name(
							index->nextrm);

					if (nextrm) /* Target route-map found,
						       jump to it */
					{
						recursion++;
						ret = route_map_apply_ext(
							nextrm, prefix,
							match_object,
							set_object, NULL);
						recursion--;
					}

					/* If nextrm returned 'deny', finish. */
					if (ret == RMAP_DENYMATCH)
						goto route_map_apply_end;
				}

				switch (index->exitpolicy) {
				case RMAP_EXIT:
					goto route_map_apply_end;
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
						goto route_map_apply_end;
					}
				}
				}
			} else if (index->type == RMAP_DENY)
			/* 'deny' */
			{
				ret = RMAP_DENYMATCH;
				goto route_map_apply_end;
			}
		}
	}

route_map_apply_end:
	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Route-map: %s, prefix: %pFX, result: %s",
			   (map ? map->name : "null"), prefix,
			   route_map_result_str(ret));

	if (pref) {
		if (index != NULL && ret == RMAP_PERMITMATCH)
			*pref = index->pref;
		else
			*pref = 65536;
	}

	return (ret);
}

void route_map_add_hook(void (*func)(const char *))
{
	route_map_master.add_hook = func;
}

void route_map_delete_hook(void (*func)(const char *))
{
	route_map_master.delete_hook = func;
}

void route_map_event_hook(void (*func)(const char *name))
{
	route_map_master.event_hook = func;
}

/* Routines for route map dependency lists and dependency processing */
static bool route_map_rmap_hash_cmp(const void *p1, const void *p2)
{
	return strcmp(((const struct route_map_dep_data *)p1)->rname,
		      ((const struct route_map_dep_data *)p2)->rname)
	       == 0;
}

static bool route_map_dep_hash_cmp(const void *p1, const void *p2)
{

	return (strcmp(((const struct route_map_dep *)p1)->dep_name,
		       (const char *)p2)
		== 0);
}

static void route_map_clear_reference(struct hash_bucket *bucket, void *arg)
{
	struct route_map_dep *dep = bucket->data;
	struct route_map_dep_data *dep_data = NULL, tmp_dep_data;

	memset(&tmp_dep_data, 0, sizeof(tmp_dep_data));
	tmp_dep_data.rname = arg;
	dep_data = hash_release(dep->dep_rmap_hash, &tmp_dep_data);
	if (dep_data) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
			zlog_debug("Clearing reference for %s to %s count: %d",
				   dep->dep_name, tmp_dep_data.rname,
				   dep_data->refcnt);

		XFREE(MTYPE_ROUTE_MAP_NAME, dep_data->rname);
		XFREE(MTYPE_ROUTE_MAP_DEP_DATA, dep_data);
	}
	if (!dep->dep_rmap_hash->count) {
		dep = hash_release(dep->this_hash, (void *)dep->dep_name);
		hash_free(dep->dep_rmap_hash);
		XFREE(MTYPE_ROUTE_MAP_NAME, dep->dep_name);
		XFREE(MTYPE_ROUTE_MAP_DEP, dep);
	}
}

static void route_map_clear_all_references(char *rmap_name)
{
	int i;

	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Clearing references for %s", rmap_name);

	for (i = 1; i < ROUTE_MAP_DEP_MAX; i++) {
		hash_iterate(route_map_dep_hash[i], route_map_clear_reference,
			     (void *)rmap_name);
	}
}

static unsigned int route_map_dep_data_hash_make_key(const void *p)
{
	const struct route_map_dep_data *dep_data = p;

	return string_hash_make(dep_data->rname);
}

static void *route_map_dep_hash_alloc(void *p)
{
	char *dep_name = (char *)p;
	struct route_map_dep *dep_entry;

	dep_entry = XCALLOC(MTYPE_ROUTE_MAP_DEP, sizeof(struct route_map_dep));
	dep_entry->dep_name = XSTRDUP(MTYPE_ROUTE_MAP_NAME, dep_name);
	dep_entry->dep_rmap_hash =
		hash_create_size(8, route_map_dep_data_hash_make_key,
				 route_map_rmap_hash_cmp, "Route Map Dep Hash");
	dep_entry->this_hash = NULL;

	return dep_entry;
}

static void *route_map_name_hash_alloc(void *p)
{
	struct route_map_dep_data *dep_data = NULL, *tmp_dep_data = NULL;

	dep_data = XCALLOC(MTYPE_ROUTE_MAP_DEP_DATA,
			   sizeof(struct route_map_dep_data));
	tmp_dep_data = p;
	dep_data->rname = XSTRDUP(MTYPE_ROUTE_MAP_NAME, tmp_dep_data->rname);
	return dep_data;
}

static unsigned int route_map_dep_hash_make_key(const void *p)
{
	return (string_hash_make((char *)p));
}

static void route_map_print_dependency(struct hash_bucket *bucket, void *data)
{
	struct route_map_dep_data *dep_data = bucket->data;
	char *rmap_name = dep_data->rname;
	char *dep_name = data;

	zlog_debug("%s: Dependency for %s: %s", __func__, dep_name, rmap_name);
}

static int route_map_dep_update(struct hash *dephash, const char *dep_name,
				const char *rmap_name, route_map_event_t type)
{
	struct route_map_dep *dep = NULL;
	char *dname, *rname;
	int ret = 0;
	struct route_map_dep_data *dep_data = NULL, *ret_dep_data = NULL;
	struct route_map_dep_data tmp_dep_data;

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
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
			zlog_debug("Adding dependency for filter %s in route-map %s",
				   dep_name, rmap_name);
		dep = (struct route_map_dep *)hash_get(
			dephash, dname, route_map_dep_hash_alloc);
		if (!dep) {
			ret = -1;
			goto out;
		}

		if (!dep->this_hash)
			dep->this_hash = dephash;

		memset(&tmp_dep_data, 0, sizeof(tmp_dep_data));
		tmp_dep_data.rname = rname;
		dep_data = hash_lookup(dep->dep_rmap_hash, &tmp_dep_data);
		if (!dep_data)
			dep_data = hash_get(dep->dep_rmap_hash, &tmp_dep_data,
					    route_map_name_hash_alloc);

		dep_data->refcnt++;
		break;
	case RMAP_EVENT_PLIST_DELETED:
	case RMAP_EVENT_CLIST_DELETED:
	case RMAP_EVENT_ECLIST_DELETED:
	case RMAP_EVENT_ASLIST_DELETED:
	case RMAP_EVENT_LLIST_DELETED:
	case RMAP_EVENT_CALL_DELETED:
	case RMAP_EVENT_FILTER_DELETED:
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
			zlog_debug("Deleting dependency for filter %s in route-map %s",
				   dep_name, rmap_name);
		dep = (struct route_map_dep *)hash_get(dephash, dname, NULL);
		if (!dep) {
			goto out;
		}

		memset(&tmp_dep_data, 0, sizeof(tmp_dep_data));
		tmp_dep_data.rname = rname;
		dep_data = hash_lookup(dep->dep_rmap_hash, &tmp_dep_data);
		/*
		 * If dep_data is NULL then something has gone seriously
		 * wrong in route-map handling.  Note it and prevent
		 * the crash.
		 */
		if (!dep_data) {
			zlog_warn(
				"route-map dependency for route-map %s: %s is not correct",
				rmap_name, dep_name);
			goto out;
		}

		dep_data->refcnt--;

		if (!dep_data->refcnt) {
			ret_dep_data = hash_release(dep->dep_rmap_hash,
						    &tmp_dep_data);
			if (ret_dep_data) {
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      ret_dep_data->rname);
				XFREE(MTYPE_ROUTE_MAP_DEP_DATA, ret_dep_data);
			}
		}

		if (!dep->dep_rmap_hash->count) {
			dep = hash_release(dephash, dname);
			hash_free(dep->dep_rmap_hash);
			XFREE(MTYPE_ROUTE_MAP_NAME, dep->dep_name);
			XFREE(MTYPE_ROUTE_MAP_DEP, dep);
		}
		break;
	case RMAP_EVENT_SET_ADDED:
	case RMAP_EVENT_SET_DELETED:
	case RMAP_EVENT_SET_REPLACED:
	case RMAP_EVENT_MATCH_ADDED:
	case RMAP_EVENT_MATCH_DELETED:
	case RMAP_EVENT_MATCH_REPLACED:
	case RMAP_EVENT_INDEX_ADDED:
	case RMAP_EVENT_INDEX_DELETED:
		break;
	}

	if (dep) {
		if (CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP))
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
	case RMAP_EVENT_MATCH_ADDED:
	case RMAP_EVENT_MATCH_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_RMAP];
		break;
	case RMAP_EVENT_FILTER_ADDED:
	case RMAP_EVENT_FILTER_DELETED:
		upd8_hash = route_map_dep_hash[ROUTE_MAP_DEP_FILTER];
		break;
	/*
	 * Should we actually be ignoring these?
	 * I am not sure but at this point in time, let
	 * us get them into this switch and we can peel
	 * them into the appropriate place in the future
	 */
	case RMAP_EVENT_SET_ADDED:
	case RMAP_EVENT_SET_DELETED:
	case RMAP_EVENT_SET_REPLACED:
	case RMAP_EVENT_MATCH_REPLACED:
	case RMAP_EVENT_INDEX_ADDED:
	case RMAP_EVENT_INDEX_DELETED:
		upd8_hash = NULL;
		break;
	}
	return (upd8_hash);
}

static void route_map_process_dependency(struct hash_bucket *bucket, void *data)
{
	struct route_map_dep_data *dep_data = NULL;
	char *rmap_name = NULL;

	dep_data = bucket->data;
	rmap_name = dep_data->rname;

	if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
		zlog_debug("Notifying %s of dependency", rmap_name);
	if (route_map_master.event_hook)
		(*route_map_master.event_hook)(rmap_name);
}

void route_map_upd8_dependency(route_map_event_t type, const char *arg,
			       const char *rmap_name)
{
	struct hash *upd8_hash = NULL;

	if ((upd8_hash = route_map_get_dep_hash(type))) {
		route_map_dep_update(upd8_hash, arg, rmap_name, type);

		if (type == RMAP_EVENT_CALL_ADDED) {
			/* Execute hook. */
			if (route_map_master.add_hook)
				(*route_map_master.add_hook)(rmap_name);
		} else if (type == RMAP_EVENT_CALL_DELETED) {
			/* Execute hook. */
			if (route_map_master.delete_hook)
				(*route_map_master.delete_hook)(rmap_name);
		}
	}
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

		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)))
			zlog_debug("Filter %s updated", dep->dep_name);
		hash_iterate(dep->dep_rmap_hash, route_map_process_dependency,
			     (void *)event);
	}

	XFREE(MTYPE_ROUTE_MAP_NAME, name);
}

/* VTY related functions. */
static void clear_route_map_helper(struct route_map *map)
{
	struct route_map_index *index;

	map->applied_clear = map->applied;
	for (index = map->head; index; index = index->next)
		index->applied_clear = index->applied;
}

DEFPY (rmap_clear_counters,
       rmap_clear_counters_cmd,
       "clear route-map counters [RMAP_NAME$rmapname]",
       CLEAR_STR
       "route-map information\n"
       "counters associated with the specified route-map\n"
       "route-map name\n")
{
	struct route_map *map;

	if (rmapname) {
		map = route_map_lookup_by_name(rmapname);

		if (map)
			clear_route_map_helper(map);
		else {
			vty_out(vty, "%s: 'route-map %s' not found\n",
				frr_protonameinst, rmapname);
			return CMD_SUCCESS;
		}
	} else {
		for (map = route_map_master.head; map; map = map->next)
			clear_route_map_helper(map);
	}

	return CMD_SUCCESS;

}

DEFUN_NOSH (rmap_show_name,
            rmap_show_name_cmd,
            "show route-map [WORD] [json]",
            SHOW_STR
            "route-map information\n"
            "route-map name\n"
            JSON_STR)
{
	bool uj = use_json(argc, argv);
	int idx = 0;
	const char *name = NULL;

	if (argv_find(argv, argc, "WORD", &idx))
		name = argv[idx]->arg;

	return vty_show_route_map(vty, name, uj);
}

DEFUN (rmap_show_unused,
       rmap_show_unused_cmd,
       "show route-map-unused",
       SHOW_STR
       "unused route-map information\n")
{
	return vty_show_unused_route_map(vty);
}

DEFPY (debug_rmap,
       debug_rmap_cmd,
       "debug route-map [detail]$detail",
       DEBUG_STR
       "Debug option set for route-maps\n"
       "Detailed output\n")
{
	if (!detail)
		SET_FLAG(rmap_debug, DEBUG_ROUTEMAP);
	else
		SET_FLAG(rmap_debug, DEBUG_ROUTEMAP | DEBUG_ROUTEMAP_DETAIL);

	return CMD_SUCCESS;
}

DEFPY (no_debug_rmap,
       no_debug_rmap_cmd,
       "no debug route-map [detail]$detail",
       NO_STR
       DEBUG_STR
       "Debug option set for route-maps\n"
       "Detailed output\n")
{
	if (!detail)
		UNSET_FLAG(rmap_debug, DEBUG_ROUTEMAP);
	else
		UNSET_FLAG(rmap_debug, DEBUG_ROUTEMAP | DEBUG_ROUTEMAP_DETAIL);

	return CMD_SUCCESS;
}

/* Debug node. */
static int rmap_config_write_debug(struct vty *vty);
static struct cmd_node rmap_debug_node = {
	.name = "route-map debug",
	.node = RMAP_DEBUG_NODE,
	.prompt = "",
	.config_write = rmap_config_write_debug,
};

void route_map_show_debug(struct vty *vty)
{
	if (CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP))
		vty_out(vty, "debug route-map\n");
}

/* Configuration write function. */
static int rmap_config_write_debug(struct vty *vty)
{
	int write = 0;

	if (CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP)) {
		vty_out(vty, "debug route-map\n");
		write++;
	}

	return write;
}

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
	struct route_map_rule_cmd_proxy *proxy;

	/* these 2 hash tables have INIT_HASH initializers, so the "default"
	 * state is "initialized & empty" => fini() followed by init() to
	 * return to that same state
	 */
	while ((proxy = rmap_cmd_name_pop(rmap_match_cmds)))
		(void)proxy;
	rmap_cmd_name_fini(rmap_match_cmds);
	rmap_cmd_name_init(rmap_match_cmds);

	while ((proxy = rmap_cmd_name_pop(rmap_set_cmds)))
		(void)proxy;
	rmap_cmd_name_fini(rmap_set_cmds);
	rmap_cmd_name_init(rmap_set_cmds);

	/*
	 * All protocols are setting these to NULL
	 * by default on shutdown( route_map_finish )
	 * Why are we making them do this work?
	 */
	route_map_master.add_hook = NULL;
	route_map_master.delete_hook = NULL;
	route_map_master.event_hook = NULL;

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

/* Increment the use_count counter while attaching the route map */
void route_map_counter_increment(struct route_map *map)
{
	if (map)
		map->use_count++;
}

/* Decrement the use_count counter while detaching the route map. */
void route_map_counter_decrement(struct route_map *map)
{
	if (map) {
		if (map->use_count <= 0)
			return;
		map->use_count--;
	}
}

DEFUN_HIDDEN(show_route_map_pfx_tbl, show_route_map_pfx_tbl_cmd,
	     "show route-map RMAP_NAME prefix-table",
	     SHOW_STR
	     "route-map\n"
	     "route-map name\n"
	     "internal prefix-table\n")
{
	const char *rmap_name = argv[2]->arg;
	struct route_map *rmap = NULL;
	struct route_table *rm_pfx_tbl4 = NULL;
	struct route_table *rm_pfx_tbl6 = NULL;
	struct route_node *rn = NULL, *prn = NULL;
	struct list *rmap_index_list = NULL;
	struct listnode *ln = NULL, *nln = NULL;
	struct route_map_index *index = NULL;
	uint8_t len = 54;

	vty_out(vty, "%s:\n", frr_protonameinst);
	rmap = route_map_lookup_by_name(rmap_name);
	if (rmap) {
		rm_pfx_tbl4 = rmap->ipv4_prefix_table;
		if (rm_pfx_tbl4) {
			vty_out(vty, "\n%s%43s%s\n", "IPv4 Prefix", "",
				"Route-map Index List");
			vty_out(vty, "%s%39s%s\n", "_______________", "",
				"____________________");
			for (rn = route_top(rm_pfx_tbl4); rn;
			     rn = route_next(rn)) {
				vty_out(vty, "    %pRN (%d)\n", rn,
					route_node_get_lock_count(rn));

				vty_out(vty, "(P) ");
				prn = rn->parent;
				if (prn) {
					vty_out(vty, "%pRN\n", prn);
				}

				vty_out(vty, "\n");
				rmap_index_list = (struct list *)rn->info;
				if (!rmap_index_list
				    || !listcount(rmap_index_list))
					vty_out(vty, "%*s%s\n", len, "", "-");
				else
					for (ALL_LIST_ELEMENTS(rmap_index_list,
							       ln, nln,
							       index)) {
						vty_out(vty, "%*s%s seq %d\n",
							len, "",
							index->map->name,
							index->pref);
					}
				vty_out(vty, "\n");
			}
		}

		rm_pfx_tbl6 = rmap->ipv6_prefix_table;
		if (rm_pfx_tbl6) {
			vty_out(vty, "\n%s%43s%s\n", "IPv6 Prefix", "",
				"Route-map Index List");
			vty_out(vty, "%s%39s%s\n", "_______________", "",
				"____________________");
			for (rn = route_top(rm_pfx_tbl6); rn;
			     rn = route_next(rn)) {
				vty_out(vty, "    %pRN (%d)\n", rn,
					route_node_get_lock_count(rn));

				vty_out(vty, "(P) ");
				prn = rn->parent;
				if (prn) {
					vty_out(vty, "%pRN\n", prn);
				}

				vty_out(vty, "\n");
				rmap_index_list = (struct list *)rn->info;
				if (!rmap_index_list
				    || !listcount(rmap_index_list))
					vty_out(vty, "%*s%s\n", len, "", "-");
				else
					for (ALL_LIST_ELEMENTS(rmap_index_list,
							       ln, nln,
							       index)) {
						vty_out(vty, "%*s%s seq %d\n",
							len, "",
							index->map->name,
							index->pref);
					}
				vty_out(vty, "\n");
			}
		}
	}

	vty_out(vty, "\n");
	return CMD_SUCCESS;
}

/* Initialization of route map vector. */
void route_map_init_new(bool in_backend)
{
	int i;

	route_map_master_hash =
		hash_create_size(8, route_map_hash_key_make, route_map_hash_cmp,
				 "Route Map Master Hash");

	for (i = 1; i < ROUTE_MAP_DEP_MAX; i++)
		route_map_dep_hash[i] = hash_create_size(
			8, route_map_dep_hash_make_key, route_map_dep_hash_cmp,
			"Route Map Dep Hash");

	UNSET_FLAG(rmap_debug, DEBUG_ROUTEMAP);

	if (!in_backend) {
		/* we do not want to handle config commands in the backend */
		route_map_cli_init();
	}

	/* Install route map top node. */
	install_node(&rmap_debug_node);

	/* Install route map commands. */
	install_element(CONFIG_NODE, &debug_rmap_cmd);
	install_element(CONFIG_NODE, &no_debug_rmap_cmd);

	/* Install show command */
	install_element(ENABLE_NODE, &rmap_clear_counters_cmd);

	install_element(ENABLE_NODE, &rmap_show_name_cmd);
	install_element(ENABLE_NODE, &rmap_show_unused_cmd);

	install_element(ENABLE_NODE, &debug_rmap_cmd);
	install_element(ENABLE_NODE, &no_debug_rmap_cmd);

	install_element(ENABLE_NODE, &show_route_map_pfx_tbl_cmd);
}

void route_map_init(void)
{
	route_map_init_new(false);
}
