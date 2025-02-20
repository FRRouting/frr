// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_redist.c
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
 */

#include <zebra.h>

#include "command.h"
#include "if.h"
#include "linklist.h"
#include "memory.h"
#include "prefix.h"
#include "routemap.h"
#include "stream.h"
#include "table.h"
#include "vty.h"
#include "srcdest_table.h"

#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_misc.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_route.h"
#include "isisd/isis_zebra.h"

DEFINE_MTYPE_STATIC(ISISD, ISIS_EXT_ROUTE, "ISIS redistributed route");
DEFINE_MTYPE_STATIC(ISISD, ISIS_EXT_INFO,  "ISIS redistributed route info");
DEFINE_MTYPE_STATIC(ISISD, ISIS_RMAP_NAME, "ISIS redistribute route-map name");
DEFINE_MTYPE_STATIC(ISISD, ISIS_REDISTRIBUTE, "ISIS redistribute");

static int redist_protocol(int family)
{
	if (family == AF_INET)
		return 0;
	if (family == AF_INET6)
		return 1;

	assert(!"Unsupported address family!");
	return 0;
}

afi_t afi_for_redist_protocol(int protocol)
{
	if (protocol == 0)
		return AFI_IP;
	if (protocol == 1)
		return AFI_IP6;

	assert(!"Unknown redist protocol!");
	return AFI_IP;
}

static struct route_table *get_ext_info(struct isis *i, int family)
{
	int protocol = redist_protocol(family);

	return i->ext_info[protocol];
}

static struct isis_redist *isis_redist_lookup(struct isis_area *area,
					      int family, int type, int level,
					      uint16_t table)
{
	int protocol = redist_protocol(family);
	struct listnode *node;
	struct isis_redist *red;

	if (area->redist_settings[protocol][type][level - 1]) {
		for (ALL_LIST_ELEMENTS_RO(area->redist_settings[protocol][type]
							       [level - 1],
					  node, red))
			if (red->table == table)
				return red;
	}
	return NULL;
}

static struct isis_redist *isis_redist_get(struct isis_area *area, int family,
					   int type, int level, uint16_t table)
{
	struct isis_redist *red;
	int protocol;

	red = isis_redist_lookup(area, family, type, level, table);
	if (red)
		return red;

	protocol = redist_protocol(family);
	if (area->redist_settings[protocol][type][level - 1] == NULL)
		area->redist_settings[protocol][type][level - 1] = list_new();

	red = XCALLOC(MTYPE_ISIS_REDISTRIBUTE, sizeof(struct isis_redist));
	red->table = table;

	listnode_add(area->redist_settings[protocol][type][level - 1], red);
	return red;
}

struct route_table *get_ext_reach(struct isis_area *area, int family, int level)
{
	int protocol = redist_protocol(family);

	return area->ext_reach[protocol][level - 1];
}

/* Install external reachability information into a
 * specific area for a specific level.
 * Schedule an lsp regenerate if necessary */
static void isis_redist_install(struct isis_area *area, int level,
				const struct prefix *p,
				const struct prefix_ipv6 *src_p,
				struct isis_ext_info *info)
{
	int family = p->family;
	struct route_table *er_table = get_ext_reach(area, family, level);
	struct route_node *er_node;

	if (!er_table) {
		zlog_warn(
			"%s: External reachability table of area %s is not initialized.",
			__func__, area->area_tag);
		return;
	}

	er_node = srcdest_rnode_get(er_table, p, src_p);
	if (er_node->info) {
		route_unlock_node(er_node);

		/* Don't update/reschedule lsp generation if nothing changed. */
		if (!memcmp(er_node->info, info, sizeof(*info)))
			return;
	} else {
		er_node->info = XMALLOC(MTYPE_ISIS_EXT_INFO, sizeof(*info));
	}

	memcpy(er_node->info, info, sizeof(*info));
	lsp_regenerate_schedule(area, level, 0);
}

/* Remove external reachability information from a
 * specific area for a specific level.
 * Schedule an lsp regenerate if necessary. */
static void isis_redist_uninstall(struct isis_area *area, int level,
				  const struct prefix *p,
				  const struct prefix_ipv6 *src_p)
{
	int family = p->family;
	struct route_table *er_table = get_ext_reach(area, family, level);
	struct route_node *er_node;

	if (!er_table) {
		zlog_warn(
			"%s: External reachability table of area %s is not initialized.",
			__func__, area->area_tag);
		return;
	}

	er_node = srcdest_rnode_lookup(er_table, p, src_p);
	if (!er_node)
		return;
	else
		route_unlock_node(er_node);

	if (!er_node->info)
		return;

	XFREE(MTYPE_ISIS_EXT_INFO, er_node->info);
	route_unlock_node(er_node);
	lsp_regenerate_schedule(area, level, 0);
}

/* Update external reachability info of area for a given level
 * and prefix, using the given redistribution settings. */
static void isis_redist_update_ext_reach(struct isis_area *area, int level,
					 struct isis_redist *redist,
					 const struct prefix *p,
					 const struct prefix_ipv6 *src_p,
					 struct isis_ext_info *info)
{
	struct isis_ext_info area_info;
	route_map_result_t map_ret;

	memcpy(&area_info, info, sizeof(area_info));
	area_info.metric = redist->metric;

	if (redist->map_name) {
		map_ret = route_map_apply(redist->map, p, &area_info);
		if (map_ret == RMAP_DENYMATCH)
			area_info.distance = 255;
	}

	/* Allow synthesized default routes only on always orignate */
	if (area_info.origin == DEFAULT_ROUTE
	    && redist->redist != DEFAULT_ORIGINATE_ALWAYS)
		area_info.distance = 255;

	if (area_info.distance < 255)
		isis_redist_install(area, level, p, src_p, &area_info);
	else
		isis_redist_uninstall(area, level, p, src_p);
}

static void isis_redist_ensure_default(struct isis *isis, int family)
{
	struct prefix p;
	struct route_table *ei_table = get_ext_info(isis, family);
	struct route_node *ei_node;
	struct isis_ext_info *info;

	if (family == AF_INET) {
		p.family = AF_INET;
		p.prefixlen = 0;
		memset(&p.u.prefix4, 0, sizeof(p.u.prefix4));
	} else if (family == AF_INET6) {
		p.family = AF_INET6;
		p.prefixlen = 0;
		memset(&p.u.prefix6, 0, sizeof(p.u.prefix6));
	} else
		assert(!"Unknown family!");

	ei_node = srcdest_rnode_get(ei_table, &p, NULL);
	if (ei_node->info) {
		route_unlock_node(ei_node);
		return;
	}

	ei_node->info =
		XCALLOC(MTYPE_ISIS_EXT_INFO, sizeof(struct isis_ext_info));

	info = ei_node->info;
	info->origin = DEFAULT_ROUTE;
	info->distance = 254;
	info->metric = MAX_WIDE_PATH_METRIC;
}

static int _isis_redist_table_is_present(const struct lyd_node *dnode, void *arg)
{
	struct isis_redist_table_present_args *rtda = arg;

	/* This entry is the caller, so skip it. */
	if (yang_dnode_get_uint16(dnode, "table") !=
	    (uint16_t)atoi(rtda->rtda_table))
		return YANG_ITER_CONTINUE;

	/* found */
	rtda->rtda_found = true;
	return YANG_ITER_CONTINUE;
}

static int _isis_redist_table_get_first_cb(const struct lyd_node *dnode,
					   void *arg)
{
	uint16_t *table = arg;

	*table = yang_dnode_get_uint16(dnode, "table");
	return YANG_ITER_STOP;
}

uint16_t isis_redist_table_get_first(const struct vty *vty,
				     struct isis_redist_table_present_args *rtda)
{
	uint16_t table = 0;

	yang_dnode_iterate(_isis_redist_table_get_first_cb, &table,
			   vty->candidate_config->dnode,
			   "%s/redistribute/%s[protocol='table'][level='%s']/table",
			   VTY_CURR_XPATH, rtda->rtda_ip, rtda->rtda_level);
	return table;
}

bool isis_redist_table_is_present(const struct vty *vty,
				  struct isis_redist_table_present_args *rtda)
{
	rtda->rtda_found = false;
	yang_dnode_iterate(_isis_redist_table_is_present, rtda,
			   vty->candidate_config->dnode,
			   "%s/redistribute/%s[protocol='table'][level='%s']/table",
			   VTY_CURR_XPATH, rtda->rtda_ip, rtda->rtda_level);

	return rtda->rtda_found;
}

/* Handle notification about route being added */
void isis_redist_add(struct isis *isis, int type, struct prefix *p,
		     struct prefix_ipv6 *src_p, uint8_t distance,
		     uint32_t metric, const route_tag_t tag, uint16_t table)
{
	int family = p->family;
	struct route_table *ei_table = get_ext_info(isis, family);
	struct route_node *ei_node;
	struct isis_ext_info *info;
	struct listnode *node;
	struct isis_area *area;
	int level;
	struct isis_redist *redist;

	zlog_debug("%s: New route %pFX from %s: distance %d.", __func__, p,
		   zebra_route_string(type), distance);

	if (!ei_table) {
		zlog_warn("%s: External information table not initialized.",
			  __func__);
		return;
	}

	ei_node = srcdest_rnode_get(ei_table, p, src_p);
	if (ei_node->info)
		route_unlock_node(ei_node);
	else
		ei_node->info = XCALLOC(MTYPE_ISIS_EXT_INFO,
					sizeof(struct isis_ext_info));

	info = ei_node->info;
	info->origin = type;
	info->distance = distance;
	info->metric = metric;
	info->tag = tag;

	if (is_default_prefix(p)
	    && (!src_p || !src_p->prefixlen)) {
		type = DEFAULT_ROUTE;
	}

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		for (level = 1; level <= ISIS_LEVELS; level++) {
			redist = isis_redist_lookup(area, family, type, level,
						    table);
			if (!redist || !redist->redist)
				continue;

			isis_redist_update_ext_reach(area, level, redist, p,
						     src_p, info);
		}
}

void isis_redist_delete(struct isis *isis, int type, struct prefix *p,
			struct prefix_ipv6 *src_p, uint16_t table)
{
	int family = p->family;
	struct route_table *ei_table = get_ext_info(isis, family);
	struct route_node *ei_node;
	struct listnode *node;
	struct isis_area *area;
	int level;
	struct isis_redist *redist;

	zlog_debug("%s: Removing route %pFX from %s.", __func__, p,
		   zebra_route_string(type));

	if (is_default_prefix(p)
	    && (!src_p || !src_p->prefixlen)) {
		/* Don't remove default route but add synthetic route for use
		 * by "default-information originate always". Areas without the
		 * "always" setting will ignore routes with origin
		 * DEFAULT_ROUTE. */
		isis_redist_add(isis, DEFAULT_ROUTE, p, NULL, 254,
				MAX_WIDE_PATH_METRIC, 0, table);
		return;
	}

	if (!ei_table) {
		zlog_warn("%s: External information table not initialized.",
			  __func__);
		return;
	}

	ei_node = srcdest_rnode_lookup(ei_table, p, src_p);
	if (!ei_node || !ei_node->info) {
		zlog_warn(
			"%s: Got a delete for %s route %pFX, but that route was never added.",
			__func__, zebra_route_string(type), p);
		if (ei_node)
			route_unlock_node(ei_node);
		return;
	}
	route_unlock_node(ei_node);

	for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
		for (level = ISIS_LEVEL1; level <= ISIS_LEVEL2; level++) {
			redist = isis_redist_lookup(area, family, type, level,
						    table);
			if (!redist || !redist->redist)
				continue;

			isis_redist_uninstall(area, level, p, src_p);
		}

	XFREE(MTYPE_ISIS_EXT_INFO, ei_node->info);
	route_unlock_node(ei_node);
}

static void isis_redist_routemap_set(struct isis_redist *redist,
				     const char *routemap)
{
	if (redist->map_name) {
		XFREE(MTYPE_ISIS_RMAP_NAME, redist->map_name);
		route_map_counter_decrement(redist->map);
		redist->map = NULL;
	}

	if (routemap && strlen(routemap)) {
		redist->map_name = XSTRDUP(MTYPE_ISIS_RMAP_NAME, routemap);
		redist->map = route_map_lookup_by_name(routemap);
		route_map_counter_increment(redist->map);
	}
}

void isis_redist_free(struct isis *isis)
{
	struct route_node *rn;
	int i;

	for (i = 0; i < REDIST_PROTOCOL_COUNT; i++) {
		if (!isis->ext_info[i])
			continue;

		for (rn = route_top(isis->ext_info[i]); rn;
		     rn = srcdest_route_next(rn)) {
			if (rn->info)
				XFREE(MTYPE_ISIS_EXT_INFO, rn->info);
		}

		route_table_finish(isis->ext_info[i]);
		isis->ext_info[i] = NULL;
	}
}

void isis_redist_set(struct isis_area *area, int level, int family, int type,
		     uint32_t metric, const char *routemap, int originate_type,
		     uint16_t table)
{
	int protocol = redist_protocol(family);
	struct isis_redist *redist = isis_redist_get(area, family, type, level,
						     table);
	int i;
	struct route_table *ei_table;
	struct route_node *rn;
	struct isis_ext_info *info;

	redist->redist = (type == DEFAULT_ROUTE) ? originate_type : 1;
	redist->metric = metric;
	isis_redist_routemap_set(redist, routemap);

	if (!area->ext_reach[protocol][level - 1]) {
		area->ext_reach[protocol][level - 1] = srcdest_table_init();
	}

	for (i = 0; i < REDIST_PROTOCOL_COUNT; i++) {
		if (!area->isis->ext_info[i]) {
			area->isis->ext_info[i] = srcdest_table_init();
		}
	}

	isis_zebra_redistribute_set(afi_for_redist_protocol(protocol), type,
				    area->isis->vrf_id, redist->table);

	if (type == DEFAULT_ROUTE && originate_type == DEFAULT_ORIGINATE_ALWAYS)
		isis_redist_ensure_default(area->isis, family);

	ei_table = get_ext_info(area->isis, family);
	for (rn = route_top(ei_table); rn; rn = srcdest_route_next(rn)) {
		if (!rn->info)
			continue;
		info = rn->info;

		const struct prefix *p, *src_p;

		srcdest_rnode_prefixes(rn, &p, &src_p);

		if (type == DEFAULT_ROUTE) {
			if (!is_default_prefix(p)
			    || (src_p && src_p->prefixlen)) {
				continue;
			}
		} else {
			if (info->origin != type)
				continue;
		}

		isis_redist_update_ext_reach(area, level, redist, p,
					     (const struct prefix_ipv6 *)src_p,
					     info);
	}
}

void isis_redist_unset(struct isis_area *area, int level, int family, int type,
		       uint16_t table)
{
	struct isis_redist *redist = isis_redist_lookup(area, family, type,
							level, table);
	struct route_table *er_table = get_ext_reach(area, family, level);
	struct route_node *rn;
	struct isis_ext_info *info;
	struct list *redist_list;
	int protocol = redist_protocol(family);

	if (!redist || !redist->redist)
		return;

	redist->redist = 0;

	redist_list = area->redist_settings[protocol][type][level - 1];
	listnode_delete(redist_list, redist);
	XFREE(MTYPE_ISIS_REDISTRIBUTE, redist);

	if (!er_table) {
		zlog_warn("%s: External reachability table uninitialized.",
			  __func__);
		return;
	}

	for (rn = route_top(er_table); rn; rn = srcdest_route_next(rn)) {
		if (!rn->info)
			continue;
		info = rn->info;

		const struct prefix *p, *src_p;
		srcdest_rnode_prefixes(rn, &p, &src_p);

		if (type == DEFAULT_ROUTE) {
			if (!is_default_prefix(p)
			    || (src_p && src_p->prefixlen)) {
				continue;
			}
		} else {
			if (info->origin != type)
				continue;
		}

		XFREE(MTYPE_ISIS_EXT_INFO, rn->info);
		route_unlock_node(rn);
	}

	lsp_regenerate_schedule(area, level, 0);
	isis_zebra_redistribute_unset(afi_for_redist_protocol(protocol), type,
				      area->isis->vrf_id, table);
}

void isis_redist_area_finish(struct isis_area *area)
{
	struct route_node *rn;
	int protocol;
	int level;
	int type;
	struct isis_redist *redist;
	struct listnode *node, *nnode;
	struct list *redist_list;

	for (protocol = 0; protocol < REDIST_PROTOCOL_COUNT; protocol++)
		for (level = 0; level < ISIS_LEVELS; level++) {
			for (type = 0; type < ZEBRA_ROUTE_MAX + 1; type++) {
				redist_list = area->redist_settings[protocol]
								   [type][level];
				if (!redist_list)
					continue;
				for (ALL_LIST_ELEMENTS(redist_list, node, nnode,
						       redist)) {
					redist->redist = 0;
					XFREE(MTYPE_ISIS_RMAP_NAME,
					      redist->map_name);
					isis_zebra_redistribute_unset(
						afi_for_redist_protocol(protocol),
						type, area->isis->vrf_id,
						redist->table);
					listnode_delete(redist_list, redist);
					XFREE(MTYPE_ISIS_REDISTRIBUTE, redist);
				}
				list_delete(&redist_list);
			}
			if (!area->ext_reach[protocol][level])
				continue;
			for (rn = route_top(area->ext_reach[protocol][level]);
			     rn; rn = srcdest_route_next(rn)) {
				if (rn->info)
					XFREE(MTYPE_ISIS_EXT_INFO, rn->info);
			}
			route_table_finish(area->ext_reach[protocol][level]);
			area->ext_reach[protocol][level] = NULL;
		}
}

#ifdef FABRICD
DEFUN (isis_redistribute,
       isis_redistribute_cmd,
       "redistribute <ipv4 " PROTO_IP_REDIST_STR "|ipv6 " PROTO_IP6_REDIST_STR ">"
       " [{metric (0-16777215)|route-map RMAP_NAME}]",
       REDIST_STR
       "Redistribute IPv4 routes\n"
       PROTO_IP_REDIST_HELP
       "Redistribute IPv6 routes\n"
       PROTO_IP6_REDIST_HELP
       "Metric for redistributed routes\n"
       "ISIS default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int idx_afi = 1;
	int idx_protocol = 2;
	int idx_metric_rmap = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int family;
	int afi;
	int type;
	int level;
	unsigned long metric = 0;
	const char *routemap = NULL;

	family = str2family(argv[idx_afi]->text);
	if (family < 0)
		return CMD_WARNING_CONFIG_FAILED;

	afi = family2afi(family);
	if (!afi)
		return CMD_WARNING_CONFIG_FAILED;

	type = proto_redistnum(afi, argv[idx_protocol]->text);
	if (type < 0)
		return CMD_WARNING_CONFIG_FAILED;

	level = 2;

	if ((area->is_type & level) != level) {
		vty_out(vty, "Node is not a level-%d IS\n", level);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv_find(argv, argc, "metric", &idx_metric_rmap)) {
		metric = strtoul(argv[idx_metric_rmap + 1]->arg, NULL, 10);
	}

	idx_metric_rmap = 1;
	if (argv_find(argv, argc, "route-map", &idx_metric_rmap)) {
		routemap = argv[idx_metric_rmap + 1]->arg;
	}

	isis_redist_set(area, level, family, type, metric, routemap, 0, 0);
	return 0;
}

DEFUN (no_isis_redistribute,
       no_isis_redistribute_cmd,
       "no redistribute <ipv4 " PROTO_IP_REDIST_STR "|ipv6 " PROTO_IP6_REDIST_STR ">",
       NO_STR
       REDIST_STR
       "Redistribute IPv4 routes\n"
       PROTO_IP_REDIST_HELP
       "Redistribute IPv6 routes\n"
       PROTO_IP6_REDIST_HELP)
{
	int idx_afi = 2;
	int idx_protocol = 3;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int type;
	int level;
	int family;
	int afi;

	family = str2family(argv[idx_afi]->arg);
	if (family < 0)
		return CMD_WARNING_CONFIG_FAILED;

	afi = family2afi(family);
	if (!afi)
		return CMD_WARNING_CONFIG_FAILED;

	type = proto_redistnum(afi, argv[idx_protocol]->text);
	if (type < 0)
		return CMD_WARNING_CONFIG_FAILED;

	level = 2;

	isis_redist_unset(area, level, family, type, 0);
	return 0;
}

DEFUN (isis_default_originate,
       isis_default_originate_cmd,
       "default-information originate <ipv4|ipv6> [always] [{metric (0-16777215)|route-map RMAP_NAME}]",
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Distribute default route for IPv4\n"
       "Distribute default route for IPv6\n"
       "Always advertise default route\n"
       "Metric for default route\n"
       "ISIS default metric\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int idx_afi = 2;
	int idx_always = fabricd ? 3 : 4;
	int idx_metric_rmap = 1;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int family;
	int originate_type = DEFAULT_ORIGINATE;
	int level;
	unsigned long metric = 0;
	const char *routemap = NULL;

	family = str2family(argv[idx_afi]->text);
	if (family < 0)
		return CMD_WARNING_CONFIG_FAILED;

	level = 2;

	if ((area->is_type & level) != level) {
		vty_out(vty, "Node is not a level-%d IS\n", level);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc > idx_always && strmatch(argv[idx_always]->text, "always")) {
		originate_type = DEFAULT_ORIGINATE_ALWAYS;
		idx_metric_rmap++;
	}

	if (argv_find(argv, argc, "metric", &idx_metric_rmap)) {
		metric = strtoul(argv[idx_metric_rmap + 1]->arg, NULL, 10);
	}

	idx_metric_rmap = 1;
	if (argv_find(argv, argc, "route-map", &idx_metric_rmap)) {
		routemap = argv[idx_metric_rmap + 1]->arg;
	}

	if (family == AF_INET6 && originate_type != DEFAULT_ORIGINATE_ALWAYS) {
		vty_out(vty,
			"Zebra doesn't implement default-originate for IPv6 yet\n");
		vty_out(vty,
			"so use with care or use default-originate always.\n");
	}

	isis_redist_set(area, level, family, DEFAULT_ROUTE, metric, routemap,
			originate_type, 0);
	return 0;
}

DEFUN (no_isis_default_originate,
       no_isis_default_originate_cmd,
       "no default-information originate <ipv4|ipv6>",
       NO_STR
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Distribute default route for IPv4\n"
       "Distribute default route for IPv6\n")
{
	int idx_afi = 3;
	VTY_DECLVAR_CONTEXT(isis_area, area);
	int family;
	int level;

	family = str2family(argv[idx_afi]->text);
	if (family < 0)
		return CMD_WARNING_CONFIG_FAILED;

	level = 2;

	isis_redist_unset(area, level, family, DEFAULT_ROUTE, 0);
	return 0;
}
#endif /* ifdef FABRICD */

int isis_redist_config_write(struct vty *vty, struct isis_area *area,
			     int family)
{
	int type;
	int level;
	int write = 0;
	struct isis_redist *redist;
	struct list *redist_list;
	const char *family_str;
	struct listnode *node;

	if (family == AF_INET)
		family_str = "ipv4";
	else if (family == AF_INET6)
		family_str = "ipv6";
	else
		return 0;

	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		if (type == PROTO_TYPE)
			continue;

		for (level = 1; level <= ISIS_LEVELS; level++) {
			redist_list = area->redist_settings[redist_protocol(
				family)][type][level - 1];
			if (!redist_list)
				continue;
			for (ALL_LIST_ELEMENTS_RO(redist_list, node, redist)) {
				if (!redist->redist)
					continue;
				vty_out(vty, " redistribute %s %s", family_str,
					zebra_route_string(type));
				if (type == ZEBRA_ROUTE_TABLE)
					vty_out(vty, " %u", redist->table);
				if (!fabricd)
					vty_out(vty, " level-%d", level);
				if (redist->metric)
					vty_out(vty, " metric %u",
						redist->metric);
				if (redist->map_name)
					vty_out(vty, " route-map %s",
						redist->map_name);
				vty_out(vty, "\n");
				write++;
			}
		}
	}

	for (level = 1; level <= ISIS_LEVELS; level++) {
		redist = isis_redist_lookup(area, family, DEFAULT_ROUTE, level,
					    0);
		if (!redist)
			continue;
		if (!redist->redist)
			continue;
		vty_out(vty, " default-information originate %s",
			family_str);
		if (!fabricd)
			vty_out(vty, " level-%d", level);
		if (redist->redist == DEFAULT_ORIGINATE_ALWAYS)
			vty_out(vty, " always");
		if (redist->metric)
			vty_out(vty, " metric %u", redist->metric);
		if (redist->map_name)
			vty_out(vty, " route-map %s", redist->map_name);
		vty_out(vty, "\n");
		write++;
	}

	return write;
}

void isis_redist_init(void)
{
#ifdef FABRICD
	install_element(ROUTER_NODE, &isis_redistribute_cmd);
	install_element(ROUTER_NODE, &no_isis_redistribute_cmd);

	install_element(ROUTER_NODE, &isis_default_originate_cmd);
	install_element(ROUTER_NODE, &no_isis_default_originate_cmd);
#endif /* ifdef FABRICD */
}
