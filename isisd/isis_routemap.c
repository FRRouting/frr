/*
 * IS-IS Rout(e)ing protocol - isis_routemap.c
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "filter.h"
#include "hash.h"
#include "if.h"
#include "linklist.h"
#include "log.h"
#include "memory.h"
#include "prefix.h"
#include "plist.h"
#include "routemap.h"
#include "table.h"
#include "thread.h"
#include "vty.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
#include "dict.h"
#include "isisd.h"
#include "isis_misc.h"
#include "isis_adjacency.h"
#include "isis_circuit.h"
#include "isis_pdu.h"
#include "isis_lsp.h"
#include "isis_spf.h"
#include "isis_route.h"
#include "isis_zebra.h"
#include "isis_routemap.h"

static route_map_result_t route_match_ip_address(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	struct access_list *alist;

	if (type != RMAP_ISIS)
		return RMAP_NOMATCH;

	alist = access_list_lookup(AFI_IP, (char *)rule);
	if (access_list_apply(alist, prefix) != FILTER_DENY)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_ip_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address", route_match_ip_address, route_match_ip_address_compile,
	route_match_ip_address_free};

/* ------------------------------------------------------------*/

static route_map_result_t
route_match_ip_address_prefix_list(void *rule, struct prefix *prefix,
				   route_map_object_t type, void *object)
{
	struct prefix_list *plist;

	if (type != RMAP_ISIS)
		return RMAP_NOMATCH;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (prefix_list_apply(plist, prefix) != PREFIX_DENY)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_ip_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list", route_match_ip_address_prefix_list,
	route_match_ip_address_prefix_list_compile,
	route_match_ip_address_prefix_list_free};

/* ------------------------------------------------------------*/

static route_map_result_t route_match_ipv6_address(void *rule,
						   struct prefix *prefix,
						   route_map_object_t type,
						   void *object)
{
	struct access_list *alist;

	if (type != RMAP_ISIS)
		return RMAP_NOMATCH;

	alist = access_list_lookup(AFI_IP6, (char *)rule);
	if (access_list_apply(alist, prefix) != FILTER_DENY)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ipv6_address_cmd = {
	"ipv6 address", route_match_ipv6_address,
	route_match_ipv6_address_compile, route_match_ipv6_address_free};

/* ------------------------------------------------------------*/

static route_map_result_t
route_match_ipv6_address_prefix_list(void *rule, struct prefix *prefix,
				     route_map_object_t type, void *object)
{
	struct prefix_list *plist;

	if (type != RMAP_ISIS)
		return RMAP_NOMATCH;

	plist = prefix_list_lookup(AFI_IP6, (char *)rule);
	if (prefix_list_apply(plist, prefix) != PREFIX_DENY)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

struct route_map_rule_cmd route_match_ipv6_address_prefix_list_cmd = {
	"ipv6 address prefix-list", route_match_ipv6_address_prefix_list,
	route_match_ipv6_address_prefix_list_compile,
	route_match_ipv6_address_prefix_list_free};

/* ------------------------------------------------------------*/

static route_map_result_t route_set_metric(void *rule, struct prefix *prefix,
					   route_map_object_t type,
					   void *object)
{
	uint32_t *metric;
	struct isis_ext_info *info;

	if (type == RMAP_ISIS) {
		metric = rule;
		info = object;

		info->metric = *metric;
	}
	return RMAP_OKAY;
}

static void *route_set_metric_compile(const char *arg)
{
	unsigned long metric;
	char *endp;
	uint32_t *ret;

	metric = strtoul(arg, &endp, 10);
	if (arg[0] == '\0' || *endp != '\0' || metric > MAX_WIDE_PATH_METRIC)
		return NULL;

	ret = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(*ret));
	*ret = metric;

	return ret;
}

static void route_set_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_set_metric_cmd = {
	"metric", route_set_metric, route_set_metric_compile,
	route_set_metric_free};

void isis_route_map_init(void)
{
	route_map_init();

	route_map_match_ip_address_hook(generic_match_add);
	route_map_no_match_ip_address_hook(generic_match_delete);

	route_map_match_ip_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_address_prefix_list_hook(generic_match_delete);

	route_map_match_ipv6_address_hook(generic_match_add);
	route_map_no_match_ipv6_address_hook(generic_match_delete);

	route_map_match_ipv6_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ipv6_address_prefix_list_hook(generic_match_delete);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ipv6_address_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_list_cmd);
	route_map_install_set(&route_set_metric_cmd);
}
