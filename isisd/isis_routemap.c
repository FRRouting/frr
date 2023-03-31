// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_routemap.c
 *
 * Copyright (C) 2013-2015 Christian Franke <chris@opensourcerouting.org>
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
#include "frrevent.h"
#include "vty.h"

#include "isis_constants.h"
#include "isis_common.h"
#include "isis_flags.h"
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

static enum route_map_cmd_result_t
route_match_ip_address(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;

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

static const struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address",
	route_match_ip_address,
	route_match_ip_address_compile,
	route_match_ip_address_free
};

/* ------------------------------------------------------------*/

static enum route_map_cmd_result_t
route_match_ip_address_prefix_list(void *rule, const struct prefix *prefix,
				   void *object)
{
	struct prefix_list *plist;

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

static const struct route_map_rule_cmd
		route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list",
	route_match_ip_address_prefix_list,
	route_match_ip_address_prefix_list_compile,
	route_match_ip_address_prefix_list_free
};

/* ------------------------------------------------------------*/

/* `match tag TAG' */
/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_tag(void *rule, const struct prefix *p, void *object)
{
	route_tag_t *tag;
	struct isis_ext_info *info;
	route_tag_t info_tag;

	tag = rule;
	info = object;

	info_tag = info->tag;
	if (info_tag == *tag)
		return RMAP_MATCH;
	else
		return RMAP_NOMATCH;
}

/* Route map commands for tag matching. */
static const struct route_map_rule_cmd route_match_tag_cmd = {
	"tag",
	route_match_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

/* ------------------------------------------------------------*/

static enum route_map_cmd_result_t
route_match_ipv6_address(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;

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

static const struct route_map_rule_cmd route_match_ipv6_address_cmd = {
	"ipv6 address",
	route_match_ipv6_address,
	route_match_ipv6_address_compile,
	route_match_ipv6_address_free
};

/* ------------------------------------------------------------*/

static enum route_map_cmd_result_t
route_match_ipv6_address_prefix_list(void *rule, const struct prefix *prefix,
				     void *object)
{
	struct prefix_list *plist;

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

static const struct route_map_rule_cmd
		route_match_ipv6_address_prefix_list_cmd = {
	"ipv6 address prefix-list",
	route_match_ipv6_address_prefix_list,
	route_match_ipv6_address_prefix_list_compile,
	route_match_ipv6_address_prefix_list_free
};

/* ------------------------------------------------------------*/

static enum route_map_cmd_result_t
route_set_metric(void *rule, const struct prefix *prefix, void *object)
{
	uint32_t *metric;
	struct isis_ext_info *info;

	metric = rule;
	info = object;

	info->metric = *metric;

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

static const struct route_map_rule_cmd route_set_metric_cmd = {
	"metric",
	route_set_metric,
	route_set_metric_compile,
	route_set_metric_free
};

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

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ipv6_address_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_list_cmd);
	route_map_install_match(&route_match_tag_cmd);
	route_map_install_set(&route_set_metric_cmd);
}
