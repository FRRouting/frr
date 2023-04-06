// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Route map function of ospfd.
 * Copyright (C) 2000 IP Infusion Inc.
 *
 * Written by Toshiaki Takada.
 */

#include <zebra.h>

#include "memory.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "log.h"
#include "plist.h"
#include "vrf.h"
#include "frrstr.h"
#include "northbound_cli.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_errors.h"

/* Hook function for updating route_map assignment. */
static void ospf_route_map_update(const char *name)
{
	struct ospf *ospf;
	int type;
	struct listnode *n1 = NULL;

	/* If OSPF instatnce does not exist, return right now. */
	if (listcount(om->ospf) == 0)
		return;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, n1, ospf)) {
		/* Update route-map */
		for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
			struct list *red_list;
			struct listnode *node;
			struct ospf_redist *red;

			red_list = ospf->redist[type];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				if (ROUTEMAP_NAME(red)
				    && strcmp(ROUTEMAP_NAME(red), name) == 0) {
					/* Keep old route-map. */
					struct route_map *old = ROUTEMAP(red);

					ROUTEMAP(red) =
						route_map_lookup_by_name(
							ROUTEMAP_NAME(red));

					if (!old)
						route_map_counter_increment(
							ROUTEMAP(red));

					/* No update for this distribute type.
					 */
					if (old == NULL
					    && ROUTEMAP(red) == NULL)
						continue;

					ospf_distribute_list_update(
						ospf, type, red->instance);
				}
			}
		}
	}
}

static void ospf_route_map_event(const char *name)
{
	struct ospf *ospf;
	int type;
	struct listnode *n1 = NULL;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, n1, ospf)) {
		for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
			struct list *red_list;
			struct listnode *node;
			struct ospf_redist *red;

			red_list = ospf->redist[type];
			if (!red_list)
				continue;

			for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
				if (ROUTEMAP_NAME(red) && ROUTEMAP(red)
				    && !strcmp(ROUTEMAP_NAME(red), name)) {
					ospf_distribute_list_update(
						ospf, type, red->instance);
				}
			}
		}
	}
}

/* `match ip netxthop ' */
/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_ip_nexthop(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;
	struct external_info *ei = object;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefix = ei->nexthop;
	p.prefixlen = IPV4_MAX_BITLEN;

	alist = access_list_lookup(AFI_IP, (char *)rule);
	if (alist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
				__func__, (char *)rule);
		return RMAP_NOMATCH;
	}

	return (access_list_apply(alist, &p) == FILTER_DENY ? RMAP_NOMATCH
							    : RMAP_MATCH);
}

/* Route map `ip next-hop' match statement. `arg' should be
   access-list name. */
static void *route_match_ip_nexthop_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_nexthop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
static const struct route_map_rule_cmd route_match_ip_nexthop_cmd = {
	"ip next-hop",
	route_match_ip_nexthop,
	route_match_ip_nexthop_compile,
	route_match_ip_nexthop_free
};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static enum route_map_cmd_result_t
route_match_ip_next_hop_prefix_list(void *rule, const struct prefix *prefix,
				    void *object)
{
	struct prefix_list *plist;
	struct external_info *ei = object;
	struct prefix_ipv4 p;

	p.family = AF_INET;
	p.prefix = ei->nexthop;
	p.prefixlen = IPV4_MAX_BITLEN;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (plist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Prefix List %s specified does not exist defaulting to NO_MATCH",
				__func__, (char *)rule);
		return RMAP_NOMATCH;
	}

	return (prefix_list_apply(plist, &p) == PREFIX_DENY ? RMAP_NOMATCH
							    : RMAP_MATCH);
}

static void *route_match_ip_next_hop_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_next_hop_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_next_hop_prefix_list_cmd = {
	"ip next-hop prefix-list",
	route_match_ip_next_hop_prefix_list,
	route_match_ip_next_hop_prefix_list_compile,
	route_match_ip_next_hop_prefix_list_free
};

/* `match ip next-hop type <blackhole>' */

static enum route_map_cmd_result_t
route_match_ip_next_hop_type(void *rule, const struct prefix *prefix,
			     void *object)
{
	struct external_info *ei = object;

	if (prefix->family == AF_INET) {
		ei = (struct external_info *)object;
		if (!ei)
			return RMAP_NOMATCH;

		if (ei->nexthop.s_addr == INADDR_ANY && !ei->ifindex)
			return RMAP_MATCH;
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_next_hop_type_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_next_hop_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_next_hop_type_cmd = {
	"ip next-hop type",
	route_match_ip_next_hop_type,
	route_match_ip_next_hop_type_compile,
	route_match_ip_next_hop_type_free
};

/* `match ip address IP_ACCESS_LIST' */
/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_ip_address(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;
	/* struct prefix_ipv4 match; */

	alist = access_list_lookup(AFI_IP, (char *)rule);
	if (alist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Access-List Specified: %s does not exist defaulting to NO_MATCH",
				__func__, (char *)rule);
		return RMAP_NOMATCH;
	}

	return (access_list_apply(alist, prefix) == FILTER_DENY ? RMAP_NOMATCH
								: RMAP_MATCH);
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
static void *route_match_ip_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_ip_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address",
	route_match_ip_address,
	route_match_ip_address_compile,
	route_match_ip_address_free
};

/* `match ip address prefix-list PREFIX_LIST' */
static enum route_map_cmd_result_t
route_match_ip_address_prefix_list(void *rule, const struct prefix *prefix,
				   void *object)
{
	struct prefix_list *plist;

	plist = prefix_list_lookup(AFI_IP, (char *)rule);
	if (plist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug(
				"%s: Prefix List %s specified does not exist defaulting to NO_MATCH",
				__func__, (char *)rule);

		return RMAP_NOMATCH;
	}

	return (prefix_list_apply(plist, prefix) == PREFIX_DENY ? RMAP_NOMATCH
								: RMAP_MATCH);
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

/* `match interface IFNAME' */
/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_interface(void *rule, const struct prefix *prefix, void *object)
{
	struct interface *ifp;
	struct external_info *ei;

	ei = object;
	ifp = if_lookup_by_name((char *)rule, ei->ospf->vrf_id);

	if (ifp == NULL || ifp->ifindex != ei->ifindex)
		return RMAP_NOMATCH;

	return RMAP_MATCH;
}

/* Route map `interface' match statement.  `arg' should be
   interface name. */
static void *route_match_interface_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `interface' value. */
static void route_match_interface_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_interface_cmd = {
	"interface",
	route_match_interface,
	route_match_interface_compile,
	route_match_interface_free
};

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_tag(void *rule, const struct prefix *prefix, void *object)
{
	route_tag_t *tag;
	struct external_info *ei;

	tag = rule;
	ei = object;

	return ((ei->tag == *tag) ? RMAP_MATCH : RMAP_NOMATCH);
}

/* Route map commands for tag matching. */
static const struct route_map_rule_cmd route_match_tag_cmd = {
	"tag",
	route_match_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

struct ospf_metric {
	enum { metric_increment, metric_decrement, metric_absolute } type;
	bool used;
	uint32_t metric;
};

/* `set metric METRIC' */
/* Set metric to attribute. */
static enum route_map_cmd_result_t
route_set_metric(void *rule, const struct prefix *prefix, void *object)
{
	struct ospf_metric *metric;
	struct external_info *ei;

	/* Fetch routemap's rule information. */
	metric = rule;
	ei = object;

	/* Set metric out value. */
	if (!metric->used)
		return RMAP_OKAY;

	ROUTEMAP_METRIC(ei) = ei->metric;

	if (metric->type == metric_increment)
		ROUTEMAP_METRIC(ei) += metric->metric;
	else if (metric->type == metric_decrement)
		ROUTEMAP_METRIC(ei) -= metric->metric;
	else if (metric->type == metric_absolute)
		ROUTEMAP_METRIC(ei) = metric->metric;

	if ((uint32_t)ROUTEMAP_METRIC(ei) < ei->min_metric)
		ROUTEMAP_METRIC(ei) = ei->min_metric;
	if ((uint32_t)ROUTEMAP_METRIC(ei) > ei->max_metric)
		ROUTEMAP_METRIC(ei) = ei->max_metric;

	return RMAP_OKAY;
}

/* set metric compilation. */
static void *route_set_metric_compile(const char *arg)
{
	struct ospf_metric *metric;

	metric = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(*metric));
	metric->used = false;

	if (all_digit(arg))
		metric->type = metric_absolute;

	if (strmatch(arg, "+rtt") || strmatch(arg, "-rtt")) {
		flog_warn(EC_OSPF_SET_METRIC_PLUS,
			  "OSPF does not support 'set metric +rtt / -rtt'");
		return metric;
	}

	if ((arg[0] == '+') && all_digit(arg + 1)) {
		metric->type = metric_increment;
		arg++;
	}

	if ((arg[0] == '-') && all_digit(arg + 1)) {
		metric->type = metric_decrement;
		arg++;
	}

	metric->metric = strtoul(arg, NULL, 10);

	if (metric->metric)
		metric->used = true;

	return metric;
}

/* Free route map's compiled `set metric' value. */
static void route_set_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
static const struct route_map_rule_cmd route_set_metric_cmd = {
	"metric",
	route_set_metric,
	route_set_metric_compile,
	route_set_metric_free,
};

/* `set min-metric METRIC' */
/* Set min-metric to attribute. */
static enum route_map_cmd_result_t
route_set_min_metric(void *rule, const struct prefix *prefix, void *object)
{
	uint32_t *min_metric;
	struct external_info *ei;

	/* Fetch routemap's rule information. */
	min_metric = rule;
	ei = object;

	ei->min_metric = *min_metric;

	if (ei->min_metric > OSPF_LS_INFINITY)
		ei->min_metric = OSPF_LS_INFINITY;

	if ((uint32_t)ROUTEMAP_METRIC(ei) < ei->min_metric)
		ROUTEMAP_METRIC(ei) = ei->min_metric;

	return RMAP_OKAY;
}

/* set min-metric compilation. */
static void *route_set_min_metric_compile(const char *arg)
{

	uint32_t *min_metric;

	min_metric = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));

	*min_metric = strtoul(arg, NULL, 10);

	if (*min_metric)
		return min_metric;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, min_metric);
	return NULL;
}

/* Free route map's compiled `set min-metric' value. */
static void route_set_min_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
static const struct route_map_rule_cmd route_set_min_metric_cmd = {
	"min-metric",
	route_set_min_metric,
	route_set_min_metric_compile,
	route_set_min_metric_free,
};


/* `set max-metric METRIC' */
/* Set max-metric to attribute. */
static enum route_map_cmd_result_t
route_set_max_metric(void *rule, const struct prefix *prefix, void *object)
{
	uint32_t *max_metric;
	struct external_info *ei;

	/* Fetch routemap's rule information. */
	max_metric = rule;
	ei = object;

	ei->max_metric = *max_metric;

	if (ei->max_metric > OSPF_LS_INFINITY)
		ei->max_metric = OSPF_LS_INFINITY;

	if ((uint32_t)ROUTEMAP_METRIC(ei) > ei->max_metric)
		ROUTEMAP_METRIC(ei) = ei->max_metric;

	return RMAP_OKAY;
}

/* set max-metric compilation. */
static void *route_set_max_metric_compile(const char *arg)
{

	uint32_t *max_metric;

	max_metric = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));

	*max_metric = strtoul(arg, NULL, 10);

	if (*max_metric)
		return max_metric;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, max_metric);
	return NULL;
}

/* Free route map's compiled `set max-metric' value. */
static void route_set_max_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
static const struct route_map_rule_cmd route_set_max_metric_cmd = {
	"max-metric",
	route_set_max_metric,
	route_set_max_metric_compile,
	route_set_max_metric_free,
};

/* `set metric-type TYPE' */
/* Set metric-type to attribute. */
static enum route_map_cmd_result_t
route_set_metric_type(void *rule, const struct prefix *prefix, void *object)
{
	uint32_t *metric_type;
	struct external_info *ei;

	/* Fetch routemap's rule information. */
	metric_type = rule;
	ei = object;

	/* Set metric out value. */
	ROUTEMAP_METRIC_TYPE(ei) = *metric_type;

	return RMAP_OKAY;
}

/* set metric-type compilation. */
static void *route_set_metric_type_compile(const char *arg)
{
	uint32_t *metric_type;

	metric_type = XCALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));
	if (strcmp(arg, "type-1") == 0)
		*metric_type = EXTERNAL_METRIC_TYPE_1;
	else if (strcmp(arg, "type-2") == 0)
		*metric_type = EXTERNAL_METRIC_TYPE_2;

	if (*metric_type == EXTERNAL_METRIC_TYPE_1
	    || *metric_type == EXTERNAL_METRIC_TYPE_2)
		return metric_type;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, metric_type);
	return NULL;
}

/* Free route map's compiled `set metric-type' value. */
static void route_set_metric_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
static const struct route_map_rule_cmd route_set_metric_type_cmd = {
	"metric-type",
	route_set_metric_type,
	route_set_metric_type_compile,
	route_set_metric_type_free,
};

static enum route_map_cmd_result_t
route_set_tag(void *rule, const struct prefix *prefix, void *object)
{
	route_tag_t *tag;
	struct external_info *ei;

	tag = rule;
	ei = object;

	/* Set tag value */
	ei->tag = *tag;

	return RMAP_OKAY;
}

/* Route map commands for tag set. */
static const struct route_map_rule_cmd route_set_tag_cmd = {
	"tag",
	route_set_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

DEFUN_YANG (set_metric_type,
       set_metric_type_cmd,
       "set metric-type <type-1|type-2>",
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")
{
	char *ext = argv[2]->text;

	const char *xpath =
		"./set-action[action='frr-ospf-route-map:metric-type']";
	char xpath_value[XPATH_MAXLEN];

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	snprintf(xpath_value, sizeof(xpath_value),
		 "%s/rmap-set-action/frr-ospf-route-map:metric-type", xpath);
	nb_cli_enqueue_change(vty, xpath_value, NB_OP_MODIFY, ext);
	return nb_cli_apply_changes(vty, NULL);
}

DEFUN_YANG (no_set_metric_type,
       no_set_metric_type_cmd,
       "no set metric-type [<type-1|type-2>]",
       NO_STR
       SET_STR
       "Type of metric for destination routing protocol\n"
       "OSPF[6] external type 1 metric\n"
       "OSPF[6] external type 2 metric\n")
{
	const char *xpath =
		"./set-action[action='frr-ospf-route-map:metric-type']";

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

/* Route-map init */
void ospf_route_map_init(void)
{
	route_map_init();

	route_map_add_hook(ospf_route_map_update);
	route_map_delete_hook(ospf_route_map_update);
	route_map_event_hook(ospf_route_map_event);

	route_map_match_ip_next_hop_hook(generic_match_add);
	route_map_no_match_ip_next_hop_hook(generic_match_delete);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_match_ip_address_hook(generic_match_add);
	route_map_no_match_ip_address_hook(generic_match_delete);

	route_map_match_ip_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_address_prefix_list_hook(generic_match_delete);

	route_map_match_ip_next_hop_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_next_hop_prefix_list_hook(generic_match_delete);

	route_map_match_ip_next_hop_type_hook(generic_match_add);
	route_map_no_match_ip_next_hop_type_hook(generic_match_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_set_min_metric_hook(generic_set_add);
	route_map_no_set_min_metric_hook(generic_set_delete);

	route_map_set_max_metric_hook(generic_set_add);
	route_map_no_set_max_metric_hook(generic_set_delete);

	route_map_set_tag_hook(generic_set_add);
	route_map_no_set_tag_hook(generic_set_delete);

	route_map_install_match(&route_match_ip_nexthop_cmd);
	route_map_install_match(&route_match_ip_next_hop_prefix_list_cmd);
	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ip_next_hop_type_cmd);
	route_map_install_match(&route_match_interface_cmd);
	route_map_install_match(&route_match_tag_cmd);

	route_map_install_set(&route_set_metric_cmd);
	route_map_install_set(&route_set_min_metric_cmd);
	route_map_install_set(&route_set_max_metric_cmd);
	route_map_install_set(&route_set_metric_type_cmd);
	route_map_install_set(&route_set_tag_cmd);

	install_element(RMAP_NODE, &set_metric_type_cmd);
	install_element(RMAP_NODE, &no_set_metric_type_cmd);
}
