/* RIPv2 routemap.
 * Copyright (C) 2005 6WIND <alain.ritoux@6wind.com>
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "memory.h"
#include "prefix.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "filter.h"
#include "log.h"
#include "sockunion.h" /* for inet_aton () */
#include "plist.h"
#include "vrf.h"

#include "ripd/ripd.h"

struct rip_metric_modifier {
	enum { metric_increment, metric_decrement, metric_absolute } type;
	bool used;
	uint8_t metric;
};

/* Hook function for updating route_map assignment. */
/* ARGSUSED */
static void rip_route_map_update(const char *notused)
{
	int i;

	if (rip) {
		for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
			if (rip->route_map[i].name)
				rip->route_map[i].map =
					route_map_lookup_by_name(
						rip->route_map[i].name);
		}
	}
}

/* `match metric METRIC' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_metric(void *rule, struct prefix *prefix,
					     route_map_object_t type,
					     void *object)
{
	uint32_t *metric;
	uint32_t check;
	struct rip_info *rinfo;

	if (type == RMAP_RIP) {
		metric = rule;
		rinfo = object;

		/* If external metric is available, the route-map should
		   work on this one (for redistribute purpose)  */
		check = (rinfo->external_metric) ? rinfo->external_metric
						 : rinfo->metric;
		if (check == *metric)
			return RMAP_MATCH;
		else
			return RMAP_NOMATCH;
	}
	return RMAP_NOMATCH;
}

/* Route map `match metric' match statement. `arg' is METRIC value */
static void *route_match_metric_compile(const char *arg)
{
	uint32_t *metric;

	metric = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));
	*metric = atoi(arg);

	if (*metric > 0)
		return metric;

	XFREE(MTYPE_ROUTE_MAP_COMPILED, metric);
	return NULL;
}

/* Free route map's compiled `match metric' value. */
static void route_match_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for metric matching. */
struct route_map_rule_cmd route_match_metric_cmd = {
	"metric", route_match_metric, route_match_metric_compile,
	route_match_metric_free};

/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_interface(void *rule,
						struct prefix *prefix,
						route_map_object_t type,
						void *object)
{
	struct rip_info *rinfo;
	struct interface *ifp;
	char *ifname;

	if (type == RMAP_RIP) {
		ifname = rule;
		ifp = if_lookup_by_name(ifname, VRF_DEFAULT);

		if (!ifp)
			return RMAP_NOMATCH;

		rinfo = object;

		if (rinfo->ifindex_out == ifp->ifindex
		    || rinfo->nh.ifindex == ifp->ifindex)
			return RMAP_MATCH;
		else
			return RMAP_NOMATCH;
	}
	return RMAP_NOMATCH;
}

/* Route map `match interface' match statement. `arg' is IFNAME value */
/* XXX I don`t know if I need to check does interface exist? */
static void *route_match_interface_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `match interface' value. */
static void route_match_interface_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for interface matching. */
struct route_map_rule_cmd route_match_interface_cmd = {
	"interface", route_match_interface, route_match_interface_compile,
	route_match_interface_free};

/* `match ip next-hop IP_ACCESS_LIST' */

/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_ip_next_hop(void *rule,
						  struct prefix *prefix,
						  route_map_object_t type,
						  void *object)
{
	struct access_list *alist;
	struct rip_info *rinfo;
	struct prefix_ipv4 p;

	if (type == RMAP_RIP) {
		rinfo = object;
		p.family = AF_INET;
		p.prefix = (rinfo->nh.gate.ipv4.s_addr) ? rinfo->nh.gate.ipv4
							: rinfo->from;
		p.prefixlen = IPV4_MAX_BITLEN;

		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

		return (access_list_apply(alist, &p) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

/* Route map `ip next-hop' match statement.  `arg' should be
   access-list name. */
static void *route_match_ip_next_hop_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `. */
static void route_match_ip_next_hop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip next-hop matching. */
static struct route_map_rule_cmd route_match_ip_next_hop_cmd = {
	"ip next-hop", route_match_ip_next_hop, route_match_ip_next_hop_compile,
	route_match_ip_next_hop_free};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_next_hop_prefix_list(void *rule, struct prefix *prefix,
				    route_map_object_t type, void *object)
{
	struct prefix_list *plist;
	struct rip_info *rinfo;
	struct prefix_ipv4 p;

	if (type == RMAP_RIP) {
		rinfo = object;
		p.family = AF_INET;
		p.prefix = (rinfo->nh.gate.ipv4.s_addr) ? rinfo->nh.gate.ipv4
							: rinfo->from;
		p.prefixlen = IPV4_MAX_BITLEN;

		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

		return (prefix_list_apply(plist, &p) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
}

static void *route_match_ip_next_hop_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ip_next_hop_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static struct route_map_rule_cmd route_match_ip_next_hop_prefix_list_cmd = {
	"ip next-hop prefix-list", route_match_ip_next_hop_prefix_list,
	route_match_ip_next_hop_prefix_list_compile,
	route_match_ip_next_hop_prefix_list_free};

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static route_map_result_t route_match_ip_address(void *rule,
						 struct prefix *prefix,
						 route_map_object_t type,
						 void *object)
{
	struct access_list *alist;

	if (type == RMAP_RIP) {
		alist = access_list_lookup(AFI_IP, (char *)rule);
		if (alist == NULL)
			return RMAP_NOMATCH;

		return (access_list_apply(alist, prefix) == FILTER_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
	return RMAP_NOMATCH;
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
static struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address", route_match_ip_address, route_match_ip_address_compile,
	route_match_ip_address_free};

/* `match ip address prefix-list PREFIX_LIST' */

static route_map_result_t
route_match_ip_address_prefix_list(void *rule, struct prefix *prefix,
				   route_map_object_t type, void *object)
{
	struct prefix_list *plist;

	if (type == RMAP_RIP) {
		plist = prefix_list_lookup(AFI_IP, (char *)rule);
		if (plist == NULL)
			return RMAP_NOMATCH;

		return (prefix_list_apply(plist, prefix) == PREFIX_DENY
				? RMAP_NOMATCH
				: RMAP_MATCH);
	}
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

static struct route_map_rule_cmd route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list", route_match_ip_address_prefix_list,
	route_match_ip_address_prefix_list_compile,
	route_match_ip_address_prefix_list_free};

/* `match tag TAG' */
/* Match function return 1 if match is success else return zero. */
static route_map_result_t route_match_tag(void *rule, struct prefix *prefix,
					  route_map_object_t type, void *object)
{
	route_tag_t *tag;
	struct rip_info *rinfo;
	route_tag_t rinfo_tag;

	if (type == RMAP_RIP) {
		tag = rule;
		rinfo = object;

		/* The information stored by rinfo is host ordered. */
		rinfo_tag = rinfo->tag;
		if (rinfo_tag == *tag)
			return RMAP_MATCH;
		else
			return RMAP_NOMATCH;
	}
	return RMAP_NOMATCH;
}

/* Route map commands for tag matching. */
static struct route_map_rule_cmd route_match_tag_cmd = {
	"tag", route_match_tag, route_map_rule_tag_compile,
	route_map_rule_tag_free,
};

/* `set metric METRIC' */

/* Set metric to attribute. */
static route_map_result_t route_set_metric(void *rule, struct prefix *prefix,
					   route_map_object_t type,
					   void *object)
{
	if (type == RMAP_RIP) {
		struct rip_metric_modifier *mod;
		struct rip_info *rinfo;

		mod = rule;
		rinfo = object;

		if (!mod->used)
			return RMAP_OKAY;

		if (mod->type == metric_increment)
			rinfo->metric_out += mod->metric;
		else if (mod->type == metric_decrement)
			rinfo->metric_out -= mod->metric;
		else if (mod->type == metric_absolute)
			rinfo->metric_out = mod->metric;

		if ((signed int)rinfo->metric_out < 1)
			rinfo->metric_out = 1;
		if (rinfo->metric_out > RIP_METRIC_INFINITY)
			rinfo->metric_out = RIP_METRIC_INFINITY;

		rinfo->metric_set = 1;
	}
	return RMAP_OKAY;
}

/* set metric compilation. */
static void *route_set_metric_compile(const char *arg)
{
	int len;
	const char *pnt;
	long metric;
	char *endptr = NULL;
	struct rip_metric_modifier *mod;

	mod = XMALLOC(MTYPE_ROUTE_MAP_COMPILED,
		      sizeof(struct rip_metric_modifier));
	mod->used = false;

	len = strlen(arg);
	pnt = arg;

	if (len == 0)
		return mod;

	/* Examine first character. */
	if (arg[0] == '+') {
		mod->type = metric_increment;
		pnt++;
	} else if (arg[0] == '-') {
		mod->type = metric_decrement;
		pnt++;
	} else
		mod->type = metric_absolute;

	/* Check beginning with digit string. */
	if (*pnt < '0' || *pnt > '9')
		return mod;

	/* Convert string to integer. */
	metric = strtol(pnt, &endptr, 10);

	if (*endptr != '\0' || metric < 0) {
		return mod;
	}
	if (metric > RIP_METRIC_INFINITY) {
		zlog_info(
			"%s: Metric specified: %ld is greater than RIP_METRIC_INFINITY, using INFINITY instead",
			__PRETTY_FUNCTION__, metric);
		mod->metric = RIP_METRIC_INFINITY;
	} else
		mod->metric = metric;

	mod->used = true;

	return mod;
}

/* Free route map's compiled `set metric' value. */
static void route_set_metric_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set metric rule structure. */
static struct route_map_rule_cmd route_set_metric_cmd = {
	"metric", route_set_metric, route_set_metric_compile,
	route_set_metric_free,
};

/* `set ip next-hop IP_ADDRESS' */

/* Set nexthop to object.  ojbect must be pointer to struct attr. */
static route_map_result_t route_set_ip_nexthop(void *rule,
					       struct prefix *prefix,
					       route_map_object_t type,
					       void *object)
{
	struct in_addr *address;
	struct rip_info *rinfo;

	if (type == RMAP_RIP) {
		/* Fetch routemap's rule information. */
		address = rule;
		rinfo = object;

		/* Set next hop value. */
		rinfo->nexthop_out = *address;
	}

	return RMAP_OKAY;
}

/* Route map `ip nexthop' compile function.  Given string is converted
   to struct in_addr structure. */
static void *route_set_ip_nexthop_compile(const char *arg)
{
	int ret;
	struct in_addr *address;

	address = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(struct in_addr));

	ret = inet_aton(arg, address);

	if (ret == 0) {
		XFREE(MTYPE_ROUTE_MAP_COMPILED, address);
		return NULL;
	}

	return address;
}

/* Free route map's compiled `ip nexthop' value. */
static void route_set_ip_nexthop_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip nexthop set. */
static struct route_map_rule_cmd route_set_ip_nexthop_cmd = {
	"ip next-hop", route_set_ip_nexthop, route_set_ip_nexthop_compile,
	route_set_ip_nexthop_free};

/* `set tag TAG' */

/* Set tag to object.  ojbect must be pointer to struct attr. */
static route_map_result_t route_set_tag(void *rule, struct prefix *prefix,
					route_map_object_t type, void *object)
{
	route_tag_t *tag;
	struct rip_info *rinfo;

	if (type == RMAP_RIP) {
		/* Fetch routemap's rule information. */
		tag = rule;
		rinfo = object;

		/* Set next hop value. */
		rinfo->tag_out = *tag;
	}

	return RMAP_OKAY;
}

/* Route map commands for tag set. */
static struct route_map_rule_cmd route_set_tag_cmd = {
	"tag", route_set_tag, route_map_rule_tag_compile,
	route_map_rule_tag_free};

#define MATCH_STR "Match values from routing table\n"
#define SET_STR "Set values in destination routing protocol\n"

void rip_route_map_reset()
{
	;
}

/* Route-map init */
void rip_route_map_init()
{
	route_map_init();

	route_map_add_hook(rip_route_map_update);
	route_map_delete_hook(rip_route_map_update);

	route_map_match_interface_hook(generic_match_add);
	route_map_no_match_interface_hook(generic_match_delete);

	route_map_match_ip_address_hook(generic_match_add);
	route_map_no_match_ip_address_hook(generic_match_delete);

	route_map_match_ip_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_address_prefix_list_hook(generic_match_delete);

	route_map_match_ip_next_hop_hook(generic_match_add);
	route_map_no_match_ip_next_hop_hook(generic_match_delete);

	route_map_match_ip_next_hop_prefix_list_hook(generic_match_add);
	route_map_no_match_ip_next_hop_prefix_list_hook(generic_match_delete);

	route_map_match_metric_hook(generic_match_add);
	route_map_no_match_metric_hook(generic_match_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_set_ip_nexthop_hook(generic_set_add);
	route_map_no_set_ip_nexthop_hook(generic_set_delete);

	route_map_set_metric_hook(generic_set_add);
	route_map_no_set_metric_hook(generic_set_delete);

	route_map_set_tag_hook(generic_set_add);
	route_map_no_set_tag_hook(generic_set_delete);

	route_map_install_match(&route_match_metric_cmd);
	route_map_install_match(&route_match_interface_cmd);
	route_map_install_match(&route_match_ip_next_hop_cmd);
	route_map_install_match(&route_match_ip_next_hop_prefix_list_cmd);
	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_tag_cmd);

	route_map_install_set(&route_set_metric_cmd);
	route_map_install_set(&route_set_ip_nexthop_cmd);
	route_map_install_set(&route_set_tag_cmd);
}
