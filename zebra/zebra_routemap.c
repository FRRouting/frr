// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra routemap.
 * Copyright (C) 2006 IBM Corporation
 */

#include <zebra.h>

#include "memory.h"
#include "prefix.h"
#include "rib.h"
#include "vty.h"
#include "routemap.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "nexthop.h"
#include "lib/route_types.h"
#include "vrf.h"
#include "frrstr.h"

#include "zebra/zebra_router.h"
#include "zebra/redistribute.h"
#include "zebra/debug.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_vrf.h"

#include "zebra/zebra_routemap_clippy.c"

static uint32_t zebra_rmap_update_timer = ZEBRA_RMAP_DEFAULT_UPDATE_TIMER;
static struct event *zebra_t_rmap_update = NULL;
char *zebra_import_table_routemap[AFI_MAX][SAFI_MAX][ZEBRA_KERNEL_TABLE_MAX];

struct zebra_rmap_obj {
	struct nexthop *nexthop;
	struct route_entry *re;
};

/* 'match tag TAG'
 * Match function return 1 if match is success else return 0
 */
static enum route_map_cmd_result_t
route_match_tag(void *rule, const struct prefix *prefix, void *object)
{
	route_tag_t *tag;
	struct zebra_rmap_obj *rm_data;

	tag = rule;
	rm_data = object;

	if (rm_data->re->tag == *tag)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map commands for tag matching */
static const struct route_map_rule_cmd route_match_tag_cmd = {
	"tag",
	route_match_tag,
	route_map_rule_tag_compile,
	route_map_rule_tag_free,
};


/* `match interface IFNAME' */
/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_interface(void *rule, const struct prefix *prefix, void *object)
{
	struct zebra_rmap_obj *rm_data;
	char *ifname = rule;
	ifindex_t ifindex;

	if (strcasecmp(ifname, "any") == 0)
		return RMAP_MATCH;
	rm_data = object;
	if (!rm_data || !rm_data->nexthop)
		return RMAP_NOMATCH;
	ifindex = ifname2ifindex(ifname, rm_data->nexthop->vrf_id);
	if (ifindex == 0)
		return RMAP_NOMATCH;
	if (rm_data->nexthop->ifindex == ifindex)
		return RMAP_MATCH;

	return RMAP_NOMATCH;
}

/* Route map `match interface' match statement. `arg' is IFNAME value */
static void *route_match_interface_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `match interface' value. */
static void route_match_interface_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static void show_vrf_proto_rm(struct vty *vty, struct zebra_vrf *zvrf,
			      int af_type)
{
	int i;

	vty_out(vty, "Protocol                  : route-map\n");
	vty_out(vty, "-------------------------------------\n");

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (PROTO_RM_NAME(zvrf, af_type, i))
			vty_out(vty, "%-24s  : %-10s\n", zebra_route_string(i),
				PROTO_RM_NAME(zvrf, af_type, i));
		else
			vty_out(vty, "%-24s  : none\n", zebra_route_string(i));
	}

	if (PROTO_RM_NAME(zvrf, af_type, i))
		vty_out(vty, "%-24s  : %-10s\n", "any",
			PROTO_RM_NAME(zvrf, af_type, i));
	else
		vty_out(vty, "%-24s  : none\n", "any");
}

static void show_vrf_nht_rm(struct vty *vty, struct zebra_vrf *zvrf,
			    int af_type, json_object *json)
{
	int i;

	if (!json) {
		vty_out(vty, "Protocol                  : route-map\n");
		vty_out(vty, "-------------------------------------\n");
	}

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (json) {
			if (NHT_RM_NAME(zvrf, af_type, i))
				json_object_string_add(
					json, zebra_route_string(i),
					NHT_RM_NAME(zvrf, af_type, i));
			else
				json_object_string_add(
					json, zebra_route_string(i), "none");
		} else {
			if (NHT_RM_NAME(zvrf, af_type, i))
				vty_out(vty, "%-24s  : %-10s\n",
					zebra_route_string(i),
					NHT_RM_NAME(zvrf, af_type, i));
			else
				vty_out(vty, "%-24s  : none\n",
					zebra_route_string(i));
		}
	}

	if (json) {
		if (NHT_RM_NAME(zvrf, af_type, i))
			json_object_string_add(json, "any",
					       NHT_RM_NAME(zvrf, af_type, i));
		else
			json_object_string_add(json, "any", "none");
	} else {
		if (NHT_RM_NAME(zvrf, af_type, i))
			vty_out(vty, "%-24s  : %-10s\n", "any",
				NHT_RM_NAME(zvrf, af_type, i));
		else
			vty_out(vty, "%-24s  : none\n", "any");
	}
}

static int show_proto_rm(struct vty *vty, int af_type, const char *vrf_all,
			 const char *vrf_name)
{
	struct zebra_vrf *zvrf;

	if (vrf_all) {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = (struct zebra_vrf *)vrf->info;
			if (zvrf == NULL)
				continue;
			vty_out(vty, "VRF: %s\n", zvrf->vrf->name);
			show_vrf_proto_rm(vty, zvrf, af_type);
		}
	} else {
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, false);

		zvrf = zebra_vrf_lookup_by_id(vrf_id);
		if (!zvrf)
			return CMD_SUCCESS;

		vty_out(vty, "VRF: %s\n", zvrf->vrf->name);
		show_vrf_proto_rm(vty, zvrf, af_type);
	}

	return CMD_SUCCESS;
}

static int show_nht_rm(struct vty *vty, int af_type, const char *vrf_all,
		       const char *vrf_name, bool use_json)
{
	struct zebra_vrf *zvrf;
	json_object *json = NULL;
	json_object *json_vrfs = NULL;

	if (use_json) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
		json_object_string_add(json, "afi",
				       (af_type == AFI_IP) ? "ipv4" : "ipv6");
	}

	if (vrf_all) {
		struct vrf *vrf;

		if (use_json)
			json_object_object_add(json, "vrfs", json_vrfs);

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = (struct zebra_vrf *)vrf->info;
			if (zvrf == NULL)
				continue;

			if (use_json) {
				json_object *json_proto = NULL;
				json_object *json_vrf = NULL;
				json_vrf = json_object_new_object();
				json_object_object_add(
					json_vrfs, zvrf->vrf->name, json_vrf);
				json_proto = json_object_new_object();
				json_object_object_add(json_vrf, "protocols",
						       json_proto);
				show_vrf_nht_rm(vty, zvrf, af_type, json_proto);
			} else {
				vty_out(vty, "VRF: %s\n", zvrf->vrf->name);
				show_vrf_nht_rm(vty, zvrf, af_type, NULL);
			}
		}
	} else {
		json_object *json_proto = NULL;
		json_object *json_vrf = NULL;
		vrf_id_t vrf_id = VRF_DEFAULT;

		if (vrf_name)
			VRF_GET_ID(vrf_id, vrf_name, false);

		zvrf = zebra_vrf_lookup_by_id(vrf_id);
		if (!zvrf) {
			json_object_free(json);
			json_object_free(json_vrfs);
			return CMD_SUCCESS;
		}

		if (use_json) {
			json_object_object_add(json, "vrfs", json_vrfs);
			json_vrf = json_object_new_object();
			json_object_object_add(json_vrfs, zvrf->vrf->name,
					       json_vrf);
			json_proto = json_object_new_object();
			json_object_object_add(json_vrf, "protocols",
					       json_proto);
			show_vrf_nht_rm(vty, zvrf, af_type, json_proto);
		} else {
			vty_out(vty, "VRF: %s\n", zvrf->vrf->name);
			show_vrf_nht_rm(vty, zvrf, af_type, NULL);
		}
	}

	if (use_json)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

/* Route map commands for interface matching */
static const struct route_map_rule_cmd route_match_interface_cmd = {
	"interface",
	route_match_interface,
	route_match_interface_compile,
	route_match_interface_free
};

int ip_protocol_rm_add(struct zebra_vrf *zvrf, const char *rmap, int rtype,
		       afi_t afi, safi_t safi)
{
	struct route_table *table;

	if (PROTO_RM_NAME(zvrf, afi, rtype)) {
		if (strcmp(PROTO_RM_NAME(zvrf, afi, rtype), rmap) == 0)
			return CMD_SUCCESS;

		XFREE(MTYPE_ROUTE_MAP_NAME, PROTO_RM_NAME(zvrf, afi, rtype));
	}
	route_map_counter_decrement(PROTO_RM_MAP(zvrf, afi, rtype));
	PROTO_RM_NAME(zvrf, afi, rtype) = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
	PROTO_RM_MAP(zvrf, afi, rtype) =
		route_map_lookup_by_name(PROTO_RM_NAME(zvrf, afi, rtype));
	route_map_counter_increment(PROTO_RM_MAP(zvrf, afi, rtype));

	if (PROTO_RM_NAME(zvrf, afi, rtype)) {
		if (IS_ZEBRA_DEBUG_RIB_DETAILED)
			zlog_debug(
				"%u: IPv4 Routemap config for protocol %d scheduling RIB processing",
				zvrf->vrf->vrf_id, rtype);
		/* Process routes of interested address-families. */
		table = zebra_vrf_table(afi, safi, zvrf->vrf->vrf_id);
		if (table)
			rib_update_table(table, RIB_UPDATE_RMAP_CHANGE,
					 rtype);
	}

	return CMD_SUCCESS;
}

int ip_protocol_rm_del(struct zebra_vrf *zvrf, const char *rmap, int rtype,
		       afi_t afi, safi_t safi)
{
	struct route_table *table;

	if (!PROTO_RM_NAME(zvrf, afi, rtype))
		return CMD_SUCCESS;

	if (!rmap || strcmp(rmap, PROTO_RM_NAME(zvrf, afi, rtype)) == 0) {

		route_map_counter_decrement(PROTO_RM_MAP(zvrf, afi, rtype));
		if (PROTO_RM_NAME(zvrf, afi, rtype)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"%u: IPv4 Routemap unconfig for protocol %d, scheduling RIB processing",
					zvrf->vrf->vrf_id, rtype);
			PROTO_RM_MAP(zvrf, afi, rtype) = NULL;

			/* Process routes of interested address-families. */
			table = zebra_vrf_table(afi, safi, zvrf->vrf->vrf_id);
			if (table)
				rib_update_table(table, RIB_UPDATE_RMAP_CHANGE,
						 rtype);
		}
		XFREE(MTYPE_ROUTE_MAP_NAME, PROTO_RM_NAME(zvrf, afi, rtype));
	}
	return CMD_SUCCESS;
}

int ip_nht_rm_add(struct zebra_vrf *zvrf, const char *rmap, int rtype, int afi)
{

	if (NHT_RM_NAME(zvrf, afi, rtype)) {
		if (strcmp(NHT_RM_NAME(zvrf, afi, rtype), rmap) == 0)
			return CMD_SUCCESS;

		XFREE(MTYPE_ROUTE_MAP_NAME, NHT_RM_NAME(zvrf, afi, rtype));
	}
	route_map_counter_decrement(NHT_RM_MAP(zvrf, afi, rtype));
	NHT_RM_NAME(zvrf, afi, rtype) = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap);
	NHT_RM_MAP(zvrf, afi, rtype) =
		route_map_lookup_by_name(NHT_RM_NAME(zvrf, afi, rtype));
	route_map_counter_increment(NHT_RM_MAP(zvrf, afi, rtype));

	if (NHT_RM_MAP(zvrf, afi, rtype))
		zebra_evaluate_rnh(zvrf, afi, 1, NULL, SAFI_UNICAST);

	return CMD_SUCCESS;
}

int ip_nht_rm_del(struct zebra_vrf *zvrf, const char *rmap, int rtype, int afi)
{

	if (!NHT_RM_NAME(zvrf, afi, rtype))
		return CMD_SUCCESS;

	if (!rmap || strcmp(rmap, NHT_RM_NAME(zvrf, afi, rtype)) == 0) {
		route_map_counter_decrement(NHT_RM_MAP(zvrf, afi, rtype));
		if (NHT_RM_MAP(zvrf, afi, rtype)) {
			if (IS_ZEBRA_DEBUG_RIB_DETAILED)
				zlog_debug(
					"%u: IPv4 Routemap unconfig for protocol %d, scheduling RIB processing",
					zvrf->vrf->vrf_id, rtype);
			NHT_RM_MAP(zvrf, afi, rtype) = NULL;

			zebra_evaluate_rnh(zvrf, afi, 1, NULL, SAFI_UNICAST);
		}
		XFREE(MTYPE_ROUTE_MAP_NAME, NHT_RM_NAME(zvrf, afi, rtype));
	}
	return CMD_SUCCESS;
}

DEFPY (show_ip_protocol,
       show_ip_protocol_cmd,
       "show ip protocol [vrf <NAME$vrf_name|all$vrf_all>]",
       SHOW_STR
       IP_STR
       "IP protocol filtering status\n"
       VRF_FULL_CMD_HELP_STR)
{
	int ret = show_proto_rm(vty, AFI_IP, vrf_all, vrf_name);

	return ret;
}

DEFPY (show_ipv6_protocol,
       show_ipv6_protocol_cmd,
       "show ipv6 protocol [vrf <NAME$vrf_name|all$vrf_all>]",
       SHOW_STR
       IP6_STR
       "IPv6 protocol filtering status\n"
       VRF_FULL_CMD_HELP_STR)
{
	int ret = show_proto_rm(vty, AFI_IP6, vrf_all, vrf_name);

	return ret;
}

DEFPY (show_ip_protocol_nht,
       show_ip_protocol_nht_cmd,
       "show ip nht route-map [vrf <NAME$vrf_name|all$vrf_all>] [json]",
       SHOW_STR
       IP_STR
       "IPv4 nexthop tracking table\n"
       "IPv4 Next Hop tracking filtering status\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       JSON_STR)
{
	int ret;
	bool uj = use_json(argc, argv);

	ret = show_nht_rm(vty, AFI_IP, vrf_all, vrf_name, uj);

	return ret;
}

DEFPY (show_ipv6_protocol_nht,
       show_ipv6_protocol_nht_cmd,
       "show ipv6 nht route-map [vrf <NAME$vrf_name|all$vrf_all>] [json]",
       SHOW_STR
       IP6_STR
       "IPv6 nexthop tracking table\n"
       "IPv6 Next Hop tracking filtering status\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       JSON_STR)
{
	int ret;
	bool uj = use_json(argc, argv);

	ret = show_nht_rm(vty, AFI_IP6, vrf_all, vrf_name, uj);

	return ret;
}

/*XXXXXXXXXXXXXXXXXXXXXXXXXXXX*/

/* `match ip next-hop IP_ACCESS_LIST' */

/* Match function return 1 if match is success else return zero. */
static enum route_map_cmd_result_t
route_match_ip_next_hop(void *rule, const struct prefix *prefix, void *object)
{
	struct access_list *alist;
	struct zebra_rmap_obj *rm_data;
	struct prefix_ipv4 p;

	rm_data = object;
	if (!rm_data)
		return RMAP_NOMATCH;

	switch (rm_data->nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		/* Interface routes can't match ip next-hop */
		return RMAP_NOMATCH;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
		p.family = AF_INET;
		p.prefix = rm_data->nexthop->gate.ipv4;
		p.prefixlen = IPV4_MAX_BITLEN;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return RMAP_NOMATCH;
	}
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
static const struct route_map_rule_cmd route_match_ip_next_hop_cmd = {
	"ip next-hop",
	route_match_ip_next_hop,
	route_match_ip_next_hop_compile,
	route_match_ip_next_hop_free
};

/* `match ip next-hop prefix-list PREFIX_LIST' */

static enum route_map_cmd_result_t
route_match_ip_next_hop_prefix_list(void *rule, const struct prefix *prefix,
				    void *object)
{
	struct prefix_list *plist;
	struct zebra_rmap_obj *rm_data;
	struct prefix_ipv4 p;

	rm_data = (struct zebra_rmap_obj *)object;
	if (!rm_data)
		return RMAP_NOMATCH;

	switch (rm_data->nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		/* Interface routes can't match ip next-hop */
		return RMAP_NOMATCH;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
		p.family = AF_INET;
		p.prefix = rm_data->nexthop->gate.ipv4;
		p.prefixlen = IPV4_MAX_BITLEN;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return RMAP_NOMATCH;
	}
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

/* `match ip address IP_ACCESS_LIST' */

/* Match function should return 1 if match is success else return
   zero. */
static enum route_map_cmd_result_t
route_match_address(afi_t afi, void *rule, const struct prefix *prefix,
		    void *object)
{
	struct access_list *alist;

	alist = access_list_lookup(afi, (char *)rule);
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

static enum route_map_cmd_result_t
route_match_ip_address(void *rule, const struct prefix *prefix, void *object)
{
	return route_match_address(AFI_IP, rule, prefix, object);
}

static enum route_map_cmd_result_t
route_match_ipv6_address(void *rule, const struct prefix *prefix, void *object)
{
	return route_match_address(AFI_IP6, rule, prefix, object);
}

/* Route map `ip address' match statement.  `arg' should be
   access-list name. */
static void *route_match_address_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

/* Free route map's compiled `ip address' value. */
static void route_match_address_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Route map commands for ip address matching. */
static const struct route_map_rule_cmd route_match_ip_address_cmd = {
	"ip address",
	route_match_ip_address,
	route_match_address_compile,
	route_match_address_free
};

/* Route map commands for ipv6 address matching. */
static const struct route_map_rule_cmd route_match_ipv6_address_cmd = {
	"ipv6 address",
	route_match_ipv6_address,
	route_match_address_compile,
	route_match_address_free
};

/* `match ip address prefix-list PREFIX_LIST' */

static enum route_map_cmd_result_t
route_match_address_prefix_list(void *rule, const struct prefix *prefix,
				void *object, afi_t afi)
{
	struct prefix_list *plist;

	plist = prefix_list_lookup(afi, (char *)rule);
	if (plist == NULL) {
		if (unlikely(CHECK_FLAG(rmap_debug, DEBUG_ROUTEMAP_DETAIL)))
			zlog_debug("%s: Prefix List %s (%s) specified does not exist defaulting to NO_MATCH",
				   __func__, (char *)rule, afi2str(afi));
		return RMAP_NOMATCH;
	}

	return (prefix_list_apply(plist, prefix) == PREFIX_DENY ? RMAP_NOMATCH
								: RMAP_MATCH);
}

static enum route_map_cmd_result_t
route_match_ip_address_prefix_list(void *rule, const struct prefix *prefix,
				   void *object)
{
	return (route_match_address_prefix_list(rule, prefix, object, AFI_IP));
}

static void *route_match_address_prefix_list_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_address_prefix_list_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_address_prefix_list_cmd = {
	"ip address prefix-list",
	route_match_ip_address_prefix_list,
	route_match_address_prefix_list_compile,
	route_match_address_prefix_list_free
};

static enum route_map_cmd_result_t
route_match_ipv6_address_prefix_list(void *rule, const struct prefix *prefix,
				     void *object)
{
	return (route_match_address_prefix_list(rule, prefix, object, AFI_IP6));
}

static const struct route_map_rule_cmd
		route_match_ipv6_address_prefix_list_cmd = {
	"ipv6 address prefix-list",
	route_match_ipv6_address_prefix_list,
	route_match_address_prefix_list_compile,
	route_match_address_prefix_list_free
};

/* `match ipv6 next-hop type <TYPE>' */

static enum route_map_cmd_result_t
route_match_ipv6_next_hop_type(void *rule, const struct prefix *prefix,
			       void *object)
{
	struct zebra_rmap_obj *rm_data;

	if (prefix->family == AF_INET6) {
		rm_data = (struct zebra_rmap_obj *)object;
		if (!rm_data)
			return RMAP_NOMATCH;

		if (rm_data->nexthop->type == NEXTHOP_TYPE_BLACKHOLE)
			return RMAP_MATCH;
	}

	return RMAP_NOMATCH;
}

static void *route_match_ipv6_next_hop_type_compile(const char *arg)
{
	return XSTRDUP(MTYPE_ROUTE_MAP_COMPILED, arg);
}

static void route_match_ipv6_next_hop_type_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ipv6_next_hop_type_cmd = {
	"ipv6 next-hop type",
	route_match_ipv6_next_hop_type,
	route_match_ipv6_next_hop_type_compile,
	route_match_ipv6_next_hop_type_free
};

/* `match ip address prefix-len PREFIXLEN' */

static enum route_map_cmd_result_t
route_match_address_prefix_len(void *rule, const struct prefix *prefix,
			       void *object)
{
	uint32_t *prefixlen = (uint32_t *)rule;

	return ((prefix->prefixlen == *prefixlen) ? RMAP_MATCH : RMAP_NOMATCH);
}

static void *route_match_address_prefix_len_compile(const char *arg)
{
	uint32_t *prefix_len;
	char *endptr = NULL;
	unsigned long tmpval;

	/* prefix len value shoud be integer. */
	if (!all_digit(arg))
		return NULL;

	errno = 0;
	tmpval = strtoul(arg, &endptr, 10);
	if (*endptr != '\0' || errno || tmpval > UINT32_MAX)
		return NULL;

	prefix_len = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));

	*prefix_len = tmpval;
	return prefix_len;
}

static void route_match_address_prefix_len_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd
		route_match_ip_address_prefix_len_cmd = {
	"ip address prefix-len",
	route_match_address_prefix_len,
	route_match_address_prefix_len_compile,
	route_match_address_prefix_len_free
};

static const struct route_map_rule_cmd
		route_match_ipv6_address_prefix_len_cmd = {
	"ipv6 address prefix-len",
	route_match_address_prefix_len,
	route_match_address_prefix_len_compile,
	route_match_address_prefix_len_free
};

/* `match ip nexthop prefix-len PREFIXLEN' */

static enum route_map_cmd_result_t
route_match_ip_nexthop_prefix_len(void *rule, const struct prefix *prefix,
				  void *object)
{
	uint32_t *prefixlen = (uint32_t *)rule;
	struct zebra_rmap_obj *rm_data;
	struct prefix_ipv4 p;

	rm_data = (struct zebra_rmap_obj *)object;
	if (!rm_data || !rm_data->nexthop)
		return RMAP_NOMATCH;

	switch (rm_data->nexthop->type) {
	case NEXTHOP_TYPE_IFINDEX:
		/* Interface routes can't match ip next-hop */
		return RMAP_NOMATCH;
	case NEXTHOP_TYPE_IPV4_IFINDEX:
	case NEXTHOP_TYPE_IPV4:
		p.family = AF_INET;
		p.prefix = rm_data->nexthop->gate.ipv4;
		p.prefixlen = IPV4_MAX_BITLEN;
		break;
	case NEXTHOP_TYPE_IPV6:
	case NEXTHOP_TYPE_IPV6_IFINDEX:
	case NEXTHOP_TYPE_BLACKHOLE:
		return RMAP_NOMATCH;
	}
	return ((p.prefixlen == *prefixlen) ? RMAP_MATCH : RMAP_NOMATCH);
}

static const struct route_map_rule_cmd
		route_match_ip_nexthop_prefix_len_cmd = {
	"ip next-hop prefix-len",
	route_match_ip_nexthop_prefix_len,
	route_match_address_prefix_len_compile, /* reuse */
	route_match_address_prefix_len_free     /* reuse */
};

/* `match ip next-hop type <blackhole>' */

static enum route_map_cmd_result_t
route_match_ip_next_hop_type(void *rule, const struct prefix *prefix,
			     void *object)
{
	struct zebra_rmap_obj *rm_data;

	if (prefix->family == AF_INET) {
		rm_data = (struct zebra_rmap_obj *)object;
		if (!rm_data)
			return RMAP_NOMATCH;

		if (rm_data->nexthop->type == NEXTHOP_TYPE_BLACKHOLE)
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

/* `match source-protocol PROTOCOL' */

static enum route_map_cmd_result_t
route_match_source_protocol(void *rule, const struct prefix *p, void *object)
{
	int32_t *rib_type = (int32_t *)rule;
	struct zebra_rmap_obj *rm_data;

	rm_data = (struct zebra_rmap_obj *)object;
	if (!rm_data)
		return RMAP_NOMATCH;

	return ((rm_data->re->type == *rib_type) ? RMAP_MATCH : RMAP_NOMATCH);
}

static void *route_match_source_protocol_compile(const char *arg)
{
	uint32_t *rib_type;
	int i;

	i = proto_name2num(arg);
	rib_type = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint32_t));

	*rib_type = i;

	return rib_type;
}

static void route_match_source_protocol_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_source_protocol_cmd = {
	"source-protocol",
	route_match_source_protocol,
	route_match_source_protocol_compile,
	route_match_source_protocol_free
};

/* `source-instance` */
static enum route_map_cmd_result_t
route_match_source_instance(void *rule, const struct prefix *p, void *object)
{
	uint8_t *instance = (uint8_t *)rule;
	struct zebra_rmap_obj *rm_data;

	rm_data = (struct zebra_rmap_obj *)object;
	if (!rm_data)
		return RMAP_NOMATCH;

	return (rm_data->re->instance == *instance) ? RMAP_MATCH : RMAP_NOMATCH;
}

static void *route_match_source_instance_compile(const char *arg)
{
	uint8_t *instance;
	int i;

	i = atoi(arg);
	instance = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(uint8_t));

	*instance = i;

	return instance;
}

static void route_match_source_instance_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

static const struct route_map_rule_cmd route_match_source_instance_cmd = {
	"source-instance",
	route_match_source_instance,
	route_match_source_instance_compile,
	route_match_source_instance_free
};

/* `set src A.B.C.D' */

/* Set src. */
static enum route_map_cmd_result_t
route_set_src(void *rule, const struct prefix *prefix, void *object)
{
	struct zebra_rmap_obj *rm_data;

	rm_data = (struct zebra_rmap_obj *)object;
	rm_data->nexthop->rmap_src = *(union g_addr *)rule;

	return RMAP_OKAY;
}

/* set src compilation. */
static void *route_set_src_compile(const char *arg)
{
	union g_addr src, *psrc;

	if ((inet_pton(AF_INET6, arg, &src.ipv6) == 1)
	    || (inet_pton(AF_INET, arg, &src.ipv4) == 1)) {
		psrc = XMALLOC(MTYPE_ROUTE_MAP_COMPILED, sizeof(union g_addr));
		*psrc = src;
		return psrc;
	}
	return NULL;
}

/* Free route map's compiled `set src' value. */
static void route_set_src_free(void *rule)
{
	XFREE(MTYPE_ROUTE_MAP_COMPILED, rule);
}

/* Set src rule structure. */
static const struct route_map_rule_cmd route_set_src_cmd = {
	"src",
	route_set_src,
	route_set_src_compile,
	route_set_src_free,
};

/* The function checks if the changed routemap specified by parameter rmap
 * matches the configured protocol routemaps in proto_rm table. If there is
 * a match then rib_update_table() to process the routes.
 */
static void zebra_rib_table_rm_update(const char *rmap)
{
	int i = 0;
	struct route_table *table;
	struct vrf *vrf = NULL;
	struct zebra_vrf *zvrf = NULL;
	char *rmap_name;
	struct route_map *old = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;
		if (!zvrf)
			continue;
		for (i = 0; i <= ZEBRA_ROUTE_MAX; i++) {
			rmap_name = PROTO_RM_NAME(zvrf, AFI_IP, i);
			if (rmap_name && (strcmp(rmap_name, rmap) == 0)) {
				if (IS_ZEBRA_DEBUG_EVENT)
					zlog_debug(
						"%s : AFI_IP rmap %s, route type %s",
						__func__, rmap,
						zebra_route_string(i));

				old = PROTO_RM_MAP(zvrf, AFI_IP, i);

				PROTO_RM_MAP(zvrf, AFI_IP, i) =
					route_map_lookup_by_name(rmap_name);
				/* old is NULL. i.e Route map creation event.
				 * So update applied_counter.
				 * If Old is not NULL, i.e It may be routemap
				 * updation or deletion.
				 * So no need to update the counter.
				 */
				if (!old)
					route_map_counter_increment(
						PROTO_RM_MAP(zvrf, AFI_IP, i));
				/* There is single rib table for all protocols
				 */
				table = zvrf->table[AFI_IP][SAFI_UNICAST];
				if (table) {
					rib_update_table(
						table,
						RIB_UPDATE_RMAP_CHANGE,
						i);
				}
			}
			rmap_name = PROTO_RM_NAME(zvrf, AFI_IP6, i);
			if (rmap_name && (strcmp(rmap_name, rmap) == 0)) {
				if (IS_ZEBRA_DEBUG_EVENT)
					zlog_debug(
						"%s : AFI_IP6 rmap %s, route type %s",
						__func__, rmap,
						zebra_route_string(i));

				old = PROTO_RM_MAP(zvrf, AFI_IP6, i);

				PROTO_RM_MAP(zvrf, AFI_IP6, i) =
					route_map_lookup_by_name(rmap_name);
				if (!old)
					route_map_counter_increment(
						PROTO_RM_MAP(zvrf, AFI_IP6, i));
				/* There is single rib table for all protocols
				 */
				table = zvrf->table[AFI_IP6][SAFI_UNICAST];
				if (table) {
					rib_update_table(
						table,
						RIB_UPDATE_RMAP_CHANGE,
						i);
				}
			}
		}
	}
}

/* The function checks if the changed routemap specified by parameter rmap
 * matches the configured protocol routemaps in nht_rm table. If there is
 * a match then zebra_evaluate_rnh() to process the nexthops.
 */
static void zebra_nht_rm_update(const char *rmap)
{
	int i = 0;
	struct route_table *table;
	struct vrf *vrf = NULL;
	struct zebra_vrf *zvrf = NULL;
	char *rmap_name;
	char afi_ip = 0;
	char afi_ipv6 = 0;
	struct route_map *old = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		zvrf = vrf->info;
		if (!zvrf)
			continue;
		for (i = 0; i <= ZEBRA_ROUTE_MAX; i++) {
			rmap_name = NHT_RM_NAME(zvrf, AFI_IP, i);
			if (rmap_name && (strcmp(rmap_name, rmap) == 0)) {
				if (IS_ZEBRA_DEBUG_EVENT)
					zlog_debug(
						"%s : AFI_IP rmap %s, route type %s",
						__func__, rmap,
						zebra_route_string(i));

				old = NHT_RM_MAP(zvrf, AFI_IP, i);

				NHT_RM_MAP(zvrf, AFI_IP, i) =
					route_map_lookup_by_name(rmap_name);
				if (!old)
					route_map_counter_increment(
						NHT_RM_MAP(zvrf, AFI_IP, i));
				/* There is single rib table for all protocols
				 */
				if (afi_ip == 0) {
					table = zvrf->table[AFI_IP]
							   [SAFI_UNICAST];
					if (table) {

						afi_ip = 1;

						zebra_evaluate_rnh(
							zvrf, AFI_IP, 1, NULL,
							SAFI_UNICAST);
					}
				}
			}

			rmap_name = NHT_RM_NAME(zvrf, AFI_IP6, i);
			if (rmap_name && (strcmp(rmap_name, rmap) == 0)) {
				if (IS_ZEBRA_DEBUG_EVENT)
					zlog_debug(
						"%s : AFI_IP6 rmap %s, route type %s",
						__func__, rmap,
						zebra_route_string(i));

				old = NHT_RM_MAP(zvrf, AFI_IP6, i);

				NHT_RM_MAP(zvrf, AFI_IP6, i) =
					route_map_lookup_by_name(rmap_name);
				if (!old)
					route_map_counter_increment(
						NHT_RM_MAP(zvrf, AFI_IP6, i));
				/* There is single rib table for all protocols
				 */
				if (afi_ipv6 == 0) {
					table = zvrf->table[AFI_IP6]
							   [SAFI_UNICAST];
					if (table) {

						afi_ipv6 = 1;

						zebra_evaluate_rnh(
							zvrf, AFI_IP6, 1, NULL,
							SAFI_UNICAST);
					}
				}
			}
		}
	}
}

static void zebra_route_map_process_update_cb(char *rmap_name)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("Event handler for route-map: %s",
			   rmap_name);
	zebra_import_table_rm_update(rmap_name);
	zebra_rib_table_rm_update(rmap_name);
	zebra_nht_rm_update(rmap_name);
}

static void zebra_route_map_update_timer(struct event *thread)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("Event driven route-map update triggered");

	if (IS_ZEBRA_DEBUG_RIB_DETAILED)
		zlog_debug(
			"%u: Routemap update-timer fired, scheduling RIB processing",
			VRF_DEFAULT);

	route_map_walk_update_list(zebra_route_map_process_update_cb);

	/*
	 * This code needs to be updated to be:
	 * 1) VRF Aware <sigh>
	 * 2) Route-map aware
	 */
}

void zebra_route_map_set_delay_timer(uint32_t value)
{
	zebra_rmap_update_timer = value;
	if (!value && zebra_t_rmap_update) {
		/* Event driven route map updates is being disabled */
		/* But there's a pending timer. Fire it off now */
		EVENT_OFF(zebra_t_rmap_update);
		zebra_route_map_update_timer(NULL);
	}
}

void zebra_routemap_finish(void)
{
	/* Set zebra_rmap_update_timer to 0 so that it wont schedule again */
	zebra_rmap_update_timer = 0;
	/* Thread off if any scheduled already */
	EVENT_OFF(zebra_t_rmap_update);
	route_map_finish();
}

route_map_result_t zebra_route_map_check(afi_t family, struct route_entry *re,
					 const struct prefix *p,
					 struct nexthop *nexthop,
					 struct zebra_vrf *zvrf)
{
	struct route_map *rmap = NULL;
	char *rm_name;
	route_map_result_t ret = RMAP_PERMITMATCH;
	struct zebra_rmap_obj rm_obj;

	rm_obj.nexthop = nexthop;
	rm_obj.re = re;

	if (re->type >= 0 && re->type < ZEBRA_ROUTE_MAX) {
		rm_name = PROTO_RM_NAME(zvrf, family, re->type);
		rmap = PROTO_RM_MAP(zvrf, family, re->type);

		if (rm_name && !rmap)
			return RMAP_DENYMATCH;
	}
	if (!rmap) {
		rm_name = PROTO_RM_NAME(zvrf, family, ZEBRA_ROUTE_MAX);
		rmap = PROTO_RM_MAP(zvrf, family, ZEBRA_ROUTE_MAX);

		if (rm_name && !rmap)
			return RMAP_DENYMATCH;
	}
	if (rmap) {
		ret = route_map_apply(rmap, p, &rm_obj);
	}

	return (ret);
}

char *zebra_get_import_table_route_map(afi_t afi, safi_t safi, uint32_t table)
{
	return zebra_import_table_routemap[afi][safi][table];
}

void zebra_add_import_table_route_map(afi_t afi, safi_t safi, const char *rmap_name, uint32_t table)
{
	zebra_import_table_routemap[afi][safi][table] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
}

void zebra_del_import_table_route_map(afi_t afi, safi_t safi, uint32_t table)
{
	XFREE(MTYPE_ROUTE_MAP_NAME, zebra_import_table_routemap[afi][safi][table]);
}

route_map_result_t zebra_import_table_route_map_check(int family,
						      struct route_entry *re,
						      const struct prefix *p,
						      struct nexthop *nexthop,
						      const char *rmap_name)
{
	struct route_map *rmap = NULL;
	route_map_result_t ret = RMAP_DENYMATCH;
	struct zebra_rmap_obj rm_obj;

	rm_obj.nexthop = nexthop;
	rm_obj.re = re;

	if (re->type >= 0 && re->type < ZEBRA_ROUTE_MAX)
		rmap = route_map_lookup_by_name(rmap_name);
	if (rmap) {
		ret = route_map_apply(rmap, p, &rm_obj);
	}

	return (ret);
}

route_map_result_t zebra_nht_route_map_check(afi_t afi, int client_proto,
					     const struct prefix *p,
					     struct zebra_vrf *zvrf,
					     struct route_entry *re,
					     struct nexthop *nexthop)
{
	struct route_map *rmap = NULL;
	route_map_result_t ret = RMAP_PERMITMATCH;
	struct zebra_rmap_obj rm_obj;

	rm_obj.nexthop = nexthop;
	rm_obj.re = re;

	if (client_proto >= 0 && client_proto < ZEBRA_ROUTE_MAX)
		rmap = NHT_RM_MAP(zvrf, afi, client_proto);
	if (!rmap && NHT_RM_MAP(zvrf, afi, ZEBRA_ROUTE_MAX))
		rmap = NHT_RM_MAP(zvrf, afi, ZEBRA_ROUTE_MAX);
	if (rmap)
		ret = route_map_apply(rmap, p, &rm_obj);

	return ret;
}

static void zebra_route_map_mark_update(const char *rmap_name)
{
	/* rmap_update_timer of 0 means don't do route updates */
	if (zebra_rmap_update_timer)
		EVENT_OFF(zebra_t_rmap_update);

	event_add_timer(zrouter.master, zebra_route_map_update_timer, NULL,
			zebra_rmap_update_timer, &zebra_t_rmap_update);
}

static void zebra_route_map_add(const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		zebra_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void zebra_route_map_delete(const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		zebra_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void zebra_route_map_event(const char *rmap_name)
{
	if (route_map_mark_updated(rmap_name) == 0)
		zebra_route_map_mark_update(rmap_name);

	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

void zebra_routemap_vrf_delete(struct zebra_vrf *zvrf)
{
	afi_t afi;
	uint8_t type;

	for (afi = AFI_IP; afi < AFI_MAX; afi++) {
		for (type = 0; type <= ZEBRA_ROUTE_MAX; type++) {
			if (PROTO_RM_NAME(zvrf, afi, type))
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      PROTO_RM_NAME(zvrf, afi, type));
			if (NHT_RM_NAME(zvrf, afi, type))
				XFREE(MTYPE_ROUTE_MAP_NAME,
				      NHT_RM_NAME(zvrf, afi, type));
		}
	}
}

void zebra_route_map_init(void)
{
	install_element(VIEW_NODE, &show_ip_protocol_cmd);
	install_element(VIEW_NODE, &show_ipv6_protocol_cmd);
	install_element(VIEW_NODE, &show_ip_protocol_nht_cmd);
	install_element(VIEW_NODE, &show_ipv6_protocol_nht_cmd);

	route_map_init_new(true);

	route_map_add_hook(zebra_route_map_add);
	route_map_delete_hook(zebra_route_map_delete);
	route_map_event_hook(zebra_route_map_event);

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

	route_map_match_ip_next_hop_type_hook(generic_match_add);
	route_map_no_match_ip_next_hop_type_hook(generic_match_delete);

	route_map_match_tag_hook(generic_match_add);
	route_map_no_match_tag_hook(generic_match_delete);

	route_map_match_ipv6_address_hook(generic_match_add);
	route_map_no_match_ipv6_address_hook(generic_match_delete);

	route_map_match_ipv6_address_prefix_list_hook(generic_match_add);
	route_map_no_match_ipv6_address_prefix_list_hook(generic_match_delete);

	route_map_match_ipv6_next_hop_type_hook(generic_match_add);
	route_map_no_match_ipv6_next_hop_type_hook(generic_match_delete);

	route_map_install_match(&route_match_tag_cmd);
	route_map_install_match(&route_match_interface_cmd);
	route_map_install_match(&route_match_ip_next_hop_cmd);
	route_map_install_match(&route_match_ip_next_hop_prefix_list_cmd);
	route_map_install_match(&route_match_ip_address_cmd);
	route_map_install_match(&route_match_ipv6_address_cmd);
	route_map_install_match(&route_match_ip_address_prefix_list_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_list_cmd);
	route_map_install_match(&route_match_ip_address_prefix_len_cmd);
	route_map_install_match(&route_match_ipv6_address_prefix_len_cmd);
	route_map_install_match(&route_match_ip_nexthop_prefix_len_cmd);
	route_map_install_match(&route_match_ip_next_hop_type_cmd);
	route_map_install_match(&route_match_ipv6_next_hop_type_cmd);
	route_map_install_match(&route_match_source_protocol_cmd);
	route_map_install_match(&route_match_source_instance_cmd);

	/* */
	route_map_install_set(&route_set_src_cmd);
}
