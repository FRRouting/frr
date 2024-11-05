// SPDX-License-Identifier: GPL-2.0-or-later
/* OSPF VTY interface.
 * Copyright (C) 2005 6WIND <alain.ritoux@6wind.com>
 * Copyright (C) 2000 Toshiaki Takada
 */

#include <zebra.h>
#include <string.h>

#include "printfrr.h"
#include "monotime.h"
#include "memory.h"
#include "frrevent.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include <lib/json.h>
#include "defaults.h"
#include "lib/printfrr.h"
#include "keychain.h"
#include "frrdistance.h"

#include "ospfd/ospfd.h"
#include "ospfd/ospf_asbr.h"
#include "ospfd/ospf_lsa.h"
#include "ospfd/ospf_lsdb.h"
#include "ospfd/ospf_ism.h"
#include "ospfd/ospf_interface.h"
#include "ospfd/ospf_nsm.h"
#include "ospfd/ospf_neighbor.h"
#include "ospfd/ospf_flood.h"
#include "ospfd/ospf_abr.h"
#include "ospfd/ospf_spf.h"
#include "ospfd/ospf_route.h"
#include "ospfd/ospf_zebra.h"
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_bfd.h"
#include "ospfd/ospf_ldp_sync.h"
#include "ospfd/ospf_network.h"
#include "ospfd/ospf_memory.h"

FRR_CFG_DEFAULT_BOOL(OSPF_LOG_ADJACENCY_CHANGES,
	{ .val_bool = true, .match_profile = "datacenter", },
	{ .val_bool = false },
);

static const char *const ospf_network_type_str[] = {
	"Null",	"POINTOPOINT", "BROADCAST", "NBMA", "POINTOMULTIPOINT",
	"VIRTUALLINK", "LOOPBACK"};

/* Utility functions. */
int str2area_id(const char *str, struct in_addr *area_id, int *area_id_fmt)
{
	char *ep;

	area_id->s_addr = htonl(strtoul(str, &ep, 10));
	if (*ep && !inet_aton(str, area_id))
		return -1;

	*area_id_fmt =
		*ep ? OSPF_AREA_ID_FMT_DOTTEDQUAD : OSPF_AREA_ID_FMT_DECIMAL;

	return 0;
}

static void area_id2str(char *buf, int length, struct in_addr *area_id,
			int area_id_fmt)
{
	if (area_id_fmt == OSPF_AREA_ID_FMT_DOTTEDQUAD)
		inet_ntop(AF_INET, area_id, buf, length);
	else
		snprintf(buf, length, "%lu",
			 (unsigned long)ntohl(area_id->s_addr));
}

static int str2metric(const char *str, int *metric)
{
	/* Sanity check. */
	if (str == NULL)
		return 0;

	*metric = strtol(str, NULL, 10);
	if (*metric < 0 || *metric > 16777214) {
		/* vty_out (vty, "OSPF metric value is invalid\n"); */
		return 0;
	}

	return 1;
}

static int str2metric_type(const char *str, int *metric_type)
{
	/* Sanity check. */
	if (str == NULL)
		return 0;

	if (strncmp(str, "1", 1) == 0)
		*metric_type = EXTERNAL_METRIC_TYPE_1;
	else if (strncmp(str, "2", 1) == 0)
		*metric_type = EXTERNAL_METRIC_TYPE_2;
	else
		return 0;

	return 1;
}

int ospf_oi_count(struct interface *ifp)
{
	struct route_node *rn;
	int i = 0;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn))
		if (rn->info)
			i++;

	return i;
}

#define OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf)             \
	if (argv_find(argv, argc, "vrf", &idx_vrf)) {                          \
		vrf_name = argv[idx_vrf + 1]->arg;                             \
		all_vrf = strmatch(vrf_name, "all");                           \
	}

static int ospf_router_cmd_parse(struct vty *vty, struct cmd_token *argv[],
				 const int argc, unsigned short *instance,
				 const char **vrf_name)
{
	int idx_vrf = 0, idx_inst = 0;

	*instance = 0;
	if (argv_find(argv, argc, "(1-65535)", &idx_inst)) {
		if (ospf_instance == 0) {
			vty_out(vty,
				"%% OSPF is not running in instance mode\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		*instance = strtoul(argv[idx_inst]->arg, NULL, 10);
	}

	*vrf_name = VRF_DEFAULT_NAME;
	if (argv_find(argv, argc, "vrf", &idx_vrf)) {
		if (ospf_instance != 0) {
			vty_out(vty,
				"%% VRF is not supported in instance mode\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		*vrf_name = argv[idx_vrf + 1]->arg;
	}

	return CMD_SUCCESS;
}

static void ospf_show_vrf_name(struct ospf *ospf, struct vty *vty,
			       json_object *json, uint8_t use_vrf)
{
	if (use_vrf) {
		if (json) {
			json_object_string_add(json, "vrfName",
					       ospf_get_name(ospf));
			json_object_int_add(json, "vrfId", ospf->vrf_id);
		} else
			vty_out(vty, "VRF Name: %s\n", ospf_get_name(ospf));
	}
}

#include "ospfd/ospf_vty_clippy.c"

DEFUN_NOSH (router_ospf,
       router_ospf_cmd,
       "router ospf [{(1-65535)|vrf NAME}]",
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR)
{
	unsigned short instance;
	const char *vrf_name;
	bool created = false;
	struct ospf *ospf;
	int ret;

	ret = ospf_router_cmd_parse(vty, argv, argc, &instance, &vrf_name);
	if (ret != CMD_SUCCESS)
		return ret;

	if (instance != ospf_instance) {
		VTY_PUSH_CONTEXT_NULL(OSPF_NODE);
		return CMD_NOT_MY_INSTANCE;
	}

	ospf = ospf_get(instance, vrf_name, &created);

	if (created)
		if (DFLT_OSPF_LOG_ADJACENCY_CHANGES)
			SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);

	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"Config command 'router ospf %d' received, vrf %s id %u oi_running %u",
			ospf->instance, ospf_get_name(ospf), ospf->vrf_id,
			ospf->oi_running);

	VTY_PUSH_CONTEXT(OSPF_NODE, ospf);

	return ret;
}

DEFUN (no_router_ospf,
       no_router_ospf_cmd,
       "no router ospf [{(1-65535)|vrf NAME}]",
       NO_STR
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR)
{
	unsigned short instance;
	const char *vrf_name;
	struct ospf *ospf;
	int ret;

	ret = ospf_router_cmd_parse(vty, argv, argc, &instance, &vrf_name);
	if (ret != CMD_SUCCESS)
		return ret;

	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup(instance, vrf_name);
	if (ospf) {
		if (ospf->gr_info.restart_support)
			ospf_gr_nvm_delete(ospf);

		ospf_finish(ospf);
	} else
		ret = CMD_WARNING_CONFIG_FAILED;

	return ret;
}


DEFPY (ospf_router_id,
       ospf_router_id_cmd,
       "ospf router-id A.B.C.D",
       "OSPF specific commands\n"
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	struct listnode *node;
	struct ospf_area *area;

	ospf->router_id_static = router_id;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->full_nbrs) {
			vty_out(vty,
				"For this router-id change to take effect, use \"clear ip ospf process\" command\n");
			return CMD_SUCCESS;
		}

	ospf_router_id_update(ospf);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_router_id_old,
              ospf_router_id_old_cmd,
              "router-id A.B.C.D",
              "router-id for the OSPF process\n"
              "OSPF router-id in IP address format\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 1;
	struct listnode *node;
	struct ospf_area *area;
	struct in_addr router_id;
	int ret;

	ret = inet_aton(argv[idx_ipv4]->arg, &router_id);
	if (!ret) {
		vty_out(vty, "Please specify Router ID by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ospf->router_id_static = router_id;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->full_nbrs) {
			vty_out(vty,
				"For this router-id change to take effect, use \"clear ip ospf process\" command\n");
			return CMD_SUCCESS;
		}

	ospf_router_id_update(ospf);

	return CMD_SUCCESS;
}

DEFPY (no_ospf_router_id,
       no_ospf_router_id_cmd,
       "no ospf router-id [A.B.C.D]",
       NO_STR
       "OSPF specific commands\n"
       "router-id for the OSPF process\n"
       "OSPF router-id in IP address format\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *node;
	struct ospf_area *area;

	if (router_id_str) {
		if (!IPV4_ADDR_SAME(&ospf->router_id_static, &router_id)) {
			vty_out(vty, "%% OSPF router-id doesn't match\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
	}

	ospf->router_id_static.s_addr = 0;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area))
		if (area->full_nbrs) {
			vty_out(vty,
				"For this router-id change to take effect, use \"clear ip ospf process\" command\n");
			return CMD_SUCCESS;
		}

	ospf_router_id_update(ospf);

	return CMD_SUCCESS;
}

ALIAS_HIDDEN (no_ospf_router_id,
              no_router_id_cmd,
              "no router-id [A.B.C.D]",
              NO_STR
              "router-id for the OSPF process\n"
              "OSPF router-id in IP address format\n")

static void ospf_passive_interface_default_update(struct ospf *ospf,
						  uint8_t newval)
{
	struct listnode *ln;
	struct ospf_interface *oi;

	ospf->passive_interface_default = newval;

	/* update multicast memberships */
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, ln, oi))
		ospf_if_set_multicast(oi);
}

static void ospf_passive_interface_update(struct interface *ifp,
					  struct ospf_if_params *params,
					  struct in_addr addr, uint8_t newval)
{
	struct route_node *rn;

	if (OSPF_IF_PARAM_CONFIGURED(params, passive_interface)) {
		if (params->passive_interface == newval)
			return;

		params->passive_interface = newval;
		UNSET_IF_PARAM(params, passive_interface);
		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, addr);
			ospf_if_update_params(ifp, addr);
		}
	} else {
		params->passive_interface = newval;
		SET_IF_PARAM(params, passive_interface);
	}

	/*
	 * XXX We should call ospf_if_set_multicast on exactly those
	 * interfaces for which the passive property changed.  It is too much
	 * work to determine this set, so we do this for every interface.
	 * This is safe and reasonable because ospf_if_set_multicast uses a
	 * record of joined groups to avoid systems calls if the desired
	 * memberships match the current memership.
	 */

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi)
			ospf_if_set_multicast(oi);
	}

	/*
	 * XXX It is not clear what state transitions the interface needs to
	 * undergo when going from active to passive and vice versa. Fixing
	 * this will require precise identification of interfaces having such a
	 * transition.
	 */
}

DEFUN (ospf_passive_interface_default,
       ospf_passive_interface_default_cmd,
       "passive-interface default",
       "Suppress routing updates on an interface\n"
       "Suppress routing updates on interfaces by default\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_passive_interface_default_update(ospf, OSPF_IF_PASSIVE);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_passive_interface_addr,
       ospf_passive_interface_addr_cmd,
       "passive-interface IFNAME [A.B.C.D]",
       "Suppress routing updates on an interface\n"
       "Interface's name\n"
       "IPv4 address\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 2;
	struct interface *ifp = NULL;
	struct in_addr addr = {.s_addr = INADDR_ANY};
	struct ospf_if_params *params;
	int ret;

	vty_out(vty,
		"This command is deprecated, because it is not VRF-aware.\n");
	vty_out(vty,
		"Please, use \"ip ospf passive\" on an interface instead.\n");

	if (ospf->vrf_id != VRF_UNKNOWN)
		ifp = if_get_by_name(argv[1]->arg, ospf->vrf_id, ospf->name);

	if (ifp == NULL) {
		vty_out(vty, "interface %s not found.\n", (char *)argv[1]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc == 3) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	} else {
		params = IF_DEF_PARAMS(ifp);
	}

	ospf_passive_interface_update(ifp, params, addr, OSPF_IF_PASSIVE);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_passive_interface_default,
       no_ospf_passive_interface_default_cmd,
       "no passive-interface default",
       NO_STR
       "Allow routing updates on an interface\n"
       "Allow routing updates on interfaces by default\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_passive_interface_default_update(ospf, OSPF_IF_ACTIVE);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_passive_interface,
       no_ospf_passive_interface_addr_cmd,
       "no passive-interface IFNAME [A.B.C.D]",
       NO_STR
       "Allow routing updates on an interface\n"
       "Interface's name\n"
       "IPv4 address\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 3;
	struct interface *ifp = NULL;
	struct in_addr addr = {.s_addr = INADDR_ANY};
	struct ospf_if_params *params;
	int ret;

	vty_out(vty,
		"This command is deprecated, because it is not VRF-aware.\n");
	vty_out(vty,
		"Please, use \"no ip ospf passive\" on an interface instead.\n");

	if (ospf->vrf_id != VRF_UNKNOWN)
		ifp = if_get_by_name(argv[2]->arg, ospf->vrf_id, ospf->name);

	if (ifp == NULL) {
		vty_out(vty, "interface %s not found.\n", (char *)argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc == 4) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	} else {
		params = IF_DEF_PARAMS(ifp);
	}

	ospf_passive_interface_update(ifp, params, addr, OSPF_IF_ACTIVE);

	return CMD_SUCCESS;
}


DEFUN (ospf_network_area,
       ospf_network_area_cmd,
       "network A.B.C.D/M area <A.B.C.D|(0-4294967295)>",
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_prefixlen = 1;
	int idx_ipv4_number = 3;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int ret, format;
	uint32_t count;

	if (ospf->instance) {
		vty_out(vty,
			"The network command is not supported in multi-instance ospf\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	count = ospf_count_area_params(ospf);
	if (count > 0) {
		vty_out(vty,
			"Please remove all ip ospf area x.x.x.x commands first.\n");
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s ospf vrf %s num of %u ip ospf area x config",
				__func__, ospf_get_name(ospf), count);
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get network prefix and Area ID. */
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);
	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	ret = ospf_network_set(ospf, &p, area_id, format);
	if (ret == 0) {
		vty_out(vty, "There is already same network statement.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf_network_area,
       no_ospf_network_area_cmd,
       "no network A.B.C.D/M area <A.B.C.D|(0-4294967295)>",
       NO_STR
       "Enable routing on an IP network\n"
       "OSPF network prefix\n"
       "Set the OSPF area ID\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_prefixlen = 2;
	int idx_ipv4_number = 4;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int ret, format;

	if (ospf->instance) {
		vty_out(vty,
			"The network command is not supported in multi-instance ospf\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get network prefix and Area ID. */
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);
	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	ret = ospf_network_unset(ospf, &p, area_id);
	if (ret == 0) {
		vty_out(vty,
			"Can't find specified network area configuration.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_area_range,
       ospf_area_range_cmd,
       "area <A.B.C.D|(0-4294967295)> range A.B.C.D/M [advertise [cost (0-16777215)]]",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "Advertise this range (default)\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	int idx_cost = 6;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;
	uint32_t cost;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	ospf_area_range_set(ospf, area, area->ranges, &p,
			    OSPF_AREA_RANGE_ADVERTISE, false);
	if (argc > 5) {
		cost = strtoul(argv[idx_cost]->arg, NULL, 10);
		ospf_area_range_cost_set(ospf, area, area->ranges, &p, cost);
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_area_range_cost,
       ospf_area_range_cost_cmd,
       "area <A.B.C.D|(0-4294967295)> range A.B.C.D/M {cost (0-16777215)|substitute A.B.C.D/M}",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n"
       "Announce area range as another prefix\n"
       "Network prefix to be announced instead of range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	int idx = 4;
	struct prefix_ipv4 p, s;
	struct in_addr area_id;
	int format;
	uint32_t cost;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	ospf_area_range_set(ospf, area, area->ranges, &p,
			    OSPF_AREA_RANGE_ADVERTISE, false);
	if (argv_find(argv, argc, "cost", &idx)) {
		cost = strtoul(argv[idx + 1]->arg, NULL, 10);
		ospf_area_range_cost_set(ospf, area, area->ranges, &p, cost);
	}

	idx = 4;
	if (argv_find(argv, argc, "substitute", &idx)) {
		str2prefix_ipv4(argv[idx + 1]->arg, &s);
		ospf_area_range_substitute_set(ospf, area, &p, &s);
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_area_range_not_advertise,
       ospf_area_range_not_advertise_cmd,
       "area <A.B.C.D|(0-4294967295)> range A.B.C.D/M not-advertise",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "DoNotAdvertise this range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	ospf_area_range_set(ospf, area, area->ranges, &p, 0, false);
	ospf_area_range_substitute_unset(ospf, area, &p);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_range,
       no_ospf_area_range_cmd,
       "no area <A.B.C.D|(0-4294967295)> range A.B.C.D/M [<cost [(0-16777215)]|advertise [cost [(0-16777215)]]|not-advertise>]",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n"
       "Advertise this range (default)\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n"
       "DoNotAdvertise this range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	int idx_ipv4_number = 2;
	int idx_ipv4_prefixlen = 4;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	ospf_area_range_unset(ospf, area, area->ranges, &p);

	ospf_area_check_free(ospf, area_id);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_range_substitute,
       no_ospf_area_range_substitute_cmd,
       "no area <A.B.C.D|(0-4294967295)> range A.B.C.D/M substitute A.B.C.D/M",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "Announce area range as another prefix\n"
       "Network prefix to be announced instead of range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	int idx_ipv4_number = 2;
	int idx_ipv4_prefixlen = 4;
	int idx_ipv4_prefixlen_2 = 6;
	struct prefix_ipv4 p, s;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen_2]->arg, &s);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	ospf_area_range_substitute_unset(ospf, area, &p);

	ospf_area_check_free(ospf, area_id);

	return CMD_SUCCESS;
}


/* Command Handler Logic in VLink stuff is delicate!!

	ALTER AT YOUR OWN RISK!!!!

	Various dummy values are used to represent 'NoChange' state for
	VLink configuration NOT being changed by a VLink command, and
	special syntax is used within the command strings so that the
	typed in command verbs can be seen in the configuration command
	bacckend handler.  This is to drastically reduce the verbeage
	required to coe up with a reasonably compatible Cisco VLink command

	- Matthew Grant <grantma@anathoth.gen.nz>
	Wed, 21 Feb 2001 15:13:52 +1300
 */

/* Configuration data for virtual links
 */
struct ospf_vl_config_data {
	struct vty *vty;	/* vty stuff */
	struct in_addr area_id; /* area ID from command line */
	int area_id_fmt;	/* command line area ID format */
	struct in_addr vl_peer; /* command line vl_peer */
	int auth_type;		/* Authehntication type, if given */
	char *auth_key;		/* simple password if present */
	int crypto_key_id;      /* Cryptographic key ID */
	char *md5_key;		/* MD5 authentication key */
	char *keychain;     /* Cryptographic keychain */
	int del_keychain;
	int hello_interval;     /* Obvious what these are... */
	int retransmit_interval;
	int retransmit_window;
	int transmit_delay;
	int dead_interval;
};

static void ospf_vl_config_data_init(struct ospf_vl_config_data *vl_config,
				     struct vty *vty)
{
	memset(vl_config, 0, sizeof(struct ospf_vl_config_data));
	vl_config->auth_type = OSPF_AUTH_CMD_NOTSEEN;
	vl_config->vty = vty;
}

static struct ospf_vl_data *
ospf_find_vl_data(struct ospf *ospf, struct ospf_vl_config_data *vl_config)
{
	struct ospf_area *area;
	struct ospf_vl_data *vl_data;
	struct vty *vty;
	struct in_addr area_id;

	vty = vl_config->vty;
	area_id = vl_config->area_id;

	if (area_id.s_addr == OSPF_AREA_BACKBONE) {
		vty_out(vty,
			"Configuring VLs over the backbone is not allowed\n");
		return NULL;
	}
	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, vl_config->area_id_fmt);

	if (area->external_routing != OSPF_AREA_DEFAULT) {
		if (vl_config->area_id_fmt == OSPF_AREA_ID_FMT_DOTTEDQUAD)
			vty_out(vty, "Area %pI4 is %s\n", &area_id,
				area->external_routing == OSPF_AREA_NSSA
					? "nssa"
					: "stub");
		else
			vty_out(vty, "Area %ld is %s\n",
				(unsigned long)ntohl(area_id.s_addr),
				area->external_routing == OSPF_AREA_NSSA
					? "nssa"
					: "stub");
		return NULL;
	}

	if ((vl_data = ospf_vl_lookup(ospf, area, vl_config->vl_peer))
	    == NULL) {
		vl_data = ospf_vl_data_new(area, vl_config->vl_peer);
		if (vl_data->vl_oi == NULL) {
			vl_data->vl_oi = ospf_vl_new(ospf, vl_data);
			ospf_vl_add(ospf, vl_data);
			ospf_spf_calculate_schedule(ospf,
						    SPF_FLAG_CONFIG_CHANGE);
		}
	}
	return vl_data;
}


static int ospf_vl_set_security(struct ospf_vl_data *vl_data,
				struct ospf_vl_config_data *vl_config)
{
	struct crypt_key *ck;
	struct vty *vty;
	struct interface *ifp = vl_data->vl_oi->ifp;

	vty = vl_config->vty;

	if (vl_config->auth_type != OSPF_AUTH_CMD_NOTSEEN) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), auth_type);
		IF_DEF_PARAMS(ifp)->auth_type = vl_config->auth_type;
	}

	if (vl_config->auth_key) {
		memset(IF_DEF_PARAMS(ifp)->auth_simple, 0,
		       OSPF_AUTH_SIMPLE_SIZE + 1);
		strlcpy((char *)IF_DEF_PARAMS(ifp)->auth_simple,
			vl_config->auth_key,
			sizeof(IF_DEF_PARAMS(ifp)->auth_simple));
	} else if (vl_config->keychain) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), keychain_name);
		XFREE(MTYPE_OSPF_IF_PARAMS, IF_DEF_PARAMS(ifp)->keychain_name);
		IF_DEF_PARAMS(ifp)->keychain_name = XSTRDUP(MTYPE_OSPF_IF_PARAMS, vl_config->keychain);
	} else if (vl_config->md5_key) {
		if (ospf_crypt_key_lookup(IF_DEF_PARAMS(ifp)->auth_crypt,
					  vl_config->crypto_key_id)
		    != NULL) {
			vty_out(vty, "OSPF: Key %d already exists\n",
				vl_config->crypto_key_id);
			return CMD_WARNING;
		}
		ck = ospf_crypt_key_new();
		ck->key_id = vl_config->crypto_key_id;
		memset(ck->auth_key, 0, OSPF_AUTH_MD5_SIZE + 1);
		strlcpy((char *)ck->auth_key, vl_config->md5_key,
			sizeof(ck->auth_key));

		ospf_crypt_key_add(IF_DEF_PARAMS(ifp)->auth_crypt, ck);
	} else if (vl_config->crypto_key_id != 0) {
		/* Delete a key */

		if (ospf_crypt_key_lookup(IF_DEF_PARAMS(ifp)->auth_crypt,
					  vl_config->crypto_key_id)
		    == NULL) {
			vty_out(vty, "OSPF: Key %d does not exist\n",
				vl_config->crypto_key_id);
			return CMD_WARNING_CONFIG_FAILED;
		}

		ospf_crypt_key_delete(IF_DEF_PARAMS(ifp)->auth_crypt,
				      vl_config->crypto_key_id);
	} else if (vl_config->del_keychain) {
		UNSET_IF_PARAM(IF_DEF_PARAMS(ifp), keychain_name);
		XFREE(MTYPE_OSPF_IF_PARAMS, IF_DEF_PARAMS(ifp)->keychain_name);
	}

	return CMD_SUCCESS;
}

static int ospf_vl_set_timers(struct ospf_vl_data *vl_data,
			      struct ospf_vl_config_data *vl_config)
{
	struct interface *ifp = vl_data->vl_oi->ifp;
	/* Virtual Link data initialised to defaults, so only set
	   if a value given */
	if (vl_config->hello_interval) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), v_hello);
		IF_DEF_PARAMS(ifp)->v_hello = vl_config->hello_interval;
	}

	if (vl_config->dead_interval) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), v_wait);
		IF_DEF_PARAMS(ifp)->v_wait = vl_config->dead_interval;
	}

	if (vl_config->retransmit_interval) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), retransmit_interval);
		IF_DEF_PARAMS(ifp)->retransmit_interval =
			vl_config->retransmit_interval;
	}

	if (vl_config->retransmit_window) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), retransmit_window);
		IF_DEF_PARAMS(ifp)->retransmit_window =
			vl_config->retransmit_window;
	}

	if (vl_config->transmit_delay) {
		SET_IF_PARAM(IF_DEF_PARAMS(ifp), transmit_delay);
		IF_DEF_PARAMS(ifp)->transmit_delay = vl_config->transmit_delay;
	}

	return CMD_SUCCESS;
}


/* The business end of all of the above */
static int ospf_vl_set(struct ospf *ospf, struct ospf_vl_config_data *vl_config)
{
	struct ospf_vl_data *vl_data;
	int ret;

	vl_data = ospf_find_vl_data(ospf, vl_config);
	if (!vl_data)
		return CMD_WARNING_CONFIG_FAILED;

	/* Process this one first as it can have a fatal result, which can
	   only logically occur if the virtual link exists already
	   Thus a command error does not result in a change to the
	   running configuration such as unexpectedly altered timer
	   values etc.*/
	ret = ospf_vl_set_security(vl_data, vl_config);
	if (ret != CMD_SUCCESS)
		return ret;

	/* Set any time based parameters, these area already range checked */

	ret = ospf_vl_set_timers(vl_data, vl_config);
	if (ret != CMD_SUCCESS)
		return ret;

	return CMD_SUCCESS;
}

/* This stuff exists to make specifying all the alias commands A LOT simpler
 */
#define VLINK_HELPSTR_IPADDR                                                   \
	"OSPF area parameters\n"                                               \
	"OSPF area ID in IP address format\n"                                  \
	"OSPF area ID as a decimal value\n"                                    \
	"Configure a virtual link\n"                                           \
	"Router ID of the remote ABR\n"

#define VLINK_HELPSTR_AUTHTYPE_SIMPLE                                          \
	"Enable authentication on this virtual link\n"                         \
	"dummy string \n"

#define VLINK_HELPSTR_AUTHTYPE_ALL                                             \
	VLINK_HELPSTR_AUTHTYPE_SIMPLE                                          \
	"Use null authentication\n"                                            \
	"Use message-digest authentication\n"

#define VLINK_HELPSTR_TIME_PARAM                                                \
	"Time between HELLO packets\n"                                          \
	"Seconds\n"                                                             \
	"Time between retransmitting lost link state advertisements\n"          \
	"Seconds\n"                                                             \
	"Window for LSA retransmit - Retransmit LSAs expiring in this window\n" \
	"Milliseconds\n"                                                        \
	"Link state transmit delay\n"                                           \
	"Seconds\n"                                                             \
	"Interval time after which a neighbor is declared down\n"               \
	"Seconds\n"

#define VLINK_HELPSTR_AUTH_SIMPLE                                              \
	"Authentication password (key)\n"                                      \
	"The OSPF password (key)\n"

#define VLINK_HELPSTR_AUTH_MD5                                                 \
	"Message digest authentication password (key)\n"                       \
	"Key ID\n"                                                             \
	"Use MD5 algorithm\n"                                                  \
	"The OSPF password (key)\n"

DEFUN (ospf_area_vlink,
       ospf_area_vlink_cmd,
       "area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D [authentication [<key-chain KEYCHAIN_NAME|message-digest|null>]] [<message-digest-key (1-255) md5 KEY|authentication-key AUTH_KEY>]",
       VLINK_HELPSTR_IPADDR
       "Enable authentication on this virtual link\n"
	   "Use a key-chain for cryptographic authentication keys\n"
	   "Key-chain name\n"
       "Use message-digest authentication\n"
       "Use null authentication\n"
       VLINK_HELPSTR_AUTH_MD5
       VLINK_HELPSTR_AUTH_SIMPLE)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	int idx_ipv4 = 3;
	struct ospf_vl_config_data vl_config;
	char auth_key[OSPF_AUTH_SIMPLE_SIZE + 1];
	char md5_key[OSPF_AUTH_MD5_SIZE + 1];
	int ret;
	int idx = 0;

	ospf_vl_config_data_init(&vl_config, vty);

	/* Read off first 2 parameters and check them */
	ret = str2area_id(argv[idx_ipv4_number]->arg, &vl_config.area_id,
			  &vl_config.area_id_fmt);
	if (ret < 0) {
		vty_out(vty, "OSPF area ID is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = inet_aton(argv[idx_ipv4]->arg, &vl_config.vl_peer);
	if (!ret) {
		vty_out(vty, "Please specify valid Router ID as a.b.c.d\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc <= 4) {
		/* Thats all folks! - BUGS B. strikes again!!!*/

		return ospf_vl_set(ospf, &vl_config);
	}

	if (argv_find(argv, argc, "authentication", &idx)) {
		/* authentication  - this option can only occur
		at start of command line */
		vl_config.auth_type = OSPF_AUTH_SIMPLE;
	}

	if (argv_find(argv, argc, "key-chain", &idx)) {
		vl_config.auth_type = OSPF_AUTH_CRYPTOGRAPHIC;
		vl_config.keychain = argv[idx+1]->arg;
	} else if (argv_find(argv, argc, "message-digest", &idx)) {
		/* authentication message-digest */
		vl_config.auth_type = OSPF_AUTH_CRYPTOGRAPHIC;
	} else if (argv_find(argv, argc, "null", &idx)) {
		/* "authentication null" */
		vl_config.auth_type = OSPF_AUTH_NULL;
	}

	if (argv_find(argv, argc, "message-digest-key", &idx)) {
		vl_config.md5_key = NULL;
		vl_config.crypto_key_id = strtol(argv[idx + 1]->arg, NULL, 10);
		if (vl_config.crypto_key_id < 0)
			return CMD_WARNING_CONFIG_FAILED;

		strlcpy(md5_key, argv[idx + 3]->arg, sizeof(md5_key));
		vl_config.md5_key = md5_key;
	}

	if (argv_find(argv, argc, "authentication-key", &idx)) {
		strlcpy(auth_key, argv[idx + 1]->arg, sizeof(auth_key));
		vl_config.auth_key = auth_key;
	}

	/* Action configuration */

	return ospf_vl_set(ospf, &vl_config);
}

DEFUN (no_ospf_area_vlink,
       no_ospf_area_vlink_cmd,
       "no area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D [authentication [<key-chain KEYCHAIN_NAME|message-digest|null>]] [<message-digest-key (1-255) md5 KEY|authentication-key AUTH_KEY>]",
       NO_STR
       VLINK_HELPSTR_IPADDR
       "Enable authentication on this virtual link\n"
	   "Use a key-chain for cryptographic authentication keys\n"
	   "Key-chain name\n"
       "Use message-digest authentication\n"
       "Use null authentication\n"
       VLINK_HELPSTR_AUTH_MD5
       VLINK_HELPSTR_AUTH_SIMPLE)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	int idx_ipv4 = 4;
	struct ospf_area *area;
	struct ospf_vl_config_data vl_config;
	struct ospf_vl_data *vl_data = NULL;
	char auth_key[OSPF_AUTH_SIMPLE_SIZE + 1];
	int idx = 0;
	int ret, format;

	ospf_vl_config_data_init(&vl_config, vty);

	ret = str2area_id(argv[idx_ipv4_number]->arg, &vl_config.area_id,
			  &format);
	if (ret < 0) {
		vty_out(vty, "OSPF area ID is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	area = ospf_area_lookup_by_area_id(ospf, vl_config.area_id);
	if (!area) {
		vty_out(vty, "Area does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = inet_aton(argv[idx_ipv4]->arg, &vl_config.vl_peer);
	if (!ret) {
		vty_out(vty, "Please specify valid Router ID as a.b.c.d\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	vl_data = ospf_vl_lookup(ospf, area, vl_config.vl_peer);
	if (!vl_data) {
		vty_out(vty, "Virtual link does not exist\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc <= 5) {
		/* Basic VLink no command */
		/* Thats all folks! - BUGS B. strikes again!!!*/
		ospf_vl_delete(ospf, vl_data);
		ospf_area_check_free(ospf, vl_config.area_id);
		return CMD_SUCCESS;
	}

	/* If we are down here, we are reseting parameters */
	/* Deal with other parameters */

	if (argv_find(argv, argc, "authentication", &idx)) {
		/* authentication  - this option can only occur
		at start of command line */
		vl_config.auth_type = OSPF_AUTH_NOTSET;
	}

	if (argv_find(argv, argc, "key-chain", &idx)) {
		vl_config.del_keychain = 1;
		vl_config.keychain = NULL;
	}

	if (argv_find(argv, argc, "message-digest-key", &idx)) {
		vl_config.md5_key = NULL;
		vl_config.crypto_key_id = strtol(argv[idx + 1]->arg, NULL, 10);
		if (vl_config.crypto_key_id < 0)
			return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv_find(argv, argc, "authentication-key", &idx)) {
		/* Reset authentication-key to 0 */
		memset(auth_key, 0, OSPF_AUTH_SIMPLE_SIZE + 1);
		vl_config.auth_key = auth_key;
	}

	/* Action configuration */

	return ospf_vl_set(ospf, &vl_config);
}

DEFUN (ospf_area_vlink_intervals,
       ospf_area_vlink_intervals_cmd,
       "area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D {hello-interval (1-65535)|retransmit-interval (1-65535)|retransmit-window (20-10000)|transmit-delay (1-65535)|dead-interval (1-65535)}",
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_vl_config_data vl_config;
	int ret = 0;

	ospf_vl_config_data_init(&vl_config, vty);

	char *area_id = argv[1]->arg;
	char *router_id = argv[3]->arg;

	ret = str2area_id(area_id, &vl_config.area_id, &vl_config.area_id_fmt);
	if (ret < 0) {
		vty_out(vty, "OSPF area ID is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = inet_aton(router_id, &vl_config.vl_peer);
	if (!ret) {
		vty_out(vty, "Please specify valid Router ID as a.b.c.d\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (int idx = 4; idx < argc; idx++) {
		if (strmatch(argv[idx]->text, "hello-interval"))
			vl_config.hello_interval =
				strtol(argv[++idx]->arg, NULL, 10);
		else if (strmatch(argv[idx]->text, "retransmit-interval"))
			vl_config.retransmit_interval =
				strtol(argv[++idx]->arg, NULL, 10);
		else if (strmatch(argv[idx]->text, "retransmit-window"))
			vl_config.retransmit_window = strtol(argv[++idx]->arg,
							     NULL, 10);
		else if (strmatch(argv[idx]->text, "transmit-delay"))
			vl_config.transmit_delay =
				strtol(argv[++idx]->arg, NULL, 10);
		else if (strmatch(argv[idx]->text, "dead-interval"))
			vl_config.dead_interval =
				strtol(argv[++idx]->arg, NULL, 10);
	}

	/* Action configuration */
	return ospf_vl_set(ospf, &vl_config);
}

DEFUN (no_ospf_area_vlink_intervals,
       no_ospf_area_vlink_intervals_cmd,
       "no area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D {hello-interval [(1-65535)]|retransmit-interval [(1-65535)]|retransmit-window [(20-1000)]|transmit-delay [(1-65535)]|dead-interval [(1-65535)]}",
       NO_STR
       VLINK_HELPSTR_IPADDR
       VLINK_HELPSTR_TIME_PARAM)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_vl_config_data vl_config;
	int ret = 0;

	ospf_vl_config_data_init(&vl_config, vty);

	char *area_id = argv[2]->arg;
	char *router_id = argv[4]->arg;

	ret = str2area_id(area_id, &vl_config.area_id, &vl_config.area_id_fmt);
	if (ret < 0) {
		vty_out(vty, "OSPF area ID is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = inet_aton(router_id, &vl_config.vl_peer);
	if (!ret) {
		vty_out(vty, "Please specify valid Router ID as a.b.c.d\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	for (int idx = 5; idx < argc; idx++) {
		if (strmatch(argv[idx]->text, "hello-interval"))
			vl_config.hello_interval = OSPF_HELLO_INTERVAL_DEFAULT;
		else if (strmatch(argv[idx]->text, "retransmit-interval"))
			vl_config.retransmit_interval =
				OSPF_RETRANSMIT_INTERVAL_DEFAULT;
		else if (strmatch(argv[idx]->text, "retransmit-window"))
			vl_config.retransmit_window =
				OSPF_RETRANSMIT_WINDOW_DEFAULT;
		else if (strmatch(argv[idx]->text, "transmit-delay"))
			vl_config.transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;
		else if (strmatch(argv[idx]->text, "dead-interval"))
			vl_config.dead_interval =
				OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
	}

	/* Action configuration */
	return ospf_vl_set(ospf, &vl_config);
}

DEFUN (ospf_area_shortcut,
       ospf_area_shortcut_cmd,
       "area <A.B.C.D|(0-4294967295)> shortcut <default|enable|disable>",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure the area's shortcutting mode\n"
       "Set default shortcutting behavior\n"
       "Enable shortcutting through the area\n"
       "Disable shortcutting through the area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	int idx_enable_disable = 3;
	struct ospf_area *area;
	struct in_addr area_id;
	int mode;
	int format;

	VTY_GET_OSPF_AREA_ID_NO_BB("shortcut", area_id, format,
				   argv[idx_ipv4_number]->arg);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	if (strncmp(argv[idx_enable_disable]->arg, "de", 2) == 0)
		mode = OSPF_SHORTCUT_DEFAULT;
	else if (strncmp(argv[idx_enable_disable]->arg, "di", 2) == 0)
		mode = OSPF_SHORTCUT_DISABLE;
	else if (strncmp(argv[idx_enable_disable]->arg, "e", 1) == 0)
		mode = OSPF_SHORTCUT_ENABLE;
	else
		return CMD_WARNING_CONFIG_FAILED;

	ospf_area_shortcut_set(ospf, area, mode);

	if (ospf->abr_type != OSPF_ABR_SHORTCUT)
		vty_out(vty,
			"Shortcut area setting will take effect only when the router is configured as Shortcut ABR\n");

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_shortcut,
       no_ospf_area_shortcut_cmd,
       "no area <A.B.C.D|(0-4294967295)> shortcut <default|enable|disable>",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure the area's shortcutting mode\n"
       "Deconfigure default shortcutting through the area\n"
       "Deconfigure enabled shortcutting through the area\n"
       "Deconfigure disabled shortcutting through the area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID_NO_BB("shortcut", area_id, format,
				   argv[idx_ipv4_number]->arg);

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!area)
		return CMD_SUCCESS;

	ospf_area_shortcut_unset(ospf, area);

	return CMD_SUCCESS;
}


DEFUN (ospf_area_stub,
       ospf_area_stub_cmd,
       "area <A.B.C.D|(0-4294967295)> stub",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	struct in_addr area_id;
	int ret, format;

	VTY_GET_OSPF_AREA_ID_NO_BB("stub", area_id, format,
				   argv[idx_ipv4_number]->arg);

	ret = ospf_area_stub_set(ospf, area_id);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	if (ret == 0) {
		vty_out(vty,
			"First deconfigure all virtual link through this area\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Flush the external LSAs from the specified area */
	ospf_flush_lsa_from_area(ospf, area_id, OSPF_AS_EXTERNAL_LSA);
	ospf_area_no_summary_unset(ospf, area_id);

	return CMD_SUCCESS;
}

DEFUN (ospf_area_stub_no_summary,
       ospf_area_stub_no_summary_cmd,
       "area <A.B.C.D|(0-4294967295)> stub no-summary",
       "OSPF stub parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into stub\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	struct in_addr area_id;
	int ret, format;

	VTY_GET_OSPF_AREA_ID_NO_BB("stub", area_id, format,
				   argv[idx_ipv4_number]->arg);

	ret = ospf_area_stub_set(ospf, area_id);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	if (ret == 0) {
		vty_out(vty,
			"%% Area cannot be stub as it contains a virtual link\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ospf_area_no_summary_set(ospf, area_id);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_stub,
       no_ospf_area_stub_cmd,
       "no area <A.B.C.D|(0-4294967295)> stub",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID_NO_BB("stub", area_id, format,
				   argv[idx_ipv4_number]->arg);

	ospf_area_stub_unset(ospf, area_id);
	ospf_area_no_summary_unset(ospf, area_id);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_stub_no_summary,
       no_ospf_area_stub_no_summary_cmd,
       "no area <A.B.C.D|(0-4294967295)> stub no-summary",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as stub\n"
       "Do not inject inter-area routes into area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID_NO_BB("stub", area_id, format,
				   argv[idx_ipv4_number]->arg);
	ospf_area_no_summary_unset(ospf, area_id);

	return CMD_SUCCESS;
}

DEFPY (ospf_area_nssa,
       ospf_area_nssa_cmd,
       "area <A.B.C.D|(0-4294967295)>$area_str nssa\
         [{\
	   <translate-candidate|translate-never|translate-always>$translator_role\
	   |default-information-originate$dflt_originate [{metric (0-16777214)$mval|metric-type (1-2)$mtype}]\
	   |no-summary$no_summary\
	   |suppress-fa$suppress_fa\
	 }]",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Configure NSSA-ABR for translate election (default)\n"
       "Configure NSSA-ABR to never translate\n"
       "Configure NSSA-ABR to always translate\n"
       "Originate Type 7 default into NSSA area\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Do not inject inter-area routes into nssa\n"
       "Suppress forwarding address\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct in_addr area_id;
	int ret, format;

	VTY_GET_OSPF_AREA_ID_NO_BB("NSSA", area_id, format, area_str);

	ret = ospf_area_nssa_set(ospf, area_id);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	if (ret == 0) {
		vty_out(vty,
			"%% Area cannot be nssa as it contains a virtual link\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (translator_role) {
		if (strncmp(translator_role, "translate-c", 11) == 0)
			ospf_area_nssa_translator_role_set(
				ospf, area_id, OSPF_NSSA_ROLE_CANDIDATE);
		else if (strncmp(translator_role, "translate-n", 11) == 0)
			ospf_area_nssa_translator_role_set(
				ospf, area_id, OSPF_NSSA_ROLE_NEVER);
		else if (strncmp(translator_role, "translate-a", 11) == 0)
			ospf_area_nssa_translator_role_set(
				ospf, area_id, OSPF_NSSA_ROLE_ALWAYS);
	} else {
		ospf_area_nssa_translator_role_set(ospf, area_id,
						   OSPF_NSSA_ROLE_CANDIDATE);
	}

	if (dflt_originate) {
		int metric_type = DEFAULT_METRIC_TYPE;

		if (mval_str == NULL)
			mval = -1;
		if (mtype_str)
			(void)str2metric_type(mtype_str, &metric_type);
		ospf_area_nssa_default_originate_set(ospf, area_id, mval,
						     metric_type);
	} else
		ospf_area_nssa_default_originate_unset(ospf, area_id);

	if (no_summary)
		ospf_area_nssa_no_summary_set(ospf, area_id);
	else
		ospf_area_no_summary_unset(ospf, area_id);

	if (suppress_fa)
		ospf_area_nssa_suppress_fa_set(ospf, area_id);
	else
		ospf_area_nssa_suppress_fa_unset(ospf, area_id);

	/* Flush the external LSA for the specified area */
	ospf_flush_lsa_from_area(ospf, area_id, OSPF_AS_EXTERNAL_LSA);
	ospf_schedule_abr_task(ospf);
	ospf_schedule_asbr_redist_update(ospf);

	return CMD_SUCCESS;
}

DEFPY (no_ospf_area_nssa,
       no_ospf_area_nssa_cmd,
       "no area <A.B.C.D|(0-4294967295)>$area_str nssa\
         [{\
	   <translate-candidate|translate-never|translate-always>\
	   |default-information-originate [{metric [(0-16777214)]|metric-type [(1-2)]}]\
	   |no-summary\
	   |suppress-fa\
	 }]",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Configure NSSA-ABR for translate election (default)\n"
       "Configure NSSA-ABR to never translate\n"
       "Configure NSSA-ABR to always translate\n"
       "Originate Type 7 default into NSSA area\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Do not inject inter-area routes into nssa\n"
       "Suppress forwarding address\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID_NO_BB("NSSA", area_id, format, area_str);

	/* Flush the NSSA LSA for the specified area */
	ospf_flush_lsa_from_area(ospf, area_id, OSPF_AS_NSSA_LSA);
	ospf_area_no_summary_unset(ospf, area_id);
	ospf_area_nssa_default_originate_unset(ospf, area_id);
	ospf_area_nssa_suppress_fa_unset(ospf, area_id);
	ospf_area_nssa_unset(ospf, area_id);

	ospf_schedule_abr_task(ospf);

	return CMD_SUCCESS;
}

DEFPY (ospf_area_nssa_range,
       ospf_area_nssa_range_cmd,
       "area <A.B.C.D|(0-4294967295)>$area_str nssa range A.B.C.D/M$prefix [<not-advertise$not_adv|cost (0-16777215)$cost>]",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Configured address range\n"
       "Specify IPv4 prefix\n"
       "Do not advertise\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	struct in_addr area_id;
	int format;
	int advertise = 0;

	VTY_GET_OSPF_AREA_ID(area_id, format, area_str);
	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	if (area->external_routing != OSPF_AREA_NSSA) {
		vty_out(vty, "%% First configure %s as an NSSA area\n",
			area_str);
		return CMD_WARNING;
	}

	if (!not_adv)
		advertise = OSPF_AREA_RANGE_ADVERTISE;

	ospf_area_range_set(ospf, area, area->nssa_ranges,
			    (struct prefix_ipv4 *)prefix, advertise, true);
	if (cost_str)
		ospf_area_range_cost_set(ospf, area, area->nssa_ranges,
					 (struct prefix_ipv4 *)prefix, cost);

	return CMD_SUCCESS;
}

DEFPY (no_ospf_area_nssa_range,
       no_ospf_area_nssa_range_cmd,
       "no area <A.B.C.D|(0-4294967295)>$area_str nssa range A.B.C.D/M$prefix [<not-advertise|cost [(0-16777215)]>]",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Configured address range\n"
       "Specify IPv4 prefix\n"
       "Do not advertise\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, area_str);
	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	if (area->external_routing != OSPF_AREA_NSSA) {
		vty_out(vty, "%% First configure %s as an NSSA area\n",
			area_str);
		return CMD_WARNING;
	}

	ospf_area_range_unset(ospf, area, area->nssa_ranges,
			      (struct prefix_ipv4 *)prefix);

	return CMD_SUCCESS;
}

DEFUN (ospf_area_default_cost,
       ospf_area_default_cost_cmd,
       "area <A.B.C.D|(0-4294967295)> default-cost (0-16777215)",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	int idx_number = 3;
	struct ospf_area *area;
	struct in_addr area_id;
	uint32_t cost;
	int format;
	struct prefix_ipv4 p;

	VTY_GET_OSPF_AREA_ID_NO_BB("default-cost", area_id, format,
				   argv[idx_ipv4_number]->arg);
	cost = strtoul(argv[idx_number]->arg, NULL, 10);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);

	if (area->external_routing == OSPF_AREA_DEFAULT) {
		vty_out(vty, "The area is neither stub, nor NSSA\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	area->default_cost = cost;

	p.family = AF_INET;
	p.prefix.s_addr = OSPF_DEFAULT_DESTINATION;
	p.prefixlen = 0;
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"ospf_abr_announce_stub_defaults(): announcing 0.0.0.0/0 to area %pI4",
			&area->area_id);
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_default_cost,
       no_ospf_area_default_cost_cmd,
       "no area <A.B.C.D|(0-4294967295)> default-cost [(0-16777215)]",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Set the summary-default cost of a NSSA or stub area\n"
       "Stub's advertised default summary cost\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;
	struct prefix_ipv4 p;

	VTY_GET_OSPF_AREA_ID_NO_BB("default-cost", area_id, format,
				   argv[idx_ipv4_number]->arg);

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return CMD_SUCCESS;

	if (area->external_routing == OSPF_AREA_DEFAULT) {
		vty_out(vty, "The area is neither stub, nor NSSA\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	area->default_cost = 1;

	p.family = AF_INET;
	p.prefix.s_addr = OSPF_DEFAULT_DESTINATION;
	p.prefixlen = 0;
	if (IS_DEBUG_OSPF_EVENT)
		zlog_debug(
			"ospf_abr_announce_stub_defaults(): announcing 0.0.0.0/0 to area %pI4",
			&area->area_id);
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);


	ospf_area_check_free(ospf, area_id);

	return CMD_SUCCESS;
}

DEFUN (ospf_area_export_list,
       ospf_area_export_list_cmd,
       "area <A.B.C.D|(0-4294967295)> export-list ACCESSLIST4_NAME",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);
	ospf_area_export_list_set(ospf, area, argv[3]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_export_list,
       no_ospf_area_export_list_cmd,
       "no area <A.B.C.D|(0-4294967295)> export-list ACCESSLIST4_NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return CMD_SUCCESS;

	ospf_area_export_list_unset(ospf, area);

	return CMD_SUCCESS;
}


DEFUN (ospf_area_import_list,
       ospf_area_import_list_cmd,
       "area <A.B.C.D|(0-4294967295)> import-list ACCESSLIST4_NAME",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Set the filter for networks from other areas announced to the specified one\n"
       "Name of the access-list\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);
	ospf_area_import_list_set(ospf, area, argv[3]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_import_list,
       no_ospf_area_import_list_cmd,
       "no area <A.B.C.D|(0-4294967295)> import-list ACCESSLIST4_NAME",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Unset the filter for networks announced to other areas\n"
       "Name of the access-list\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return CMD_SUCCESS;

	ospf_area_import_list_unset(ospf, area);

	return CMD_SUCCESS;
}

DEFUN (ospf_area_filter_list,
       ospf_area_filter_list_cmd,
       "area <A.B.C.D|(0-4294967295)> filter-list prefix PREFIXLIST4_NAME <in|out>",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Filter networks between OSPF areas\n"
       "Filter prefixes between OSPF areas\n"
       "Name of an IP prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	int idx_word = 4;
	int idx_in_out = 5;
	struct ospf_area *area;
	struct in_addr area_id;
	struct prefix_list *plist;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);
	plist = prefix_list_lookup(AFI_IP, argv[idx_word]->arg);
	if (strncmp(argv[idx_in_out]->arg, "in", 2) == 0) {
		PREFIX_LIST_IN(area) = plist;
		if (PREFIX_NAME_IN(area))
			free(PREFIX_NAME_IN(area));

		PREFIX_NAME_IN(area) = strdup(argv[idx_word]->arg);
		ospf_schedule_abr_task(ospf);
	} else {
		PREFIX_LIST_OUT(area) = plist;
		if (PREFIX_NAME_OUT(area))
			free(PREFIX_NAME_OUT(area));

		PREFIX_NAME_OUT(area) = strdup(argv[idx_word]->arg);
		ospf_schedule_abr_task(ospf);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_filter_list,
       no_ospf_area_filter_list_cmd,
       "no area <A.B.C.D|(0-4294967295)> filter-list prefix PREFIXLIST4_NAME <in|out>",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Filter networks between OSPF areas\n"
       "Filter prefixes between OSPF areas\n"
       "Name of an IP prefix-list\n"
       "Filter networks sent to this area\n"
       "Filter networks sent from this area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	int idx_word = 5;
	int idx_in_out = 6;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	if ((area = ospf_area_lookup_by_area_id(ospf, area_id)) == NULL)
		return CMD_SUCCESS;

	if (strncmp(argv[idx_in_out]->arg, "in", 2) == 0) {
		if (PREFIX_NAME_IN(area))
			if (strcmp(PREFIX_NAME_IN(area), argv[idx_word]->arg)
			    != 0)
				return CMD_SUCCESS;

		PREFIX_LIST_IN(area) = NULL;
		if (PREFIX_NAME_IN(area))
			free(PREFIX_NAME_IN(area));

		PREFIX_NAME_IN(area) = NULL;

		ospf_schedule_abr_task(ospf);
	} else {
		if (PREFIX_NAME_OUT(area))
			if (strcmp(PREFIX_NAME_OUT(area), argv[idx_word]->arg)
			    != 0)
				return CMD_SUCCESS;

		PREFIX_LIST_OUT(area) = NULL;
		if (PREFIX_NAME_OUT(area))
			free(PREFIX_NAME_OUT(area));

		PREFIX_NAME_OUT(area) = NULL;

		ospf_schedule_abr_task(ospf);
	}

	return CMD_SUCCESS;
}


DEFUN (ospf_area_authentication_message_digest,
       ospf_area_authentication_message_digest_cmd,
       "[no] area <A.B.C.D|(0-4294967295)> authentication message-digest",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n"
       "Use message-digest authentication\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx = 0;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	argv_find(argv, argc, "area", &idx);
	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx + 1]->arg);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);
	area->auth_type = strmatch(argv[0]->text, "no")
				  ? OSPF_AUTH_NULL
				  : OSPF_AUTH_CRYPTOGRAPHIC;

	return CMD_SUCCESS;
}

DEFUN (ospf_area_authentication,
       ospf_area_authentication_cmd,
       "area <A.B.C.D|(0-4294967295)> authentication",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_get(ospf, area_id);
	ospf_area_display_format_set(ospf, area, format);
	area->auth_type = OSPF_AUTH_SIMPLE;

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_authentication,
       no_ospf_area_authentication_cmd,
       "no area <A.B.C.D|(0-4294967295)> authentication",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Enable authentication\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct ospf_area *area;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);

	area = ospf_area_lookup_by_area_id(ospf, area_id);
	if (area == NULL)
		return CMD_SUCCESS;

	area->auth_type = OSPF_AUTH_NULL;

	ospf_area_check_free(ospf, area_id);

	return CMD_SUCCESS;
}


DEFUN (ospf_abr_type,
       ospf_abr_type_cmd,
       "ospf abr-type <cisco|ibm|shortcut|standard>",
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, cisco implementation\n"
       "Alternative ABR, IBM implementation\n"
       "Shortcut ABR\n"
       "Standard behavior (RFC2328)\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_vendor = 2;
	uint8_t abr_type = OSPF_ABR_UNKNOWN;

	if (strncmp(argv[idx_vendor]->arg, "c", 1) == 0)
		abr_type = OSPF_ABR_CISCO;
	else if (strncmp(argv[idx_vendor]->arg, "i", 1) == 0)
		abr_type = OSPF_ABR_IBM;
	else if (strncmp(argv[idx_vendor]->arg, "sh", 2) == 0)
		abr_type = OSPF_ABR_SHORTCUT;
	else if (strncmp(argv[idx_vendor]->arg, "st", 2) == 0)
		abr_type = OSPF_ABR_STAND;
	else
		return CMD_WARNING_CONFIG_FAILED;

	/* If ABR type value is changed, schedule ABR task. */
	if (ospf->abr_type != abr_type) {
		ospf->abr_type = abr_type;
		ospf_schedule_abr_task(ospf);

		/* The ABR task might not initiate SPF recalculation if the
		 * OSPF flags remain the same. And inter-area routes would not
		 * be added/deleted according to the new ABR type. So this
		 * needs to be done here too.
		 */
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_ABR_STATUS_CHANGE);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf_abr_type,
       no_ospf_abr_type_cmd,
       "no ospf abr-type [<cisco|ibm|shortcut|standard>]",
       NO_STR
       "OSPF specific commands\n"
       "Set OSPF ABR type\n"
       "Alternative ABR, cisco implementation\n"
       "Alternative ABR, IBM implementation\n"
       "Shortcut ABR\n"
       "Standard ABR\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_vendor = 3;
	uint8_t abr_type = OSPF_ABR_UNKNOWN;

	if (strncmp(argv[idx_vendor]->arg, "c", 1) == 0)
		abr_type = OSPF_ABR_CISCO;
	else if (strncmp(argv[idx_vendor]->arg, "i", 1) == 0)
		abr_type = OSPF_ABR_IBM;
	else if (strncmp(argv[idx_vendor]->arg, "sh", 2) == 0)
		abr_type = OSPF_ABR_SHORTCUT;
	else if (strncmp(argv[idx_vendor]->arg, "st", 2) == 0)
		abr_type = OSPF_ABR_STAND;
	else
		return CMD_WARNING_CONFIG_FAILED;

	/* If ABR type value is changed, schedule ABR task. */
	if (ospf->abr_type == abr_type) {
		ospf->abr_type = OSPF_ABR_DEFAULT;
		ospf_schedule_abr_task(ospf);
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_log_adjacency_changes,
       ospf_log_adjacency_changes_cmd,
       "log-adjacency-changes",
       "Log changes in adjacency state\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
	UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
	return CMD_SUCCESS;
}

DEFUN (ospf_log_adjacency_changes_detail,
       ospf_log_adjacency_changes_detail_cmd,
       "log-adjacency-changes detail",
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
	SET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
	return CMD_SUCCESS;
}

DEFUN (no_ospf_log_adjacency_changes,
       no_ospf_log_adjacency_changes_cmd,
       "no log-adjacency-changes",
       NO_STR
       "Log changes in adjacency state\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
	UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES);
	return CMD_SUCCESS;
}

DEFUN (no_ospf_log_adjacency_changes_detail,
       no_ospf_log_adjacency_changes_detail_cmd,
       "no log-adjacency-changes detail",
       NO_STR
       "Log changes in adjacency state\n"
       "Log all state changes\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	UNSET_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL);
	return CMD_SUCCESS;
}

DEFUN (ospf_compatible_rfc1583,
       ospf_compatible_rfc1583_cmd,
       "compatible rfc1583",
       "OSPF compatibility list\n"
       "compatible with RFC 1583\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (!CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
		SET_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE);
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
	}
	return CMD_SUCCESS;
}

DEFUN (no_ospf_compatible_rfc1583,
       no_ospf_compatible_rfc1583_cmd,
       "no compatible rfc1583",
       NO_STR
       "OSPF compatibility list\n"
       "compatible with RFC 1583\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
		UNSET_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE);
		ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);
	}
	return CMD_SUCCESS;
}

ALIAS(ospf_compatible_rfc1583, ospf_rfc1583_flag_cmd,
      "ospf rfc1583compatibility",
      "OSPF specific commands\n"
      "Enable the RFC1583Compatibility flag\n")

ALIAS(no_ospf_compatible_rfc1583, no_ospf_rfc1583_flag_cmd,
      "no ospf rfc1583compatibility", NO_STR
      "OSPF specific commands\n"
      "Disable the RFC1583Compatibility flag\n")

static void ospf_table_reinstall_routes(struct ospf *ospf,
					struct route_table *rt)
{
	struct route_node *rn;

	if (!rt)
		return;

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		struct ospf_route *or;

		or = rn->info;
		if (!or)
			continue;

		if (or->type == OSPF_DESTINATION_NETWORK)
			ospf_zebra_add(ospf, (struct prefix_ipv4 *)&rn->p, or);
		else if (or->type == OSPF_DESTINATION_DISCARD)
			ospf_zebra_add_discard(ospf,
					       (struct prefix_ipv4 *)&rn->p);
	}
}

static void ospf_reinstall_routes(struct ospf *ospf)
{
	ospf_table_reinstall_routes(ospf, ospf->new_table);
	ospf_table_reinstall_routes(ospf, ospf->new_external_route);
}

DEFPY (ospf_send_extra_data,
       ospf_send_extra_data_cmd,
       "[no] ospf send-extra-data zebra",
       NO_STR
       OSPF_STR
       "Extra data to Zebra for display/use\n"
       "To zebra\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (no && CHECK_FLAG(ospf->config, OSPF_SEND_EXTRA_DATA_TO_ZEBRA)) {
		UNSET_FLAG(ospf->config, OSPF_SEND_EXTRA_DATA_TO_ZEBRA);
		ospf_reinstall_routes(ospf);
	} else if (!CHECK_FLAG(ospf->config, OSPF_SEND_EXTRA_DATA_TO_ZEBRA)) {
		SET_FLAG(ospf->config, OSPF_SEND_EXTRA_DATA_TO_ZEBRA);
		ospf_reinstall_routes(ospf);
	}

	return CMD_SUCCESS;
}

static int ospf_timers_spf_set(struct vty *vty, unsigned int delay,
			       unsigned int hold, unsigned int max)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (ospf->spf_delay != delay || ospf->spf_holdtime != hold ||
	    ospf->spf_max_holdtime != max)
		ospf->spf_hold_multiplier = 1;

	ospf->spf_delay = delay;
	ospf->spf_holdtime = hold;
	ospf->spf_max_holdtime = max;

	return CMD_SUCCESS;
}

DEFPY (ospf_timers_min_ls_interval,
       ospf_timers_min_ls_interval_cmd,
       "[no] timers throttle lsa all ![(0-5000)]$lsa_refresh_interval",
       NO_STR
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "LSA delay between transmissions\n"
       "All LSA types\n"
       "Delay (msec) between sending LSAs\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (no)
		ospf->min_ls_interval = OSPF_MIN_LS_INTERVAL;
	else
		ospf->min_ls_interval = strtoul(lsa_refresh_interval_str, NULL, 10);

	return CMD_SUCCESS;
}

DEFUN (ospf_timers_throttle_spf,
       ospf_timers_throttle_spf_cmd,
       "timers throttle spf (0-600000) (0-600000) (0-600000)",
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "OSPF SPF timers\n"
       "Delay (msec) from first change received till SPF calculation\n"
       "Initial hold time (msec) between consecutive SPF calculations\n"
       "Maximum hold time (msec)\n")
{
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 5;
	unsigned int delay, hold, max;

	if (argc < 6) {
		vty_out(vty, "Insufficient arguments\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	delay = strtoul(argv[idx_number]->arg, NULL, 10);
	hold = strtoul(argv[idx_number_2]->arg, NULL, 10);
	max = strtoul(argv[idx_number_3]->arg, NULL, 10);

	return ospf_timers_spf_set(vty, delay, hold, max);
}

DEFUN (no_ospf_timers_throttle_spf,
       no_ospf_timers_throttle_spf_cmd,
       "no timers throttle spf [(0-600000)(0-600000)(0-600000)]",
       NO_STR
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "OSPF SPF timers\n"
       "Delay (msec) from first change received till SPF calculation\n"
       "Initial hold time (msec) between consecutive SPF calculations\n"
       "Maximum hold time (msec)\n")
{
	return ospf_timers_spf_set(vty, OSPF_SPF_DELAY_DEFAULT,
				   OSPF_SPF_HOLDTIME_DEFAULT,
				   OSPF_SPF_MAX_HOLDTIME_DEFAULT);
}


DEFPY (ospf_timers_lsa_min_arrival,
       ospf_timers_lsa_min_arrival_cmd,
       "[no] timers lsa min-arrival ![(0-5000)]$min_arrival",
       NO_STR
       "Adjust routing timers\n"
       "OSPF LSA timers\n"
       "Minimum delay in receiving new version of an LSA\n"
       "Delay in milliseconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	if (no)
		ospf->min_ls_arrival = OSPF_MIN_LS_ARRIVAL;
	else
		ospf->min_ls_arrival = strtoul(min_arrival_str, NULL, 10);
	return CMD_SUCCESS;
}

DEFPY_HIDDEN (ospf_timers_lsa_min_arrival_deprecated,
	      ospf_timers_lsa_min_arrival_deprecated_cmd,
	      "timers lsa min-arrival [(5001-60000)]$min_arrival",
	      "Adjust routing timers\n"
	      "OSPF LSA timers\n"
	      "Minimum delay in receiving new version of an LSA\n"
	      "Deprecated delay in milliseconds - delays in this range default to 5000 msec\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	vty_out(vty, "%% OSPF `timers lsa min-arrival` set to the maximum of %u milliseconds\n",
		OSPF_MIN_LS_ARRIVAL_MAX);
	ospf->min_ls_arrival = OSPF_MIN_LS_ARRIVAL_MAX;

	return CMD_SUCCESS;
}

DEFPY(ospf_neighbor, ospf_neighbor_cmd,
      "[no] neighbor A.B.C.D$nbr_address [{priority (0-255)$priority | poll-interval (1-65535)$interval}]",
      NO_STR
      NEIGHBOR_STR
      "Neighbor IP address\n"
      "Neighbor Priority\n"
      "Priority\n"
      "Dead Neighbor Polling interval\n"
      "Seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (no)
		ospf_nbr_nbma_unset(ospf, nbr_address);
	else {
		ospf_nbr_nbma_set(ospf, nbr_address);
		if (priority_str)
			ospf_nbr_nbma_priority_set(ospf, nbr_address, priority);

		if (interval_str)
			ospf_nbr_nbma_poll_interval_set(ospf, nbr_address,
							interval);
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_refresh_timer,
       ospf_refresh_timer_cmd,
       "refresh timer (10-1800)",
       "Adjust refresh parameters\n"
       "Set refresh timer\n"
       "Timer value in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 2;
	unsigned int interval;

	interval = strtoul(argv[idx_number]->arg, NULL, 10);
	interval = (interval / OSPF_LSA_REFRESHER_GRANULARITY)
		   * OSPF_LSA_REFRESHER_GRANULARITY;

	ospf_timers_refresh_set(ospf, interval);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_refresh_timer,
       no_ospf_refresh_timer_val_cmd,
       "no refresh timer [(10-1800)]",
       NO_STR
       "Adjust refresh parameters\n"
       "Unset refresh timer\n"
       "Timer value in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 3;
	unsigned int interval;

	if (argc == 1) {
		interval = strtoul(argv[idx_number]->arg, NULL, 10);

		if (ospf->lsa_refresh_interval != interval
		    || interval == OSPF_LSA_REFRESH_INTERVAL_DEFAULT)
			return CMD_SUCCESS;
	}

	ospf_timers_refresh_unset(ospf);

	return CMD_SUCCESS;
}


DEFUN (ospf_auto_cost_reference_bandwidth,
       ospf_auto_cost_reference_bandwidth_cmd,
       "auto-cost reference-bandwidth (1-4294967)",
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n"
       "The reference bandwidth in terms of Mbits per second\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	int idx_number = 2;
	uint32_t refbw;
	struct interface *ifp;

	refbw = strtol(argv[idx_number]->arg, NULL, 10);
	if (refbw < 1 || refbw > 4294967) {
		vty_out(vty, "reference-bandwidth value is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* If reference bandwidth is changed. */
	if ((refbw) == ospf->ref_bandwidth)
		return CMD_SUCCESS;

	ospf->ref_bandwidth = refbw;
	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_recalculate_output_cost(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_auto_cost_reference_bandwidth,
       no_ospf_auto_cost_reference_bandwidth_cmd,
       "no auto-cost reference-bandwidth [(1-4294967)]",
       NO_STR
       "Calculate OSPF interface cost according to bandwidth\n"
       "Use reference bandwidth method to assign OSPF cost\n"
       "The reference bandwidth in terms of Mbits per second\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;

	if (ospf->ref_bandwidth == OSPF_DEFAULT_REF_BANDWIDTH)
		return CMD_SUCCESS;

	ospf->ref_bandwidth = OSPF_DEFAULT_REF_BANDWIDTH;
	vty_out(vty, "%% OSPF: Reference bandwidth is changed.\n");
	vty_out(vty,
		"        Please ensure reference bandwidth is consistent across all routers\n");

	FOR_ALL_INTERFACES (vrf, ifp)
		ospf_if_recalculate_output_cost(ifp);

	return CMD_SUCCESS;
}

DEFUN (ospf_write_multiplier,
       ospf_write_multiplier_cmd,
       "ospf write-multiplier (1-100)",
       "OSPF specific commands\n"
       "Write multiplier\n"
       "Maximum number of interface serviced per write\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number;
	uint32_t write_oi_count;

	if (argc == 3)
		idx_number = 2;
	else
		idx_number = 1;

	write_oi_count = strtol(argv[idx_number]->arg, NULL, 10);
	if (write_oi_count < 1 || write_oi_count > 100) {
		vty_out(vty, "write-multiplier value is invalid\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ospf->write_oi_count = write_oi_count;
	return CMD_SUCCESS;
}

ALIAS(ospf_write_multiplier, write_multiplier_cmd, "write-multiplier (1-100)",
      "Write multiplier\n"
      "Maximum number of interface serviced per write\n")

DEFUN (no_ospf_write_multiplier,
       no_ospf_write_multiplier_cmd,
       "no ospf write-multiplier [(1-100)]",
       NO_STR
       "OSPF specific commands\n"
       "Write multiplier\n"
       "Maximum number of interface serviced per write\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->write_oi_count = OSPF_WRITE_INTERFACE_COUNT_DEFAULT;
	return CMD_SUCCESS;
}

ALIAS(no_ospf_write_multiplier, no_write_multiplier_cmd,
      "no write-multiplier [(1-100)]", NO_STR
      "Write multiplier\n"
      "Maximum number of interface serviced per write\n")

DEFUN(ospf_ti_lfa, ospf_ti_lfa_cmd, "fast-reroute ti-lfa [node-protection]",
      "Fast Reroute for MPLS and IP resilience\n"
      "Topology Independent LFA (Loop-Free Alternate)\n"
      "TI-LFA node protection (default is link protection)\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->ti_lfa_enabled = true;

	if (argc == 3)
		ospf->ti_lfa_protection_type = OSPF_TI_LFA_NODE_PROTECTION;
	else
		ospf->ti_lfa_protection_type = OSPF_TI_LFA_LINK_PROTECTION;

	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);

	return CMD_SUCCESS;
}

DEFUN(no_ospf_ti_lfa, no_ospf_ti_lfa_cmd,
      "no fast-reroute ti-lfa [node-protection]",
      NO_STR
      "Fast Reroute for MPLS and IP resilience\n"
      "Topology Independent LFA (Loop-Free Alternate)\n"
      "TI-LFA node protection (default is link protection)\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->ti_lfa_enabled = false;

	ospf->ti_lfa_protection_type = OSPF_TI_LFA_UNDEFINED_PROTECTION;

	ospf_spf_calculate_schedule(ospf, SPF_FLAG_CONFIG_CHANGE);

	return CMD_SUCCESS;
}

static void ospf_maxpath_set(struct vty *vty, struct ospf *ospf, uint16_t paths)
{
	if (ospf->max_multipath == paths)
		return;

	ospf->max_multipath = paths;

	/* Send deletion notification to zebra to delete all
	 * ospf specific routes and reinitiat SPF to reflect
	 * the new max multipath.
	 */
	ospf_restart_spf(ospf);
}

/* Ospf Maximum multiple paths config support */
DEFUN (ospf_max_multipath,
       ospf_max_multipath_cmd,
       "maximum-paths " CMD_RANGE_STR(1, MULTIPATH_NUM),
       "Max no of multiple paths for ECMP support\n"
       "Number of paths\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 1;
	uint16_t maxpaths;

	maxpaths = strtol(argv[idx_number]->arg, NULL, 10);

	ospf_maxpath_set(vty, ospf, maxpaths);
	return CMD_SUCCESS;
}

DEFUN (no_ospf_max_multipath,
       no_ospf_max_multipath_cmd,
       "no maximum-paths [" CMD_RANGE_STR(1, MULTIPATH_NUM)"]",
       NO_STR
       "Max no of multiple paths for ECMP support\n"
       "Number of paths\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	uint16_t maxpaths = MULTIPATH_NUM;

	ospf_maxpath_set(vty, ospf, maxpaths);
	return CMD_SUCCESS;
}

static const char *const ospf_abr_type_descr_str[] = {
	"Unknown", "Standard (RFC2328)", "Alternative IBM",
	"Alternative Cisco", "Alternative Shortcut"
};

static const char *const ospf_shortcut_mode_descr_str[] = {
	"Default", "Enabled", "Disabled"
};

static void show_ip_ospf_area(struct vty *vty, struct ospf_area *area,
			      json_object *json_areas, bool use_json)
{
	json_object *json_area = NULL;
	char buf[PREFIX_STRLEN];

	if (use_json)
		json_area = json_object_new_object();

	/* Show Area ID. */
	if (!use_json)
		vty_out(vty, " Area ID: %pI4", &area->area_id);

	/* Show Area type/mode. */
	if (OSPF_IS_AREA_BACKBONE(area)) {
		if (use_json)
			json_object_boolean_true_add(json_area, "backbone");
		else
			vty_out(vty, " (Backbone)\n");
	} else {
		if (use_json) {
			if (area->external_routing == OSPF_AREA_STUB) {
				if (area->no_summary)
					json_object_boolean_true_add(
						json_area, "stubNoSummary");
				if (area->shortcut_configured)
					json_object_boolean_true_add(
						json_area, "stubShortcut");
			} else if (area->external_routing == OSPF_AREA_NSSA) {
				if (area->no_summary)
					json_object_boolean_true_add(
						json_area, "nssaNoSummary");
				if (area->shortcut_configured)
					json_object_boolean_true_add(
						json_area, "nssaShortcut");
			}

			json_object_string_add(
				json_area, "shortcuttingMode",
				ospf_shortcut_mode_descr_str
					[area->shortcut_configured]);
			if (area->shortcut_capability)
				json_object_boolean_true_add(json_area,
							     "sBitConcensus");
		} else {
			if (area->external_routing == OSPF_AREA_STUB)
				vty_out(vty, " (Stub%s%s)",
					area->no_summary ? ", no summary" : "",
					area->shortcut_configured ? "; " : "");
			else if (area->external_routing == OSPF_AREA_NSSA)
				vty_out(vty, " (NSSA%s%s)",
					area->no_summary ? ", no summary" : "",
					area->shortcut_configured ? "; " : "");

			vty_out(vty, "\n");
			vty_out(vty, "   Shortcutting mode: %s",
				ospf_shortcut_mode_descr_str
					[area->shortcut_configured]);
			vty_out(vty, ", S-bit consensus: %s\n",
				area->shortcut_capability ? "ok" : "no");
		}
	}

	/* Show number of interfaces */
	if (use_json) {
		json_object_int_add(json_area, "areaIfTotalCounter",
				    listcount(area->oiflist));
		json_object_int_add(json_area, "areaIfActiveCounter",
				    area->act_ints);
	} else
		vty_out(vty,
			"   Number of interfaces in this area: Total: %d, Active: %d\n",
			listcount(area->oiflist), area->act_ints);

	if (area->external_routing == OSPF_AREA_NSSA) {
		if (use_json) {
			json_object_boolean_true_add(json_area, "nssa");
			if (!IS_OSPF_ABR(area->ospf))
				json_object_boolean_false_add(json_area, "abr");
			else if (area->NSSATranslatorState) {
				json_object_boolean_true_add(json_area, "abr");
				if (area->NSSATranslatorRole
				    == OSPF_NSSA_ROLE_CANDIDATE)
					json_object_boolean_true_add(
						json_area,
						"nssaTranslatorElected");
				else if (area->NSSATranslatorRole
					 == OSPF_NSSA_ROLE_ALWAYS)
					json_object_boolean_true_add(
						json_area,
						"nssaTranslatorAlways");
				else
					json_object_boolean_true_add(
						json_area,
						"nssaTranslatorNever");
			} else {
				json_object_boolean_true_add(json_area, "abr");
				if (area->NSSATranslatorRole
				    == OSPF_NSSA_ROLE_CANDIDATE)
					json_object_boolean_false_add(
						json_area,
						"nssaTranslatorElected");
				else
					json_object_boolean_true_add(
						json_area,
						"nssaTranslatorNever");
			}
		} else {
			vty_out(vty,
				"   It is an NSSA configuration.\n   Elected NSSA/ABR performs type-7/type-5 LSA translation.\n");
			if (!IS_OSPF_ABR(area->ospf))
				vty_out(vty,
					"   It is not ABR, therefore not Translator.\n");
			else if (area->NSSATranslatorState) {
				vty_out(vty, "   We are an ABR and ");
				if (area->NSSATranslatorRole
				    == OSPF_NSSA_ROLE_CANDIDATE)
					vty_out(vty,
						"the NSSA Elected Translator.\n");
				else if (area->NSSATranslatorRole
					 == OSPF_NSSA_ROLE_ALWAYS)
					vty_out(vty,
						"always an NSSA Translator.\n");
				else
					vty_out(vty,
						"never an NSSA Translator.\n");
			} else {
				vty_out(vty, "   We are an ABR, but ");
				if (area->NSSATranslatorRole
				    == OSPF_NSSA_ROLE_CANDIDATE)
					vty_out(vty,
						"not the NSSA Elected Translator.\n");
				else
					vty_out(vty,
						"never an NSSA Translator.\n");
			}
		}
	}

	/* Stub-router state for this area */
	if (CHECK_FLAG(area->stub_router_state, OSPF_AREA_IS_STUB_ROUTED)) {
		char timebuf[OSPF_TIME_DUMP_SIZE];

		if (use_json) {
			json_object_boolean_true_add(
				json_area, "originStubMaxDistRouterLsa");
			if (CHECK_FLAG(area->stub_router_state,
				       OSPF_AREA_ADMIN_STUB_ROUTED))
				json_object_boolean_true_add(
					json_area, "indefiniteActiveAdmin");
			if (area->t_stub_router) {
				long time_store;
				time_store =
					monotime_until(
						&area->t_stub_router->u.sands,
						NULL)
					/ 1000LL;
				json_object_int_add(
					json_area,
					"activeStartupRemainderMsecs",
					time_store);
			}
		} else {
			vty_out(vty,
				"   Originating stub / maximum-distance Router-LSA\n");
			if (CHECK_FLAG(area->stub_router_state,
				       OSPF_AREA_ADMIN_STUB_ROUTED))
				vty_out(vty,
					"     Administratively activated (indefinitely)\n");
			if (area->t_stub_router)
				vty_out(vty,
					"     Active from startup, %s remaining\n",
					ospf_timer_dump(area->t_stub_router,
							timebuf,
							sizeof(timebuf)));
		}
	}

	if (use_json) {
		/* Show number of fully adjacent neighbors. */
		json_object_int_add(json_area, "nbrFullAdjacentCounter",
				    area->full_nbrs);

		/* Show authentication type. */
		if (area->auth_type == OSPF_AUTH_NULL)
			json_object_string_add(json_area, "authentication",
					       "authenticationNone");
		else if (area->auth_type == OSPF_AUTH_SIMPLE)
			json_object_string_add(json_area, "authentication",
					       "authenticationSimplePassword");
		else if (area->auth_type == OSPF_AUTH_CRYPTOGRAPHIC)
			json_object_string_add(json_area, "authentication",
					       "authenticationMessageDigest");

		if (!OSPF_IS_AREA_BACKBONE(area))
			json_object_int_add(json_area,
					    "virtualAdjacenciesPassingCounter",
					    area->full_vls);

		/* Show SPF calculation times. */
		json_object_int_add(json_area, "spfExecutedCounter",
				    area->spf_calculation);
		json_object_int_add(json_area, "lsaNumber", area->lsdb->total);
		json_object_int_add(
			json_area, "lsaRouterNumber",
			ospf_lsdb_count(area->lsdb, OSPF_ROUTER_LSA));
		json_object_int_add(
			json_area, "lsaRouterChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_ROUTER_LSA));
		json_object_int_add(
			json_area, "lsaNetworkNumber",
			ospf_lsdb_count(area->lsdb, OSPF_NETWORK_LSA));
		json_object_int_add(
			json_area, "lsaNetworkChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_NETWORK_LSA));
		json_object_int_add(
			json_area, "lsaSummaryNumber",
			ospf_lsdb_count(area->lsdb, OSPF_SUMMARY_LSA));
		json_object_int_add(
			json_area, "lsaSummaryChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_SUMMARY_LSA));
		json_object_int_add(
			json_area, "lsaAsbrNumber",
			ospf_lsdb_count(area->lsdb, OSPF_ASBR_SUMMARY_LSA));
		json_object_int_add(
			json_area, "lsaAsbrChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_ASBR_SUMMARY_LSA));
		json_object_int_add(
			json_area, "lsaNssaNumber",
			ospf_lsdb_count(area->lsdb, OSPF_AS_NSSA_LSA));
		json_object_int_add(
			json_area, "lsaNssaChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_AS_NSSA_LSA));
	} else {
		/* Show number of fully adjacent neighbors. */
		vty_out(vty,
			"   Number of fully adjacent neighbors in this area: %d\n",
			area->full_nbrs);

		/* Show authentication type. */
		vty_out(vty, "   Area has ");
		if (area->auth_type == OSPF_AUTH_NULL)
			vty_out(vty, "no authentication\n");
		else if (area->auth_type == OSPF_AUTH_SIMPLE)
			vty_out(vty, "simple password authentication\n");
		else if (area->auth_type == OSPF_AUTH_CRYPTOGRAPHIC)
			vty_out(vty, "message digest authentication\n");

		if (!OSPF_IS_AREA_BACKBONE(area))
			vty_out(vty,
				"   Number of full virtual adjacencies going through this area: %d\n",
				area->full_vls);

		/* Show SPF calculation times. */
		vty_out(vty, "   SPF algorithm executed %d times\n",
			area->spf_calculation);

		/* Show number of LSA. */
		vty_out(vty, "   Number of LSA %ld\n", area->lsdb->total);
		vty_out(vty,
			"   Number of router LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_ROUTER_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_ROUTER_LSA));
		vty_out(vty,
			"   Number of network LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_NETWORK_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_NETWORK_LSA));
		vty_out(vty,
			"   Number of summary LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_SUMMARY_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_SUMMARY_LSA));
		vty_out(vty,
			"   Number of ASBR summary LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_ASBR_SUMMARY_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_ASBR_SUMMARY_LSA));
		vty_out(vty, "   Number of NSSA LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_AS_NSSA_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_AS_NSSA_LSA));
	}

	if (use_json) {
		json_object_int_add(
			json_area, "lsaOpaqueLinkNumber",
			ospf_lsdb_count(area->lsdb, OSPF_OPAQUE_LINK_LSA));
		json_object_int_add(
			json_area, "lsaOpaqueLinkChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_OPAQUE_LINK_LSA));
		json_object_int_add(
			json_area, "lsaOpaqueAreaNumber",
			ospf_lsdb_count(area->lsdb, OSPF_OPAQUE_AREA_LSA));
		json_object_int_add(
			json_area, "lsaOpaqueAreaChecksum",
			ospf_lsdb_checksum(area->lsdb, OSPF_OPAQUE_AREA_LSA));
	} else {
		vty_out(vty,
			"   Number of opaque link LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_OPAQUE_LINK_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_OPAQUE_LINK_LSA));
		vty_out(vty,
			"   Number of opaque area LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(area->lsdb, OSPF_OPAQUE_AREA_LSA),
			ospf_lsdb_checksum(area->lsdb, OSPF_OPAQUE_AREA_LSA));
	}

	if (area->fr_info.configured) {
		if (use_json)
			json_object_string_add(json_area, "areaFloodReduction",
					       "configured");
		else
			vty_out(vty, "   Flood Reduction is configured.\n");
	}

	if (area->fr_info.enabled) {
		if (use_json) {
			json_object_boolean_true_add(
				json_area, "areaFloodReductionEnabled");
			if (area->fr_info.router_lsas_recv_dc_bit)
				json_object_boolean_true_add(
					json_area, "lsasRecvDCbitSet");
			if (area->fr_info.area_ind_lsa_recvd)
				json_object_string_add(json_area,
						       "areaIndicationLsaRecv",
						       "received");
			if (area->fr_info.indication_lsa_self)
				json_object_string_addf(
					json_area, "areaIndicationLsa", "%pI4",
					&area->fr_info.indication_lsa_self->data
						 ->id);
		} else {
			vty_out(vty, "   Flood Reduction is enabled.\n");
			vty_out(vty, "   No of LSAs rcv'd with DC bit set %d\n",
				area->fr_info.router_lsas_recv_dc_bit);
			if (area->fr_info.area_ind_lsa_recvd)
				vty_out(vty, "   Ind LSA by other abr.\n");
			if (area->fr_info.indication_lsa_self)
				vty_out(vty, "   Ind LSA generated %pI4\n",
					&area->fr_info.indication_lsa_self->data
						 ->id);
		}
	}

	if (use_json)
		json_object_object_add(json_areas,
				       inet_ntop(AF_INET, &area->area_id,
						 buf, sizeof(buf)),
				       json_area);
	else
		vty_out(vty, "\n");
}

static int show_ip_ospf_common(struct vty *vty, struct ospf *ospf,
			       json_object *json, uint8_t use_vrf)
{
	struct listnode *node, *nnode;
	struct ospf_area *area;
	struct timeval result;
	char timebuf[OSPF_TIME_DUMP_SIZE];
	json_object *json_vrf = NULL;
	json_object *json_areas = NULL;

	if (json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
		json_areas = json_object_new_object();
	}

	if (ospf->instance) {
		if (json) {
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		} else {
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
		}
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	/* Show Router ID. */
	if (json) {
		json_object_string_addf(json_vrf, "routerId", "%pI4",
					&ospf->router_id);
	} else {
		vty_out(vty, " OSPF Routing Process, Router ID: %pI4\n",
			&ospf->router_id);
	}

	/* Graceful shutdown */
	if (ospf->t_deferred_shutdown) {
		if (json) {
			long time_store;
			time_store =
				monotime_until(
					&ospf->t_deferred_shutdown->u.sands,
					NULL)
				/ 1000LL;
			json_object_int_add(json_vrf, "deferredShutdownMsecs",
					    time_store);
		} else {
			vty_out(vty,
				" Deferred shutdown in progress, %s remaining\n",
				ospf_timer_dump(ospf->t_deferred_shutdown,
						timebuf, sizeof(timebuf)));
		}
	}

	/* Show capability. */
	if (json) {
		json_object_boolean_true_add(json_vrf, "tosRoutesOnly");
		json_object_boolean_true_add(json_vrf, "rfc2328Conform");
		if (CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)) {
			json_object_boolean_true_add(json_vrf,
						     "rfc1583Compatibility");
		}
	} else {
		vty_out(vty, " Supports only single TOS (TOS0) routes\n");
		vty_out(vty, " This implementation conforms to RFC2328\n");
		vty_out(vty, " RFC1583Compatibility flag is %s\n",
			CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE)
				? "enabled"
				: "disabled");
	}

	if (json) {
		if (CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)) {
			json_object_boolean_true_add(json_vrf, "opaqueCapable");
		}
	} else {
		vty_out(vty, " OpaqueCapability flag is %s\n",
			CHECK_FLAG(ospf->config, OSPF_OPAQUE_CAPABLE)
				? "enabled"
				: "disabled");
	}

	/* Show stub-router configuration */
	if (ospf->stub_router_startup_time != OSPF_STUB_ROUTER_UNCONFIGURED
	    || ospf->stub_router_shutdown_time
		       != OSPF_STUB_ROUTER_UNCONFIGURED) {
		if (json) {
			json_object_boolean_true_add(json_vrf,
						     "stubAdvertisement");
			if (ospf->stub_router_startup_time
			    != OSPF_STUB_ROUTER_UNCONFIGURED)
				json_object_int_add(
					json_vrf, "postStartEnabledSecs",
					ospf->stub_router_startup_time);
			if (ospf->stub_router_shutdown_time
			    != OSPF_STUB_ROUTER_UNCONFIGURED)
				json_object_int_add(
					json_vrf, "preShutdownEnabledSecs",
					ospf->stub_router_shutdown_time);
		} else {
			vty_out(vty,
				" Stub router advertisement is configured\n");
			if (ospf->stub_router_startup_time
			    != OSPF_STUB_ROUTER_UNCONFIGURED)
				vty_out(vty,
					"   Enabled for %us after start-up\n",
					ospf->stub_router_startup_time);
			if (ospf->stub_router_shutdown_time
			    != OSPF_STUB_ROUTER_UNCONFIGURED)
				vty_out(vty,
					"   Enabled for %us prior to full shutdown\n",
					ospf->stub_router_shutdown_time);
		}
	}

	/* Show SPF timers. */
	if (json) {
		json_object_int_add(json_vrf, "spfScheduleDelayMsecs",
				    ospf->spf_delay);
		json_object_int_add(json_vrf, "holdtimeMinMsecs",
				    ospf->spf_holdtime);
		json_object_int_add(json_vrf, "holdtimeMaxMsecs",
				    ospf->spf_max_holdtime);
		json_object_int_add(json_vrf, "holdtimeMultplier",
				    ospf->spf_hold_multiplier);
	} else {
		vty_out(vty,
			" Initial SPF scheduling delay %d millisec(s)\n"
			" Minimum hold time between consecutive SPFs %d millisec(s)\n"
			" Maximum hold time between consecutive SPFs %d millisec(s)\n"
			" Hold time multiplier is currently %d\n",
			ospf->spf_delay, ospf->spf_holdtime,
			ospf->spf_max_holdtime, ospf->spf_hold_multiplier);
	}

	if (json) {
		if (ospf->ts_spf.tv_sec || ospf->ts_spf.tv_usec) {
			long time_store = 0;

			time_store =
				monotime_since(&ospf->ts_spf, NULL) / 1000LL;
			json_object_int_add(json_vrf, "spfLastExecutedMsecs",
					    time_store);

			time_store = (1000 * ospf->ts_spf_duration.tv_sec)
				     + (ospf->ts_spf_duration.tv_usec / 1000);
			json_object_int_add(json_vrf, "spfLastDurationMsecs",
					    time_store);
		} else
			json_object_boolean_true_add(json_vrf, "spfHasNotRun");
	} else {
		vty_out(vty, " SPF algorithm ");
		if (ospf->ts_spf.tv_sec || ospf->ts_spf.tv_usec) {
			monotime_since(&ospf->ts_spf, &result);
			vty_out(vty, "last executed %s ago\n",
				ospf_timeval_dump(&result, timebuf,
						  sizeof(timebuf)));
			vty_out(vty, " Last SPF duration %s\n",
				ospf_timeval_dump(&ospf->ts_spf_duration,
						  timebuf, sizeof(timebuf)));
		} else
			vty_out(vty, "has not been run\n");
	}

	if (json) {
		if (ospf->t_spf_calc) {
			long time_store;
			time_store =
				monotime_until(&ospf->t_spf_calc->u.sands, NULL)
				/ 1000LL;
			json_object_int_add(json_vrf, "spfTimerDueInMsecs",
					    time_store);
		}

		json_object_int_add(json_vrf, "lsaMinIntervalMsecs",
				    ospf->min_ls_interval);
		json_object_int_add(json_vrf, "lsaMinArrivalMsecs",
				    ospf->min_ls_arrival);
		/* Show write multiplier values */
		json_object_int_add(json_vrf, "writeMultiplier",
				    ospf->write_oi_count);
		/* Show refresh parameters. */
		json_object_int_add(json_vrf, "refreshTimerMsecs",
				    ospf->lsa_refresh_interval * 1000);

		/* show max multipath */
		json_object_int_add(json_vrf, "maximumPaths",
				    ospf->max_multipath);

		/* show administrative distance */
		json_object_int_add(json_vrf, "preference",
				    ospf->distance_all
					    ? ospf->distance_all
					    : ZEBRA_OSPF_DISTANCE_DEFAULT);
	} else {
		vty_out(vty, " SPF timer %s%s\n",
			(ospf->t_spf_calc ? "due in " : "is "),
			ospf_timer_dump(ospf->t_spf_calc, timebuf,
					sizeof(timebuf)));

		vty_out(vty, " LSA minimum interval %d msecs\n",
			ospf->min_ls_interval);
		vty_out(vty, " LSA minimum arrival %d msecs\n",
			ospf->min_ls_arrival);

		/* Show write multiplier values */
		vty_out(vty, " Write Multiplier set to %d \n",
			ospf->write_oi_count);

		/* Show refresh parameters. */
		vty_out(vty, " Refresh timer %d secs\n",
			ospf->lsa_refresh_interval);

		/* show max multipath */
		vty_out(vty, " Maximum multiple paths(ECMP) supported %d\n",
			ospf->max_multipath);

		/* show administrative distance */
		vty_out(vty, " Administrative distance %u\n",
			ospf->distance_all ? ospf->distance_all
					   : ZEBRA_OSPF_DISTANCE_DEFAULT);
	}

	if (ospf->fr_configured) {
		if (json)
			json_object_string_add(json_vrf, "floodReduction",
					       "configured");
		else
			vty_out(vty, " Flood Reduction is configured.\n");
	}

	/* Show ABR/ASBR flags. */
	if (CHECK_FLAG(ospf->flags, OSPF_FLAG_ABR)) {
		if (json)
			json_object_string_add(
				json_vrf, "abrType",
				ospf_abr_type_descr_str[ospf->abr_type]);
		else
			vty_out(vty,
				" This router is an ABR, ABR type is: %s\n",
				ospf_abr_type_descr_str[ospf->abr_type]);
	}
	if (CHECK_FLAG(ospf->flags, OSPF_FLAG_ASBR)) {
		if (json)
			json_object_string_add(
				json_vrf, "asbrRouter",
				"injectingExternalRoutingInformation");
		else
			vty_out(vty,
				" This router is an ASBR (injecting external routing information)\n");
	}

	/* Show Number of AS-external-LSAs. */
	if (json) {
		json_object_int_add(
			json_vrf, "lsaExternalCounter",
			ospf_lsdb_count(ospf->lsdb, OSPF_AS_EXTERNAL_LSA));
		json_object_int_add(
			json_vrf, "lsaExternalChecksum",
			ospf_lsdb_checksum(ospf->lsdb, OSPF_AS_EXTERNAL_LSA));
	} else {
		vty_out(vty,
			" Number of external LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(ospf->lsdb, OSPF_AS_EXTERNAL_LSA),
			ospf_lsdb_checksum(ospf->lsdb, OSPF_AS_EXTERNAL_LSA));
	}

	if (json) {
		json_object_int_add(
			json_vrf, "lsaAsopaqueCounter",
			ospf_lsdb_count(ospf->lsdb, OSPF_OPAQUE_AS_LSA));
		json_object_int_add(
			json_vrf, "lsaAsOpaqueChecksum",
			ospf_lsdb_checksum(ospf->lsdb, OSPF_OPAQUE_AS_LSA));
	} else {
		vty_out(vty,
			" Number of opaque AS LSA %ld. Checksum Sum 0x%08x\n",
			ospf_lsdb_count(ospf->lsdb, OSPF_OPAQUE_AS_LSA),
			ospf_lsdb_checksum(ospf->lsdb, OSPF_OPAQUE_AS_LSA));
	}

	/* Show number of areas attached. */
	if (json)
		json_object_int_add(json_vrf, "attachedAreaCounter",
				    listcount(ospf->areas));
	else
		vty_out(vty, " Number of areas attached to this router: %d\n",
			listcount(ospf->areas));

	if (CHECK_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES)) {
		if (CHECK_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL)) {
			if (json)
				json_object_boolean_true_add(
					json_vrf, "adjacencyChangesLoggedAll");
			else
				vty_out(vty,
					" All adjacency changes are logged\n");
		} else {
			if (json)
				json_object_boolean_true_add(
					json_vrf, "adjacencyChangesLogged");
			else
				vty_out(vty, " Adjacency changes are logged\n");
		}
	}

	/* show LDP-Sync status */
	ospf_ldp_sync_show_info(vty, ospf, json_vrf, json ? 1 : 0);

	/* Socket buffer sizes */
	if (json) {
		if (ospf->recv_sock_bufsize != OSPF_DEFAULT_SOCK_BUFSIZE)
			json_object_int_add(json_vrf, "recvSockBufsize",
					    ospf->recv_sock_bufsize);
		if (ospf->send_sock_bufsize != OSPF_DEFAULT_SOCK_BUFSIZE)
			json_object_int_add(json_vrf, "sendSockBufsize",
					    ospf->send_sock_bufsize);
	} else {
		if (ospf->recv_sock_bufsize != OSPF_DEFAULT_SOCK_BUFSIZE)
			vty_out(vty, " Receive socket bufsize: %u\n",
				ospf->recv_sock_bufsize);
		if (ospf->send_sock_bufsize != OSPF_DEFAULT_SOCK_BUFSIZE)
			vty_out(vty, " Send socket bufsize: %u\n",
				ospf->send_sock_bufsize);
	}

	/* Show each area status. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
		show_ip_ospf_area(vty, area, json_areas, json ? 1 : 0);

	if (json) {
		if (use_vrf) {
			json_object_object_add(json_vrf, "areas", json_areas);
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
		} else {
			json_object_object_add(json, "areas", json_areas);
		}
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf,
       show_ip_ospf_cmd,
       "show ip ospf [vrf <NAME|all>] [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0;
	json_object *json = NULL;
	uint8_t use_vrf = 0;

	if (listcount(om->ospf) == 0)
		return CMD_SUCCESS;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		bool ospf_output = false;

		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ospf_output = true;
				ret = show_ip_ospf_common(vty, ospf, json,
							  use_vrf);
			}
			if (uj)
				vty_json(vty, json);
			else if (!ospf_output)
				vty_out(vty, "%% OSPF is not enabled\n");
			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if ((ospf == NULL) || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);

			return CMD_SUCCESS;
		}
	} else {
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		/* Display default ospf (instance 0) info */
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf default\n");

			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		show_ip_ospf_common(vty, ospf, json, use_vrf);
		if (uj)
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
	}

	if (uj)
		json_object_free(json);

	return ret;
}

DEFUN (show_ip_ospf_instance,
       show_ip_ospf_instance_cmd,
       "show ip ospf (1-65535) [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       JSON_STR)
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);
	int ret = CMD_SUCCESS;
	json_object *json = NULL;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_common(vty, ospf, json, 0);

	if (uj)
		vty_json(vty, json);

	return ret;
}

static void ospf_interface_auth_show(struct vty *vty, struct ospf_interface *oi,
				     json_object *json, bool use_json)
{
	int auth_type;

	auth_type = OSPF_IF_PARAM(oi, auth_type);

	switch (auth_type) {
	case OSPF_AUTH_NULL:
		if (use_json)
			json_object_string_add(json, "authentication",
					       "authenticationNone");
		else
			vty_out(vty, "  Authentication NULL is enabled\n");
		break;
	case OSPF_AUTH_SIMPLE: {
		if (use_json)
			json_object_string_add(json, "authentication",
					       "authenticationSimplePassword");
		else
			vty_out(vty,
				"  Simple password authentication enabled\n");
		break;
	}
	case OSPF_AUTH_CRYPTOGRAPHIC: {
		struct crypt_key *ckey;

		if (OSPF_IF_PARAM(oi, keychain_name)) {
			if (use_json) {
				json_object_string_add(json, "authentication",
							  "authenticationKeyChain");
				json_object_string_add(json, "keychain",
							  OSPF_IF_PARAM(oi, keychain_name));
			} else {
				vty_out(vty,
					"  Cryptographic authentication enabled\n");
				struct keychain *keychain = keychain_lookup(OSPF_IF_PARAM(oi, keychain_name));

				if (keychain) {
					struct key *key = key_lookup_for_send(keychain);

					if (key) {
						vty_out(vty, "    Sending SA: Key %u, Algorithm %s - key chain %s\n",
								key->index, keychain_get_algo_name_by_id(key->hash_algo),
								OSPF_IF_PARAM(oi, keychain_name));
					}
				}
			}
		} else {
			if (list_isempty(OSPF_IF_PARAM(oi, auth_crypt)))
				return;

			ckey = listgetdata(listtail(OSPF_IF_PARAM(oi, auth_crypt)));
			if (ckey) {
				if (use_json) {
					json_object_string_add(json, "authentication",
								"authenticationMessageDigest");
				} else {
					vty_out(vty,
						"  Cryptographic authentication enabled\n");
					vty_out(vty, "  Algorithm:MD5\n");
				}
			}
		}
		break;
	}
	default:
		break;
	}
}

static void show_ip_ospf_interface_sub(struct vty *vty, struct ospf *ospf,
				       struct interface *ifp,
				       json_object *json_interface_sub,
				       bool use_json)
{
	int is_up;
	struct ospf_neighbor *nbr;
	struct route_node *rn;
	uint32_t bandwidth = ifp->bandwidth ? ifp->bandwidth : ifp->speed;
	struct ospf_if_params *params;

	/* Is interface up? */
	if (use_json) {
		is_up = if_is_operative(ifp);
		if (is_up)
			json_object_boolean_true_add(json_interface_sub,
						     "ifUp");
		else
			json_object_boolean_false_add(json_interface_sub,
						      "ifDown");

		json_object_int_add(json_interface_sub, "ifIndex",
				    ifp->ifindex);
		json_object_int_add(json_interface_sub, "mtuBytes", ifp->mtu);
		json_object_int_add(json_interface_sub, "bandwidthMbit",
				    bandwidth);
		json_object_string_add(json_interface_sub, "ifFlags",
				       if_flag_dump(ifp->flags));
	} else {
		vty_out(vty, "%s is %s\n", ifp->name,
			((is_up = if_is_operative(ifp)) ? "up" : "down"));
		vty_out(vty, "  ifindex %u, MTU %u bytes, BW %u Mbit %s\n",
			ifp->ifindex, ifp->mtu, bandwidth,
			if_flag_dump(ifp->flags));
	}

	/* Is interface OSPF enabled? */
	if (use_json) {
		if (ospf_oi_count(ifp) == 0) {
			json_object_boolean_false_add(json_interface_sub,
						      "ospfEnabled");
			return;
		} else if (!is_up) {
			json_object_boolean_false_add(json_interface_sub,
						      "ospfRunning");
			return;
		} else
			json_object_boolean_true_add(json_interface_sub,
						     "ospfEnabled");
	} else {
		if (ospf_oi_count(ifp) == 0) {
			vty_out(vty, "  OSPF not enabled on this interface\n");
			return;
		} else if (!is_up) {
			vty_out(vty,
				"  OSPF is enabled, but not running on this interface\n");
			return;
		}
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi == NULL)
			continue;

		if (CHECK_FLAG(oi->connected->flags, ZEBRA_IFA_UNNUMBERED)) {
			if (use_json)
				json_object_boolean_true_add(json_interface_sub,
							     "ifUnnumbered");
			else
				vty_out(vty, "  This interface is UNNUMBERED,");
		} else {
			struct in_addr dest;
			const char *dstr;

			/* Show OSPF interface information. */
			if (use_json) {
				json_object_string_addf(
					json_interface_sub, "ipAddress", "%pI4",
					&oi->address->u.prefix4);
				json_object_int_add(json_interface_sub,
						    "ipAddressPrefixlen",
						    oi->address->prefixlen);
			} else
				vty_out(vty, "  Internet Address %pFX,",
					oi->address);

			/* For Vlinks, showing the peer address is
			 * probably more informative than the local
			 * interface that is being used */
			if (oi->type == OSPF_IFTYPE_VIRTUALLINK) {
				dstr = "Peer";
				dest = oi->vl_data->peer_addr;
			} else if (CONNECTED_PEER(oi->connected)
					 && oi->connected->destination) {
				dstr = "Peer";
				dest = oi->connected->destination->u.prefix4;
			} else {
				dstr = "Broadcast";
				dest.s_addr = ipv4_broadcast_addr(
						oi->connected->address->u.prefix4.s_addr,
						oi->connected->address->prefixlen);
			}

			if (use_json) {
				json_object_string_add(json_interface_sub,
						       "ospfIfType", dstr);

				if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
					json_object_string_addf(
						json_interface_sub, "vlinkPeer",
						"%pI4", &dest);
				else
					json_object_string_addf(
						json_interface_sub,
						"localIfUsed", "%pI4", &dest);
			} else
				vty_out(vty, " %s %pI4,", dstr,
					&dest);
		}
		if (use_json) {
			json_object_string_add(json_interface_sub, "area",
					       ospf_area_desc_string(oi->area));

			if (OSPF_IF_PARAM(oi, mtu_ignore))
				json_object_boolean_true_add(
					json_interface_sub,
					"mtuMismatchDetect");

			json_object_string_addf(json_interface_sub, "routerId",
						"%pI4", &ospf->router_id);
			json_object_string_add(json_interface_sub,
					       "networkType",
					       ospf_network_type_str[oi->type]);
			json_object_int_add(json_interface_sub, "cost",
					    oi->output_cost);
			json_object_int_add(json_interface_sub,
					    "transmitDelaySecs",
					    OSPF_IF_PARAM(oi, transmit_delay));
			json_object_string_add(json_interface_sub, "state",
					       lookup_msg(ospf_ism_state_msg,
							  oi->state, NULL));
			json_object_int_add(json_interface_sub, "priority",
					    PRIORITY(oi));
			json_object_boolean_add(
				json_interface_sub, "opaqueCapable",
				OSPF_IF_PARAM(oi, opaque_capable));
		} else {
			vty_out(vty, " Area %s\n",
				ospf_area_desc_string(oi->area));

			vty_out(vty, "  MTU mismatch detection: %s\n",
				OSPF_IF_PARAM(oi, mtu_ignore) ? "disabled"
							      : "enabled");

			vty_out(vty,
				"  Router ID %pI4, Network Type %s, Cost: %d\n",
				&ospf->router_id,
				ospf_network_type_str[oi->type],
				oi->output_cost);

			vty_out(vty,
				"  Transmit Delay is %d sec, State %s, Priority %d\n",
				OSPF_IF_PARAM(oi, transmit_delay),
				lookup_msg(ospf_ism_state_msg, oi->state, NULL),
				PRIORITY(oi));
                        if (!OSPF_IF_PARAM(oi, opaque_capable))
                                vty_out(vty,
                                        "  Opaque LSA capability disabled on interface\n");
		}

		/* Show DR information. */
		if (DR(oi).s_addr == INADDR_ANY) {
			if (!use_json)
				vty_out(vty,
					"  No backup designated router on this network\n");
		} else {
			nbr = ospf_nbr_lookup_by_addr(oi->nbrs, &DR(oi));
			if (nbr) {
				if (use_json) {
					json_object_string_addf(
						json_interface_sub, "drId",
						"%pI4", &nbr->router_id);
					json_object_string_addf(
						json_interface_sub, "drAddress",
						"%pI4",
						&nbr->address.u.prefix4);
				} else {
					vty_out(vty,
						"  Designated Router (ID) %pI4",
						&nbr->router_id);
					vty_out(vty,
						" Interface Address %pFX\n",
						&nbr->address);
				}
			}
			nbr = NULL;

			nbr = ospf_nbr_lookup_by_addr(oi->nbrs, &BDR(oi));
			if (nbr == NULL) {
				if (!use_json)
					vty_out(vty,
						"  No backup designated router on this network\n");
			} else {
				if (use_json) {
					json_object_string_addf(
						json_interface_sub, "bdrId",
						"%pI4", &nbr->router_id);
					json_object_string_addf(
						json_interface_sub,
						"bdrAddress", "%pI4",
						&nbr->address.u.prefix4);
				} else {
					vty_out(vty,
						"  Backup Designated Router (ID) %pI4,",
						&nbr->router_id);
					vty_out(vty, " Interface Address %pI4\n",
						&nbr->address.u.prefix4);
				}
			}
		}

		/* Next network-LSA sequence number we'll use, if we're elected
		 * DR */
		if (oi->params
		    && ntohl(oi->params->network_lsa_seqnum)
			       != OSPF_INITIAL_SEQUENCE_NUMBER) {
			if (use_json)
				json_object_int_add(
					json_interface_sub,
					"networkLsaSequence",
					ntohl(oi->params->network_lsa_seqnum));
			else
				vty_out(vty,
					"  Saved Network-LSA sequence number 0x%x\n",
					ntohl(oi->params->network_lsa_seqnum));
		}

		if (use_json) {
			if (OI_MEMBER_CHECK(oi, MEMBER_ALLROUTERS)
			    || OI_MEMBER_CHECK(oi, MEMBER_DROUTERS)) {
				if (OI_MEMBER_CHECK(oi, MEMBER_ALLROUTERS))
					json_object_boolean_true_add(
						json_interface_sub,
						"mcastMemberOspfAllRouters");
				if (OI_MEMBER_CHECK(oi, MEMBER_DROUTERS))
					json_object_boolean_true_add(
						json_interface_sub,
						"mcastMemberOspfDesignatedRouters");
			}
		} else {
			vty_out(vty, "  Multicast group memberships:");
			if (OI_MEMBER_CHECK(oi, MEMBER_ALLROUTERS)
			    || OI_MEMBER_CHECK(oi, MEMBER_DROUTERS)) {
				if (OI_MEMBER_CHECK(oi, MEMBER_ALLROUTERS))
					vty_out(vty, " OSPFAllRouters");
				if (OI_MEMBER_CHECK(oi, MEMBER_DROUTERS))
					vty_out(vty, " OSPFDesignatedRouters");
			} else
				vty_out(vty, " <None>");
			vty_out(vty, "\n");
		}

		if (use_json) {
			if (OSPF_IF_PARAM(oi, fast_hello) == 0)
				json_object_int_add(
					json_interface_sub, "timerMsecs",
					OSPF_IF_PARAM(oi, v_hello) * 1000);
			else
				json_object_int_add(
					json_interface_sub, "timerMsecs",
					1000 / OSPF_IF_PARAM(oi, fast_hello));
			json_object_int_add(json_interface_sub, "timerDeadSecs",
					    OSPF_IF_PARAM(oi, v_wait));
			json_object_int_add(json_interface_sub, "timerWaitSecs",
					    OSPF_IF_PARAM(oi, v_wait));
			json_object_int_add(
				json_interface_sub, "timerRetransmitSecs",
				OSPF_IF_PARAM(oi, retransmit_interval));
			json_object_int_add(json_interface_sub,
					    "timerRetransmitWindowMsecs",
					    OSPF_IF_PARAM(oi,
							  retransmit_window));
		} else {
			vty_out(vty, "  Timer intervals configured,");
			vty_out(vty, " Hello ");
			if (OSPF_IF_PARAM(oi, fast_hello) == 0)
				vty_out(vty, "%ds,",
					OSPF_IF_PARAM(oi, v_hello));
			else
				vty_out(vty, "%dms,",
					1000 / OSPF_IF_PARAM(oi, fast_hello));
			vty_out(vty, " Dead %ds, Wait %ds, Retransmit %d\n",
				OSPF_IF_PARAM(oi, v_wait),
				OSPF_IF_PARAM(oi, v_wait),
				OSPF_IF_PARAM(oi, retransmit_interval));
		}

		if (OSPF_IF_PASSIVE_STATUS(oi) == OSPF_IF_ACTIVE) {
			char timebuf[OSPF_TIME_DUMP_SIZE];
			if (use_json) {
				long time_store = 0;
				if (oi->t_hello)
					time_store =
						monotime_until(
							&oi->t_hello->u.sands,
							NULL)
						/ 1000LL;
				json_object_int_add(json_interface_sub,
						    "timerHelloInMsecs",
						    time_store);
			} else
				vty_out(vty, "    Hello due in %s\n",
					ospf_timer_dump(oi->t_hello, timebuf,
							sizeof(timebuf)));
		} else /* passive-interface is set */
		{
			if (use_json)
				json_object_boolean_true_add(
					json_interface_sub,
					"timerPassiveIface");
			else
				vty_out(vty,
					"    No Hellos (Passive interface)\n");
		}

		if (use_json) {
			json_object_int_add(json_interface_sub, "nbrCount",
					    ospf_nbr_count(oi, 0));
			json_object_int_add(json_interface_sub,
					    "nbrAdjacentCount",
					    ospf_nbr_count(oi, NSM_Full));
		} else
			vty_out(vty,
				"  Neighbor Count is %d, Adjacent neighbor count is %d\n",
				ospf_nbr_count(oi, 0),
				ospf_nbr_count(oi, NSM_Full));

		params = IF_DEF_PARAMS(ifp);
		if (params &&
		    OSPF_IF_PARAM_CONFIGURED(params, v_gr_hello_delay)) {
			if (use_json)
				json_object_int_add(json_interface_sub,
						    "grHelloDelaySecs",
						    params->v_gr_hello_delay);
			else
				vty_out(vty,
					"  Graceful Restart hello delay: %us\n",
					params->v_gr_hello_delay);
		}

		ospf_interface_bfd_show(vty, ifp, json_interface_sub);

		if (use_json)
			json_object_boolean_add(json_interface_sub,
						"prefixSuppression",
						OSPF_IF_PARAM(oi,
							      prefix_suppression));
		else if (OSPF_IF_PARAM(oi, prefix_suppression))
			vty_out(vty,
				"  Suppress advertisement of interface IP prefix\n");

		/* OSPF Authentication information */
		ospf_interface_auth_show(vty, oi, json_interface_sub, use_json);

		/* Point-to-Multipoint Interface options. */
		if (oi->type == OSPF_IFTYPE_POINTOMULTIPOINT) {
			if (use_json)
				json_object_boolean_add(json_interface_sub,
							"p2mpDelayReflood",
							oi->p2mp_delay_reflood);
			else
				vty_out(vty,
					"  %sDelay reflooding LSAs received on P2MP interface\n",
					oi->p2mp_delay_reflood ? "" : "Don't ");
			if (use_json)
				json_object_boolean_add(json_interface_sub,
							"p2mpNonBroadcast",
							oi->p2mp_non_broadcast);
			else
				vty_out(vty,
					"  P2MP interface does %ssupport broadcast\n",
					oi->p2mp_non_broadcast ? "not " : "");
		}

		if (oi->nbr_filter) {
			if (use_json)
				json_object_string_add(json_interface_sub,
						       "nbrFilterPrefixList",
						       prefix_list_name(
							       oi->nbr_filter));
			else
				vty_out(vty,
					"  Neighbor filter prefix-list: %s\n",
					prefix_list_name(oi->nbr_filter));
		} else {
			if (use_json)
				json_object_string_add(json_interface_sub,
						       "nbrFilterPrefixList",
						       "N/A");
		}

		/* Non-Traffic interface counters
		 */
		if (use_json)
			json_object_int_add(json_interface_sub,
					    "lsaRetransmissions",
					    oi->ls_rxmt_lsa);
		else
			vty_out(vty, "  LSA retransmissions: %u\n",
				oi->ls_rxmt_lsa);
	}
}

static int show_ip_ospf_interface_common(struct vty *vty, struct ospf *ospf,
					 char *intf_name, uint8_t use_vrf,
					 json_object *json, bool use_json)
{
	struct interface *ifp;
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	json_object *json_vrf = NULL;
	json_object *json_interface_sub = NULL, *json_interface = NULL;

	if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
		json_interface = json_object_new_object();
	}

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	if (intf_name == NULL) {
		/* Show All Interfaces.*/
		FOR_ALL_INTERFACES (vrf, ifp) {
			if (ospf_oi_count(ifp)) {
				if (use_json) {
					json_interface_sub =
						json_object_new_object();
				}
				show_ip_ospf_interface_sub(vty, ospf, ifp,
							   json_interface_sub,
							   use_json);

				if (use_json) {
					json_object_object_add(
						json_interface, ifp->name,
						json_interface_sub);
				}
			}
		}
		if (use_json)
			json_object_object_add(json_vrf, "interfaces",
					       json_interface);
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(intf_name, ospf->vrf_id);
		if (ifp == NULL) {
			if (use_json) {
				json_object_boolean_true_add(json_vrf,
							     "noSuchIface");
				json_object_free(json_interface);
			} else
				vty_out(vty, "No such interface name\n");
		} else {
			if (use_json)
				json_interface_sub = json_object_new_object();

			show_ip_ospf_interface_sub(
				vty, ospf, ifp, json_interface_sub, use_json);

			if (use_json) {
				json_object_object_add(json_interface,
						       ifp->name,
						       json_interface_sub);
				json_object_object_add(json_vrf, "interfaces",
						       json_interface);
			}
		}
	}

	if (use_json) {
		if (use_vrf) {
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
		}
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

static void show_ip_ospf_interface_traffic_sub(struct vty *vty,
					       struct ospf_interface *oi,
					       json_object *json_interface_sub,
					       bool use_json)
{
	if (use_json) {
		json_object_int_add(json_interface_sub, "ifIndex",
				    oi->ifp->ifindex);
		json_object_int_add(json_interface_sub, "helloIn",
				    oi->hello_in);
		json_object_int_add(json_interface_sub, "helloOut",
				    oi->hello_out);
		json_object_int_add(json_interface_sub, "dbDescIn",
				    oi->db_desc_in);
		json_object_int_add(json_interface_sub, "dbDescOut",
				    oi->db_desc_out);
		json_object_int_add(json_interface_sub, "lsReqIn",
				    oi->ls_req_in);
		json_object_int_add(json_interface_sub, "lsReqOut",
				    oi->ls_req_out);
		json_object_int_add(json_interface_sub, "lsUpdIn",
				    oi->ls_upd_in);
		json_object_int_add(json_interface_sub, "lsUpdOut",
				    oi->ls_upd_out);
		json_object_int_add(json_interface_sub, "lsAckIn",
				    oi->ls_ack_in);
		json_object_int_add(json_interface_sub, "lsAckOut",
				    oi->ls_ack_out);
		json_object_int_add(json_interface_sub, "packetsQueued",
				    listcount(oi->obuf));
	} else {
		vty_out(vty,
			"%-10s %8u/%-8u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u %12lu\n",
			oi->ifp->name, oi->hello_in, oi->hello_out,
			oi->db_desc_in, oi->db_desc_out, oi->ls_req_in,
			oi->ls_req_out, oi->ls_upd_in, oi->ls_upd_out,
			oi->ls_ack_in, oi->ls_ack_out, listcount(oi->obuf));
	}
}

/* OSPFv2 Packet Counters */
static int show_ip_ospf_interface_traffic_common(
	struct vty *vty, struct ospf *ospf, char *intf_name, json_object *json,
	int display_once, uint8_t use_vrf, bool use_json)
{
	struct vrf *vrf = NULL;
	struct interface *ifp = NULL;
	json_object *json_vrf = NULL;
	json_object *json_interface_sub = NULL;

	if (!use_json && !display_once) {
		vty_out(vty, "\n");
		vty_out(vty, "%-12s%-17s%-17s%-17s%-17s%-17s%-17s\n",
			"Interface", "    HELLO", "    DB-Desc", "   LS-Req",
			"   LS-Update", "   LS-Ack", "    Packets");
		vty_out(vty, "%-10s%-18s%-18s%-17s%-17s%-17s%-17s\n", "",
			"      Rx/Tx", "     Rx/Tx", "    Rx/Tx", "    Rx/Tx",
			"    Rx/Tx", "    Queued");
		vty_out(vty,
			"-------------------------------------------------------------------------------------------------------------\n");
	} else if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	if (intf_name == NULL) {
		vrf = vrf_lookup_by_id(ospf->vrf_id);
		FOR_ALL_INTERFACES (vrf, ifp) {
			struct route_node *rn;
			struct ospf_interface *oi;

			if (ospf_oi_count(ifp) == 0)
				continue;

			for (rn = route_top(IF_OIFS(ifp)); rn;
			     rn = route_next(rn)) {
				oi = rn->info;

				if (oi == NULL)
					continue;

				if (use_json) {
					json_interface_sub =
						json_object_new_object();
				}

				show_ip_ospf_interface_traffic_sub(
					vty, oi, json_interface_sub, use_json);
				if (use_json) {
					json_object_object_add(
						json_vrf, ifp->name,
						json_interface_sub);
				}
			}
		}
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(intf_name, ospf->vrf_id);
		if (ifp != NULL) {
			struct route_node *rn;
			struct ospf_interface *oi;

			if (ospf_oi_count(ifp) == 0) {
				vty_out(vty,
					"  OSPF not enabled on this interface %s\n",
					ifp->name);
				return CMD_SUCCESS;
			}

			for (rn = route_top(IF_OIFS(ifp)); rn;
			     rn = route_next(rn)) {
				oi = rn->info;

				if (oi == NULL)
					continue;

				if (use_json) {
					json_interface_sub =
						json_object_new_object();
				}

				show_ip_ospf_interface_traffic_sub(
					vty, oi, json_interface_sub, use_json);
				if (use_json) {
					json_object_object_add(
						json_vrf, ifp->name,
						json_interface_sub);
				}
			}
		}
	}

	if (use_json) {
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_interface,
       show_ip_ospf_interface_cmd,
       "show ip ospf [vrf <NAME|all>] interface [INTERFACE] [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Interface information\n"
       "Interface name\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	struct listnode *node = NULL;
	char *vrf_name = NULL, *intf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0, idx_intf = 0;
	uint8_t use_vrf = 0;
	json_object *json = NULL;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		intf_name = argv[idx_intf]->arg;

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = show_ip_ospf_interface_common(
					vty, ospf, intf_name, use_vrf, json,
					uj);
			}

			if (uj)
				vty_json(vty, json);
			else if (!ospf)
				vty_out(vty, "%% OSPF is not enabled\n");

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);

			return CMD_SUCCESS;
		}
		ret = show_ip_ospf_interface_common(vty, ospf, intf_name,
						    use_vrf, json, uj);

	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf default\n");

			return CMD_SUCCESS;
		}
		ret = show_ip_ospf_interface_common(vty, ospf, intf_name,
						    use_vrf, json, uj);
	}

	if (uj)
		vty_json(vty, json);

	return ret;
}

DEFUN (show_ip_ospf_instance_interface,
       show_ip_ospf_instance_interface_cmd,
       "show ip ospf (1-65535) interface [INTERFACE] [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Interface information\n"
       "Interface name\n"
       JSON_STR)
{
	int idx_number = 3;
	int idx_intf = 0;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);
	char *intf_name = NULL;
	int ret = CMD_SUCCESS;
	json_object *json = NULL;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		intf_name = argv[idx_intf]->arg;

	ret = show_ip_ospf_interface_common(vty, ospf, intf_name, 0, json, uj);

	if (uj)
		vty_json(vty, json);

	return ret;
}

DEFUN (show_ip_ospf_interface_traffic,
       show_ip_ospf_interface_traffic_cmd,
       "show ip ospf [vrf <NAME|all>] interface traffic [INTERFACE] [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Interface information\n"
       "Protocol Packet counters\n"
       "Interface name\n"
       JSON_STR)
{
	struct ospf *ospf = NULL;
	struct listnode *node = NULL;
	char *vrf_name = NULL, *intf_name = NULL;
	bool all_vrf = false;
	int inst = 0;
	int idx_vrf = 0, idx_intf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	int ret = CMD_SUCCESS;
	int display_once = 0;
	uint8_t use_vrf = 0;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		intf_name = argv[idx_intf]->arg;

	if (uj)
		json = json_object_new_object();

	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;

				ret = show_ip_ospf_interface_traffic_common(
					vty, ospf, intf_name, json,
					display_once, use_vrf, uj);
				display_once = 1;
			}

			if (uj)
				vty_json(vty, json);

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				json_object_free(json);
			return CMD_SUCCESS;
		}

		ret = show_ip_ospf_interface_traffic_common(
			vty, ospf, intf_name, json, display_once, use_vrf, uj);
	} else {
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				json_object_free(json);
			return CMD_SUCCESS;
		}

		ret = show_ip_ospf_interface_traffic_common(
			vty, ospf, intf_name, json, display_once, use_vrf, uj);
	}

	if (uj)
		vty_json(vty, json);

	return ret;
}


static void show_ip_ospf_neighbour_header(struct vty *vty)
{
	vty_out(vty, "\n%-15s %-3s %-15s %-15s %-9s %-15s %-32s %5s %5s %5s\n",
		"Neighbor ID", "Pri", "State", "Up Time", "Dead Time",
		"Address", "Interface", "RXmtL", "RqstL", "DBsmL");
}

static void show_ip_ospf_neighbour_brief(struct vty *vty,
					 struct ospf_neighbor *nbr,
					 struct ospf_neighbor *prev_nbr,
					 json_object *json, bool use_json)
{
	char msgbuf[16];
	char timebuf[OSPF_TIME_DUMP_SIZE];
	json_object *json_neighbor = NULL, *json_neigh_array = NULL;
	struct timeval res = {.tv_sec = 0, .tv_usec = 0};
	long time_val = 0;
	char uptime[OSPF_TIME_DUMP_SIZE];

	if (nbr->ts_last_progress.tv_sec || nbr->ts_last_progress.tv_usec)
		time_val =
			monotime_since(&nbr->ts_last_progress, &res) / 1000LL;

	if (use_json) {
		char neigh_str[INET_ADDRSTRLEN];

		if (prev_nbr && !IPV4_ADDR_SAME(&prev_nbr->src, &nbr->src)) {
			/* Start new neigh list */
			json_neigh_array = NULL;
		}

		if (nbr->state == NSM_Attempt &&
		    nbr->router_id.s_addr == INADDR_ANY)
			strlcpy(neigh_str, "neighbor", sizeof(neigh_str));
		else
			inet_ntop(AF_INET, &nbr->router_id, neigh_str,
				  sizeof(neigh_str));

		json_object_object_get_ex(json, neigh_str, &json_neigh_array);

		if (!json_neigh_array) {
			json_neigh_array = json_object_new_array();
			json_object_object_add(json, neigh_str,
					       json_neigh_array);
		}

		json_neighbor = json_object_new_object();

		ospf_nbr_ism_state_message(nbr, msgbuf, sizeof(msgbuf));
		json_object_string_add(json_neighbor, "nbrState", msgbuf);

		json_object_int_add(json_neighbor, "nbrPriority",
				    nbr->priority);

		json_object_string_add(
			json_neighbor, "converged",
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL));
		json_object_string_add(json_neighbor, "role",
				       lookup_msg(ospf_ism_state_msg,
						  ospf_nbr_ism_state(nbr),
						  NULL));
		if (nbr->t_inactivity) {
			long time_store;

			time_store = monotime_until(&nbr->t_inactivity->u.sands,
						    NULL) /
				     1000LL;
			json_object_int_add(json_neighbor, "upTimeInMsec",
					    time_val);
			json_object_int_add(json_neighbor,
					    "routerDeadIntervalTimerDueMsec",
					    time_store);
			json_object_string_add(
				json_neighbor, "upTime",
				ospf_timeval_dump(&res, uptime,
						  sizeof(uptime)));
			json_object_string_add(
				json_neighbor, "deadTime",
				ospf_timer_dump(nbr->t_inactivity, timebuf,
						sizeof(timebuf)));
		} else {
			json_object_string_add(json_neighbor, "deadTimeMsecs",
					       "inactive");
			json_object_string_add(json_neighbor,
					       "routerDeadIntervalTimerDueMsec",
					       "inactive");
		}
		json_object_string_addf(json_neighbor, "ifaceAddress", "%pI4",
					&nbr->src);
		json_object_string_add(json_neighbor, "ifaceName",
				       IF_NAME(nbr->oi));
		json_object_int_add(json_neighbor,
				    "linkStateRetransmissionListCounter",
				    ospf_ls_retransmit_count(nbr));
		json_object_int_add(json_neighbor,
				    "linkStateRequestListCounter",
				    ospf_ls_request_count(nbr));
		json_object_int_add(json_neighbor, "databaseSummaryListCounter",
				    ospf_db_summary_count(nbr));

		json_object_array_add(json_neigh_array, json_neighbor);
	} else {
		ospf_nbr_ism_state_message(nbr, msgbuf, sizeof(msgbuf));

		if (nbr->state == NSM_Attempt &&
		    nbr->router_id.s_addr == INADDR_ANY)
			vty_out(vty, "%-15s %3d %-15s ", "-", nbr->priority,
				msgbuf);
		else
			vty_out(vty, "%-15pI4 %3d %-15s ", &nbr->router_id,
				nbr->priority, msgbuf);

		vty_out(vty, "%-15s ",
			ospf_timeval_dump(&res, uptime, sizeof(uptime)));

		vty_out(vty, "%9s ",
			ospf_timer_dump(nbr->t_inactivity, timebuf,
					sizeof(timebuf)));
		vty_out(vty, "%-15pI4 ", &nbr->src);
		vty_out(vty, "%-32s %5ld %5ld %5d\n", IF_NAME(nbr->oi),
			ospf_ls_retransmit_count(nbr),
			ospf_ls_request_count(nbr), ospf_db_summary_count(nbr));
	}
}

static void show_ip_ospf_neighbor_sub(struct vty *vty,
				      struct ospf_interface *oi,
				      json_object *json, bool use_json)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr, *prev_nbr = NULL;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;

		if (!nbr)
			continue;

		/* Do not show myself. */
		if (nbr == oi->nbr_self)
			continue;
		/* Down state is not shown. */
		if (nbr->state == NSM_Down)
			continue;

		prev_nbr = nbr;

		show_ip_ospf_neighbour_brief(vty, nbr, prev_nbr, json,
					     use_json);
	}
}

static int show_ip_ospf_neighbor_common(struct vty *vty, struct ospf *ospf,
					json_object *json, bool use_json,
					uint8_t use_vrf)
{
	struct ospf_interface *oi;
	struct listnode *node;
	json_object *json_vrf = NULL;
	json_object *json_nbr_sub = NULL;

	if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
		json_nbr_sub = json_object_new_object();
	}

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);
	if (!use_json)
		show_ip_ospf_neighbour_header(vty);

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		if (ospf_interface_neighbor_count(oi) == 0)
			continue;
		show_ip_ospf_neighbor_sub(vty, oi, json_nbr_sub, use_json);
	}

	if (use_json) {
		json_object_object_add(json_vrf, "neighbors", json_nbr_sub);
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor,
       show_ip_ospf_neighbor_cmd,
       "show ip ospf [vrf <NAME|all>] neighbor [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Neighbor list\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0;
	uint8_t use_vrf = 0;
	json_object *json = NULL;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = show_ip_ospf_neighbor_common(
					vty, ospf, json, uj, use_vrf);
			}

			if (uj)
				vty_json(vty, json);
			else if (!ospf)
				vty_out(vty, "OSPF is not enabled\n");

			return ret;
		}

		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);

			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf default\n");

			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		ret = show_ip_ospf_neighbor_common(vty, ospf, json, uj,
						   use_vrf);

		if (uj) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
		}
	}

	if (uj)
		json_object_free(json);

	return ret;
}


DEFUN (show_ip_ospf_instance_neighbor,
       show_ip_ospf_instance_neighbor_cmd,
       "show ip ospf (1-65535) neighbor [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       JSON_STR)
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	int ret = CMD_SUCCESS;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_common(vty, ospf, json, uj, 0);

	if (uj)
		vty_json(vty, json);

	return ret;
}

static int show_ip_ospf_neighbor_all_common(struct vty *vty, struct ospf *ospf,
					    json_object *json, bool use_json,
					    uint8_t use_vrf)
{
	struct listnode *node;
	struct ospf_interface *oi;
	char buf[PREFIX_STRLEN];
	json_object *json_vrf = NULL;
	json_object *json_neighbor_sub = NULL;

	if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);
	if (!use_json)
		show_ip_ospf_neighbour_header(vty);

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json_vrf, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		struct listnode *nbr_node;
		struct ospf_nbr_nbma *nbr_nbma;

		show_ip_ospf_neighbor_sub(vty, oi, json_vrf, use_json);

		/* print Down neighbor status */
		for (ALL_LIST_ELEMENTS_RO(oi->nbr_nbma, nbr_node, nbr_nbma)) {
			if (nbr_nbma->nbr == NULL
			    || nbr_nbma->nbr->state == NSM_Down) {
				if (use_json) {
					json_neighbor_sub =
						json_object_new_object();
					json_object_int_add(json_neighbor_sub,
							    "nbrNbmaPriority",
							    nbr_nbma->priority);
					json_object_boolean_true_add(
						json_neighbor_sub,
						"nbrNbmaDown");
					json_object_string_add(
						json_neighbor_sub,
						"nbrNbmaIfaceName",
						IF_NAME(oi));
					json_object_int_add(
						json_neighbor_sub,
						"nbrNbmaRetransmitCounter", 0);
					json_object_int_add(
						json_neighbor_sub,
						"nbrNbmaRequestCounter", 0);
					json_object_int_add(
						json_neighbor_sub,
						"nbrNbmaDbSummaryCounter", 0);
					json_object_object_add(
						json_vrf,
						inet_ntop(AF_INET,
							  &nbr_nbma->addr, buf,
							  sizeof(buf)),
						json_neighbor_sub);
				} else {
					vty_out(vty, "%-15s %3d %-15s %9s ",
						"-", nbr_nbma->priority, "Down",
						"-");
					vty_out(vty,
						"%-32pI4 %-20s %5d %5d %5d\n",
						&nbr_nbma->addr,
						IF_NAME(oi), 0, 0, 0);
				}
			}
		}
	}

	if (use_json) {
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_all,
       show_ip_ospf_neighbor_all_cmd,
       "show ip ospf [vrf <NAME|all>] neighbor all [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Neighbor list\n"
       "include down status neighbor\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0;
	uint8_t use_vrf = 0;
	json_object *json = NULL;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = show_ip_ospf_neighbor_all_common(
					vty, ospf, json, uj, use_vrf);
			}

			if (uj)
				vty_json(vty, json);

			return ret;
		}

		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				json_object_free(json);
			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				json_object_free(json);
			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		ret = show_ip_ospf_neighbor_all_common(vty, ospf, json, uj,
						       use_vrf);
		if (uj) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
		}
	}

	if (uj)
		json_object_free(json);

	return ret;
}

DEFUN (show_ip_ospf_instance_neighbor_all,
       show_ip_ospf_instance_neighbor_all_cmd,
       "show ip ospf (1-65535) neighbor all [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       "include down status neighbor\n"
       JSON_STR)
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	int ret = CMD_SUCCESS;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;
	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_all_common(vty, ospf, json, uj, 0);

	if (uj)
		vty_json(vty, json);

	return ret;
}

static int show_ip_ospf_neighbor_int_common(struct vty *vty, struct ospf *ospf,
					    const char *ifname, bool use_json,
					    uint8_t use_vrf)
{
	struct interface *ifp;
	struct route_node *rn;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json, use_vrf);

	ifp = if_lookup_by_name(ifname, ospf->vrf_id);
	if (!ifp) {
		if (use_json)
			json_object_boolean_true_add(json, "noSuchIface");
		else
			vty_out(vty, "No such interface.\n");
		return CMD_WARNING;
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi == NULL)
			continue;

		show_ip_ospf_neighbor_sub(vty, oi, json, use_json);
	}

	if (use_json)
		vty_json(vty, json);
	else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFPY(show_ip_ospf_instance_neighbor_int,
      show_ip_ospf_instance_neighbor_int_cmd,
      "show ip ospf (1-65535)$instance neighbor IFNAME$ifname [json$json]",
      SHOW_STR
      IP_STR
      "OSPF information\n"
      "Instance ID\n"
      "Neighbor list\n"
      "Interface name\n"
      JSON_STR)
{
	struct ospf *ospf;

	if (!json)
		show_ip_ospf_neighbour_header(vty);

	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	if (!json)
		show_ip_ospf_neighbour_header(vty);

	return show_ip_ospf_neighbor_int_common(vty, ospf, ifname, !!json, 0);
}

static void show_ip_ospf_nbr_nbma_detail_sub(struct vty *vty,
					     struct ospf_interface *oi,
					     struct ospf_nbr_nbma *nbr_nbma,
					     bool use_json, json_object *json)
{
	char timebuf[OSPF_TIME_DUMP_SIZE];
	json_object *json_sub = NULL;

	if (use_json)
		json_sub = json_object_new_object();
	else /* Show neighbor ID. */
		vty_out(vty, " Neighbor %s,", "-");

	/* Show interface address. */
	if (use_json)
		json_object_string_addf(json_sub, "ifaceAddress", "%pI4",
					&nbr_nbma->addr);
	else
		vty_out(vty, " interface address %pI4\n",
			&nbr_nbma->addr);

	/* Show Area ID. */
	if (use_json) {
		json_object_string_add(json_sub, "areaId",
				       ospf_area_desc_string(oi->area));
		json_object_string_add(json_sub, "iface", IF_NAME(oi));
	} else
		vty_out(vty, "    In the area %s via interface %s\n",
			ospf_area_desc_string(oi->area), IF_NAME(oi));

	/* Show neighbor priority and state. */
	if (use_json) {
		json_object_int_add(json_sub, "nbrPriority",
				    nbr_nbma->priority);
		json_object_string_add(json_sub, "nbrState", "down");
	} else
		vty_out(vty, "    Neighbor priority is %d, State is %s,",
			nbr_nbma->priority, "Down");

	/* Show state changes. */
	if (use_json)
		json_object_int_add(json_sub, "stateChangeCounter",
				    nbr_nbma->state_change);
	else
		vty_out(vty, " %d state changes\n", nbr_nbma->state_change);

	/* Show PollInterval */
	if (use_json)
		json_object_int_add(json_sub, "pollInterval", nbr_nbma->v_poll);
	else
		vty_out(vty, "    Poll interval %d\n", nbr_nbma->v_poll);

	/* Show poll-interval timer. */
	if (nbr_nbma->t_poll) {
		if (use_json) {
			long time_store;
			time_store = monotime_until(&nbr_nbma->t_poll->u.sands,
						    NULL) / 1000LL;
			json_object_int_add(json_sub,
					    "pollIntervalTimerDueMsec",
					    time_store);
		} else
			vty_out(vty, "    Poll timer due in %s\n",
				ospf_timer_dump(nbr_nbma->t_poll, timebuf,
						sizeof(timebuf)));
	}

	/* Show poll-interval timer thread. */
	if (use_json) {
		if (nbr_nbma->t_poll != NULL)
			json_object_string_add(json_sub,
					       "pollIntervalTimerThread", "on");
	} else
		vty_out(vty, "    Thread Poll Timer %s\n",
			nbr_nbma->t_poll != NULL ? "on" : "off");

	if (use_json)
		json_object_object_add(json, "noNbrId", json_sub);
}

static void show_ip_ospf_neighbor_detail_sub(struct vty *vty,
					     struct ospf_interface *oi,
					     struct ospf_neighbor *nbr,
					     struct ospf_neighbor *prev_nbr,
					     json_object *json, bool use_json)
{
	char timebuf[OSPF_TIME_DUMP_SIZE];
	json_object *json_neigh = NULL, *json_neigh_array = NULL;
	char neigh_str[INET_ADDRSTRLEN] = {0};
	char neigh_state[16] = {0};
	struct ospf_neighbor *nbr_dr, *nbr_bdr;

	if (use_json) {
		if (prev_nbr &&
		    !IPV4_ADDR_SAME(&prev_nbr->src, &nbr->src)) {
			json_neigh_array = NULL;
		}

		if (nbr->state == NSM_Attempt
		    && nbr->router_id.s_addr == INADDR_ANY)
			strlcpy(neigh_str, "noNbrId", sizeof(neigh_str));
		else
			inet_ntop(AF_INET, &nbr->router_id,
				  neigh_str, sizeof(neigh_str));

		json_object_object_get_ex(json, neigh_str, &json_neigh_array);

		if (!json_neigh_array) {
			json_neigh_array = json_object_new_array();
			json_object_object_add(json, neigh_str,
					       json_neigh_array);
		}

		json_neigh = json_object_new_object();

	} else {
		/* Show neighbor ID. */
		if (nbr->state == NSM_Attempt
		    && nbr->router_id.s_addr == INADDR_ANY)
			vty_out(vty, " Neighbor %s,", "-");
		else
			vty_out(vty, " Neighbor %pI4,",
				&nbr->router_id);
	}

	/* Show interface address. */
	if (use_json)
		json_object_string_addf(json_neigh, "ifaceAddress", "%pI4",
					&nbr->address.u.prefix4);
	else
		vty_out(vty, " interface address %pI4\n",
			&nbr->address.u.prefix4);

	/* Show Area ID. */
	if (use_json) {
		json_object_string_add(json_neigh, "areaId",
				       ospf_area_desc_string(oi->area));
		json_object_string_add(json_neigh, "ifaceName", oi->ifp->name);
		if (oi->address)
			json_object_string_addf(json_neigh, "localIfaceAddress",
						"%pI4",
						&oi->address->u.prefix4);
	} else {
		vty_out(vty, "    In the area %s via interface %s",
			ospf_area_desc_string(oi->area), oi->ifp->name);
		if (oi->address)
			vty_out(vty, " local interface IP %pI4\n",
				&oi->address->u.prefix4);
		else
			vty_out(vty, "\n");
	}

	/* Show neighbor priority and state. */
	ospf_nbr_ism_state_message(nbr, neigh_state, sizeof(neigh_state));
	if (use_json) {
		json_object_int_add(json_neigh, "nbrPriority", nbr->priority);
		json_object_string_add(json_neigh, "nbrState", neigh_state);
		json_object_string_add(json_neigh, "role",
				       lookup_msg(ospf_ism_state_msg,
						  ospf_nbr_ism_state(nbr),
						  NULL));
	} else {
		vty_out(vty,
			"    Neighbor priority is %d, State is %s, Role is %s,",
			nbr->priority, neigh_state,
			lookup_msg(ospf_ism_state_msg, ospf_nbr_ism_state(nbr),
				   NULL));
	}

	/* Show state changes. */
	if (use_json)
		json_object_int_add(json_neigh, "stateChangeCounter",
				    nbr->state_change);
	else
		vty_out(vty, "    %d state changes\n", nbr->state_change);

	/* Show LSA retransmissions. */
	if (use_json)
		json_object_int_add(json_neigh, "lsaRetransmissions",
				    nbr->ls_rxmt_lsa);
	else
		vty_out(vty, "    %u LSA retransmissions\n", nbr->ls_rxmt_lsa);

	if (nbr->ts_last_progress.tv_sec || nbr->ts_last_progress.tv_usec) {
		struct timeval res;
		long time_store;

		time_store =
			monotime_since(&nbr->ts_last_progress, &res) / 1000LL;
		if (use_json) {
			json_object_int_add(json_neigh, "lastPrgrsvChangeMsec",
					    time_store);
		} else {
			vty_out(vty,
				"    Most recent state change statistics:\n");
			vty_out(vty, "      Progressive change %s ago\n",
				ospf_timeval_dump(&res, timebuf,
						  sizeof(timebuf)));
		}
	}

	if (nbr->ts_last_regress.tv_sec || nbr->ts_last_regress.tv_usec) {
		struct timeval res;
		long time_store;

		time_store =
			monotime_since(&nbr->ts_last_regress, &res) / 1000LL;
		if (use_json) {
			json_object_int_add(json_neigh,
					    "lastRegressiveChangeMsec",
					    time_store);
			if (nbr->last_regress_str)
				json_object_string_add(
					json_neigh,
					"lastRegressiveChangeReason",
					nbr->last_regress_str);
		} else {
			vty_out(vty,
				"      Regressive change %s ago, due to %s\n",
				ospf_timeval_dump(&res, timebuf,
						  sizeof(timebuf)),
				(nbr->last_regress_str ? nbr->last_regress_str
						       : "??"));
		}
	}

	/* Show Designated Router ID. */
	if (DR(oi).s_addr == INADDR_ANY) {
		if (!use_json)
			vty_out(vty,
				"    No designated router on this network\n");
	} else {
		nbr_dr = ospf_nbr_lookup_by_addr(oi->nbrs, &DR(oi));
		if (nbr_dr) {
			if (use_json)
				json_object_string_addf(
					json_neigh, "routerDesignatedId",
					"%pI4", &nbr_dr->router_id);
			else
				vty_out(vty, "    DR is %pI4,",
					&nbr_dr->router_id);
		}
	}

	/* Show Backup Designated Router ID. */
	nbr_bdr = ospf_nbr_lookup_by_addr(oi->nbrs, &BDR(oi));
	if (nbr_bdr == NULL) {
		if (!use_json)
			vty_out(vty,
				"    No backup designated router on this network\n");
	} else {
		if (use_json)
			json_object_string_addf(json_neigh,
						"routerDesignatedBackupId",
						"%pI4", &nbr_bdr->router_id);
		else
			vty_out(vty, "     BDR is %pI4\n", &nbr_bdr->router_id);
	}

	/* Show options. */
	if (use_json) {
		json_object_int_add(json_neigh, "optionsCounter", nbr->options);
		json_object_string_add(json_neigh, "optionsList",
				       ospf_options_dump(nbr->options));
	} else
		vty_out(vty, "    Options %d %s\n", nbr->options,
			ospf_options_dump(nbr->options));

	/* Show Router Dead interval timer. */
	if (use_json) {
		if (nbr->t_inactivity) {
			long time_store;
			time_store = monotime_until(&nbr->t_inactivity->u.sands,
						    NULL)
				     / 1000LL;
			json_object_int_add(json_neigh,
					    "routerDeadIntervalTimerDueMsec",
					    time_store);
		} else
			json_object_int_add(
				json_neigh,
				"routerDeadIntervalTimerDueMsec", -1);
	} else
		vty_out(vty, "    Dead timer due in %s\n",
			ospf_timer_dump(nbr->t_inactivity, timebuf,
					sizeof(timebuf)));

	/* Show Database Summary list. */
	if (use_json)
		json_object_int_add(json_neigh, "databaseSummaryListCounter",
				    ospf_db_summary_count(nbr));
	else
		vty_out(vty, "    Database Summary List %d\n",
			ospf_db_summary_count(nbr));

	/* Show Link State Request list. */
	if (use_json)
		json_object_int_add(json_neigh, "linkStateRequestListCounter",
				    ospf_ls_request_count(nbr));
	else
		vty_out(vty, "    Link State Request List %ld\n",
			ospf_ls_request_count(nbr));

	/* Show Link State Retransmission list. */
	if (use_json)
		json_object_int_add(json_neigh,
				    "linkStateRetransmissionListCounter",
				    ospf_ls_retransmit_count(nbr));
	else
		vty_out(vty, "    Link State Retransmission List %ld\n",
			ospf_ls_retransmit_count(nbr));

	/* Show inactivity timer thread. */
	if (use_json) {
		if (nbr->t_inactivity != NULL)
			json_object_string_add(json_neigh,
					       "threadInactivityTimer", "on");
	} else
		vty_out(vty, "    Thread Inactivity Timer %s\n",
			nbr->t_inactivity != NULL ? "on" : "off");

	/* Show Database Description retransmission thread. */
	if (use_json) {
		if (nbr->t_db_desc != NULL)
			json_object_string_add(
				json_neigh,
				"threadDatabaseDescriptionRetransmission",
				"on");
	} else
		vty_out(vty,
			"    Thread Database Description Retransmision %s\n",
			nbr->t_db_desc != NULL ? "on" : "off");

	/* Show Link State Request Retransmission thread. */
	if (use_json) {
		if (nbr->t_ls_req != NULL)
			json_object_string_add(
				json_neigh,
				"threadLinkStateRequestRetransmission", "on");
	} else
		vty_out(vty,
			"    Thread Link State Request Retransmission %s\n",
			nbr->t_ls_req != NULL ? "on" : "off");

	/* Show Link State Update Retransmission thread. */
	if (use_json) {
		if (nbr->t_ls_rxmt != NULL)
			json_object_string_add(
				json_neigh,
				"threadLinkStateUpdateRetransmission",
				"on");
	} else
		vty_out(vty,
			"    Thread Link State Update Retransmission %s\n\n",
			nbr->t_ls_rxmt != NULL ? "on" : "off");

	if (!use_json) {
		vty_out(vty, "    Graceful restart Helper info:\n");

		if (OSPF_GR_IS_ACTIVE_HELPER(nbr)) {
			vty_out(vty,
				"      Graceful Restart HELPER Status : Inprogress.\n");

			vty_out(vty,
				"      Graceful Restart grace period time: %d (seconds).\n",
				nbr->gr_helper_info.recvd_grace_period);
			vty_out(vty, "      Graceful Restart reason: %s.\n",
				ospf_restart_reason2str(
					nbr->gr_helper_info.gr_restart_reason));
		} else {
			vty_out(vty,
				"      Graceful Restart HELPER Status : None\n");
		}

		if (nbr->gr_helper_info.rejected_reason
		    != OSPF_HELPER_REJECTED_NONE)
			vty_out(vty, "      Helper rejected reason: %s.\n",
				ospf_rejected_reason2str(
					nbr->gr_helper_info.rejected_reason));

		if (nbr->gr_helper_info.helper_exit_reason
		    != OSPF_GR_HELPER_EXIT_NONE)
			vty_out(vty, "      Last helper exit reason: %s.\n\n",
				ospf_exit_reason2str(
					nbr->gr_helper_info.helper_exit_reason));
		else
			vty_out(vty, "\n");
	} else {
		json_object_string_add(json_neigh, "grHelperStatus",
				       OSPF_GR_IS_ACTIVE_HELPER(nbr) ?
							"Inprogress"
							: "None");
		if (OSPF_GR_IS_ACTIVE_HELPER(nbr)) {
			json_object_int_add(
				json_neigh, "graceInterval",
				nbr->gr_helper_info.recvd_grace_period);
			json_object_string_add(
				json_neigh, "grRestartReason",
				ospf_restart_reason2str(
					nbr->gr_helper_info.gr_restart_reason));
		}

		if (nbr->gr_helper_info.rejected_reason
		    != OSPF_HELPER_REJECTED_NONE)
			json_object_string_add(
				json_neigh, "helperRejectReason",
				ospf_rejected_reason2str(
					nbr->gr_helper_info.rejected_reason));

		if (nbr->gr_helper_info.helper_exit_reason
		    != OSPF_GR_HELPER_EXIT_NONE)
			json_object_string_add(
				json_neigh, "helperExitReason",
				ospf_exit_reason2str(
					nbr->gr_helper_info
						 .helper_exit_reason));
	}

	bfd_sess_show(vty, json_neigh, nbr->bfd_session);

	if (use_json)
		json_object_array_add(json_neigh_array, json_neigh);

}

static int show_ip_ospf_neighbor_id_common(struct vty *vty, struct ospf *ospf,
					   struct in_addr *router_id,
					   bool use_json, uint8_t use_vrf,
					   bool is_detail,
					   json_object *json_vrf)
{
	struct listnode *node;
	struct ospf_neighbor *nbr;
	struct ospf_interface *oi;
	json_object *json = NULL;

	if (use_json)
		json = json_object_new_object();

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json, use_vrf);

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		nbr = ospf_nbr_lookup_by_routerid(oi->nbrs, router_id);

		if (!nbr)
			continue;

		if (is_detail)
			show_ip_ospf_neighbor_detail_sub(vty, oi, nbr, NULL,
							 json, use_json);
		else
			show_ip_ospf_neighbour_brief(vty, nbr, NULL, json,
						     use_json);
	}

	if (json_vrf && use_json) {
		json_object_object_add(
			json_vrf,
			(ospf->vrf_id == VRF_DEFAULT) ? "default" : ospf->name,
			json);
		return CMD_SUCCESS;
	}

	if (use_json)
		vty_json(vty, json);
	else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFPY(show_ip_ospf_neighbor_id,
      show_ip_ospf_neighbor_id_cmd,
      "show ip ospf [vrf NAME$vrf_name] neighbor A.B.C.D$router_id [detail$detail] [json$json]",
      SHOW_STR
      IP_STR
      "OSPF information\n"
      VRF_CMD_HELP_STR
      "Neighbor list\n"
      "Neighbor ID\n"
      "Detailed output\n"
      JSON_STR)
{
	struct ospf *ospf;
	struct listnode *node;
	int ret = CMD_SUCCESS;
	int inst = 0;

	if (vrf_name && !strmatch(vrf_name, "all")) {
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (!json)
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);
			else
				vty_json_empty(vty, NULL);
			return CMD_SUCCESS;
		}
		ret = show_ip_ospf_neighbor_id_common(
			vty, ospf, &router_id, !!json, 0, !!detail, NULL);
	} else {
		json_object *json_vrf = NULL;

		if (json)
			json_vrf = json_object_new_object();
		for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
			if (!ospf->oi_running)
				continue;
			ret = show_ip_ospf_neighbor_id_common(
				vty, ospf, &router_id, !!json, 0, !!detail,
				json_vrf);
		}
		if (json)
			vty_json(vty, json_vrf);
	}

	return ret;
}

DEFPY(show_ip_ospf_instance_neighbor_id, show_ip_ospf_instance_neighbor_id_cmd,
      "show ip ospf (1-65535)$instance neighbor A.B.C.D$router_id [detail$detail] [json$json]",
      SHOW_STR IP_STR
      "OSPF information\n"
      "Instance ID\n"
      "Neighbor list\n"
      "Neighbor ID\n"
      "Detailed output\n" JSON_STR)
{
	struct ospf *ospf;

	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_neighbor_id_common(vty, ospf, &router_id, !!json, 0,
					       !!detail, NULL);
}

static int show_ip_ospf_neighbor_detail_common(struct vty *vty,
					       struct ospf *ospf,
					       json_object *json, bool use_json,
					       uint8_t use_vrf)
{
	struct ospf_interface *oi;
	struct listnode *node;
	json_object *json_vrf = NULL;
	json_object *json_nbr_sub = NULL;

	if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;

		json_nbr_sub = json_object_new_object();
	}

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		struct route_node *rn;
		struct ospf_neighbor *nbr, *prev_nbr = NULL;

		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;

			if (!nbr)
				continue;

			if (nbr != oi->nbr_self) {
				if (nbr->state != NSM_Down) {
					show_ip_ospf_neighbor_detail_sub(
						vty, oi, nbr, prev_nbr,
						json_nbr_sub, use_json);
				}
			}
			prev_nbr = nbr;
		}
	}

	if (use_json) {
		json_object_object_add(json_vrf, "neighbors",
				       json_nbr_sub);
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFPY(show_ip_ospf_neighbor_detail,
      show_ip_ospf_neighbor_detail_cmd,
      "show ip ospf [vrf <NAME|all>$vrf_name] neighbor detail [json$json]",
      SHOW_STR
      IP_STR
      "OSPF information\n"
      VRF_CMD_HELP_STR
      "All VRFs\n"
      "Neighbor list\n"
      "detail of all neighbors\n"
      JSON_STR)
{
	struct ospf *ospf;
	struct listnode *node = NULL;
	int ret = CMD_SUCCESS;
	int inst = 0;
	uint8_t use_vrf = 0;
	json_object *json_vrf = NULL;

	if (json)
		json_vrf = json_object_new_object();

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		use_vrf = 1;
		if (strmatch(vrf_name, "all")) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = show_ip_ospf_neighbor_detail_common(
					vty, ospf, json_vrf, !!json, use_vrf);
			}
			if (json)
				vty_json(vty, json_vrf);

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (json)
				vty_json(vty, json_vrf);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);
			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (json)
				vty_json(vty, json_vrf);
			else
				vty_out(vty, "%% OSPF is not enabled\n");
			return CMD_SUCCESS;
		}
	}

	if (ospf)
		ret = show_ip_ospf_neighbor_detail_common(vty, ospf, json_vrf,
							  !!json, use_vrf);

	if (json)
		vty_json(vty, json_vrf);

	return ret;
}

DEFUN (show_ip_ospf_instance_neighbor_detail,
       show_ip_ospf_instance_neighbor_detail_cmd,
       "show ip ospf (1-65535) neighbor detail [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       "detail of all neighbors\n"
       JSON_STR)
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	int ret = CMD_SUCCESS;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_detail_common(vty, ospf, json, uj, 0);

	if (uj)
		vty_json(vty, json);

	return ret;
}

static int show_ip_ospf_neighbor_detail_all_common(struct vty *vty,
						   struct ospf *ospf,
						   json_object *json,
						   bool use_json,
						   uint8_t use_vrf)
{
	struct listnode *node;
	struct ospf_interface *oi;
	json_object *json_vrf = NULL;

	if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		struct route_node *rn;
		struct ospf_neighbor *nbr, *prev_nbr = NULL;
		struct ospf_nbr_nbma *nbr_nbma;

		for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
			nbr = rn->info;

			if (!nbr)
				continue;

			if (nbr != oi->nbr_self)
				if (nbr->state != NSM_Down)
					show_ip_ospf_neighbor_detail_sub(
						vty, oi, rn->info, prev_nbr,
						json_vrf, use_json);
			prev_nbr = nbr;
		}

		if (!OSPF_IF_NON_BROADCAST(oi))
			continue;

		struct listnode *nd;

		for (ALL_LIST_ELEMENTS_RO(oi->nbr_nbma, nd, nbr_nbma)) {
			if (nbr_nbma->nbr == NULL ||
			    nbr_nbma->nbr->state == NSM_Down)
				show_ip_ospf_nbr_nbma_detail_sub(
					vty, oi, nbr_nbma, use_json, json_vrf);
		}
	}

	if (use_json) {
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_detail_all,
       show_ip_ospf_neighbor_detail_all_cmd,
       "show ip ospf [vrf <NAME|all>] neighbor detail all [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Neighbor list\n"
       "detail of all neighbors\n"
       "include down status neighbor\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0;
	uint8_t use_vrf = 0;
	json_object *json = NULL;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = show_ip_ospf_neighbor_detail_all_common(
					vty, ospf, json, uj, use_vrf);
			}

			if (uj)
				vty_json(vty, json);

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				json_object_free(json);
			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				json_object_free(json);
			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		ret = show_ip_ospf_neighbor_detail_all_common(vty, ospf, json,
							      uj, use_vrf);
		if (uj) {
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_PRETTY));
		}
	}

	if (uj)
		json_object_free(json);

	return ret;
}

DEFUN (show_ip_ospf_instance_neighbor_detail_all,
       show_ip_ospf_instance_neighbor_detail_all_cmd,
       "show ip ospf (1-65535) neighbor detail all [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       "detail of all neighbors\n"
       "include down status neighbor\n"
       JSON_STR)
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	int ret = CMD_SUCCESS;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_detail_all_common(vty, ospf, json, uj, 0);

	if (uj)
		vty_json(vty, json);

	return ret;
}

static int show_ip_ospf_neighbor_int_detail_common(struct vty *vty,
						   struct ospf *ospf,
						   const char *ifname,
						   bool use_json,
						   json_object *json_vrf)
{
	struct ospf_interface *oi;
	struct interface *ifp;
	struct route_node *rn, *nrn;
	struct ospf_neighbor *nbr;
	json_object *json = NULL;

	if (use_json) {
		json = json_object_new_object();
		if (json_vrf)
			json_object_object_add(json_vrf,
					       (ospf->vrf_id == VRF_DEFAULT)
						       ? "default"
						       : ospf->name,
					       json);
	}

	if (ospf->instance) {
		if (use_json)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ifp = if_lookup_by_name(ifname, ospf->vrf_id);
	if (!ifp) {
		if (!use_json) {
			vty_out(vty, "No such interface.\n");
		} else {
			if (!json_vrf)
				vty_json(vty, json);
		}
		return CMD_WARNING;
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		oi = rn->info;

		if (!oi)
			continue;

		for (nrn = route_top(oi->nbrs); nrn; nrn = route_next(nrn)) {
			nbr = nrn->info;

			if (!nbr)
				continue;

			if (nbr == oi->nbr_self)
				continue;

			if (nbr->state == NSM_Down)
				continue;

			show_ip_ospf_neighbor_detail_sub(vty, oi, nbr, NULL,
							 json, use_json);
		}
	}

	if (use_json) {
		if (!json_vrf)
			vty_json(vty, json);
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFPY(show_ip_ospf_neighbor_int,
      show_ip_ospf_neighbor_int_cmd,
      "show ip ospf [vrf NAME$vrf_name] neighbor IFNAME$ifname [json$json]",
      SHOW_STR
      IP_STR
      "OSPF information\n"
      VRF_CMD_HELP_STR
      "Neighbor list\n"
      "Interface name\n"
      JSON_STR)
{
	struct ospf *ospf;
	int ret = CMD_SUCCESS;
	struct interface *ifp = NULL;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct vrf *vrf = NULL;

	if (vrf_name && strmatch(vrf_name, VRF_DEFAULT_NAME))
		vrf_name = NULL;
	if (vrf_name) {
		vrf = vrf_lookup_by_name(vrf_name);
		if (vrf)
			vrf_id = vrf->vrf_id;
	}
	ospf = ospf_lookup_by_vrf_id(vrf_id);

	if (!ospf || !ospf->oi_running) {
		if (json)
			vty_json_empty(vty, NULL);
		return ret;
	}

	if (!json)
		show_ip_ospf_neighbour_header(vty);

	ifp = if_lookup_by_name(ifname, vrf_id);
	if (!ifp) {
		if (json)
			vty_json_empty(vty, NULL);
		else
			vty_out(vty, "No such interface.\n");
		return ret;
	}

	ret = show_ip_ospf_neighbor_int_common(vty, ospf, ifname, !!json, 0);
	return ret;
}

DEFPY(show_ip_ospf_neighbor_int_detail,
      show_ip_ospf_neighbor_int_detail_cmd,
      "show ip ospf [vrf NAME$vrf_name] neighbor IFNAME$ifname detail [json$json]",
      SHOW_STR
      IP_STR
      "OSPF information\n"
      VRF_CMD_HELP_STR
      "Neighbor list\n"
      "Interface name\n"
      "detail of all neighbors\n"
      JSON_STR)
{
	struct ospf *ospf;
	struct listnode *node = NULL;
	int ret = CMD_SUCCESS;
	bool ospf_output = false;

	if (vrf_name && !strmatch(vrf_name, "all")) {
		int inst = 0;

		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (!json)
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);
			else
				vty_json_empty(vty, NULL);
			return CMD_SUCCESS;
		}
		return show_ip_ospf_neighbor_int_detail_common(
			vty, ospf, ifname, !!json, NULL);
	}

	json_object *json_vrf = NULL;

	if (json)
		json_vrf = json_object_new_object();

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		if (!ospf->oi_running)
			continue;
		ospf_output = true;
		ret = show_ip_ospf_neighbor_int_detail_common(vty, ospf, ifname,
							      !!json, json_vrf);
	}

	if (json) {
		vty_json(vty, json_vrf);
		return ret;
	}

	if (!ospf_output)
		vty_out(vty, "%% OSPF instance not found\n");

	return ret;
}

DEFPY(show_ip_ospf_instance_neighbor_int_detail,
      show_ip_ospf_instance_neighbor_int_detail_cmd,
      "show ip ospf (1-65535)$instance neighbor IFNAME$ifname detail [json$json]",
      SHOW_STR
      IP_STR
      "OSPF information\n"
      "Instance ID\n"
      "Neighbor list\n"
      "Interface name\n"
      "detail of all neighbors\n"
      JSON_STR)
{
	struct ospf *ospf;

	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_neighbor_int_detail_common(vty, ospf, ifname,
						       !!json, NULL);
}

/* Show functions */
static int show_lsa_summary(struct vty *vty, struct ospf_lsa *lsa, int self,
			    json_object *json_lsa)
{
	struct router_lsa *rl;
	struct summary_lsa *sl;
	struct as_external_lsa *asel;
	struct prefix_ipv4 p;

	if (lsa == NULL)
		return 0;

	/* If self option is set, check LSA self flag. */
	if (self == 0 || IS_LSA_SELF(lsa)) {

		if (!json_lsa) {
			/* LSA common part show. */
			vty_out(vty, "%-15pI4", &lsa->data->id);
			vty_out(vty, "%-15pI4 %4d 0x%08lx 0x%04x",
				&lsa->data->adv_router, LS_AGE(lsa),
				(unsigned long)ntohl(lsa->data->ls_seqnum),
				ntohs(lsa->data->checksum));
		} else {
			char seqnum[10];
			char checksum[10];

			snprintf(seqnum, sizeof(seqnum), "%x",
				 ntohl(lsa->data->ls_seqnum));
			snprintf(checksum, sizeof(checksum), "%x",
				 ntohs(lsa->data->checksum));
			json_object_string_addf(json_lsa, "lsId", "%pI4",
						&lsa->data->id);
			json_object_string_addf(json_lsa, "advertisedRouter",
						"%pI4", &lsa->data->adv_router);
			json_object_int_add(json_lsa, "lsaAge", LS_AGE(lsa));
			json_object_string_add(json_lsa, "sequenceNumber",
					       seqnum);
			json_object_string_add(json_lsa, "checksum", checksum);
		}

		/* LSA specific part show. */
		switch (lsa->data->type) {
		case OSPF_ROUTER_LSA:
			rl = (struct router_lsa *)lsa->data;

			if (!json_lsa)
				vty_out(vty, " %-d", ntohs(rl->links));
			else
				json_object_int_add(json_lsa,
						    "numOfRouterLinks",
						    ntohs(rl->links));
			break;
		case OSPF_SUMMARY_LSA:
			sl = (struct summary_lsa *)lsa->data;

			p.family = AF_INET;
			p.prefix = sl->header.id;
			p.prefixlen = ip_masklen(sl->mask);
			apply_mask_ipv4(&p);

			if (!json_lsa)
				vty_out(vty, " %pFX", &p);
			else {
				json_object_string_addf(
					json_lsa, "summaryAddress", "%pFX", &p);
			}
			break;
		case OSPF_AS_EXTERNAL_LSA:
		case OSPF_AS_NSSA_LSA:
			asel = (struct as_external_lsa *)lsa->data;

			p.family = AF_INET;
			p.prefix = asel->header.id;
			p.prefixlen = ip_masklen(asel->mask);
			apply_mask_ipv4(&p);

			if (!json_lsa)
				vty_out(vty, " %s %pFX [0x%lx]",
					IS_EXTERNAL_METRIC(asel->e[0].tos)
						? "E2"
						: "E1",
					&p,
					(unsigned long)ntohl(
						asel->e[0].route_tag));
			else {
				json_object_string_add(
					json_lsa, "metricType",
					IS_EXTERNAL_METRIC(asel->e[0].tos)
						? "E2"
						: "E1");
				json_object_string_addf(json_lsa, "route",
							"%pFX", &p);
				json_object_int_add(
					json_lsa, "tag",
					(unsigned long)ntohl(
						asel->e[0].route_tag));
			}
			break;
		case OSPF_NETWORK_LSA:
		case OSPF_ASBR_SUMMARY_LSA:
		case OSPF_OPAQUE_LINK_LSA:
		case OSPF_OPAQUE_AREA_LSA:
		case OSPF_OPAQUE_AS_LSA:
		default:
			break;
		}

		if (!json_lsa)
			vty_out(vty, "\n");
	}

	return 1;
}

static const char *const show_database_desc[] = {
	"unknown",
	"Router Link States",
	"Net Link States",
	"Summary Link States",
	"ASBR-Summary Link States",
	"AS External Link States",
	"Group Membership LSA",
	"NSSA-external Link States",
	"Type-8 LSA",
	"Link-Local Opaque-LSA",
	"Area-Local Opaque-LSA",
	"AS-external Opaque-LSA",
};

static const char * const show_database_desc_json[] = {
	"unknown",
	"routerLinkStates",
	"networkLinkStates",
	"summaryLinkStates",
	"asbrSummaryLinkStates",
	"asExternalLinkStates",
	"groupMembershipLsa",
	"nssaExternalLinkStates",
	"type8Lsa",
	"linkLocalOpaqueLsa",
	"areaLocalOpaqueLsa",
	"asExternalOpaqueLsa",
};

static const char *const show_database_desc_count_json[] = {
	"unknownCount",
	"routerLinkStatesCount",
	"networkLinkStatesCount",
	"summaryLinkStatesCount",
	"asbrSummaryLinkStatesCount",
	"asExternalLinkStatesCount",
	"groupMembershipLsaCount",
	"nssaExternalLinkStatesCount",
	"type8LsaCount",
	"linkLocalOpaqueLsaCount",
	"areaLocalOpaqueLsaCount",
	"asExternalOpaqueLsaCount",
};

static const char *const show_database_header[] = {
	"",
	"Link ID         ADV Router      Age  Seq#       CkSum  Link count",
	"Link ID         ADV Router      Age  Seq#       CkSum",
	"Link ID         ADV Router      Age  Seq#       CkSum  Route",
	"Link ID         ADV Router      Age  Seq#       CkSum",
	"Link ID         ADV Router      Age  Seq#       CkSum  Route",
	" --- header for Group Member ----",
	"Link ID         ADV Router      Age  Seq#       CkSum  Route",
	" --- type-8 ---",
	"Opaque-Type/Id  ADV Router      Age  Seq#       CkSum",
	"Opaque-Type/Id  ADV Router      Age  Seq#       CkSum",
	"Opaque-Type/Id  ADV Router      Age  Seq#       CkSum",
};

static void show_ip_ospf_database_header(struct vty *vty, struct ospf_lsa *lsa,
					 json_object *json)
{
	struct router_lsa *rlsa = (struct router_lsa *)lsa->data;

	if (!json) {
		if (IS_LSA_SELF(lsa))
			vty_out(vty, "  LS age: %d%s\n", LS_AGE(lsa),
				CHECK_FLAG(lsa->data->ls_age, DO_NOT_AGE)
					? "(S-DNA)"
					: "");
		else
			vty_out(vty, "  LS age: %d%s\n", LS_AGE(lsa),
				CHECK_FLAG(lsa->data->ls_age, DO_NOT_AGE)
					? "(DNA)"
					: "");
		vty_out(vty, "  Options: 0x%-2x : %s\n", lsa->data->options,
			ospf_options_dump(lsa->data->options));
		vty_out(vty, "  LS Flags: 0x%-2x %s\n", lsa->flags,
			((lsa->flags & OSPF_LSA_LOCAL_XLT)
				 ? "(Translated from Type-7)"
				 : ""));

		if (lsa->data->type == OSPF_ROUTER_LSA) {
			vty_out(vty, "  Flags: 0x%x", rlsa->flags);

			if (rlsa->flags)
				vty_out(vty, " :%s%s%s%s",
					IS_ROUTER_LSA_BORDER(rlsa) ? " ABR"
								   : "",
					IS_ROUTER_LSA_EXTERNAL(rlsa) ? " ASBR"
								     : "",
					IS_ROUTER_LSA_VIRTUAL(rlsa)
						? " VL-endpoint"
						: "",
					IS_ROUTER_LSA_SHORTCUT(rlsa)
						? " Shortcut"
						: "");

			vty_out(vty, "\n");
		}
		vty_out(vty, "  LS Type: %s\n",
			lookup_msg(ospf_lsa_type_msg, lsa->data->type, NULL));
		vty_out(vty, "  Link State ID: %pI4 %s\n",
			&lsa->data->id,
			lookup_msg(ospf_link_state_id_type_msg, lsa->data->type,
				   NULL));
		vty_out(vty, "  Advertising Router: %pI4\n",
			&lsa->data->adv_router);
		vty_out(vty, "  LS Seq Number: %08lx\n",
			(unsigned long)ntohl(lsa->data->ls_seqnum));
		vty_out(vty, "  Checksum: 0x%04x\n",
			ntohs(lsa->data->checksum));
		vty_out(vty, "  Length: %d\n\n", ntohs(lsa->data->length));
	} else {
		char seqnum[10];
		char checksum[10];

		snprintf(seqnum, 10, "%x", ntohl(lsa->data->ls_seqnum));
		snprintf(checksum, 10, "%x", ntohs(lsa->data->checksum));

		json_object_int_add(json, "lsaAge", LS_AGE(lsa));
		json_object_string_add(json, "options",
				       ospf_options_dump(lsa->data->options));
		json_object_int_add(json, "lsaFlags", lsa->flags);

		if (lsa->flags & OSPF_LSA_LOCAL_XLT)
			json_object_boolean_true_add(json,
						     "translatedFromType7");

		if (lsa->data->type == OSPF_ROUTER_LSA) {
			json_object_int_add(json, "flags", rlsa->flags);

			if (rlsa->flags) {
				if (IS_ROUTER_LSA_BORDER(rlsa))
					json_object_boolean_true_add(json,
								     "abr");
				if (IS_ROUTER_LSA_EXTERNAL(rlsa))
					json_object_boolean_true_add(json,
								     "asbr");
				if (IS_ROUTER_LSA_VIRTUAL(rlsa))
					json_object_boolean_true_add(
						json, "vlEndpoint");
				if (IS_ROUTER_LSA_SHORTCUT(rlsa))
					json_object_boolean_true_add(
						json, "shortcut");
			}
		}

		json_object_string_add(
			json, "lsaType",
			lookup_msg(ospf_lsa_type_msg, lsa->data->type, NULL));
		json_object_string_addf(json, "linkStateId", "%pI4",
					&lsa->data->id);
		json_object_string_addf(json, "advertisingRouter", "%pI4",
					&lsa->data->adv_router);
		json_object_string_add(json, "lsaSeqNumber", seqnum);
		json_object_string_add(json, "checksum", checksum);
		json_object_int_add(json, "length", ntohs(lsa->data->length));
	}
}

static const char *const link_type_desc[] = {
	"(null)",
	"another Router (point-to-point)",
	"a Transit Network",
	"Stub Network",
	"a Virtual Link",
};

static const char *const link_id_desc[] = {
	"(null)", "Neighboring Router ID", "Designated Router address",
	"Net",    "Neighboring Router ID",
};

static const char *const link_data_desc[] = {
	"(null)",       "Router Interface address", "Router Interface address",
	"Network Mask", "Router Interface address",
};

static const char *const link_id_desc_json[] = {
	"null",		  "neighborRouterId", "designatedRouterAddress",
	"networkAddress", "neighborRouterId",
};

static const char *const link_data_desc_json[] = {
	"null",	"routerInterfaceAddress", "routerInterfaceAddress",
	"networkMask", "routerInterfaceAddress",
};

/* Show router-LSA each Link information. */
static void show_ip_ospf_database_router_links(struct vty *vty,
					       struct router_lsa *rl,
					       json_object *json)
{
	int len, type;
	unsigned short i;
	json_object *json_links = NULL;
	json_object *json_link = NULL;
	int metric = 0;
	char buf[PREFIX_STRLEN];

	if (json)
		json_links = json_object_new_object();

	len = ntohs(rl->header.length) - 4;
	for (i = 0; i < ntohs(rl->links) && len > 0; len -= 12, i++) {
		type = rl->link[i].type;

		if (json) {
			char link[16];

			snprintf(link, sizeof(link), "link%u", i);
			json_link = json_object_new_object();
			json_object_string_add(json_link, "linkType",
					       link_type_desc[type]);
			json_object_string_add(json_link,
					       link_id_desc_json[type],
					       inet_ntop(AF_INET,
							 &rl->link[i].link_id,
							 buf, sizeof(buf)));
			json_object_string_add(
				json_link, link_data_desc_json[type],
				inet_ntop(AF_INET, &rl->link[i].link_data,
					  buf, sizeof(buf)));
			json_object_int_add(json_link, "numOfTosMetrics",
					    metric);
			json_object_int_add(json_link, "tos0Metric",
					    ntohs(rl->link[i].metric));
			json_object_object_add(json_links, link, json_link);
		} else {
			vty_out(vty, "    Link connected to: %s\n",
				link_type_desc[type]);
			vty_out(vty, "     (Link ID) %s: %pI4\n",
				link_id_desc[type],
				&rl->link[i].link_id);
			vty_out(vty, "     (Link Data) %s: %pI4\n",
				link_data_desc[type],
				&rl->link[i].link_data);
			vty_out(vty, "      Number of TOS metrics: 0\n");
			vty_out(vty, "       TOS 0 Metric: %d\n",
				ntohs(rl->link[i].metric));
			vty_out(vty, "\n");
		}
	}
	if (json)
		json_object_object_add(json, "routerLinks", json_links);
}

/* Show router-LSA detail information. */
static int show_router_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
				  json_object *json)
{
	if (lsa != NULL) {
		struct router_lsa *rl = (struct router_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa, json);

		if (!json)
			vty_out(vty, "   Number of Links: %d\n\n",
				ntohs(rl->links));
		else
			json_object_int_add(json, "numOfLinks",
					    ntohs(rl->links));

		show_ip_ospf_database_router_links(vty, rl, json);

		if (!json)
			vty_out(vty, "\n");
	}

	return 0;
}

/* Show network-LSA detail information. */
static int show_network_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
				   json_object *json)
{
	int length, i;
	char buf[PREFIX_STRLEN];
	json_object *json_attached_rt = NULL;
	json_object *json_router = NULL;

	if (json)
		json_attached_rt = json_object_new_object();

	if (lsa != NULL) {
		struct network_lsa *nl = (struct network_lsa *)lsa->data;
		struct in_addr *addr;

		show_ip_ospf_database_header(vty, lsa, json);

		if (!json)
			vty_out(vty, "  Network Mask: /%d\n",
				ip_masklen(nl->mask));
		else
			json_object_int_add(json, "networkMask",
					    ip_masklen(nl->mask));

		length = lsa->size - OSPF_LSA_HEADER_SIZE - 4;
		addr = &nl->routers[0];
		for (i = 0; length > 0 && addr;
		     length -= 4, addr = &nl->routers[++i])
			if (!json) {
				vty_out(vty, "        Attached Router: %pI4\n",
					addr);
				vty_out(vty, "\n");
			} else {
				json_router = json_object_new_object();
				json_object_string_add(
					json_router, "attachedRouterId",
					inet_ntop(AF_INET, addr, buf,
						  sizeof(buf)));
				json_object_object_add(json_attached_rt,
						       inet_ntop(AF_INET, addr,
								 buf,
								 sizeof(buf)),
						       json_router);
			}
	}

	if (json)
		json_object_object_add(json, "attchedRouters",
				       json_attached_rt);

	return 0;
}

/* Show summary-LSA detail information. */
static int show_summary_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
				   json_object *json)
{
	if (lsa != NULL) {
		struct summary_lsa *sl = (struct summary_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa, json);

		if (!json) {
			vty_out(vty, "  Network Mask: /%d\n",
				ip_masklen(sl->mask));
			vty_out(vty, "        TOS: 0  Metric: %d\n",
				GET_METRIC(sl->metric));
			vty_out(vty, "\n");
		} else {
			json_object_int_add(json, "networkMask",
					    ip_masklen(sl->mask));
			json_object_int_add(json, "tos0Metric",
					    GET_METRIC(sl->metric));
		}
	}

	return 0;
}

/* Show summary-ASBR-LSA detail information. */
static int show_summary_asbr_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
					json_object *json)
{
	if (lsa != NULL) {
		struct summary_lsa *sl = (struct summary_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa, json);

		if (!json) {
			vty_out(vty, "  Network Mask: /%d\n",
				ip_masklen(sl->mask));
			vty_out(vty, "        TOS: 0  Metric: %d\n",
				GET_METRIC(sl->metric));
			vty_out(vty, "\n");
		} else {
			json_object_int_add(json, "networkMask",
					    ip_masklen(sl->mask));
			json_object_int_add(json, "tos0Metric",
					    GET_METRIC(sl->metric));
		}
	}

	return 0;
}

/* Show AS-external-LSA detail information. */
static int show_as_external_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
				       json_object *json)
{
	int tos = 0;

	if (lsa != NULL) {
		struct as_external_lsa *al =
			(struct as_external_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa, json);

		if (!json) {
			vty_out(vty, "  Network Mask: /%d\n",
				ip_masklen(al->mask));
			vty_out(vty, "        Metric Type: %s\n",
				IS_EXTERNAL_METRIC(al->e[0].tos)
					? "2 (Larger than any link state path)"
					: "1");
			vty_out(vty, "        TOS: 0\n");
			vty_out(vty, "        Metric: %d\n",
				GET_METRIC(al->e[0].metric));
			vty_out(vty, "        Forward Address: %pI4\n",
				&al->e[0].fwd_addr);
			vty_out(vty,
				"        External Route Tag: %" ROUTE_TAG_PRI "\n\n",
				(route_tag_t)ntohl(al->e[0].route_tag));
		} else {
			json_object_int_add(json, "networkMask",
					    ip_masklen(al->mask));
			json_object_string_add(
				json, "metricType",
				IS_EXTERNAL_METRIC(al->e[0].tos)
					? "E2 (Larger than any link state path)"
					: "E1");
			json_object_int_add(json, "tos", tos);
			json_object_int_add(json, "metric",
					    GET_METRIC(al->e[0].metric));
			json_object_string_addf(json, "forwardAddress", "%pI4",
						&(al->e[0].fwd_addr));
			json_object_int_add(
				json, "externalRouteTag",
				(route_tag_t)ntohl(al->e[0].route_tag));
		}
	}

	return 0;
}

/* Show AS-NSSA-LSA detail information. */
static int show_as_nssa_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
				   json_object *json)
{
	int tos = 0;

	if (lsa != NULL) {
		struct as_external_lsa *al =
			(struct as_external_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa, json);

		if (!json) {
			vty_out(vty, "  Network Mask: /%d\n",
				ip_masklen(al->mask));
			vty_out(vty, "        Metric Type: %s\n",
				IS_EXTERNAL_METRIC(al->e[0].tos)
					? "2 (Larger than any link state path)"
					: "1");
			vty_out(vty, "        TOS: 0\n");
			vty_out(vty, "        Metric: %d\n",
				GET_METRIC(al->e[0].metric));
			vty_out(vty, "        NSSA: Forward Address: %pI4\n",
				&al->e[0].fwd_addr);
			vty_out(vty,
				"        External Route Tag: %" ROUTE_TAG_PRI
				"\n\n",
				(route_tag_t)ntohl(al->e[0].route_tag));
		} else {
			json_object_int_add(json, "networkMask",
					    ip_masklen(al->mask));
			json_object_string_add(
				json, "metricType",
				IS_EXTERNAL_METRIC(al->e[0].tos)
					? "E2 (Larger than any link state path)"
					: "E1");
			json_object_int_add(json, "tos", tos);
			json_object_int_add(json, "metric",
					    GET_METRIC(al->e[0].metric));
			json_object_string_addf(json, "nssaForwardAddress",
						"%pI4", &al->e[0].fwd_addr);
			json_object_int_add(
				json, "externalRouteTag",
				(route_tag_t)ntohl(al->e[0].route_tag));
		}
	}

	return 0;
}

static int show_func_dummy(struct vty *vty, struct ospf_lsa *lsa,
			   json_object *json)
{
	return 0;
}

static int show_opaque_lsa_detail(struct vty *vty, struct ospf_lsa *lsa,
				  json_object *json)
{
	if (lsa != NULL) {
		show_ip_ospf_database_header(vty, lsa, json);
		show_opaque_info_detail(vty, lsa, json);
		if (!json)
			vty_out(vty, "\n");
	}
	return 0;
}

int (*show_function[])(struct vty *, struct ospf_lsa *, json_object *) = {
	NULL,
	show_router_lsa_detail,
	show_network_lsa_detail,
	show_summary_lsa_detail,
	show_summary_asbr_lsa_detail,
	show_as_external_lsa_detail,
	show_func_dummy,
	show_as_nssa_lsa_detail, /* almost same as external */
	NULL,			 /* type-8 */
	show_opaque_lsa_detail,
	show_opaque_lsa_detail,
	show_opaque_lsa_detail,
};

static void show_lsa_prefix_set(struct vty *vty, struct prefix_ls *lp,
				struct in_addr *id, struct in_addr *adv_router)
{
	memset(lp, 0, sizeof(struct prefix_ls));
	lp->family = AF_UNSPEC;
	if (id == NULL)
		lp->prefixlen = 0;
	else if (adv_router == NULL) {
		lp->prefixlen = IPV4_MAX_BITLEN;
		lp->id = *id;
	} else {
		lp->prefixlen = 64;
		lp->id = *id;
		lp->adv_router = *adv_router;
	}
}

static void show_lsa_detail_proc(struct vty *vty, struct route_table *rt,
				 struct in_addr *id, struct in_addr *adv_router,
				 json_object *json)
{
	struct prefix_ls lp;
	struct route_node *rn, *start;
	struct ospf_lsa *lsa;
	json_object *json_lsa = NULL;

	show_lsa_prefix_set(vty, &lp, id, adv_router);
	start = route_node_get(rt, (struct prefix *)&lp);
	if (start) {
		route_lock_node(start);
		for (rn = start; rn; rn = route_next_until(rn, start))
			if ((lsa = rn->info)) {
				if (show_function[lsa->data->type] != NULL) {
					if (json) {
						json_lsa =
							json_object_new_object();
						json_object_array_add(json,
								      json_lsa);
					}

					show_function[lsa->data->type](
						vty, lsa, json_lsa);
				}
			}
		route_unlock_node(start);
	}
}

/* Show detail LSA information
   -- if id is NULL then show all LSAs. */
static void show_lsa_detail(struct vty *vty, struct ospf *ospf, int type,
			    struct in_addr *id, struct in_addr *adv_router,
			    json_object *json)
{
	struct listnode *node;
	struct ospf_area *area;
	char buf[PREFIX_STRLEN];
	json_object *json_lsa_type = NULL;
	json_object *json_areas = NULL;
	json_object *json_lsa_array = NULL;

	switch (type) {
	case OSPF_AS_EXTERNAL_LSA:
	case OSPF_OPAQUE_AS_LSA:
		if (!json)
			vty_out(vty, "                %s \n\n",
				show_database_desc[type]);
		else
			json_lsa_array = json_object_new_array();

		show_lsa_detail_proc(vty, AS_LSDB(ospf, type), id, adv_router,
				     json_lsa_array);
		if (json)
			json_object_object_add(json,
					       show_database_desc_json[type],
					       json_lsa_array);

		break;
	default:
		if (json)
			json_areas = json_object_new_object();

		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
			if (!json) {
				vty_out(vty,
					"\n                %s (Area %s)\n\n",
					show_database_desc[type],
					ospf_area_desc_string(area));
			} else {
				json_lsa_array = json_object_new_array();
				json_object_object_add(json_areas,
						       inet_ntop(AF_INET,
								 &area->area_id,
								 buf,
								 sizeof(buf)),
						       json_lsa_array);
			}

			show_lsa_detail_proc(vty, AREA_LSDB(area, type), id,
					     adv_router, json_lsa_array);
		}

		if (json) {
			json_lsa_type = json_object_new_object();
			json_object_object_add(json_lsa_type, "areas",
					       json_areas);
			json_object_object_add(json,
					       show_database_desc_json[type],
					       json_lsa_type);
		}
		break;
	}
}

static void show_lsa_detail_adv_router_proc(struct vty *vty,
					    struct route_table *rt,
					    struct in_addr *adv_router,
					    json_object *json)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;
	json_object *json_lsa = NULL;

	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((lsa = rn->info)) {
			if (IPV4_ADDR_SAME(adv_router,
					   &lsa->data->adv_router)) {
				if (CHECK_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT))
					continue;
				if (json) {
					json_lsa = json_object_new_object();
					json_object_array_add(json, json_lsa);
				}

				if (show_function[lsa->data->type] != NULL)
					show_function[lsa->data->type](
						vty, lsa, json_lsa);
			}
		}
}

/* Show detail LSA information. */
static void show_lsa_detail_adv_router(struct vty *vty, struct ospf *ospf,
				       int type, struct in_addr *adv_router,
				       json_object *json)
{
	struct listnode *node;
	struct ospf_area *area;
	char buf[PREFIX_STRLEN];
	json_object *json_lsa_type = NULL;
	json_object *json_areas = NULL;
	json_object *json_lsa_array = NULL;

	if (json)
		json_lsa_type = json_object_new_object();

	switch (type) {
	case OSPF_AS_EXTERNAL_LSA:
	case OSPF_OPAQUE_AS_LSA:
		if (!json)
			vty_out(vty, "                %s \n\n",
				show_database_desc[type]);
		else
			json_lsa_array = json_object_new_array();

		show_lsa_detail_adv_router_proc(vty, AS_LSDB(ospf, type),
						adv_router, json_lsa_array);
		if (json)
			json_object_object_add(json,
					       show_database_desc_json[type],
					       json_lsa_array);
		break;
	default:
		if (json)
			json_areas = json_object_new_object();

		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
			if (!json) {
				vty_out(vty,
					"\n                %s (Area %s)\n\n",
					show_database_desc[type],
					ospf_area_desc_string(area));
			} else {
				json_lsa_array = json_object_new_array();
				json_object_object_add(
					json_areas,
					inet_ntop(AF_INET, &area->area_id, buf,
						  sizeof(buf)),
					json_lsa_array);
			}

			show_lsa_detail_adv_router_proc(
				vty, AREA_LSDB(area, type), adv_router,
				json_lsa_array);
		}

		if (json) {
			json_object_object_add(json_lsa_type, "areas",
					       json_areas);
			json_object_object_add(json,
					       show_database_desc_json[type],
					       json_lsa_type);
		}
		break;
	}
}

void show_ip_ospf_database_summary(struct vty *vty, struct ospf *ospf, int self,
				   json_object *json)
{
	struct ospf_lsa *lsa;
	struct route_node *rn;
	struct ospf_area *area;
	struct listnode *node;
	char buf[PREFIX_STRLEN];
	json_object *json_areas = NULL;
	json_object *json_area = NULL;
	json_object *json_lsa = NULL;
	int type;
	json_object *json_lsa_array = NULL;
	uint32_t count;

	if (json)
		json_areas = json_object_new_object();

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		if (json)
			json_area = json_object_new_object();

		for (type = OSPF_MIN_LSA; type < OSPF_MAX_LSA; type++) {
			count = 0;
			switch (type) {
			case OSPF_AS_EXTERNAL_LSA:
			case OSPF_OPAQUE_AS_LSA:
				continue;
			default:
				break;
			}
			if (ospf_lsdb_count_self(area->lsdb, type) > 0
			    || (!self
				&& ospf_lsdb_count(area->lsdb, type) > 0)) {

				if (!json) {
					vty_out(vty,
						"                %s (Area %s)\n\n",
						show_database_desc[type],
						ospf_area_desc_string(area));
					vty_out(vty, "%s\n",
						show_database_header[type]);
				} else {
					json_lsa_array =
						json_object_new_array();
					json_object_object_add(
						json_area,
						show_database_desc_json[type],
						json_lsa_array);
				}

				LSDB_LOOP (AREA_LSDB(area, type), rn, lsa) {
					if (json) {
						json_lsa =
						json_object_new_object();
						json_object_array_add(
							json_lsa_array,
							json_lsa);
					}

					count += show_lsa_summary(
						vty, lsa, self, json_lsa);
				}

				if (!json)
					vty_out(vty, "\n");
				else
					json_object_int_add(
						json_area,

						show_database_desc_count_json
							[type],
						count);
			}
		}
		if (json)
			json_object_object_add(json_areas,
					       inet_ntop(AF_INET,
							 &area->area_id,
							 buf, sizeof(buf)),
					       json_area);
	}

	if (json)
		json_object_object_add(json, "areas", json_areas);

	for (type = OSPF_MIN_LSA; type < OSPF_MAX_LSA; type++) {
		count = 0;
		switch (type) {
		case OSPF_AS_EXTERNAL_LSA:
		case OSPF_OPAQUE_AS_LSA:
			break;
		default:
			continue;
		}
		if (ospf_lsdb_count_self(ospf->lsdb, type)
		    || (!self && ospf_lsdb_count(ospf->lsdb, type))) {
			if (!json) {
				vty_out(vty, "                %s\n\n",
					show_database_desc[type]);
				vty_out(vty, "%s\n",
					show_database_header[type]);
			} else {
				json_lsa_array = json_object_new_array();
				json_object_object_add(
					json, show_database_desc_json[type],
					json_lsa_array);
			}

			LSDB_LOOP (AS_LSDB(ospf, type), rn, lsa) {
				if (json) {
					json_lsa = json_object_new_object();
					json_object_array_add(json_lsa_array,
							      json_lsa);
				}

				count += show_lsa_summary(vty, lsa, self,
							  json_lsa);
			}

			if (!json)
				vty_out(vty, "\n");
			else
				json_object_int_add(
					json,
					show_database_desc_count_json[type],
					count);
		}
	}

	if (!json)
		vty_out(vty, "\n");
}

static void show_ip_ospf_database_maxage(struct vty *vty, struct ospf *ospf,
					 json_object *json)
{
	struct route_node *rn;
	char buf[PREFIX_STRLEN];
	json_object *json_maxage = NULL;

	if (!json)
		vty_out(vty, "\n                MaxAge Link States:\n\n");
	else
		json_maxage = json_object_new_object();

	for (rn = route_top(ospf->maxage_lsa); rn; rn = route_next(rn)) {
		struct ospf_lsa *lsa;
		json_object *json_lsa = NULL;

		if ((lsa = rn->info) != NULL) {
			if (!json) {
				vty_out(vty, "Link type: %d\n",
					lsa->data->type);
				vty_out(vty, "Link State ID: %pI4\n",
					&lsa->data->id);
				vty_out(vty, "Advertising Router: %pI4\n",
					&lsa->data->adv_router);
				vty_out(vty, "LSA lock count: %d\n", lsa->lock);
				vty_out(vty, "\n");
			} else {
				json_lsa = json_object_new_object();
				json_object_int_add(json_lsa, "linkType",
						    lsa->data->type);
				json_object_string_addf(json_lsa, "linkStateId",
							"%pI4", &lsa->data->id);
				json_object_string_addf(
					json_lsa, "advertisingRouter", "%pI4",
					&lsa->data->adv_router);
				json_object_int_add(json_lsa, "lsaLockCount",
						    lsa->lock);
				json_object_object_add(
					json_maxage,
					inet_ntop(AF_INET,
						  &lsa->data->id,
						  buf, sizeof(buf)),
					json_lsa);
			}
		}
	}
	if (json)
		json_object_object_add(json, "maxAgeLinkStates", json_maxage);
}

#define OSPF_LSA_TYPE_NSSA_DESC      "NSSA external link state\n"
#define OSPF_LSA_TYPE_NSSA_CMD_STR   "|nssa-external"

#define OSPF_LSA_TYPE_OPAQUE_LINK_DESC "Link local Opaque-LSA\n"
#define OSPF_LSA_TYPE_OPAQUE_AREA_DESC "Link area Opaque-LSA\n"
#define OSPF_LSA_TYPE_OPAQUE_AS_DESC   "Link AS Opaque-LSA\n"
#define OSPF_LSA_TYPE_OPAQUE_CMD_STR   "|opaque-link|opaque-area|opaque-as"

#define OSPF_LSA_TYPES_DESC                                                    \
	"ASBR summary link states\n"                                           \
	"External link states\n"                                               \
	"Network link states\n"                                                \
	"Router link states\n"                                                 \
	"Network summary link states\n" OSPF_LSA_TYPE_NSSA_DESC                \
		OSPF_LSA_TYPE_OPAQUE_LINK_DESC OSPF_LSA_TYPE_OPAQUE_AREA_DESC  \
			OSPF_LSA_TYPE_OPAQUE_AS_DESC

static int
show_ip_ospf_database_common(struct vty *vty, struct ospf *ospf, bool maxage,
			     bool self, bool detail, const char *type_name,
			     struct in_addr *lsid, struct in_addr *adv_router,
			     bool use_vrf, json_object *json, bool uj)
{
	int type;
	json_object *json_vrf = NULL;

	if (uj) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	if (ospf->instance) {
		if (uj)
			json_object_int_add(json_vrf, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	/* Show Router ID. */
	if (uj) {
		json_object_string_addf(json_vrf, "routerId", "%pI4",
					&ospf->router_id);
	} else {
		vty_out(vty, "\n       OSPF Router with ID (%pI4)\n\n",
			&ospf->router_id);
	}

	/* Show MaxAge LSAs */
	if (maxage) {
		show_ip_ospf_database_maxage(vty, ospf, json_vrf);
		if (json) {
			if (use_vrf) {
				if (ospf->vrf_id == VRF_DEFAULT)
					json_object_object_add(json, "default",
							       json_vrf);
				else
					json_object_object_add(json, ospf->name,
							       json_vrf);
			}
		}
		return CMD_SUCCESS;
	}

	/* Show all LSAs. */
	if (!type_name) {
		if (detail) {
			for (int i = OSPF_ROUTER_LSA; i <= OSPF_OPAQUE_AS_LSA;
			     i++) {
				switch (i) {
				case OSPF_GROUP_MEMBER_LSA:
				case OSPF_EXTERNAL_ATTRIBUTES_LSA:
					/* ignore deprecated LSA types */
					continue;
				default:
					break;
				}

				if (adv_router && !lsid)
					show_lsa_detail_adv_router(vty, ospf, i,
								   adv_router,
								   json_vrf);
				else
					show_lsa_detail(vty, ospf, i, lsid,
							adv_router, json_vrf);
			}
		} else
			show_ip_ospf_database_summary(vty, ospf, self,
						      json_vrf);

		if (json) {
			if (use_vrf) {
				if (ospf->vrf_id == VRF_DEFAULT)
					json_object_object_add(json, "default",
							       json_vrf);
				else
					json_object_object_add(json, ospf->name,
							       json_vrf);
			}
		}
		return CMD_SUCCESS;
	}

	/* Set database type to show. */
	if (strncmp(type_name, "r", 1) == 0)
		type = OSPF_ROUTER_LSA;
	else if (strncmp(type_name, "ne", 2) == 0)
		type = OSPF_NETWORK_LSA;
	else if (strncmp(type_name, "ns", 2) == 0)
		type = OSPF_AS_NSSA_LSA;
	else if (strncmp(type_name, "su", 2) == 0)
		type = OSPF_SUMMARY_LSA;
	else if (strncmp(type_name, "a", 1) == 0)
		type = OSPF_ASBR_SUMMARY_LSA;
	else if (strncmp(type_name, "e", 1) == 0)
		type = OSPF_AS_EXTERNAL_LSA;
	else if (strncmp(type_name, "opaque-l", 8) == 0)
		type = OSPF_OPAQUE_LINK_LSA;
	else if (strncmp(type_name, "opaque-ar", 9) == 0)
		type = OSPF_OPAQUE_AREA_LSA;
	else if (strncmp(type_name, "opaque-as", 9) == 0)
		type = OSPF_OPAQUE_AS_LSA;
	else {
		if (uj) {
			if (use_vrf)
				json_object_free(json_vrf);
		}
		return CMD_WARNING;
	}

	if (adv_router && !lsid)
		show_lsa_detail_adv_router(vty, ospf, type, adv_router,
					   json_vrf);
	else
		show_lsa_detail(vty, ospf, type, lsid, adv_router, json_vrf);

	if (json) {
		if (use_vrf) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
						       json_vrf);
		}
	}

	return CMD_SUCCESS;
}

DEFPY (show_ip_ospf_database,
       show_ip_ospf_database_cmd,
       "show ip ospf [(1-65535)$instance_id] [vrf <NAME|all>$vrf_name] database\
         [<\
	   max-age$maxage\
	   |self-originate$selforig\
	   |<\
	     detail$detail\
             |<asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as>$type_name\
	    >\
	    [{\
	      A.B.C.D$lsid\
	      |<adv-router A.B.C.D$adv_router|self-originate$adv_router_self>\
	    }]\
	 >]\
	 [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Database summary\n"
       "LSAs in MaxAge list\n"
       "Self-originated link states\n"
       "Show detailed information\n"
       OSPF_LSA_TYPES_DESC
       "Link State ID (as an IP address)\n"
       "Advertising Router link states\n"
       "Advertising Router (as an IP address)\n"
       "Self-originated link states\n"
       JSON_STR)
{
	struct ospf *ospf;
	int ret = CMD_SUCCESS;
	bool use_vrf = !!vrf_name;
	bool uj = use_json(argc, argv);
	struct in_addr *lsid_p = NULL;
	struct in_addr *adv_router_p = NULL;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();
	if (lsid_str)
		lsid_p = &lsid;
	if (adv_router_str)
		adv_router_p = &adv_router;

	if (vrf_name && strmatch(vrf_name, "all")) {
		struct listnode *node;
		bool ospf_output = false;

		for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
			if (!ospf->oi_running)
				continue;
			if (ospf->instance != instance_id)
				continue;

			if (adv_router_self)
				adv_router_p = &ospf->router_id;

			ospf_output = true;
			ret = show_ip_ospf_database_common(
				vty, ospf, !!maxage, !!selforig, !!detail,
				type_name, lsid_p, adv_router_p, use_vrf, json,
				uj);
		}

		if (!ospf_output && !uj)
			vty_out(vty, "%% OSPF is not enabled\n");
	} else {
		if (!vrf_name)
			vrf_name = VRF_DEFAULT_NAME;
		ospf = ospf_lookup_by_inst_name(instance_id, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}
		if (adv_router_self)
			adv_router_p = &ospf->router_id;

		ret = (show_ip_ospf_database_common(
			vty, ospf, !!maxage, !!selforig, !!detail, type_name,
			lsid_p, adv_router_p, use_vrf, json, uj));
	}

	if (uj)
		vty_json(vty, json);

	return ret;
}

DEFUN (ip_ospf_authentication_args,
       ip_ospf_authentication_args_addr_cmd,
       "ip ospf authentication <null|message-digest|key-chain KEYCHAIN_NAME> [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable authentication on this interface\n"
       "Use null authentication\n"
       "Use message-digest authentication\n"
	   "Use a key-chain for cryptographic authentication keys\n"
	   "Key-chain name\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_encryption = 3;
	int idx_ipv4 = argc-1;
	struct in_addr addr;
	int ret;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (argv[idx_ipv4]->type == IPV4_TKN) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	/* Handle null authentication */
	if (argv[idx_encryption]->arg[0] == 'n') {
		SET_IF_PARAM(params, auth_type);
		params->auth_type = OSPF_AUTH_NULL;
		return CMD_SUCCESS;
	}

	/* Handle message-digest authentication */
	if (argv[idx_encryption]->arg[0] == 'm') {
		SET_IF_PARAM(params, auth_type);
		params->auth_type = OSPF_AUTH_CRYPTOGRAPHIC;
		UNSET_IF_PARAM(params, keychain_name);
		XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
		return CMD_SUCCESS;
	}

	if (argv[idx_encryption]->arg[0] == 'k') {
		SET_IF_PARAM(params, auth_type);
		params->auth_type = OSPF_AUTH_CRYPTOGRAPHIC;
		SET_IF_PARAM(params, keychain_name);
		params->keychain_name = XSTRDUP(MTYPE_OSPF_IF_PARAMS, argv[idx_encryption+1]->arg);
		UNSET_IF_PARAM(params, auth_crypt);
		return CMD_SUCCESS;
	}

	vty_out(vty, "You shouldn't get here!\n");
	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (ip_ospf_authentication,
       ip_ospf_authentication_addr_cmd,
       "ip ospf authentication [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable authentication on this interface\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = 3;
	struct in_addr addr;
	int ret;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (argc == 4) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	SET_IF_PARAM(params, auth_type);
	params->auth_type = OSPF_AUTH_SIMPLE;

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_authentication_args,
       no_ip_ospf_authentication_args_addr_cmd,
       "no ip ospf authentication <null|message-digest|key-chain [KEYCHAIN_NAME]> [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable authentication on this interface\n"
       "Use null authentication\n"
       "Use message-digest authentication\n"
	   "Use a key-chain for cryptographic authentication keys\n"
	   "Key-chain name\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_encryption = 4;
	int idx_ipv4 = argc-1;
	struct in_addr addr;
	int ret;
	struct ospf_if_params *params;
	struct route_node *rn;
	int auth_type;

	params = IF_DEF_PARAMS(ifp);

	if (argv[idx_ipv4]->type == IPV4_TKN) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL) {
			vty_out(vty, "Ip Address specified is unknown\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params->auth_type = OSPF_AUTH_NOTSET;
		UNSET_IF_PARAM(params, auth_type);

		XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
		UNSET_IF_PARAM(params, keychain_name);

		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, addr);
			ospf_if_update_params(ifp, addr);
		}
	} else {
		if (argv[idx_encryption]->arg[0] == 'n') {
			auth_type = OSPF_AUTH_NULL;
		} else if (argv[idx_encryption]->arg[0] == 'm' ||
				   argv[idx_encryption]->arg[0] == 'k') {
			auth_type = OSPF_AUTH_CRYPTOGRAPHIC;
		} else {
			vty_out(vty, "Unexpected input encountered\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		/*
		 * Here we have a case where the user has entered
		 * 'no ip ospf authentication (null | message_digest )'
		 * we need to find if we have any ip addresses underneath it
		 * that
		 * correspond to the associated type.
		 */
		if (params->auth_type == auth_type) {
			params->auth_type = OSPF_AUTH_NOTSET;
			UNSET_IF_PARAM(params, auth_type);
			XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
			UNSET_IF_PARAM(params, keychain_name);
		}

		for (rn = route_top(IF_OIFS_PARAMS(ifp)); rn;
		     rn = route_next(rn)) {
			if ((params = rn->info)) {
				if (params->auth_type == auth_type) {
					params->auth_type = OSPF_AUTH_NOTSET;
					UNSET_IF_PARAM(params, auth_type);
					XFREE(MTYPE_OSPF_IF_PARAMS, params->keychain_name);
					UNSET_IF_PARAM(params, keychain_name);
					if (params != IF_DEF_PARAMS(ifp)) {
						ospf_free_if_params(
							ifp, rn->p.u.prefix4);
						ospf_if_update_params(
							ifp, rn->p.u.prefix4);
					}
				}
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_authentication,
       no_ip_ospf_authentication_addr_cmd,
       "no ip ospf authentication [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable authentication on this interface\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = 4;
	struct in_addr addr;
	int ret;
	struct ospf_if_params *params;
	struct route_node *rn;

	params = IF_DEF_PARAMS(ifp);

	if (argc == 5) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL) {
			vty_out(vty, "Ip Address specified is unknown\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params->auth_type = OSPF_AUTH_NOTSET;
		UNSET_IF_PARAM(params, auth_type);
		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, addr);
			ospf_if_update_params(ifp, addr);
		}
	} else {
		/*
		 * When a user enters 'no ip ospf authentication'
		 * We should remove all authentication types from
		 * the interface.
		 */
		if ((params->auth_type == OSPF_AUTH_NULL)
		    || (params->auth_type == OSPF_AUTH_CRYPTOGRAPHIC)
		    || (params->auth_type == OSPF_AUTH_SIMPLE)) {
			params->auth_type = OSPF_AUTH_NOTSET;
			UNSET_IF_PARAM(params, auth_type);
		}

		for (rn = route_top(IF_OIFS_PARAMS(ifp)); rn;
		     rn = route_next(rn)) {
			if ((params = rn->info)) {

				if ((params->auth_type == OSPF_AUTH_NULL)
				    || (params->auth_type
					== OSPF_AUTH_CRYPTOGRAPHIC)
				    || (params->auth_type
					== OSPF_AUTH_SIMPLE)) {
					params->auth_type = OSPF_AUTH_NOTSET;
					UNSET_IF_PARAM(params, auth_type);
					if (params != IF_DEF_PARAMS(ifp)) {
						ospf_free_if_params(
							ifp, rn->p.u.prefix4);
						ospf_if_update_params(
							ifp, rn->p.u.prefix4);
					}
				}
			}
		}
	}

	return CMD_SUCCESS;
}


DEFUN (ip_ospf_authentication_key,
       ip_ospf_authentication_key_addr_cmd,
       "ip ospf authentication-key AUTH_KEY [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Authentication password (key)\n"
       "The OSPF password (key)\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	strlcpy((char *)params->auth_simple, argv[3]->arg,
		sizeof(params->auth_simple));
	SET_IF_PARAM(params, auth_simple);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_authentication_key,
              ospf_authentication_key_cmd,
              "ospf authentication-key AUTH_KEY [A.B.C.D]",
              "OSPF interface commands\n"
              VLINK_HELPSTR_AUTH_SIMPLE
              "Address of interface\n")
{
	return ip_ospf_authentication_key(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_authentication_key,
       no_ip_ospf_authentication_key_authkey_addr_cmd,
       "no ip ospf authentication-key [AUTH_KEY [A.B.C.D]]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       VLINK_HELPSTR_AUTH_SIMPLE
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr;
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	memset(params->auth_simple, 0, OSPF_AUTH_SIMPLE_SIZE);
	UNSET_IF_PARAM(params, auth_simple);

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_authentication_key,
              no_ospf_authentication_key_authkey_addr_cmd,
              "no ospf authentication-key [AUTH_KEY [A.B.C.D]]",
              NO_STR
              "OSPF interface commands\n"
              VLINK_HELPSTR_AUTH_SIMPLE
	      "Address of interface\n")
{
	return no_ip_ospf_authentication_key(self, vty, argc, argv);
}

DEFUN (ip_ospf_message_digest_key,
       ip_ospf_message_digest_key_cmd,
       "ip ospf message-digest-key (1-255) md5 KEY [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct crypt_key *ck;
	uint8_t key_id;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);
	int idx = 0;

	argv_find(argv, argc, "(1-255)", &idx);
	char *keyid = argv[idx]->arg;
	argv_find(argv, argc, "KEY", &idx);
	char *cryptkey = argv[idx]->arg;

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	key_id = strtol(keyid, NULL, 10);

	/* Remove existing key, if any */
	ospf_crypt_key_delete(params->auth_crypt, key_id);

	ck = ospf_crypt_key_new();
	ck->key_id = (uint8_t)key_id;
	strlcpy((char *)ck->auth_key, cryptkey, sizeof(ck->auth_key));

	ospf_crypt_key_add(params->auth_crypt, ck);
	SET_IF_PARAM(params, auth_crypt);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_message_digest_key,
              ospf_message_digest_key_cmd,
              "ospf message-digest-key (1-255) md5 KEY [A.B.C.D]",
              "OSPF interface commands\n"
              "Message digest authentication password (key)\n"
              "Key ID\n"
              "Use MD5 algorithm\n"
              "The OSPF password (key)\n"
              "Address of interface\n")
{
	return ip_ospf_message_digest_key(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_message_digest_key,
       no_ip_ospf_message_digest_key_cmd,
       "no ip ospf message-digest-key (1-255) [md5 KEY] [A.B.C.D]",
        NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Message digest authentication password (key)\n"
       "Key ID\n"
       "Use MD5 algorithm\n"
       "The OSPF password (key)\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct crypt_key *ck;
	int key_id;
	struct in_addr addr;
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	argv_find(argv, argc, "(1-255)", &idx);
	char *keyid = argv[idx]->arg;

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	key_id = strtol(keyid, NULL, 10);
	ck = ospf_crypt_key_lookup(params->auth_crypt, key_id);
	if (ck == NULL) {
		vty_out(vty, "OSPF: Key %d does not exist\n", key_id);
		return CMD_WARNING_CONFIG_FAILED;
	}

	ospf_crypt_key_delete(params->auth_crypt, key_id);

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_message_digest_key,
              no_ospf_message_digest_key_cmd,
              "no ospf message-digest-key (1-255) [md5 KEY] [A.B.C.D]",
              NO_STR
              "OSPF interface commands\n"
              "Message digest authentication password (key)\n"
              "Key ID\n"
              "Use MD5 algorithm\n"
              "The OSPF password (key)\n"
              "Address of interface\n")
{
	return no_ip_ospf_message_digest_key(self, vty, argc, argv);
}

DEFUN (ip_ospf_cost,
       ip_ospf_cost_cmd,
       "ip ospf cost (1-65535) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Interface cost\n"
       "Cost\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	uint32_t cost = OSPF_OUTPUT_COST_DEFAULT;
	struct in_addr addr;
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	// get arguments
	char *coststr = NULL, *ifaddr = NULL;

	argv_find(argv, argc, "(1-65535)", &idx);
	coststr = argv[idx]->arg;
	cost = strtol(coststr, NULL, 10);

	ifaddr = argv_find(argv, argc, "A.B.C.D", &idx) ? argv[idx]->arg : NULL;
	if (ifaddr) {
		if (!inet_aton(ifaddr, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	SET_IF_PARAM(params, output_cost_cmd);
	params->output_cost_cmd = cost;

	ospf_if_recalculate_output_cost(ifp);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_cost,
              ospf_cost_cmd,
              "ospf cost (1-65535) [A.B.C.D]",
              "OSPF interface commands\n"
              "Interface cost\n"
              "Cost\n"
              "Address of interface\n")
{
	return ip_ospf_cost(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_cost,
       no_ip_ospf_cost_cmd,
       "no ip ospf cost [(1-65535)] [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Interface cost\n"
       "Cost\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	// get arguments
	char *ifaddr = NULL;
	ifaddr = argv_find(argv, argc, "A.B.C.D", &idx) ? argv[idx]->arg : NULL;

	/* According to the semantics we are mimicking "no ip ospf cost N" is
	 * always treated as "no ip ospf cost" regardless of the actual value
	 * of N already configured for the interface. Thus ignore cost. */

	if (ifaddr) {
		if (!inet_aton(ifaddr, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	UNSET_IF_PARAM(params, output_cost_cmd);

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	ospf_if_recalculate_output_cost(ifp);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_cost,
              no_ospf_cost_cmd,
              "no ospf cost [(1-65535)] [A.B.C.D]",
              NO_STR
              "OSPF interface commands\n"
              "Interface cost\n"
              "Cost\n"
              "Address of interface\n")
{
	return no_ip_ospf_cost(self, vty, argc, argv);
}

static void ospf_nbr_timer_update(struct ospf_interface *oi)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		nbr = rn->info;

		if (!nbr)
			continue;

		nbr->v_inactivity = OSPF_IF_PARAM(oi, v_wait);
		nbr->v_db_desc = OSPF_IF_PARAM(oi, retransmit_interval);
		nbr->v_ls_req = OSPF_IF_PARAM(oi, retransmit_interval);
		nbr->v_ls_rxmt = OSPF_IF_PARAM(oi, retransmit_interval);
	}
}

static int ospf_vty_dead_interval_set(struct vty *vty, const char *interval_str,
				      const char *nbr_str,
				      const char *fast_hello_str)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	uint32_t seconds;
	uint8_t hellomult;
	struct in_addr addr = { INADDR_ANY };
	int ret;
	struct ospf_if_params *params;
	struct ospf_interface *oi;
	struct route_node *rn;

	params = IF_DEF_PARAMS(ifp);

	if (nbr_str) {
		ret = inet_aton(nbr_str, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	if (interval_str) {
		seconds = strtoul(interval_str, NULL, 10);

		/* reset fast_hello too, just to be sure */
		UNSET_IF_PARAM(params, fast_hello);
		params->fast_hello = OSPF_FAST_HELLO_DEFAULT;
	} else if (fast_hello_str) {
		hellomult = strtoul(fast_hello_str, NULL, 10);
		/* 1s dead-interval with sub-second hellos desired */
		seconds = OSPF_ROUTER_DEAD_INTERVAL_MINIMAL;
		SET_IF_PARAM(params, fast_hello);
		params->fast_hello = hellomult;
	} else {
		vty_out(vty,
			"Please specify dead-interval or hello-multiplier\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	SET_IF_PARAM(params, v_wait);
	params->v_wait = seconds;
	params->is_v_wait_set = true;

	/* Update timer values in neighbor structure. */
	if (nbr_str) {
		struct ospf *ospf = NULL;

		ospf = ifp->vrf->info;
		if (ospf) {
			oi = ospf_if_lookup_by_local_addr(ospf, ifp, addr);
			if (oi)
				ospf_nbr_timer_update(oi);
		}
	} else {
		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn))
			if ((oi = rn->info))
				ospf_nbr_timer_update(oi);
	}

	if (params->fast_hello != OSPF_FAST_HELLO_DEFAULT)
		ospf_reset_hello_timer(ifp, addr, false);
	return CMD_SUCCESS;
}

DEFUN (ip_ospf_dead_interval,
       ip_ospf_dead_interval_cmd,
       "ip ospf dead-interval (1-65535) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Interval time after which a neighbor is declared down\n"
       "Seconds\n"
       "Address of interface\n")
{
	int idx = 0;
	char *interval = argv_find(argv, argc, "(1-65535)", &idx)
				 ? argv[idx]->arg
				 : NULL;
	char *ifaddr =
		argv_find(argv, argc, "A.B.C.D", &idx) ? argv[idx]->arg : NULL;
	return ospf_vty_dead_interval_set(vty, interval, ifaddr, NULL);
}


DEFUN_HIDDEN (ospf_dead_interval,
              ospf_dead_interval_cmd,
              "ospf dead-interval (1-65535) [A.B.C.D]",
              "OSPF interface commands\n"
              "Interval time after which a neighbor is declared down\n"
              "Seconds\n"
              "Address of interface\n")
{
	return ip_ospf_dead_interval(self, vty, argc, argv);
}

DEFUN (ip_ospf_dead_interval_minimal,
       ip_ospf_dead_interval_minimal_addr_cmd,
       "ip ospf dead-interval minimal hello-multiplier (2-20) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Interval time after which a neighbor is declared down\n"
       "Minimal 1s dead-interval with fast sub-second hellos\n"
       "Hello multiplier factor\n"
       "Number of Hellos to send each second\n"
       "Address of interface\n")
{
	int idx_number = 5;
	int idx_ipv4 = 6;
	if (argc == 7)
		return ospf_vty_dead_interval_set(
			vty, NULL, argv[idx_ipv4]->arg, argv[idx_number]->arg);
	else
		return ospf_vty_dead_interval_set(vty, NULL, NULL,
						  argv[idx_number]->arg);
}

DEFUN (no_ip_ospf_dead_interval,
       no_ip_ospf_dead_interval_cmd,
       "no ip ospf dead-interval [<(1-65535)|minimal hello-multiplier [(2-20)]> [A.B.C.D]]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Interval time after which a neighbor is declared down\n"
       "Seconds\n"
       "Minimal 1s dead-interval with fast sub-second hellos\n"
       "Hello multiplier factor\n"
       "Number of Hellos to send each second\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = argc - 1;
	struct in_addr addr = {.s_addr = 0L};
	int ret;
	struct ospf_if_params *params;
	struct ospf_interface *oi;
	struct route_node *rn;

	params = IF_DEF_PARAMS(ifp);

	if (argv[idx_ipv4]->type == IPV4_TKN) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	UNSET_IF_PARAM(params, v_wait);
	params->v_wait = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
	params->is_v_wait_set = false;

	UNSET_IF_PARAM(params, fast_hello);
	params->fast_hello = OSPF_FAST_HELLO_DEFAULT;

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	/* Update timer values in neighbor structure. */
	if (argc == 1) {
		struct ospf *ospf = NULL;

		ospf = ifp->vrf->info;
		if (ospf) {
			oi = ospf_if_lookup_by_local_addr(ospf, ifp, addr);
			if (oi)
				ospf_nbr_timer_update(oi);
		}
	} else {
		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn))
			if ((oi = rn->info))
				ospf_nbr_timer_update(oi);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_dead_interval,
              no_ospf_dead_interval_cmd,
              "no ospf dead-interval [<(1-65535)|minimal hello-multiplier (2-20)> [A.B.C.D]]",
              NO_STR
              "OSPF interface commands\n"
              "Interval time after which a neighbor is declared down\n"
              "Seconds\n"
              "Minimal 1s dead-interval with fast sub-second hellos\n"
              "Hello multiplier factor\n"
              "Number of Hellos to send each second\n"
              "Address of interface\n")
{
	return no_ip_ospf_dead_interval(self, vty, argc, argv);
}

DEFUN (ip_ospf_hello_interval,
       ip_ospf_hello_interval_cmd,
       "ip ospf hello-interval (1-65535) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between HELLO packets\n"
       "Seconds\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr = {.s_addr = 0L};
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);
	uint32_t seconds = 0;
	bool is_addr = false;
	uint32_t old_interval = 0;

	argv_find(argv, argc, "(1-65535)", &idx);
	seconds = strtol(argv[idx]->arg, NULL, 10);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
		is_addr = true;
	}

	old_interval = params->v_hello;

	/* Return, if same interval is configured. */
	if (old_interval == seconds)
		return CMD_SUCCESS;

	SET_IF_PARAM(params, v_hello);
	params->v_hello = seconds;

	if (!params->is_v_wait_set) {
		SET_IF_PARAM(params, v_wait);
		/* As per RFC 4062
		 * The router dead interval should
		 * be some multiple of the HelloInterval (perhaps 4 times the
		 * hello interval) and must be the same for all routers
		 * attached to a common network.
		 */
		params->v_wait	= 4 * seconds;
	}

	ospf_reset_hello_timer(ifp, addr, is_addr);

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_hello_interval,
              ospf_hello_interval_cmd,
              "ospf hello-interval (1-65535) [A.B.C.D]",
              "OSPF interface commands\n"
              "Time between HELLO packets\n"
              "Seconds\n"
              "Address of interface\n")
{
	return ip_ospf_hello_interval(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_hello_interval,
       no_ip_ospf_hello_interval_cmd,
       "no ip ospf hello-interval [(1-65535) [A.B.C.D]]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between HELLO packets\n" // ignored
       "Seconds\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr = {.s_addr = 0L};
	struct ospf_if_params *params;
	struct route_node *rn;

	params = IF_DEF_PARAMS(ifp);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	UNSET_IF_PARAM(params, v_hello);
	params->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;

	if (!params->is_v_wait_set) {
		UNSET_IF_PARAM(params, v_wait);
		params->v_wait  = OSPF_ROUTER_DEAD_INTERVAL_DEFAULT;
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->type = IF_DEF_PARAMS(ifp)->type;
		oi->ptp_dmvpn = IF_DEF_PARAMS(ifp)->ptp_dmvpn;

		if (oi->state > ISM_Down) {
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
		}
	}

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_hello_interval,
              no_ospf_hello_interval_cmd,
              "no ospf hello-interval [(1-65535) [A.B.C.D]]",
              NO_STR
              "OSPF interface commands\n"
              "Time between HELLO packets\n" // ignored
              "Seconds\n"
              "Address of interface\n")
{
	return no_ip_ospf_hello_interval(self, vty, argc, argv);
}

DEFUN(ip_ospf_network, ip_ospf_network_cmd,
      "ip ospf network <broadcast|"
      "non-broadcast|"
      "point-to-multipoint [delay-reflood|non-broadcast]|"
      "point-to-point [dmvpn]>",
      "IP Information\n"
      "OSPF interface commands\n"
      "Network type\n"
      "Specify OSPF broadcast multi-access network\n"
      "Specify OSPF NBMA network\n"
      "Specify OSPF point-to-multipoint network\n"
      "Specify OSPF delayed reflooding of LSAs received on P2MP interface\n"
      "Specify OSPF point-to-multipoint network doesn't support broadcast\n"
      "Specify OSPF point-to-point network\n"
      "Specify OSPF point-to-point DMVPN network\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	int old_type = IF_DEF_PARAMS(ifp)->type;
	uint8_t old_ptp_dmvpn = IF_DEF_PARAMS(ifp)->ptp_dmvpn;
	uint8_t old_p2mp_delay_reflood = IF_DEF_PARAMS(ifp)->p2mp_delay_reflood;
	uint8_t old_p2mp_non_broadcast = IF_DEF_PARAMS(ifp)->p2mp_non_broadcast;
	struct route_node *rn;

	if (old_type == OSPF_IFTYPE_LOOPBACK) {
		vty_out(vty,
			"This is a loopback interface. Can't set network type.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	IF_DEF_PARAMS(ifp)->ptp_dmvpn = 0;
	IF_DEF_PARAMS(ifp)->p2mp_delay_reflood =
		OSPF_P2MP_DELAY_REFLOOD_DEFAULT;
	IF_DEF_PARAMS(ifp)->p2mp_non_broadcast = OSPF_P2MP_NON_BROADCAST_DEFAULT;

	if (argv_find(argv, argc, "broadcast", &idx))
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_BROADCAST;
	else if (argv_find(argv, argc, "point-to-multipoint", &idx)) {
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_POINTOMULTIPOINT;
		if (argv_find(argv, argc, "delay-reflood", &idx))
			IF_DEF_PARAMS(ifp)->p2mp_delay_reflood = true;
		if (argv_find(argv, argc, "non-broadcast", &idx))
			IF_DEF_PARAMS(ifp)->p2mp_non_broadcast = true;
	} else if (argv_find(argv, argc, "non-broadcast", &idx))
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_NBMA;
	else if (argv_find(argv, argc, "point-to-point", &idx)) {
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_POINTOPOINT;
		if (argv_find(argv, argc, "dmvpn", &idx))
			IF_DEF_PARAMS(ifp)->ptp_dmvpn = 1;
	}

	IF_DEF_PARAMS(ifp)->type_cfg = true;

	if (IF_DEF_PARAMS(ifp)->type == old_type &&
	    IF_DEF_PARAMS(ifp)->ptp_dmvpn == old_ptp_dmvpn &&
	    IF_DEF_PARAMS(ifp)->p2mp_delay_reflood == old_p2mp_delay_reflood &&
	    IF_DEF_PARAMS(ifp)->p2mp_non_broadcast == old_p2mp_non_broadcast)
		return CMD_SUCCESS;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), type);

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->type = IF_DEF_PARAMS(ifp)->type;
		oi->ptp_dmvpn = IF_DEF_PARAMS(ifp)->ptp_dmvpn;
		oi->p2mp_delay_reflood = IF_DEF_PARAMS(ifp)->p2mp_delay_reflood;
		oi->p2mp_non_broadcast = IF_DEF_PARAMS(ifp)->p2mp_non_broadcast;

		/*
		 * The OSPF interface only needs to be flapped if the network
		 * type or DMVPN parameter changes.
		 */
		if (IF_DEF_PARAMS(ifp)->type != old_type ||
		    IF_DEF_PARAMS(ifp)->ptp_dmvpn != old_ptp_dmvpn ||
		    IF_DEF_PARAMS(ifp)->p2mp_non_broadcast !=
			    old_p2mp_non_broadcast) {
			if (oi->state > ISM_Down) {
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_network,
              ospf_network_cmd,
              "ospf network <broadcast|non-broadcast|point-to-multipoint|point-to-point>",
              "OSPF interface commands\n"
              "Network type\n"
              "Specify OSPF broadcast multi-access network\n"
              "Specify OSPF NBMA network\n"
              "Specify OSPF point-to-multipoint network\n"
              "Specify OSPF point-to-point network\n")
{
	return ip_ospf_network(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_network,
       no_ip_ospf_network_cmd,
       "no ip ospf network [<broadcast|non-broadcast|point-to-multipoint|point-to-point>]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Network type\n"
       "Specify OSPF broadcast multi-access network\n"
       "Specify OSPF NBMA network\n"
       "Specify OSPF point-to-multipoint network\n"
       "Specify OSPF point-to-point network\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int old_type = IF_DEF_PARAMS(ifp)->type;
	struct route_node *rn;

	IF_DEF_PARAMS(ifp)->type = ospf_default_iftype(ifp);
	IF_DEF_PARAMS(ifp)->type_cfg = false;
	IF_DEF_PARAMS(ifp)->ptp_dmvpn = 0;
	IF_DEF_PARAMS(ifp)->p2mp_delay_reflood =
		OSPF_P2MP_DELAY_REFLOOD_DEFAULT;
	IF_DEF_PARAMS(ifp)->p2mp_non_broadcast = OSPF_P2MP_NON_BROADCAST_DEFAULT;

	if (IF_DEF_PARAMS(ifp)->type == old_type)
		return CMD_SUCCESS;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->type = IF_DEF_PARAMS(ifp)->type;
		oi->ptp_dmvpn = IF_DEF_PARAMS(ifp)->ptp_dmvpn;
		oi->p2mp_delay_reflood = IF_DEF_PARAMS(ifp)->p2mp_delay_reflood;

		if (oi->state > ISM_Down) {
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
		}
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_network,
              no_ospf_network_cmd,
              "no ospf network [<broadcast|non-broadcast|point-to-multipoint|point-to-point>]",
              NO_STR
              "OSPF interface commands\n"
              "Network type\n"
              "Specify OSPF broadcast multi-access network\n"
              "Specify OSPF NBMA network\n"
              "Specify OSPF point-to-multipoint network\n"
              "Specify OSPF point-to-point network\n")
{
	return no_ip_ospf_network(self, vty, argc, argv);
}

DEFUN (ip_ospf_priority,
       ip_ospf_priority_cmd,
       "ip ospf priority (0-255) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Router priority\n"
       "Priority\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	long priority;
	struct route_node *rn;
	struct in_addr addr;
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	argv_find(argv, argc, "(0-255)", &idx);
	priority = strtol(argv[idx]->arg, NULL, 10);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	SET_IF_PARAM(params, priority);
	params->priority = priority;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		if (PRIORITY(oi) != OSPF_IF_PARAM(oi, priority)) {
			PRIORITY(oi) = OSPF_IF_PARAM(oi, priority);
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);
		}
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_priority,
              ospf_priority_cmd,
              "ospf priority (0-255) [A.B.C.D]",
              "OSPF interface commands\n"
              "Router priority\n"
              "Priority\n"
              "Address of interface\n")
{
	return ip_ospf_priority(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_priority,
       no_ip_ospf_priority_cmd,
       "no ip ospf priority [(0-255) [A.B.C.D]]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Router priority\n" // ignored
       "Priority\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct route_node *rn;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	UNSET_IF_PARAM(params, priority);
	params->priority = OSPF_ROUTER_PRIORITY_DEFAULT;

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		if (PRIORITY(oi) != OSPF_IF_PARAM(oi, priority)) {
			PRIORITY(oi) = OSPF_IF_PARAM(oi, priority);
			OSPF_ISM_EVENT_SCHEDULE(oi, ISM_NeighborChange);
		}
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_priority,
              no_ospf_priority_cmd,
              "no ospf priority [(0-255) [A.B.C.D]]",
              NO_STR
              "OSPF interface commands\n"
              "Router priority\n"
              "Priority\n"
              "Address of interface\n")
{
	return no_ip_ospf_priority(self, vty, argc, argv);
}

DEFUN (ip_ospf_retransmit_interval,
       ip_ospf_retransmit_interval_addr_cmd,
       "ip ospf retransmit-interval (1-65535) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	uint32_t seconds;
	struct in_addr addr;
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	argv_find(argv, argc, "(1-65535)", &idx);
	seconds = strtol(argv[idx]->arg, NULL, 10);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	SET_IF_PARAM(params, retransmit_interval);
	params->retransmit_interval = seconds;

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_retransmit_interval,
              ospf_retransmit_interval_cmd,
              "ospf retransmit-interval (1-65535) [A.B.C.D]",
              "OSPF interface commands\n"
              "Time between retransmitting lost link state advertisements\n"
              "Seconds\n"
              "Address of interface\n")
{
	return ip_ospf_retransmit_interval(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_retransmit_interval,
       no_ip_ospf_retransmit_interval_addr_cmd,
       "no ip ospf retransmit-interval [(1-65535)] [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	UNSET_IF_PARAM(params, retransmit_interval);
	params->retransmit_interval = OSPF_RETRANSMIT_INTERVAL_DEFAULT;

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_ospf_retransmit_interval,
       no_ospf_retransmit_interval_cmd,
       "no ospf retransmit-interval [(1-65535)] [A.B.C.D]",
       NO_STR
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"
       "Address of interface\n")
{
	return no_ip_ospf_retransmit_interval(self, vty, argc, argv);
}

DEFPY(ip_ospf_retransmit_window, ip_ospf_retransmit_window_addr_cmd,
      "[no] ip ospf retransmit-window ![(20-1000)]$retransmit-window [A.B.C.D]$ip_addr", NO_STR
      "IP Information\n"
      "OSPF interface commands\n"
      "Window for LSA retransmit - Retransmit LSAs expiring in this window\n"
      "Milliseconds\n"
      "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (ip_addr.s_addr != INADDR_ANY) {
		params = ospf_get_if_params(ifp, ip_addr);
		ospf_if_update_params(ifp, ip_addr);
	}

	if (no) {
		UNSET_IF_PARAM(params, retransmit_window);
		params->retransmit_window = OSPF_RETRANSMIT_WINDOW_DEFAULT;
	} else {
		SET_IF_PARAM(params, retransmit_window);
		params->retransmit_window = retransmit_window;
	}

	/*
	 * There is nothing to do when the retransmit-window changes, any
	 * change will take effect the next time the interface LSA retransmision
	 * timer expires.
	 */
	return CMD_SUCCESS;
}

DEFPY (ip_ospf_gr_hdelay,
       ip_ospf_gr_hdelay_cmd,
       "ip ospf graceful-restart hello-delay (1-1800)",
       IP_STR
       "OSPF interface commands\n"
       "Graceful Restart parameters\n"
       "Delay the sending of the first hello packets.\n"
       "Delay in seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	/* Note: new or updated value won't affect ongoing graceful restart. */
	SET_IF_PARAM(params, v_gr_hello_delay);
	params->v_gr_hello_delay = hello_delay;

	return CMD_SUCCESS;
}

DEFPY (no_ip_ospf_gr_hdelay,
       no_ip_ospf_gr_hdelay_cmd,
       "no ip ospf graceful-restart hello-delay [(1-1800)]",
       NO_STR
       IP_STR
       "OSPF interface commands\n"
       "Graceful Restart parameters\n"
       "Delay the sending of the first hello packets.\n"
       "Delay in seconds\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct route_node *rn;

	params = IF_DEF_PARAMS(ifp);
	UNSET_IF_PARAM(params, v_gr_hello_delay);
	params->v_gr_hello_delay = OSPF_HELLO_DELAY_DEFAULT;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi;

		oi = rn->info;
		if (!oi)
			continue;

		oi->gr.hello_delay.elapsed_seconds = 0;
		EVENT_OFF(oi->gr.hello_delay.t_grace_send);
	}

	return CMD_SUCCESS;
}

DEFUN (ip_ospf_transmit_delay,
       ip_ospf_transmit_delay_addr_cmd,
       "ip ospf transmit-delay (1-65535) [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Link state transmit delay\n"
       "Seconds\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	uint32_t seconds;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);
	argv_find(argv, argc, "(1-65535)", &idx);
	seconds = strtol(argv[idx]->arg, NULL, 10);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	SET_IF_PARAM(params, transmit_delay);
	params->transmit_delay = seconds;

	return CMD_SUCCESS;
}

DEFUN_HIDDEN (ospf_transmit_delay,
              ospf_transmit_delay_cmd,
              "ospf transmit-delay (1-65535) [A.B.C.D]",
              "OSPF interface commands\n"
              "Link state transmit delay\n"
              "Seconds\n"
              "Address of interface\n")
{
	return ip_ospf_transmit_delay(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_transmit_delay,
       no_ip_ospf_transmit_delay_addr_cmd,
       "no ip ospf transmit-delay [(1-65535)] [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Link state transmit delay\n"
       "Seconds\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct in_addr addr;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (argv_find(argv, argc, "A.B.C.D", &idx)) {
		if (!inet_aton(argv[idx]->arg, &addr)) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	}

	UNSET_IF_PARAM(params, transmit_delay);
	params->transmit_delay = OSPF_TRANSMIT_DELAY_DEFAULT;

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	return CMD_SUCCESS;
}


DEFUN_HIDDEN (no_ospf_transmit_delay,
              no_ospf_transmit_delay_cmd,
              "no ospf transmit-delay [(1-65535) [A.B.C.D]]",
              NO_STR
              "OSPF interface commands\n"
              "Link state transmit delay\n"
              "Seconds\n"
              "Address of interface\n")
{
	return no_ip_ospf_transmit_delay(self, vty, argc, argv);
}

DEFUN (ip_ospf_area,
       ip_ospf_area_cmd,
       "ip ospf [(1-65535)] area <A.B.C.D|(0-4294967295)> [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Instance ID\n"
       "Enable OSPF on this interface\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	int format, ret;
	struct in_addr area_id;
	struct in_addr addr;
	struct ospf_if_params *params = NULL;
	struct route_node *rn;
	struct ospf *ospf = NULL;
	unsigned short instance = 0;
	char *areaid;
	uint32_t count = 0;

	if (argv_find(argv, argc, "(1-65535)", &idx))
		instance = strtol(argv[idx]->arg, NULL, 10);

	argv_find(argv, argc, "area", &idx);
	areaid = argv[idx + 1]->arg;

	if (!instance)
		ospf = ifp->vrf->info;
	else
		ospf = ospf_lookup_instance(instance);

	if (instance && instance != ospf_instance) {
		/*
		 * At this point we know we have received
		 * an instance and there is no ospf instance
		 * associated with it.  This means we are
		 * in a situation where we have an
		 * ospf command that is setup for a different
		 * process(instance).  We need to safely
		 * remove the command from ourselves and
		 * allow the other instance(process) handle
		 * the configuration command.
		 */
		count = 0;

		params = IF_DEF_PARAMS(ifp);
		if (OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
			UNSET_IF_PARAM(params, if_area);
			count++;
		}

		for (rn = route_top(IF_OIFS_PARAMS(ifp)); rn; rn = route_next(rn))
			if ((params = rn->info) && OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
				UNSET_IF_PARAM(params, if_area);
				count++;
			}

		if (count > 0) {
			ospf = ifp->vrf->info;
			if (ospf)
				ospf_interface_area_unset(ospf, ifp);
		}

		return CMD_NOT_MY_INSTANCE;
	}

	ret = str2area_id(areaid, &area_id, &format);
	if (ret < 0) {
		vty_out(vty, "Please specify area by A.B.C.D|<0-4294967295>\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (memcmp(ifp->name, "VLINK", 5) == 0) {
		vty_out(vty, "Cannot enable OSPF on a virtual link.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ospf) {
		for (rn = route_top(ospf->networks); rn; rn = route_next(rn)) {
			if (rn->info != NULL) {
				vty_out(vty,
					"Please remove all network commands first.\n");
				return CMD_WARNING_CONFIG_FAILED;
			}
		}
	}

	params = IF_DEF_PARAMS(ifp);
	if (OSPF_IF_PARAM_CONFIGURED(params, if_area)
	    && !IPV4_ADDR_SAME(&params->if_area, &area_id)) {
		vty_out(vty,
			"Must remove previous area config before changing ospf area \n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	// Check if we have an address arg and proccess it
	if (argc == idx + 3) {
		if (!inet_aton(argv[idx + 2]->arg, &addr)) {
			vty_out(vty,
				"Please specify Intf Address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		// update/create address-level params
		params = ospf_get_if_params((ifp), (addr));
		if (OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
			if (!IPV4_ADDR_SAME(&params->if_area, &area_id)) {
				vty_out(vty,
					"Must remove previous area/address config before changing ospf area\n");
				return CMD_WARNING_CONFIG_FAILED;
			} else
				return CMD_SUCCESS;
		}
		ospf_if_update_params((ifp), (addr));
	}

	/* enable ospf on this interface with area_id */
	if (params) {
		SET_IF_PARAM(params, if_area);
		params->if_area = area_id;
		params->if_area_id_fmt = format;
	}

	if (ospf)
		ospf_interface_area_set(ospf, ifp);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_area,
       no_ip_ospf_area_cmd,
       "no ip ospf [(1-65535)] area [<A.B.C.D|(0-4294967295)> [A.B.C.D]]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Instance ID\n"
       "Disable OSPF on this interface\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	struct ospf *ospf;
	struct ospf_if_params *params;
	unsigned short instance = 0;
	struct in_addr addr;
	struct in_addr area_id;

	if (argv_find(argv, argc, "(1-65535)", &idx))
		instance = strtol(argv[idx]->arg, NULL, 10);

	if (!instance)
		ospf = ifp->vrf->info;
	else
		ospf = ospf_lookup_instance(instance);

	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	argv_find(argv, argc, "area", &idx);

	// Check if we have an address arg and proccess it
	if (argc == idx + 3) {
		if (!inet_aton(argv[idx + 2]->arg, &addr)) {
			vty_out(vty,
				"Please specify Intf Address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params = ospf_lookup_if_params(ifp, addr);
		if ((params) == NULL)
			return CMD_SUCCESS;
	} else
		params = IF_DEF_PARAMS(ifp);

	area_id = params->if_area;
	if (!OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
		vty_out(vty,
			"Can't find specified interface area configuration.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	UNSET_IF_PARAM(params, if_area);
	if (params != IF_DEF_PARAMS((ifp))) {
		ospf_free_if_params((ifp), (addr));
		ospf_if_update_params((ifp), (addr));
	}

	if (ospf) {
		ospf_interface_area_unset(ospf, ifp);
		ospf_area_check_free(ospf, area_id);
	}

	return CMD_SUCCESS;
}

DEFUN (ip_ospf_passive,
       ip_ospf_passive_cmd,
       "ip ospf passive [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Suppress routing updates on an interface\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = 3;
	struct in_addr addr = {.s_addr = INADDR_ANY};
	struct ospf_if_params *params;
	int ret;

	if (argc == 4) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	} else {
		params = IF_DEF_PARAMS(ifp);
	}

	ospf_passive_interface_update(ifp, params, addr, OSPF_IF_PASSIVE);

	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_passive,
       no_ip_ospf_passive_cmd,
       "no ip ospf passive [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable routing updates on an interface\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = 4;
	struct in_addr addr = {.s_addr = INADDR_ANY};
	struct ospf_if_params *params;
	int ret;

	if (argc == 5) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params = ospf_lookup_if_params(ifp, addr);
		if (params == NULL)
			return CMD_SUCCESS;
	} else {
		params = IF_DEF_PARAMS(ifp);
	}

	ospf_passive_interface_update(ifp, params, addr, OSPF_IF_ACTIVE);

	return CMD_SUCCESS;
}

DEFUN (ospf_redistribute_source,
       ospf_redistribute_source_cmd,
       "redistribute " FRR_REDIST_STR_OSPFD " [{metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       REDIST_STR
       FRR_REDIST_HELP_STR_OSPFD
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_protocol = 1;
	int source;
	int type = -1;
	int metric = -1;
	struct ospf_redist *red;
	int idx = 0;
	bool update = false;

	/* Get distribute source. */
	source = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (source < 0)
		return CMD_WARNING_CONFIG_FAILED;

	/* Get metric value. */
	if (argv_find(argv, argc, "(0-16777214)", &idx)) {
		if (!str2metric(argv[idx]->arg, &metric))
			return CMD_WARNING_CONFIG_FAILED;
	}
	idx = 1;
	/* Get metric type. */
	if (argv_find(argv, argc, "(1-2)", &idx)) {
		if (!str2metric_type(argv[idx]->arg, &type))
			return CMD_WARNING_CONFIG_FAILED;
	}
	idx = 1;

	red = ospf_redist_lookup(ospf, source, 0);
	if (!red)
		red = ospf_redist_add(ospf, source, 0);
	else
		update = true;

	/* Get route-map */
	if (argv_find(argv, argc, "route-map", &idx)) {
		ospf_routemap_set(red, argv[idx + 1]->arg);
	} else
		ospf_routemap_unset(red);

	if (update)
		return ospf_redistribute_update(ospf, red, source, 0, type,
						metric);
	else
		return ospf_redistribute_set(ospf, red, source, 0, type,
					     metric);
}

DEFUN (no_ospf_redistribute_source,
       no_ospf_redistribute_source_cmd,
       "no redistribute " FRR_REDIST_STR_OSPFD " [{metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_OSPFD
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_protocol = 2;
	int source;
	struct ospf_redist *red;

	source = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (source < 0)
		return CMD_WARNING_CONFIG_FAILED;

	red = ospf_redist_lookup(ospf, source, 0);
	if (!red)
		return CMD_SUCCESS;

	ospf_routemap_unset(red);
	ospf_redist_del(ospf, source, 0);

	return ospf_redistribute_unset(ospf, source, 0);
}

DEFUN (ospf_redistribute_instance_source,
       ospf_redistribute_instance_source_cmd,
       "redistribute <ospf|table> (1-65535) [{metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       REDIST_STR
       "Open Shortest Path First\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table ID\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ospf_table = 1;
	int idx_number = 2;
	int idx = 3;
	int source;
	int type = -1;
	int metric = -1;
	unsigned short instance;
	struct ospf_redist *red;
	bool update = false;

	source = proto_redistnum(AFI_IP, argv[idx_ospf_table]->text);

	if (source < 0) {
		vty_out(vty, "Unknown instance redistribution\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if ((source == ZEBRA_ROUTE_OSPF) && !ospf->instance) {
		vty_out(vty,
			"Instance redistribution in non-instanced OSPF not allowed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if ((source == ZEBRA_ROUTE_OSPF) && (ospf->instance == instance)) {
		vty_out(vty, "Same instance OSPF redistribution not allowed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get metric value. */
	if (argv_find(argv, argc, "metric", &idx))
		if (!str2metric(argv[idx + 1]->arg, &metric))
			return CMD_WARNING_CONFIG_FAILED;

	idx = 3;
	/* Get metric type. */
	if (argv_find(argv, argc, "metric-type", &idx))
		if (!str2metric_type(argv[idx + 1]->arg, &type))
			return CMD_WARNING_CONFIG_FAILED;

	red = ospf_redist_lookup(ospf, source, instance);
	if (!red)
		red = ospf_redist_add(ospf, source, instance);
	else
		update = true;

	idx = 3;
	if (argv_find(argv, argc, "route-map", &idx))
		ospf_routemap_set(red, argv[idx + 1]->arg);
	else
		ospf_routemap_unset(red);

	if (update)
		return ospf_redistribute_update(ospf, red, source, instance,
						type, metric);
	else
		return ospf_redistribute_set(ospf, red, source, instance, type,
					     metric);
}

DEFUN (no_ospf_redistribute_instance_source,
       no_ospf_redistribute_instance_source_cmd,
       "no redistribute <ospf|table> (1-65535) [{metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       NO_STR
       REDIST_STR
       "Open Shortest Path First\n"
       "Non-main Kernel Routing Table\n"
       "Instance ID/Table Id\n"
       "Metric for redistributed routes\n"
       "OSPF default metric\n"
       "OSPF exterior metric type for redistributed routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ospf_table = 2;
	int idx_number = 3;
	unsigned int instance;
	struct ospf_redist *red;
	int source;

	if (strncmp(argv[idx_ospf_table]->arg, "o", 1) == 0)
		source = ZEBRA_ROUTE_OSPF;
	else
		source = ZEBRA_ROUTE_TABLE;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	if ((source == ZEBRA_ROUTE_OSPF) && !ospf->instance) {
		vty_out(vty,
			"Instance redistribution in non-instanced OSPF not allowed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if ((source == ZEBRA_ROUTE_OSPF) && (ospf->instance == instance)) {
		vty_out(vty, "Same instance OSPF redistribution not allowed\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = ospf_redist_lookup(ospf, source, instance);
	if (!red)
		return CMD_SUCCESS;

	ospf_routemap_unset(red);
	ospf_redist_del(ospf, source, instance);

	return ospf_redistribute_unset(ospf, source, instance);
}

DEFUN (ospf_distribute_list_out,
       ospf_distribute_list_out_cmd,
       "distribute-list ACCESSLIST4_NAME out " FRR_REDIST_STR_OSPFD,
       "Filter networks in routing updates\n"
       "Access-list name\n"
       OUT_STR
       FRR_REDIST_HELP_STR_OSPFD)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_word = 1;
	int source;

	char *proto = argv[argc - 1]->text;

	/* Get distribute source. */
	source = proto_redistnum(AFI_IP, proto);
	if (source < 0)
		return CMD_WARNING_CONFIG_FAILED;

	return ospf_distribute_list_out_set(ospf, source, argv[idx_word]->arg);
}

DEFUN (no_ospf_distribute_list_out,
       no_ospf_distribute_list_out_cmd,
       "no distribute-list ACCESSLIST4_NAME out " FRR_REDIST_STR_OSPFD,
       NO_STR
       "Filter networks in routing updates\n"
       "Access-list name\n"
       OUT_STR
       FRR_REDIST_HELP_STR_OSPFD)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_word = 2;
	int source;

	char *proto = argv[argc - 1]->text;
	source = proto_redistnum(AFI_IP, proto);
	if (source < 0)
		return CMD_WARNING_CONFIG_FAILED;

	return ospf_distribute_list_out_unset(ospf, source,
					      argv[idx_word]->arg);
}

/* Default information originate. */
DEFUN (ospf_default_information_originate,
       ospf_default_information_originate_cmd,
       "default-information originate [{always|metric (0-16777214)|metric-type (1-2)|route-map RMAP_NAME}]",
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int default_originate = DEFAULT_ORIGINATE_ZEBRA;
	int type = -1;
	int metric = -1;
	struct ospf_redist *red;
	int idx = 0;
	int cur_originate = ospf->default_originate;
	bool sameRtmap = false;
	char *rtmap = NULL;

	red = ospf_redist_add(ospf, DEFAULT_ROUTE, 0);

	/* Check whether "always" was specified */
	if (argv_find(argv, argc, "always", &idx))
		default_originate = DEFAULT_ORIGINATE_ALWAYS;
	idx = 1;
	/* Get metric value */
	if (argv_find(argv, argc, "(0-16777214)", &idx)) {
		if (!str2metric(argv[idx]->arg, &metric))
			return CMD_WARNING_CONFIG_FAILED;
	}
	idx = 1;
	/* Get metric type. */
	if (argv_find(argv, argc, "(1-2)", &idx)) {
		if (!str2metric_type(argv[idx]->arg, &type))
			return CMD_WARNING_CONFIG_FAILED;
	}
	idx = 1;
	/* Get route-map */
	if (argv_find(argv, argc, "route-map", &idx))
		rtmap = argv[idx + 1]->arg;

	/* To check if user is providing same route map */
	if ((!rtmap && !ROUTEMAP_NAME(red)) ||
	    (rtmap && ROUTEMAP_NAME(red) &&
	     (strcmp(rtmap, ROUTEMAP_NAME(red)) == 0)))
		sameRtmap = true;

	/* Don't allow if the same lsa is already originated. */
	if ((sameRtmap)
	    && (red->dmetric.type == type)
	    && (red->dmetric.value == metric)
	    && (cur_originate == default_originate))
		return CMD_SUCCESS;

	/* Updating Metric details */
	red->dmetric.type = type;
	red->dmetric.value = metric;

	/* updating route map details */
	if (rtmap)
		ospf_routemap_set(red, rtmap);
	else
		ospf_routemap_unset(red);

	return ospf_redistribute_default_set(ospf, default_originate, type,
					     metric);
}

DEFUN (no_ospf_default_information_originate,
       no_ospf_default_information_originate_cmd,
       "no default-information originate [{always|metric [(0-16777214)]|metric-type [(1-2)]|route-map [RMAP_NAME]}]",
       NO_STR
       "Control distribution of default information\n"
       "Distribute a default route\n"
       "Always advertise default route\n"
       "OSPF default metric\n"
       "OSPF metric\n"
       "OSPF metric type for default routes\n"
       "Set OSPF External Type 1/2 metrics\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct ospf_redist *red;

	red = ospf_redist_lookup(ospf, DEFAULT_ROUTE, 0);
	if (!red)
		return CMD_SUCCESS;

	ospf_routemap_unset(red);
	ospf_redist_del(ospf, DEFAULT_ROUTE, 0);

	return ospf_redistribute_default_set(ospf, DEFAULT_ORIGINATE_NONE,
					     0, 0);
}

DEFUN (ospf_default_metric,
       ospf_default_metric_cmd,
       "default-metric (0-16777214)",
       "Set metric of redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 1;
	int metric = -1;

	if (!str2metric(argv[idx_number]->arg, &metric))
		return CMD_WARNING_CONFIG_FAILED;

	ospf->default_metric = metric;

	ospf_schedule_asbr_redist_update(ospf);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_default_metric,
       no_ospf_default_metric_cmd,
       "no default-metric [(0-16777214)]",
       NO_STR
       "Set metric of redistributed routes\n"
       "Default metric\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->default_metric = -1;

	ospf_schedule_asbr_redist_update(ospf);

	return CMD_SUCCESS;
}


DEFUN (ospf_distance,
       ospf_distance_cmd,
       "distance (1-255)",
       "Administrative distance\n"
       "OSPF Administrative distance\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 1;
	uint8_t distance;

	distance = atoi(argv[idx_number]->arg);
	if (ospf->distance_all != distance) {
		ospf->distance_all = distance;
		ospf_restart_spf(ospf);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf_distance,
       no_ospf_distance_cmd,
       "no distance [(1-255)]",
       NO_STR
       "Administrative distance\n"
       "OSPF Administrative distance\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (ospf->distance_all) {
		ospf->distance_all = 0;
		ospf_restart_spf(ospf);
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf_distance_ospf,
       no_ospf_distance_ospf_cmd,
       "no distance ospf [{intra-area [(1-255)]|inter-area [(1-255)]|external [(1-255)]}]",
       NO_STR
       "Administrative distance\n"
       "OSPF administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx = 0;

	if (argv_find(argv, argc, "intra-area", &idx) || argc == 3)
		idx = ospf->distance_intra = 0;
	if (argv_find(argv, argc, "inter-area", &idx) || argc == 3)
		idx = ospf->distance_inter = 0;
	if (argv_find(argv, argc, "external", &idx) || argc == 3)
		ospf->distance_external = 0;

	return CMD_SUCCESS;
}

DEFUN (ospf_distance_ospf,
       ospf_distance_ospf_cmd,
       "distance ospf {intra-area (1-255)|inter-area (1-255)|external (1-255)}",
       "Administrative distance\n"
       "OSPF administrative distance\n"
       "Intra-area routes\n"
       "Distance for intra-area routes\n"
       "Inter-area routes\n"
       "Distance for inter-area routes\n"
       "External routes\n"
       "Distance for external routes\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx = 0;

	ospf->distance_intra = 0;
	ospf->distance_inter = 0;
	ospf->distance_external = 0;

	if (argv_find(argv, argc, "intra-area", &idx))
		ospf->distance_intra = atoi(argv[idx + 1]->arg);
	idx = 0;
	if (argv_find(argv, argc, "inter-area", &idx))
		ospf->distance_inter = atoi(argv[idx + 1]->arg);
	idx = 0;
	if (argv_find(argv, argc, "external", &idx))
		ospf->distance_external = atoi(argv[idx + 1]->arg);

	return CMD_SUCCESS;
}

DEFUN (ip_ospf_mtu_ignore,
       ip_ospf_mtu_ignore_addr_cmd,
       "ip ospf mtu-ignore [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Disable MTU mismatch detection on this interface\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = 3;
	struct in_addr addr;
	int ret;

	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	if (argc == 4) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}
	params->mtu_ignore = 1;
	if (params->mtu_ignore != OSPF_MTU_IGNORE_DEFAULT)
		SET_IF_PARAM(params, mtu_ignore);
	else {
		UNSET_IF_PARAM(params, mtu_ignore);
		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, addr);
			ospf_if_update_params(ifp, addr);
		}
	}
	return CMD_SUCCESS;
}

DEFUN (no_ip_ospf_mtu_ignore,
       no_ip_ospf_mtu_ignore_addr_cmd,
       "no ip ospf mtu-ignore [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Disable MTU mismatch detection on this interface\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_ipv4 = 4;
	struct in_addr addr;
	int ret;

	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	if (argc == 5) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}
		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}
	params->mtu_ignore = 0;
	if (params->mtu_ignore != OSPF_MTU_IGNORE_DEFAULT)
		SET_IF_PARAM(params, mtu_ignore);
	else {
		UNSET_IF_PARAM(params, mtu_ignore);
		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, addr);
			ospf_if_update_params(ifp, addr);
		}
	}
	return CMD_SUCCESS;
}

DEFPY(ip_ospf_capability_opaque, ip_ospf_capability_opaque_addr_cmd,
      "[no] ip ospf capability opaque [A.B.C.D]$ip_addr",
      NO_STR
      "IP Information\n"
      "OSPF interface commands\n"
      "Disable OSPF capability on this interface\n"
      "Disable OSPF opaque LSA capability on this interface\n"
      "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct route_node *rn;
	bool old_opaque_capable;
	bool opaque_capable_change;

	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);

	if (ip_addr.s_addr != INADDR_ANY) {
		params = ospf_get_if_params(ifp, ip_addr);
		ospf_if_update_params(ifp, ip_addr);
	}

	old_opaque_capable = params->opaque_capable;
	params->opaque_capable = (no) ? false : true;
        opaque_capable_change = (old_opaque_capable != params->opaque_capable);
	if (params->opaque_capable != OSPF_OPAQUE_CAPABLE_DEFAULT)
		SET_IF_PARAM(params, opaque_capable);
	else {
		UNSET_IF_PARAM(params, opaque_capable);
		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, ip_addr);
			ospf_if_update_params(ifp, ip_addr);
		}
	}

	/*
	 * If there is a change to the opaque capability, flap the interface
	 * to reset all the neighbor adjacencies.
	 */
	if (opaque_capable_change) {
		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (oi && (oi->state > ISM_Down) &&
			    (ip_addr.s_addr == INADDR_ANY ||
			     IPV4_ADDR_SAME(&oi->address->u.prefix4,
					    &ip_addr))) {
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
				OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
			}
		}
	}
	return CMD_SUCCESS;
}


DEFPY(ip_ospf_prefix_suppression, ip_ospf_prefix_suppression_addr_cmd,
      "[no] ip ospf prefix-suppression [A.B.C.D]$ip_addr", NO_STR
      "IP Information\n"
      "OSPF interface commands\n"
      "Suppress OSPF prefix advertisement on this interface\n"
      "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct route_node *rn;
	bool prefix_suppression_change;
	struct ospf_if_params *params;

	params = IF_DEF_PARAMS(ifp);

	if (ip_addr.s_addr != INADDR_ANY) {
		params = ospf_get_if_params(ifp, ip_addr);
		ospf_if_update_params(ifp, ip_addr);
	}

	prefix_suppression_change = (params->prefix_suppression == (bool)no);
	params->prefix_suppression = (no) ? false : true;
	if (params->prefix_suppression != OSPF_PREFIX_SUPPRESSION_DEFAULT)
		SET_IF_PARAM(params, prefix_suppression);
	else {
		UNSET_IF_PARAM(params, prefix_suppression);
		if (params != IF_DEF_PARAMS(ifp)) {
			ospf_free_if_params(ifp, ip_addr);
			ospf_if_update_params(ifp, ip_addr);
		}
	}

	/*
	 * If there is a change to the prefix suppression, update the Router-LSA.
	 */
	if (prefix_suppression_change) {
		for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
			struct ospf_interface *oi = rn->info;

			if (oi && (oi->state > ISM_Down) &&
			    (ip_addr.s_addr == INADDR_ANY ||
			     IPV4_ADDR_SAME(&oi->address->u.prefix4, &ip_addr))) {
				(void)ospf_router_lsa_update_area(oi->area);
				if (oi->state == ISM_DR)
					ospf_network_lsa_update(oi);
			}
		}
	}
	return CMD_SUCCESS;
}

DEFPY(ip_ospf_neighbor_filter, ip_ospf_neighbor_filter_addr_cmd,
      "[no] ip ospf neighbor-filter ![PREFIXLIST4_NAME]$prefix_list [A.B.C.D]$ip_addr", NO_STR
      "IP Information\n"
      "OSPF interface commands\n"
      "Filter OSPF neighbor packets\n"
      "Prefix-List used for filtering\n"
      "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct ospf_if_params *params;
	struct prefix_list *nbr_filter = NULL;
	struct route_node *rn;

	params = IF_DEF_PARAMS(ifp);

	if (ip_addr.s_addr != INADDR_ANY) {
		params = ospf_get_if_params(ifp, ip_addr);
		ospf_if_update_params(ifp, ip_addr);
	}

	if (params->nbr_filter_name)
		XFREE(MTYPE_OSPF_IF_PARAMS, params->nbr_filter_name);

	if (no) {
		UNSET_IF_PARAM(params, nbr_filter_name);
		params->nbr_filter_name = NULL;
	} else {
		SET_IF_PARAM(params, nbr_filter_name);
		params->nbr_filter_name = XSTRDUP(MTYPE_OSPF_IF_PARAMS,
						  prefix_list);
		nbr_filter = prefix_list_lookup(AFI_IP, params->nbr_filter_name);
	}

	/*
	 * Determine if there is a change in neighbor filter prefix-list for the
	 * interface.
	 */
	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi &&
		    (ip_addr.s_addr == INADDR_ANY ||
		     IPV4_ADDR_SAME(&oi->address->u.prefix4, &ip_addr)) &&
		    oi->nbr_filter != nbr_filter) {
			oi->nbr_filter = nbr_filter;
			if (oi->nbr_filter)
				ospf_intf_neighbor_filter_apply(oi);
		}
	}
	return CMD_SUCCESS;
}

DEFUN (ospf_max_metric_router_lsa_admin,
       ospf_max_metric_router_lsa_admin_cmd,
       "max-metric router-lsa administrative",
       "OSPF maximum / infinite-distance metric\n"
       "Advertise own Router-LSA with infinite distance (stub router)\n"
       "Administratively applied, for an indefinite period\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *ln;
	struct ospf_area *area;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		SET_FLAG(area->stub_router_state, OSPF_AREA_ADMIN_STUB_ROUTED);

		if (!CHECK_FLAG(area->stub_router_state,
				OSPF_AREA_IS_STUB_ROUTED))
			ospf_router_lsa_update_area(area);
	}

	/* Allows for areas configured later to get the property */
	ospf->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_SET;

	return CMD_SUCCESS;
}

DEFUN (no_ospf_max_metric_router_lsa_admin,
       no_ospf_max_metric_router_lsa_admin_cmd,
       "no max-metric router-lsa administrative",
       NO_STR
       "OSPF maximum / infinite-distance metric\n"
       "Advertise own Router-LSA with infinite distance (stub router)\n"
       "Administratively applied, for an indefinite period\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *ln;
	struct ospf_area *area;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		UNSET_FLAG(area->stub_router_state,
			   OSPF_AREA_ADMIN_STUB_ROUTED);

		/* Don't trample on the start-up stub timer */
		if (CHECK_FLAG(area->stub_router_state,
			       OSPF_AREA_IS_STUB_ROUTED)
		    && !area->t_stub_router) {
			UNSET_FLAG(area->stub_router_state,
				   OSPF_AREA_IS_STUB_ROUTED);
			ospf_router_lsa_update_area(area);
		}
	}
	ospf->stub_router_admin_set = OSPF_STUB_ROUTER_ADMINISTRATIVE_UNSET;
	return CMD_SUCCESS;
}

DEFUN (ospf_max_metric_router_lsa_startup,
       ospf_max_metric_router_lsa_startup_cmd,
       "max-metric router-lsa on-startup (5-86400)",
       "OSPF maximum / infinite-distance metric\n"
       "Advertise own Router-LSA with infinite distance (stub router)\n"
       "Automatically advertise stub Router-LSA on startup of OSPF\n"
       "Time (seconds) to advertise self as stub-router\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 3;
	unsigned int seconds;

	if (argc < 4) {
		vty_out(vty, "%% Must supply stub-router period\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	seconds = strtoul(argv[idx_number]->arg, NULL, 10);

	ospf->stub_router_startup_time = seconds;

	return CMD_SUCCESS;
}

DEFUN (no_ospf_max_metric_router_lsa_startup,
       no_ospf_max_metric_router_lsa_startup_cmd,
       "no max-metric router-lsa on-startup [(5-86400)]",
       NO_STR
       "OSPF maximum / infinite-distance metric\n"
       "Advertise own Router-LSA with infinite distance (stub router)\n"
       "Automatically advertise stub Router-LSA on startup of OSPF\n"
       "Time (seconds) to advertise self as stub-router\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *ln;
	struct ospf_area *area;

	ospf->stub_router_startup_time = OSPF_STUB_ROUTER_UNCONFIGURED;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		SET_FLAG(area->stub_router_state,
			 OSPF_AREA_WAS_START_STUB_ROUTED);
		EVENT_OFF(area->t_stub_router);

		/* Don't trample on admin stub routed */
		if (!CHECK_FLAG(area->stub_router_state,
				OSPF_AREA_ADMIN_STUB_ROUTED)) {
			UNSET_FLAG(area->stub_router_state,
				   OSPF_AREA_IS_STUB_ROUTED);
			ospf_router_lsa_update_area(area);
		}
	}
	return CMD_SUCCESS;
}


DEFUN (ospf_max_metric_router_lsa_shutdown,
       ospf_max_metric_router_lsa_shutdown_cmd,
       "max-metric router-lsa on-shutdown (5-100)",
       "OSPF maximum / infinite-distance metric\n"
       "Advertise own Router-LSA with infinite distance (stub router)\n"
       "Advertise stub-router prior to full shutdown of OSPF\n"
       "Time (seconds) to wait till full shutdown\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 3;
	unsigned int seconds;

	if (argc < 4) {
		vty_out(vty, "%% Must supply stub-router shutdown period\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	seconds = strtoul(argv[idx_number]->arg, NULL, 10);

	ospf->stub_router_shutdown_time = seconds;

	return CMD_SUCCESS;
}

DEFUN (no_ospf_max_metric_router_lsa_shutdown,
       no_ospf_max_metric_router_lsa_shutdown_cmd,
       "no max-metric router-lsa on-shutdown [(5-100)]",
       NO_STR
       "OSPF maximum / infinite-distance metric\n"
       "Advertise own Router-LSA with infinite distance (stub router)\n"
       "Advertise stub-router prior to full shutdown of OSPF\n"
       "Time (seconds) to wait till full shutdown\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->stub_router_shutdown_time = OSPF_STUB_ROUTER_UNCONFIGURED;

	return CMD_SUCCESS;
}

DEFUN (ospf_proactive_arp,
       ospf_proactive_arp_cmd,
       "proactive-arp",
       "Allow sending ARP requests proactively\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->proactive_arp = true;

	return CMD_SUCCESS;
}

DEFUN (no_ospf_proactive_arp,
       no_ospf_proactive_arp_cmd,
       "no proactive-arp",
	   NO_STR
       "Disallow sending ARP requests proactively\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->proactive_arp = false;

	return CMD_SUCCESS;
}

/* Graceful Restart HELPER Commands */
DEFPY(ospf_gr_helper_enable, ospf_gr_helper_enable_cmd,
      "graceful-restart helper enable [A.B.C.D$address]",
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Enable Helper support\n"
      "Advertising Router-ID\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (address_str) {
		ospf_gr_helper_support_set_per_routerid(ospf, &address,
							OSPF_GR_TRUE);
		return CMD_SUCCESS;
	}

	ospf_gr_helper_support_set(ospf, OSPF_GR_TRUE);

	return CMD_SUCCESS;
}

DEFPY(no_ospf_gr_helper_enable,
      no_ospf_gr_helper_enable_cmd,
      "no graceful-restart helper enable [A.B.C.D$address]",
      NO_STR
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Enable Helper support\n"
      "Advertising Router-ID\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	if (address_str) {
		ospf_gr_helper_support_set_per_routerid(ospf, &address,
							OSPF_GR_FALSE);
		return CMD_SUCCESS;
	}

	ospf_gr_helper_support_set(ospf, OSPF_GR_FALSE);
	return CMD_SUCCESS;
}

DEFPY(ospf_gr_helper_enable_lsacheck,
      ospf_gr_helper_enable_lsacheck_cmd,
      "graceful-restart helper strict-lsa-checking",
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Enable strict LSA check\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_gr_helper_lsa_check_set(ospf, OSPF_GR_TRUE);
	return CMD_SUCCESS;
}

DEFPY(no_ospf_gr_helper_enable_lsacheck,
      no_ospf_gr_helper_enable_lsacheck_cmd,
      "no graceful-restart helper strict-lsa-checking",
      NO_STR
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Disable strict LSA check\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_gr_helper_lsa_check_set(ospf, OSPF_GR_FALSE);
	return CMD_SUCCESS;
}

DEFPY(ospf_gr_helper_supported_grace_time,
      ospf_gr_helper_supported_grace_time_cmd,
      "graceful-restart helper supported-grace-time (10-1800)$interval",
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Supported grace timer\n"
      "Grace interval(in seconds)\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_gr_helper_supported_gracetime_set(ospf, interval);
	return CMD_SUCCESS;
}

DEFPY(no_ospf_gr_helper_supported_grace_time,
      no_ospf_gr_helper_supported_grace_time_cmd,
      "no graceful-restart helper supported-grace-time (10-1800)$interval",
      NO_STR
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Supported grace timer\n"
      "Grace interval(in seconds)\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_gr_helper_supported_gracetime_set(ospf, OSPF_MAX_GRACE_INTERVAL);
	return CMD_SUCCESS;
}

DEFPY(ospf_gr_helper_planned_only,
      ospf_gr_helper_planned_only_cmd,
      "graceful-restart helper planned-only",
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Supported only planned restart\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_gr_helper_set_supported_planned_only_restart(ospf, OSPF_GR_TRUE);

	return CMD_SUCCESS;
}

/* External Route Aggregation */
DEFUN (ospf_external_route_aggregation,
       ospf_external_route_aggregation_cmd,
       "summary-address A.B.C.D/M [tag (1-4294967295)]",
       "External summary address\n"
       "Summary address prefix\n"
       "Router tag \n"
       "Router tag value\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct prefix_ipv4 p;
	int idx = 1;
	route_tag_t tag = 0;
	int ret = OSPF_SUCCESS;

	str2prefix_ipv4(argv[idx]->arg, &p);

	if (is_default_prefix4(&p)) {
		vty_out(vty,
			"Default address shouldn't be configured as summary address.\n");
		return CMD_SUCCESS;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!is_valid_summary_addr(&p)) {
		vty_out(vty, "Not a valid summary address.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc > 2)
		tag = strtoul(argv[idx + 2]->arg, NULL, 10);

	ret = ospf_asbr_external_aggregator_set(ospf, &p, tag);
	if (ret == OSPF_INVALID)
		vty_out(vty, "Invalid configuration!!\n");

	return CMD_SUCCESS;
}

DEFUN (no_ospf_external_route_aggregation,
       no_ospf_external_route_aggregation_cmd,
       "no summary-address A.B.C.D/M [tag (1-4294967295)]",
       NO_STR
       "External summary address\n"
       "Summary address prefix\n"
       "Router tag\n"
       "Router tag value\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct prefix_ipv4 p;
	int idx = 2;
	route_tag_t tag = 0;
	int ret = OSPF_SUCCESS;

	str2prefix_ipv4(argv[idx]->arg, &p);

	if (is_default_prefix4(&p)) {
		vty_out(vty,
			"Default address shouldn't be configured as summary address.\n");
		return CMD_SUCCESS;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!is_valid_summary_addr(&p)) {
		vty_out(vty, "Not a valid summary address.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc > 3)
		tag = strtoul(argv[idx + 2]->arg, NULL, 10);

	ret = ospf_asbr_external_aggregator_unset(ospf, &p, tag);
	if (ret == OSPF_INVALID)
		vty_out(vty, "Invalid configuration!!\n");

	return CMD_SUCCESS;
}

DEFPY(no_ospf_gr_helper_planned_only,
      no_ospf_gr_helper_planned_only_cmd,
      "no graceful-restart helper planned-only",
      NO_STR
      "OSPF Graceful Restart\n"
      "OSPF GR Helper\n"
      "Supported only for planned restart\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_gr_helper_set_supported_planned_only_restart(ospf, OSPF_GR_FALSE);

	return CMD_SUCCESS;
}

static int ospf_print_vty_helper_dis_rtr_walkcb(struct hash_bucket *bucket,
						void *arg)
{
	struct advRtr *rtr = bucket->data;
	struct vty *vty = (struct vty *)arg;
	static unsigned int count;

	vty_out(vty, "%-6pI4,", &rtr->advRtrAddr);
	count++;

	if (count % 5 == 0)
		vty_out(vty, "\n");

	return HASHWALK_CONTINUE;
}

static int ospf_print_json_helper_enabled_rtr_walkcb(struct hash_bucket *bucket,
						     void *arg)
{
	struct advRtr *rtr = bucket->data;
	struct json_object *json_rid_array = arg;
	struct json_object *json_rid;

	json_rid = json_object_new_object();

	json_object_string_addf(json_rid, "routerId", "%pI4", &rtr->advRtrAddr);
	json_object_array_add(json_rid_array, json_rid);

	return HASHWALK_CONTINUE;
}

static int ospf_show_gr_helper_details(struct vty *vty, struct ospf *ospf,
				       uint8_t use_vrf, json_object *json,
				       bool uj, bool detail)
{
	struct listnode *node;
	struct ospf_interface *oi;
	char buf[PREFIX_STRLEN];
	json_object *json_vrf = NULL;

	if (uj) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	if (ospf->instance) {
		if (uj)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	if (uj) {
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else
		vty_out(vty, "\n");

	/* Show Router ID. */
	if (uj) {
		json_object_string_add(json_vrf, "routerId",
				       inet_ntop(AF_INET, &ospf->router_id,
						 buf, sizeof(buf)));
	} else {
		vty_out(vty, "\n       OSPF Router with ID (%pI4)\n\n",
			&ospf->router_id);
	}

	if (!uj) {

		if (ospf->is_helper_supported)
			vty_out(vty,
				" Graceful restart helper support enabled.\n");
		else
			vty_out(vty,
				" Graceful restart helper support disabled.\n");

		if (ospf->strict_lsa_check)
			vty_out(vty, " Strict LSA check is enabled.\n");
		else
			vty_out(vty, " Strict LSA check is disabled.\n");

		if (ospf->only_planned_restart)
			vty_out(vty,
				" Helper supported for planned restarts only.\n");
		else
			vty_out(vty,
				" Helper supported for Planned and Unplanned Restarts.\n");

		vty_out(vty,
			" Supported Graceful restart interval: %d(in seconds).\n",
			ospf->supported_grace_time);

		if (OSPF_HELPER_ENABLE_RTR_COUNT(ospf)) {
			vty_out(vty, " Enable Router list:\n");
			vty_out(vty, "   ");
			hash_walk(ospf->enable_rtr_list,
				  ospf_print_vty_helper_dis_rtr_walkcb, vty);
			vty_out(vty, "\n\n");
		}

		if (ospf->last_exit_reason != OSPF_GR_HELPER_EXIT_NONE) {
			vty_out(vty, " Last Helper exit Reason :%s\n",
				ospf_exit_reason2str(ospf->last_exit_reason));
		}

		if (ospf->active_restarter_cnt)
			vty_out(vty,
				" Number of Active neighbours in graceful restart: %d\n",
				ospf->active_restarter_cnt);
		else
			vty_out(vty, "\n");

	} else {
		json_object_string_add(
			json_vrf, "helperSupport",
			(ospf->is_helper_supported) ? "Enabled" : "Disabled");
		json_object_string_add(json_vrf, "strictLsaCheck",
				       (ospf->strict_lsa_check) ? "Enabled"
								: "Disabled");
		json_object_string_add(
			json_vrf, "restartSupport",
			(ospf->only_planned_restart)
				? "Planned Restart only"
				: "Planned and Unplanned Restarts");

		json_object_int_add(json_vrf, "supportedGracePeriod",
				    ospf->supported_grace_time);

		if (ospf->last_exit_reason != OSPF_GR_HELPER_EXIT_NONE)
			json_object_string_add(
				json_vrf, "lastExitReason",
				ospf_exit_reason2str(ospf->last_exit_reason));

		if (ospf->active_restarter_cnt)
			json_object_int_add(json_vrf, "activeRestarterCnt",
					    ospf->active_restarter_cnt);

		if (OSPF_HELPER_ENABLE_RTR_COUNT(ospf)) {
			struct json_object *json_rid_array =
				json_object_new_array();

			json_object_object_add(json_vrf, "enabledRouterIds",
					       json_rid_array);

			hash_walk(ospf->enable_rtr_list,
				  ospf_print_json_helper_enabled_rtr_walkcb,
				  json_rid_array);
		}
	}


	if (detail) {
		int cnt = 1;
		json_object *json_neighbors = NULL;

		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
			struct route_node *rn;
			struct ospf_neighbor *nbr;
			json_object *json_neigh;

			if (ospf_interface_neighbor_count(oi) == 0)
				continue;

			if (uj) {
				json_object_object_get_ex(json_vrf, "neighbors",
							  &json_neighbors);
				if (!json_neighbors) {
					json_neighbors =
						json_object_new_object();
					json_object_object_add(json_vrf,
							       "neighbors",
							       json_neighbors);
				}
			}

			for (rn = route_top(oi->nbrs); rn;
			     rn = route_next(rn)) {

				if (!rn->info)
					continue;

				nbr = rn->info;

				if (!OSPF_GR_IS_ACTIVE_HELPER(nbr))
					continue;

				if (!uj) {
					vty_out(vty, " Neighbour %d :\n", cnt);
					vty_out(vty, "   Address  : %pI4\n",
						&nbr->address.u.prefix4);
					vty_out(vty, "   Routerid : %pI4\n",
						&nbr->router_id);
					vty_out(vty,
						"   Received Grace period : %d(in seconds).\n",
						nbr->gr_helper_info
							.recvd_grace_period);
					vty_out(vty,
						"   Actual Grace period : %d(in seconds)\n",
						nbr->gr_helper_info
							.actual_grace_period);
					vty_out(vty,
						"   Remaining GraceTime:%ld(in seconds).\n",
						event_timer_remain_second(
							nbr->gr_helper_info
								.t_grace_timer));
					vty_out(vty,
						"   Graceful Restart reason: %s.\n\n",
						ospf_restart_reason2str(
							nbr->gr_helper_info
							.gr_restart_reason));
					cnt++;
				} else {
					json_neigh = json_object_new_object();
					json_object_string_add(
						json_neigh, "srcAddr",
						inet_ntop(AF_INET, &nbr->src,
							  buf, sizeof(buf)));

					json_object_string_add(
						json_neigh, "routerid",
						inet_ntop(AF_INET,
							  &nbr->router_id,
							  buf, sizeof(buf)));
					json_object_int_add(
						json_neigh,
						"recvdGraceInterval",
						nbr->gr_helper_info
							.recvd_grace_period);
					json_object_int_add(
						json_neigh,
						"actualGraceInterval",
						nbr->gr_helper_info
							.actual_grace_period);
					json_object_int_add(
						json_neigh, "remainGracetime",
						event_timer_remain_second(
							nbr->gr_helper_info
								.t_grace_timer));
					json_object_string_add(
						json_neigh, "restartReason",
						ospf_restart_reason2str(
							nbr->gr_helper_info
							.gr_restart_reason));
					json_object_object_add(
						json_neighbors,
						inet_ntop(AF_INET, &nbr->src,
							  buf, sizeof(buf)),
						json_neigh);
				}
			}
		}
	}
	return CMD_SUCCESS;
}

DEFUN (ospf_external_route_aggregation_no_adrvertise,
       ospf_external_route_aggregation_no_adrvertise_cmd,
       "summary-address A.B.C.D/M no-advertise",
       "External summary address\n"
       "Summary address prefix\n"
       "Don't advertise summary route \n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct prefix_ipv4 p;
	int idx = 1;
	int ret = OSPF_SUCCESS;

	str2prefix_ipv4(argv[idx]->arg, &p);

	if (is_default_prefix4(&p)) {
		vty_out(vty,
			"Default address shouldn't be configured as summary address.\n");
		return CMD_SUCCESS;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!is_valid_summary_addr(&p)) {
		vty_out(vty, "Not a valid summary address.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = ospf_asbr_external_rt_no_advertise(ospf, &p);
	if (ret == OSPF_INVALID)
		vty_out(vty, "Invalid configuration!!\n");

	return CMD_SUCCESS;
}

DEFUN (no_ospf_external_route_aggregation_no_adrvertise,
       no_ospf_external_route_aggregation_no_adrvertise_cmd,
       "no summary-address A.B.C.D/M no-advertise",
       NO_STR
       "External summary address\n"
       "Summary address prefix\n"
       "Advertise summary route to the AS \n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct prefix_ipv4 p;
	int idx = 2;
	int ret = OSPF_SUCCESS;

	str2prefix_ipv4(argv[idx]->arg, &p);

	if (is_default_prefix4(&p)) {
		vty_out(vty,
			"Default address shouldn't be configured as summary address.\n");
		return CMD_SUCCESS;
	}

	/* Apply mask for given prefix. */
	apply_mask(&p);

	if (!is_valid_summary_addr(&p)) {
		vty_out(vty, "Not a valid summary address.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	ret = ospf_asbr_external_rt_advertise(ospf, &p);
	if (ret == OSPF_INVALID)
		vty_out(vty, "Invalid configuration!!\n");

	return CMD_SUCCESS;
}

DEFUN (ospf_route_aggregation_timer,
       ospf_route_aggregation_timer_cmd,
       "aggregation timer (5-1800)",
       "External route aggregation\n"
       "Delay timer (in seconds)\n"
       "Timer interval(in seconds)\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	uint16_t interval = 0;

	interval = strtoul(argv[2]->arg, NULL, 10);

	ospf_external_aggregator_timer_set(ospf, interval);

	return CMD_SUCCESS;
}

DEFPY (show_ip_ospf_gr_helper,
       show_ip_ospf_gr_helper_cmd,
       "show ip ospf [{(1-65535)$instance|vrf <NAME|all>}] graceful-restart helper [detail] [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "OSPF Graceful Restart\n"
       "Helper details in the router\n"
       "Detailed information\n"
       JSON_STR)
{
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int idx_vrf = 0;
	int idx = 0;
	uint8_t use_vrf = 0;
	bool uj = use_json(argc, argv);
	struct ospf *ospf = NULL;
	json_object *json = NULL;
	struct listnode *node = NULL;
	int inst = 0;
	bool detail = false;

	if (instance && instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (instance && vrf_name) {
		vty_out(vty, "%% VRF is not supported in instance mode\n");
		return CMD_WARNING;
	}

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided */
	if (vrf_name) {
		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;

				ret = ospf_show_gr_helper_details(
					vty, ospf, use_vrf, json, uj, detail);
			}

			if (uj)
				vty_json(vty, json);

			return ret;
		}

		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
	} else {
		/* Default Vrf */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
	}

	if (ospf == NULL || !ospf->oi_running) {

		if (uj)
			vty_json(vty, json);
		else
			vty_out(vty,
				"%% OSPF is not enabled in vrf %s\n", vrf_name ? vrf_name : "default");

		return CMD_SUCCESS;
	}

	ospf_show_gr_helper_details(vty, ospf, use_vrf, json, uj, detail);
	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}
/* Graceful Restart HELPER commands end */
DEFUN (no_ospf_route_aggregation_timer,
       no_ospf_route_aggregation_timer_cmd,
       "no aggregation timer",
       NO_STR
       "External route aggregation\n"
       "Delay timer\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf_external_aggregator_timer_set(ospf, OSPF_EXTL_AGGR_DEFAULT_DELAY);

	return CMD_SUCCESS;
}

/* External Route Aggregation End */

static void config_write_stub_router(struct vty *vty, struct ospf *ospf)
{
	if (ospf->stub_router_startup_time != OSPF_STUB_ROUTER_UNCONFIGURED)
		vty_out(vty, " max-metric router-lsa on-startup %u\n",
			ospf->stub_router_startup_time);
	if (ospf->stub_router_shutdown_time != OSPF_STUB_ROUTER_UNCONFIGURED)
		vty_out(vty, " max-metric router-lsa on-shutdown %u\n",
			ospf->stub_router_shutdown_time);
	if (ospf->stub_router_admin_set == OSPF_STUB_ROUTER_ADMINISTRATIVE_SET)
		vty_out(vty, " max-metric router-lsa administrative\n");

	return;
}

static void show_ip_ospf_route_network(struct vty *vty, struct ospf *ospf,
				       struct route_table *rt,
				       json_object *json, bool detail)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct listnode *pnode, *pnnode;
	struct ospf_path *path;
	json_object *json_route = NULL, *json_nexthop_array = NULL,
		    *json_nexthop = NULL;

	if (!json)
		vty_out(vty,
			"============ OSPF network routing table ============\n");

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		char buf1[PREFIX2STR_BUFFER];

		if ((or = rn->info) == NULL)
			continue;

		prefix2str(&rn->p, buf1, sizeof(buf1));

		if (json) {
			json_route = json_object_new_object();
			json_object_object_add(json, buf1, json_route);
		}

		switch (or->path_type) {
		case OSPF_PATH_INTER_AREA:
			if (or->type == OSPF_DESTINATION_NETWORK) {
				if (json) {
					json_object_string_add(json_route,
							       "routeType",
							       "N IA");
					json_object_int_add(json_route, "cost",
							    or->cost);
					json_object_string_addf(
						json_route, "area", "%pI4",
						&or->u.std.area_id);
				} else {
					vty_out(vty,
						"N IA %-18s    [%d] area: %pI4\n",
						buf1, or->cost,
						&or->u.std.area_id);
				}
			} else if (or->type == OSPF_DESTINATION_DISCARD) {
				if (json) {
					json_object_string_add(json_route,
							       "routeType",
							       "D IA");
				} else {
					vty_out(vty,
						"D IA %-18s    Discard entry\n",
						buf1);
				}
			}
			break;
		case OSPF_PATH_INTRA_AREA:
			if (json) {
				json_object_string_add(json_route, "routeType",
						       "N");
				json_object_boolean_add(json_route, "transit",
							or->u.std.transit);
				json_object_int_add(json_route, "cost",
						    or->cost);
				json_object_string_addf(json_route, "area",
							"%pI4",
							&or->u.std.area_id);
			} else {
				vty_out(vty, "N %s  %-18s    [%d] area: %pI4\n",
					or->u.std.transit && detail ? "T" : " ",
					buf1, or->cost, &or->u.std.area_id);
			}
			break;
		default:
			break;
		}

		if (or->type == OSPF_DESTINATION_NETWORK) {
			if (json) {
				json_nexthop_array = json_object_new_array();
				json_object_object_add(json_route, "nexthops",
						       json_nexthop_array);
			}

			for (ALL_LIST_ELEMENTS(or->paths, pnode, pnnode,
					       path)) {
				if (json) {
					json_nexthop = json_object_new_object();
					json_object_array_add(
						json_nexthop_array,
						json_nexthop);
				}
				if (if_lookup_by_index(path->ifindex,
						       ospf->vrf_id)) {

					if (path->nexthop.s_addr
					    == INADDR_ANY) {
						if (json) {
							json_object_string_add(
								json_nexthop,
								"ip", " ");
							json_object_string_add(
								json_nexthop,
								"directlyAttachedTo",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						} else {
							vty_out(vty,
								"%24s   directly attached to %s\n",
								"",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						}
					} else {
						if (json) {
							json_object_string_addf(
								json_nexthop,
								"ip", "%pI4",
								&path->nexthop);
							json_object_string_add(
								json_nexthop,
								"via",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
							json_object_string_addf(
								json_nexthop,
								"advertisedRouter",
								"%pI4",
								&path->adv_router);
						} else {
							vty_out(vty,
								"%24s   via %pI4, %s\n",
								"",
								&path->nexthop,
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						}
						if (detail && !json)
							vty_out(vty,
								"%24s   adv %pI4\n",
								"",
								&path->adv_router);
					}
				}
			}
		}
	}
	if (!json)
		vty_out(vty, "\n");
}

static void show_ip_ospf_route_router(struct vty *vty, struct ospf *ospf,
				      struct route_table *rtrs,
				      json_object *json)
{
	struct route_node *rn;
	struct ospf_route * or ;
	struct listnode *pnode;
	struct listnode *node;
	struct ospf_path *path;
	char buf[PREFIX_STRLEN];
	json_object *json_route = NULL, *json_nexthop_array = NULL,
		    *json_nexthop = NULL;

	if (!json)
		vty_out(vty, "============ OSPF %s table =============\n",
			ospf->all_rtrs == rtrs ? "reachable routers"
					       : "router routing");

	for (rn = route_top(rtrs); rn; rn = route_next(rn)) {
		if (rn->info == NULL)
			continue;
		int flag = 0;

		if (json) {
			json_route = json_object_new_object();
			json_object_object_add(
				json, inet_ntop(AF_INET, &rn->p.u.prefix4,
						buf, sizeof(buf)),
				json_route);
			json_object_string_add(json_route, "routeType", "R ");
		} else {
			vty_out(vty, "R    %-15pI4    ",
				&rn->p.u.prefix4);
		}

		for (ALL_LIST_ELEMENTS_RO((struct list *)rn->info, node, or)) {
			if (flag++) {
				if (!json)
					vty_out(vty, "%24s", "");
			}

			/* Show path. */
			if (json) {
				json_object_int_add(json_route, "cost",
						    or->cost);
				json_object_string_addf(json_route, "area",
							"%pI4",
							&or->u.std.area_id);
				if (or->path_type == OSPF_PATH_INTER_AREA) {
					json_object_boolean_true_add(json_route,
								     "IA");
					json_object_boolean_true_add(json_route,
								     "ia");
				}
				if (or->u.std.flags & ROUTER_LSA_BORDER)
					json_object_string_add(json_route,
							       "routerType",
							       "abr");
				else if (or->u.std.flags & ROUTER_LSA_EXTERNAL)
					json_object_string_add(json_route,
							       "routerType",
							       "asbr");
			} else {
				vty_out(vty, "%s [%d] area: %pI4",
					(or->path_type == OSPF_PATH_INTER_AREA
						 ? "IA"
						 : "  "),
					or->cost, &or->u.std.area_id);
				/* Show flags. */
				vty_out(vty, "%s%s\n",
					(or->u.std.flags & ROUTER_LSA_BORDER
						 ? ", ABR"
						 : ""),
					(or->u.std.flags & ROUTER_LSA_EXTERNAL
						 ? ", ASBR"
						 : ""));
			}

			if (json) {
				json_nexthop_array = json_object_new_array();
				json_object_object_add(json_route, "nexthops",
						       json_nexthop_array);
			}

			for (ALL_LIST_ELEMENTS_RO(or->paths, pnode, path)) {
				if (json) {
					json_nexthop = json_object_new_object();
					json_object_array_add(
						json_nexthop_array,
						json_nexthop);
				}
				if (if_lookup_by_index(path->ifindex,
						       ospf->vrf_id)) {
					if (path->nexthop.s_addr
					    == INADDR_ANY) {
						if (json) {
							json_object_string_add(
								json_nexthop,
								"ip", " ");
							json_object_string_add(
								json_nexthop,
								"directlyAttachedTo",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						} else {
							vty_out(vty,
								"%24s   directly attached to %s\n",
								"",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						}
					} else {
						if (json) {
							json_object_string_addf(
								json_nexthop,
								"ip", "%pI4",
								&path->nexthop);
							json_object_string_add(
								json_nexthop,
								"via",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						} else {
							vty_out(vty,
								"%24s   via %pI4, %s\n",
								"",
								&path->nexthop,
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						}
					}
				}
			}
		}
	}
	if (!json)
		vty_out(vty, "\n");
}

static void show_ip_ospf_route_external(struct vty *vty, struct ospf *ospf,
					struct route_table *rt,
					json_object *json, bool detail)
{
	struct route_node *rn;
	struct ospf_route *er;
	struct listnode *pnode, *pnnode;
	struct ospf_path *path;
	json_object *json_route = NULL, *json_nexthop_array = NULL,
		    *json_nexthop = NULL;

	if (!json)
		vty_out(vty,
			"============ OSPF external routing table ===========\n");

	for (rn = route_top(rt); rn; rn = route_next(rn)) {
		if ((er = rn->info) == NULL)
			continue;

		char buf1[19];

		snprintfrr(buf1, sizeof(buf1), "%pFX", &rn->p);
		if (json) {
			json_route = json_object_new_object();
			json_object_object_add(json, buf1, json_route);
		}

		switch (er->path_type) {
		case OSPF_PATH_TYPE1_EXTERNAL:
			if (json) {
				json_object_string_add(json_route, "routeType",
						       "N E1");
				json_object_int_add(json_route, "cost",
						    er->cost);
				json_object_int_add(json_route, "tag",
						    er->u.ext.tag);
			} else {
				vty_out(vty,
					"N E1 %-18s    [%d] tag: %" ROUTE_TAG_PRI
					"\n",
					buf1, er->cost, er->u.ext.tag);
			}
			break;
		case OSPF_PATH_TYPE2_EXTERNAL:
			if (json) {
				json_object_string_add(json_route, "routeType",
						       "N E2");
				json_object_int_add(json_route, "cost",
						    er->cost);
				json_object_int_add(json_route, "type2cost",
						    er->u.ext.type2_cost);
				json_object_int_add(json_route, "tag",
						    er->u.ext.tag);
			} else {
				vty_out(vty,
					"N E2 %-18s    [%d/%d] tag: %" ROUTE_TAG_PRI
					"\n",
					buf1, er->cost, er->u.ext.type2_cost,
					er->u.ext.tag);
			}
			break;
		}

		if (json) {
			json_nexthop_array = json_object_new_array();
			json_object_object_add(json_route, "nexthops",
					       json_nexthop_array);
		}

		for (ALL_LIST_ELEMENTS(er->paths, pnode, pnnode, path)) {
			if (json) {
				json_nexthop = json_object_new_object();
				json_object_array_add(json_nexthop_array,
						      json_nexthop);
			}

			if (if_lookup_by_index(path->ifindex, ospf->vrf_id)) {
				if (path->nexthop.s_addr == INADDR_ANY) {
					if (json) {
						json_object_string_add(
							json_nexthop, "ip",
							" ");
						json_object_string_add(
							json_nexthop,
							"directlyAttachedTo",
							ifindex2ifname(
								path->ifindex,
								ospf->vrf_id));
					} else {
						vty_out(vty,
							"%24s   directly attached to %s\n",
							"",
							ifindex2ifname(
								path->ifindex,
								ospf->vrf_id));
					}
				} else {
					if (json) {
						json_object_string_addf(
							json_nexthop, "ip",
							"%pI4", &path->nexthop);
						json_object_string_add(
							json_nexthop, "via",
							ifindex2ifname(
								path->ifindex,
								ospf->vrf_id));
						json_object_string_addf(
							json_nexthop,
							"advertisedRouter",
							"%pI4",
							&path->adv_router);
					} else {
						vty_out(vty,
							"%24s   via %pI4, %s\n",
							"",
							&path->nexthop,
							ifindex2ifname(
								path->ifindex,
								ospf->vrf_id));
					}
					if (detail && !json)
						vty_out(vty,
							"%24s   adv %pI4\n", "",
							&path->adv_router);
				}
			}
		}
	}
	if (!json)
		vty_out(vty, "\n");
}

static int show_ip_ospf_reachable_routers_common(struct vty *vty,
						 struct ospf *ospf,
						 uint8_t use_vrf)
{
	if (ospf->instance)
		vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);

	ospf_show_vrf_name(ospf, vty, NULL, use_vrf);

	if (ospf->all_rtrs == NULL) {
		vty_out(vty, "No OSPF reachable router information exist\n");
		return CMD_SUCCESS;
	}

	/* Show Router routes. */
	show_ip_ospf_route_router(vty, ospf, ospf->all_rtrs, NULL);

	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_reachable_routers,
       show_ip_ospf_reachable_routers_cmd,
       "show ip ospf [vrf <NAME|all>] reachable-routers",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Show all the reachable OSPF routers\n")
{
	struct ospf *ospf = NULL;
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0;
	uint8_t use_vrf = 0;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (vrf_name) {
		bool ospf_output = false;

		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;

				ospf_output = true;
				ret = show_ip_ospf_reachable_routers_common(
					vty, ospf, use_vrf);
			}

			if (!ospf_output)
				vty_out(vty, "%% OSPF instance not found\n");
		} else {
			ospf = ospf_lookup_by_inst_name(inst, vrf_name);
			if (ospf == NULL || !ospf->oi_running) {
				vty_out(vty, "%% OSPF instance not found\n");
				return CMD_SUCCESS;
			}

			ret = show_ip_ospf_reachable_routers_common(vty, ospf,
								    use_vrf);
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}

		ret = show_ip_ospf_reachable_routers_common(vty, ospf, use_vrf);
	}

	return ret;
}

DEFUN (show_ip_ospf_instance_reachable_routers,
       show_ip_ospf_instance_reachable_routers_cmd,
       "show ip ospf (1-65535) reachable-routers",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Show all the reachable OSPF routers\n")
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_reachable_routers_common(vty, ospf, 0);
}

static int show_ip_ospf_border_routers_common(struct vty *vty,
					      struct ospf *ospf,
					      uint8_t use_vrf,
					      json_object *json)
{
	json_object *json_vrf = NULL;
	json_object *json_router = NULL;

	if (json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
		json_router = json_object_new_object();
	}

	if (ospf->instance) {
		if (!json)
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
		else
			json_object_int_add(json_vrf, "ospfInstance",
					    ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	if (ospf->new_table == NULL) {
		if (!json)
			vty_out(vty, "No OSPF routing information exist\n");
		else {
			json_object_free(json_router);
			if (use_vrf)
				json_object_free(json_vrf);
		}
		return CMD_SUCCESS;
	}

	/* Show Network routes.
	show_ip_ospf_route_network (vty, ospf->new_table);   */

	/* Show Router routes. */
	show_ip_ospf_route_router(vty, ospf, ospf->new_rtrs, json_router);

	if (json) {
		json_object_object_add(json_vrf, "routers", json_router);
		if (use_vrf) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
						       json_vrf);
		}
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFPY (show_ip_ospf_border_routers,
       show_ip_ospf_border_routers_cmd,
       "show ip ospf [vrf <NAME|all>] border-routers [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Show all the ABR's and ASBR's\n"
       JSON_STR)
{
	struct ospf *ospf = NULL;
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx_vrf = 0;
	uint8_t use_vrf = 0;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (vrf_name) {
		bool ospf_output = false;

		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;

				ospf_output = true;
				ret = show_ip_ospf_border_routers_common(
					vty, ospf, use_vrf, json);
			}

			if (uj)
				vty_json(vty, json);
			else if (!ospf_output)
				vty_out(vty, "%% OSPF is not enabled\n");

			return ret;
		} else {
			ospf = ospf_lookup_by_inst_name(inst, vrf_name);
			if (ospf == NULL || !ospf->oi_running) {
				if (uj)
					vty_json(vty, json);
				else
					vty_out(vty,
						"%% OSPF is not enabled in vrf %s\n",
						vrf_name);

				return CMD_SUCCESS;
			}
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf default\n");

			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		ret = show_ip_ospf_border_routers_common(vty, ospf, use_vrf,
							 json);
		if (uj)
			vty_json(vty, json);
	}

	return ret;
}

DEFUN (show_ip_ospf_instance_border_routers,
       show_ip_ospf_instance_border_routers_cmd,
       "show ip ospf (1-65535) border-routers",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Show all the ABR's and ASBR's\n")
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_border_routers_common(vty, ospf, 0, NULL);
}

static int show_ip_ospf_route_common(struct vty *vty, struct ospf *ospf,
				     json_object *json, uint8_t use_vrf,
				     bool detail)
{
	json_object *json_vrf = NULL;

	if (ospf->instance)
		vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);


	if (json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	if (ospf->new_table == NULL) {
		if (json) {
			if (use_vrf)
				json_object_free(json_vrf);
		} else {
			vty_out(vty, "No OSPF routing information exist\n");
		}
		return CMD_SUCCESS;
	}

	if (detail && json == NULL) {
		vty_out(vty, "Codes: N  - network     T - transitive\n");
		vty_out(vty, "       IA - inter-area  E - external route\n");
		vty_out(vty, "       D  - destination R - router\n\n");
	}

	/* Show Network routes. */
	show_ip_ospf_route_network(vty, ospf, ospf->new_table, json_vrf,
				   detail);

	/* Show Router routes. */
	show_ip_ospf_route_router(vty, ospf, ospf->new_rtrs, json_vrf);

	/* Show Router routes. */
	if (ospf->all_rtrs)
		show_ip_ospf_route_router(vty, ospf, ospf->all_rtrs, json_vrf);

	/* Show AS External routes. */
	show_ip_ospf_route_external(vty, ospf, ospf->old_external_route,
				    json_vrf, detail);

	if (json) {
		if (use_vrf) {
			// json_object_object_add(json_vrf, "areas",
			// json_areas);
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
		}
	} else {
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_route,
       show_ip_ospf_route_cmd,
	"show ip ospf [vrf <NAME|all>] route [detail] [json]",
	SHOW_STR
	IP_STR
	"OSPF information\n"
	VRF_CMD_HELP_STR
	"All VRFs\n"
	"OSPF routing table\n"
	"Detailed information\n"
	JSON_STR)
{
	struct ospf *ospf = NULL;
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx = 0;
	int idx_vrf = 0;
	uint8_t use_vrf = 0;
	bool uj = use_json(argc, argv);
	bool detail = false;
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		bool ospf_output = false;

		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ospf_output = true;
				ret = show_ip_ospf_route_common(
					vty, ospf, json, use_vrf, detail);
			}

			if (uj) {
				/* Keep Non-pretty format */
				vty_json(vty, json);
			} else if (!ospf_output)
				vty_out(vty, "%% OSPF is not enabled\n");

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);

			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf default\n");

			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		ret = show_ip_ospf_route_common(vty, ospf, json, use_vrf,
						detail);
		/* Keep Non-pretty format */
		if (uj)
			vty_out(vty, "%s\n",
				json_object_to_json_string_ext(
					json, JSON_C_TO_STRING_NOSLASHESCAPE));
	}

	if (uj)
		json_object_free(json);

	return ret;
}

DEFUN (show_ip_ospf_instance_route,
       show_ip_ospf_instance_route_cmd,
       "show ip ospf (1-65535) route [detail]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "OSPF routing table\n"
       "Detailed information\n")
{
	int idx_number = 3;
	int idx = 0;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool detail = false;

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	if (instance != ospf_instance)
		return CMD_NOT_MY_INSTANCE;

	ospf = ospf_lookup_instance(instance);
	if (!ospf || !ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_route_common(vty, ospf, NULL, 0, detail);
}


DEFUN (show_ip_ospf_vrfs,
	show_ip_ospf_vrfs_cmd,
	"show ip ospf vrfs [json]",
	SHOW_STR
	IP_STR
	"OSPF information\n"
	"Show OSPF VRFs \n"
	JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL;
	json_object *json_vrfs = NULL;
	struct ospf *ospf = NULL;
	struct listnode *node = NULL;
	int count = 0;
	static const char header[] = "Name                       Id     RouterId  ";

	if (uj) {
		json = json_object_new_object();
		json_vrfs = json_object_new_object();
	}

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		json_object *json_vrf = NULL;
		const char *name = NULL;
		int64_t vrf_id_ui = 0;

		count++;

		if (!uj && count == 1)
			vty_out(vty, "%s\n", header);
		if (uj)
			json_vrf = json_object_new_object();

		name = ospf_get_name(ospf);

		vrf_id_ui = (ospf->vrf_id == VRF_UNKNOWN)
				    ? -1
				    : (int64_t)ospf->vrf_id;

		if (uj) {
			json_object_int_add(json_vrf, "vrfId", vrf_id_ui);
			json_object_string_addf(json_vrf, "routerId", "%pI4",
						&ospf->router_id);

			json_object_object_add(json_vrfs, name, json_vrf);

		} else {
			vty_out(vty, "%-25s  %-5d  %-16pI4  \n", name,
				ospf->vrf_id, &ospf->router_id);
		}
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		json_object_int_add(json, "totalVrfs", count);

		vty_json(vty, json);
	} else {
		if (count)
			vty_out(vty, "\nTotal number of OSPF VRFs: %d\n",
				count);
	}

	return CMD_SUCCESS;
}
DEFPY (clear_ip_ospf_neighbor,
       clear_ip_ospf_neighbor_cmd,
       "clear ip ospf [(1-65535)]$instance neighbor [A.B.C.D$nbr_id]",
       CLEAR_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Reset OSPF Neighbor\n"
       "Neighbor ID\n")
{
	struct listnode *node;
	struct ospf *ospf = NULL;

	/* If user does not specify the arguments,
	 * instance = 0 and nbr_id = 0.0.0.0
	 */
	if (instance != 0) {
		/* This means clear only the particular ospf process */
		if (instance != ospf_instance)
			return CMD_NOT_MY_INSTANCE;
	}

	/* Clear all the ospf processes */
	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		if (!ospf->oi_running)
			continue;

		if (nbr_id_str && IPV4_ADDR_SAME(&ospf->router_id, &nbr_id)) {
			vty_out(vty, "Self router-id is not allowed.\r\n ");
			return CMD_SUCCESS;
		}

		ospf_neighbor_reset(ospf, nbr_id, nbr_id_str);
	}

	return CMD_SUCCESS;
}

DEFPY (clear_ip_ospf_process,
       clear_ip_ospf_process_cmd,
       "clear ip ospf [(1-65535)]$instance process",
       CLEAR_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Reset OSPF Process\n")
{
	struct listnode *node;
	struct ospf *ospf = NULL;

	/* Check if instance is not passed as an argument */
	if (instance != 0) {
		/* This means clear only the particular ospf process */
		if (instance != ospf_instance)
			return CMD_NOT_MY_INSTANCE;
	}

	/* Clear all the ospf processes */
	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		if (!ospf->oi_running)
			continue;

		ospf_process_reset(ospf);
	}

	return CMD_SUCCESS;
}

static const char *const ospf_abr_type_str[] = {
	"unknown", "standard", "ibm", "cisco", "shortcut"
};

static const char *const ospf_shortcut_mode_str[] = {
	"default", "enable", "disable"
};
static int ospf_vty_external_rt_walkcb(struct hash_bucket *bucket,
					void *arg)
{
	struct external_info *ei = bucket->data;
	struct vty *vty = (struct vty *)arg;
	static unsigned int count;

	vty_out(vty, "%-4pI4/%d, ", &ei->p.prefix, ei->p.prefixlen);
	count++;

	if (count % 5 == 0)
		vty_out(vty, "\n");

	if (OSPF_EXTERNAL_RT_COUNT(ei->aggr_route) == count)
		count = 0;

	return HASHWALK_CONTINUE;
}

static int ospf_json_external_rt_walkcb(struct hash_bucket *bucket,
					void *arg)
{
	struct external_info *ei = bucket->data;
	struct json_object *json = (struct json_object *)arg;
	char buf[PREFIX2STR_BUFFER];
	char exnalbuf[20];
	static unsigned int count;

	prefix2str(&ei->p, buf, sizeof(buf));

	snprintf(exnalbuf, 20, "Exnl Addr-%d", count);

	json_object_string_add(json, exnalbuf, buf);

	count++;

	if (OSPF_EXTERNAL_RT_COUNT(ei->aggr_route) == count)
		count = 0;

	return HASHWALK_CONTINUE;
}

static int ospf_show_summary_address(struct vty *vty, struct ospf *ospf,
				     uint8_t use_vrf, json_object *json,
				     bool uj, bool detail)
{
	struct route_node *rn;
	json_object *json_vrf = NULL;
	int mtype = 0;
	int mval = 0;
	static char header[] =
		"Summary-address     Metric-type     Metric     Tag         External_Rt_count\n";

	mtype = metric_type(ospf, 0, ospf->instance);
	mval = metric_value(ospf, 0, ospf->instance);

	if (!uj)
		vty_out(vty, "%s\n", header);

	if (uj) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
	}

	if (ospf->instance) {
		if (uj)
			json_object_int_add(json, "ospfInstance",
					    ospf->instance);
		else
			vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);
	}

	ospf_show_vrf_name(ospf, vty, json_vrf, use_vrf);

	if (!uj) {
		vty_out(vty, "aggregation delay interval: %u(in seconds)\n\n",
			ospf->aggr_delay_interval);
	} else {
		json_object_int_add(json_vrf, "aggregationDelayInterval",
				    ospf->aggr_delay_interval);
	}

	for (rn = route_top(ospf->rt_aggr_tbl); rn; rn = route_next(rn))
		if (rn->info) {
			struct ospf_external_aggr_rt *aggr = rn->info;
			json_object *json_aggr = NULL;
			char buf[PREFIX2STR_BUFFER];

			prefix2str(&aggr->p, buf, sizeof(buf));

			if (uj) {

				json_aggr = json_object_new_object();

				json_object_object_add(json_vrf, buf,
						       json_aggr);
				json_object_string_add(json_aggr,
						       "summaryAddress", buf);
				json_object_string_add(
					json_aggr, "metricType",
					(mtype == EXTERNAL_METRIC_TYPE_1)
						? "E1"
						: "E2");

				json_object_int_add(json_aggr, "metric", mval);
				json_object_int_add(json_aggr, "tag",
						    aggr->tag);
				json_object_int_add(
					json_aggr, "externalRouteCount",
					OSPF_EXTERNAL_RT_COUNT(aggr));

				if (OSPF_EXTERNAL_RT_COUNT(aggr) && detail) {
					hash_walk(
						aggr->match_extnl_hash,
						ospf_json_external_rt_walkcb,
						json_aggr);
				}

			} else {
				vty_out(vty, "%-20s", buf);

				(mtype == EXTERNAL_METRIC_TYPE_1)
					? vty_out(vty, "%-16s", "E1")
					: vty_out(vty, "%-16s", "E2");
				vty_out(vty, "%-11d", mval);

				vty_out(vty, "%-12u", aggr->tag);

				vty_out(vty, "%-5ld\n",
					OSPF_EXTERNAL_RT_COUNT(aggr));

				if (OSPF_EXTERNAL_RT_COUNT(aggr) && detail) {
					vty_out(vty,
						"Matched External routes:\n");
					hash_walk(
						aggr->match_extnl_hash,
						ospf_vty_external_rt_walkcb,
						vty);
					vty_out(vty, "\n");
				}

				vty_out(vty, "\n");
			}
		}

	if (uj) {
		if (use_vrf)
			json_object_object_add(json, ospf_get_name(ospf),
					       json_vrf);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_external_aggregator,
       show_ip_ospf_external_aggregator_cmd,
       "show ip ospf [vrf <NAME|all>] summary-address [detail] [json]",
       SHOW_STR IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Show external summary addresses\n"
       "Detailed information\n"
       JSON_STR)
{
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int idx_vrf = 0;
	int idx = 0;
	uint8_t use_vrf = 0;
	bool uj = use_json(argc, argv);
	struct ospf *ospf = NULL;
	json_object *json = NULL;
	struct listnode *node = NULL;
	int inst = 0;
	bool detail = false;

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	if (uj)
		json = json_object_new_object();

	/* vrf input is provided */
	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = ospf_show_summary_address(
					vty, ospf, use_vrf, json, uj, detail);
			}

			if (uj)
				vty_json(vty, json);

			return ret;
		}

		ospf = ospf_lookup_by_inst_name(inst, vrf_name);

		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf %s\n",
					vrf_name);

			return CMD_SUCCESS;
		}
		ospf_show_summary_address(vty, ospf, use_vrf, json, uj, detail);

	} else {
		/* Default Vrf */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj)
				vty_json(vty, json);
			else
				vty_out(vty,
					"%% OSPF is not enabled in vrf default\n");

			return CMD_SUCCESS;
		}

		ospf_show_summary_address(vty, ospf, use_vrf, json, uj, detail);
	}

	if (uj)
		vty_json(vty, json);
	return CMD_SUCCESS;
}

static const char *const ospf_int_type_str[] = {
	"unknown", /* should never be used. */
	"point-to-point",
	"broadcast",
	"non-broadcast",
	"point-to-multipoint",
	"virtual-link", /* should never be used. */
	"loopback"
};

static int interface_config_auth_str(struct ospf_if_params *params, char *buf)
{
	if (!OSPF_IF_PARAM_CONFIGURED(params, auth_type)
	    || params->auth_type == OSPF_AUTH_NOTSET)
		return 0;

	/* Translation tables are not that much help
	 * here due to syntax
	 * of the simple option */
	switch (params->auth_type) {

	case OSPF_AUTH_NULL:
		snprintf(buf, BUFSIZ, " null");
		break;

	case OSPF_AUTH_SIMPLE:
		snprintf(buf, BUFSIZ, " ");
		break;

	case OSPF_AUTH_CRYPTOGRAPHIC:
		if (OSPF_IF_PARAM_CONFIGURED(params, keychain_name))
			snprintf(buf, BUFSIZ, " key-chain %s", params->keychain_name);
		else
			snprintf(buf, BUFSIZ, " message-digest");
		break;
	}

	return 1;
}

static int config_write_interface_one(struct vty *vty, struct vrf *vrf)
{
	struct listnode *node;
	struct interface *ifp;
	struct crypt_key *ck;
	struct route_node *rn = NULL;
	struct ospf_if_params *params;
	char buf[BUFSIZ];
	int ret = 0;
	int write = 0;

	FOR_ALL_INTERFACES (vrf, ifp) {

		if (memcmp(ifp->name, "VLINK", 5) == 0)
			continue;

		if_vty_config_start(vty, ifp);

		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);

		write++;

		params = IF_DEF_PARAMS(ifp);

		do {
			/* Interface Network print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, type) &&
			    params->type != OSPF_IFTYPE_LOOPBACK &&
			    params->type_cfg) {
				vty_out(vty, " ip ospf network %s",
					ospf_int_type_str[params->type]);
				if (params->type == OSPF_IFTYPE_POINTOPOINT &&
				    params->ptp_dmvpn)
					vty_out(vty, " dmvpn");
				if (params->type ==
					    OSPF_IFTYPE_POINTOMULTIPOINT &&
				    params->p2mp_delay_reflood)
					vty_out(vty, " delay-reflood");
				if (params->type ==
					    OSPF_IFTYPE_POINTOMULTIPOINT &&
				    params->p2mp_non_broadcast)
					vty_out(vty, " non-broadcast");
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4", &rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* OSPF interface authentication print */
			ret = interface_config_auth_str(params, buf);
			if (ret) {
				vty_out(vty, " ip ospf authentication%s",
					buf);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Simple Authentication Password print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, auth_simple)
			    && params->auth_simple[0] != '\0') {
				vty_out(vty, " ip ospf authentication-key %s",
					params->auth_simple);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Cryptographic Authentication Key print. */
			if (params && params->auth_crypt) {
				for (ALL_LIST_ELEMENTS_RO(params->auth_crypt,
							  node, ck)) {
					vty_out(vty,
						" ip ospf message-digest-key %d md5 %s",
						ck->key_id, ck->auth_key);
					if (params != IF_DEF_PARAMS(ifp) && rn)
						vty_out(vty, " %pI4",
							&rn->p.u.prefix4);
					vty_out(vty, "\n");
				}
			}

			/* Interface Output Cost print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, output_cost_cmd)) {
				vty_out(vty, " ip ospf cost %u",
					params->output_cost_cmd);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Hello Interval print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, v_hello)
			    && params->v_hello != OSPF_HELLO_INTERVAL_DEFAULT) {
				vty_out(vty, " ip ospf hello-interval %u",
					params->v_hello);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}


			/* Router Dead Interval print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, v_wait)
			    && params->is_v_wait_set) {
				vty_out(vty, " ip ospf dead-interval ");

				/* fast hello ? */
				if (OSPF_IF_PARAM_CONFIGURED(params,
							     fast_hello))
					vty_out(vty,
						"minimal hello-multiplier %d",
						params->fast_hello);
				else
					vty_out(vty, "%u", params->v_wait);

				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Hello Graceful-Restart Delay print. */
			if (OSPF_IF_PARAM_CONFIGURED(params,
						     v_gr_hello_delay) &&
			    params->v_gr_hello_delay !=
				    OSPF_HELLO_DELAY_DEFAULT)
				vty_out(vty,
					" ip ospf graceful-restart hello-delay %u\n",
					params->v_gr_hello_delay);

			/* Router Priority print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, priority)
			    && params->priority
				       != OSPF_ROUTER_PRIORITY_DEFAULT) {
				vty_out(vty, " ip ospf priority %u",
					params->priority);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Retransmit Interval print. */
			if (OSPF_IF_PARAM_CONFIGURED(params,
						     retransmit_interval)
			    && params->retransmit_interval
				       != OSPF_RETRANSMIT_INTERVAL_DEFAULT) {
				vty_out(vty, " ip ospf retransmit-interval %u",
					params->retransmit_interval);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Retransmit Window print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, retransmit_window) &&
			    params->retransmit_window !=
				    OSPF_RETRANSMIT_WINDOW_DEFAULT) {
				vty_out(vty, " ip ospf retransmit-window %u",
					params->retransmit_window);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4", &rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Transmit Delay print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, transmit_delay)
			    && params->transmit_delay
				       != OSPF_TRANSMIT_DELAY_DEFAULT) {
				vty_out(vty, " ip ospf transmit-delay %u",
					params->transmit_delay);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* Area  print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
				if (ospf_instance)
					vty_out(vty, " ip ospf %d",
						ospf_instance);
				else
					vty_out(vty, " ip ospf");

				char buf[INET_ADDRSTRLEN];

				area_id2str(buf, sizeof(buf), &params->if_area,
					    params->if_area_id_fmt);
				vty_out(vty, " area %s", buf);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* bfd  print. */
			if (params && params->bfd_config)
				ospf_bfd_write_config(vty, params);

			/* MTU ignore print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, mtu_ignore)
			    && params->mtu_ignore != OSPF_MTU_IGNORE_DEFAULT) {
				if (params->mtu_ignore == 0)
					vty_out(vty, " no ip ospf mtu-ignore");
				else
					vty_out(vty, " ip ospf mtu-ignore");
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4",
						&rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			if (OSPF_IF_PARAM_CONFIGURED(params,
						     passive_interface)) {
				vty_out(vty, " %sip ospf passive",
					params->passive_interface
							== OSPF_IF_ACTIVE
						? "no "
						: "");
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4", &rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* LDP-Sync print */
			if (params && params->ldp_sync_info)
				ospf_ldp_sync_if_write_config(vty, params);

			/* Capability opaque print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, opaque_capable) &&
			    params->opaque_capable !=
				    OSPF_OPAQUE_CAPABLE_DEFAULT) {
				if (params->opaque_capable == false)
					vty_out(vty,
						" no ip ospf capability opaque");
				else
					vty_out(vty,
						" ip ospf capability opaque");
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4", &rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* prefix-suppression print. */
			if (OSPF_IF_PARAM_CONFIGURED(params,
						     prefix_suppression) &&
			    params->prefix_suppression !=
				    OSPF_PREFIX_SUPPRESSION_DEFAULT) {
				if (params->prefix_suppression == false)
					vty_out(vty,
						" no ip ospf prefix-suppression");
				else
					vty_out(vty,
						" ip ospf prefix-suppression");
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4", &rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			/* neighbor-filter print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, nbr_filter_name)) {
				vty_out(vty, " ip ospf neighbor-filter %s",
					params->nbr_filter_name);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %pI4", &rn->p.u.prefix4);
				vty_out(vty, "\n");
			}

			while (1) {
				if (rn == NULL)
					rn = route_top(IF_OIFS_PARAMS(ifp));
				else
					rn = route_next(rn);

				if (rn == NULL)
					break;
				params = rn->info;
				if (params != NULL)
					break;
			}
		} while (rn);

		ospf_opaque_config_write_if(vty, ifp);

		if_vty_config_end(vty);
	}

	return write;
}

/* Configuration write function for ospfd. */
static int config_write_interface(struct vty *vty)
{
	int write = 0;
	struct vrf *vrf = NULL;

	/* Display all VRF aware OSPF interface configuration */
	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		write += config_write_interface_one(vty, vrf);
	}

	return write;
}

static int config_write_network_area(struct vty *vty, struct ospf *ospf)
{
	struct route_node *rn;
	char buf[INET_ADDRSTRLEN];

	/* `network area' print. */
	for (rn = route_top(ospf->networks); rn; rn = route_next(rn))
		if (rn->info) {
			struct ospf_network *n = rn->info;

			/* Create Area ID string by specified Area ID format. */
			if (n->area_id_fmt == OSPF_AREA_ID_FMT_DOTTEDQUAD)
				inet_ntop(AF_INET, &n->area_id, buf,
					  sizeof(buf));
			else
				snprintf(buf, sizeof(buf), "%lu",
					 (unsigned long int)ntohl(
						 n->area_id.s_addr));

			/* Network print. */
			vty_out(vty, " network %pFX area %s\n",	&rn->p, buf);
		}

	return 0;
}

static int config_write_ospf_area(struct vty *vty, struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_area *area;
	char buf[INET_ADDRSTRLEN];

	/* Area configuration print. */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		struct route_node *rn1;

		area_id2str(buf, sizeof(buf), &area->area_id,
			    area->area_id_fmt);

		if (area->auth_type != OSPF_AUTH_NULL) {
			if (area->auth_type == OSPF_AUTH_SIMPLE)
				vty_out(vty, " area %s authentication\n", buf);
			else
				vty_out(vty,
					" area %s authentication message-digest\n",
					buf);
		}

		if (area->shortcut_configured != OSPF_SHORTCUT_DEFAULT)
			vty_out(vty, " area %s shortcut %s\n", buf,
				ospf_shortcut_mode_str
					[area->shortcut_configured]);

		if ((area->external_routing == OSPF_AREA_STUB)
		    || (area->external_routing == OSPF_AREA_NSSA)) {
			if (area->external_routing == OSPF_AREA_STUB) {
				vty_out(vty, " area %s stub", buf);
				if (area->no_summary)
					vty_out(vty, " no-summary\n");
				vty_out(vty, "\n");
			} else if (area->external_routing == OSPF_AREA_NSSA) {
				vty_out(vty, " area %s nssa", buf);

				switch (area->NSSATranslatorRole) {
				case OSPF_NSSA_ROLE_NEVER:
					vty_out(vty, " translate-never");
					break;
				case OSPF_NSSA_ROLE_ALWAYS:
					vty_out(vty, " translate-always");
					break;
				case OSPF_NSSA_ROLE_CANDIDATE:
					break;
				}

				if (area->nssa_default_originate.enabled) {
					vty_out(vty,
						" default-information-originate");
					if (area->nssa_default_originate
						    .metric_value != -1)
						vty_out(vty, " metric %d",
							area->nssa_default_originate
								.metric_value);
					if (area->nssa_default_originate
						    .metric_type !=
					    DEFAULT_METRIC_TYPE)
						vty_out(vty, " metric-type 1");
				}

				if (area->no_summary)
					vty_out(vty, " no-summary");
				if (area->suppress_fa)
					vty_out(vty, " suppress-fa");
				vty_out(vty, "\n");

				for (rn1 = route_top(area->nssa_ranges); rn1;
				     rn1 = route_next(rn1)) {
					struct ospf_area_range *range;

					range = rn1->info;
					if (!range)
						continue;

					vty_out(vty, " area %s nssa range %pFX",
						buf, &rn1->p);

					if (range->cost_config !=
					    OSPF_AREA_RANGE_COST_UNSPEC)
						vty_out(vty, " cost %u",
							range->cost_config);

					if (!CHECK_FLAG(
						    range->flags,
						    OSPF_AREA_RANGE_ADVERTISE))
						vty_out(vty, " not-advertise");

					vty_out(vty, "\n");
				}
			}

			if (area->default_cost != 1)
				vty_out(vty, " area %s default-cost %d\n", buf,
					area->default_cost);
		}

		for (rn1 = route_top(area->ranges); rn1; rn1 = route_next(rn1))
			if (rn1->info) {
				struct ospf_area_range *range = rn1->info;

				vty_out(vty, " area %s range %pFX", buf,
					&rn1->p);

				if (range->cost_config
				    != OSPF_AREA_RANGE_COST_UNSPEC)
					vty_out(vty, " cost %d",
						range->cost_config);

				if (!CHECK_FLAG(range->flags,
						OSPF_AREA_RANGE_ADVERTISE))
					vty_out(vty, " not-advertise");

				if (CHECK_FLAG(range->flags,
					       OSPF_AREA_RANGE_SUBSTITUTE))
					vty_out(vty, " substitute %pI4/%d",
						&range->subst_addr,
						range->subst_masklen);

				vty_out(vty, "\n");
			}

		if (EXPORT_NAME(area))
			vty_out(vty, " area %s export-list %s\n", buf,
				EXPORT_NAME(area));

		if (IMPORT_NAME(area))
			vty_out(vty, " area %s import-list %s\n", buf,
				IMPORT_NAME(area));

		if (PREFIX_NAME_IN(area))
			vty_out(vty, " area %s filter-list prefix %s in\n", buf,
				PREFIX_NAME_IN(area));

		if (PREFIX_NAME_OUT(area))
			vty_out(vty, " area %s filter-list prefix %s out\n",
				buf, PREFIX_NAME_OUT(area));

		if (area->fr_info.configured)
			vty_out(vty, " area %s flood-reduction\n", buf);
	}

	return 0;
}

static int config_write_ospf_nbr_nbma(struct vty *vty, struct ospf *ospf)
{
	struct ospf_nbr_nbma *nbr_nbma;
	struct route_node *rn;

	/* Static Neighbor configuration print. */
	for (rn = route_top(ospf->nbr_nbma); rn; rn = route_next(rn))
		if ((nbr_nbma = rn->info)) {
			vty_out(vty, " neighbor %pI4", &nbr_nbma->addr);

			if (nbr_nbma->priority
			    != OSPF_NEIGHBOR_PRIORITY_DEFAULT)
				vty_out(vty, " priority %d",
					nbr_nbma->priority);

			if (nbr_nbma->v_poll != OSPF_POLL_INTERVAL_DEFAULT)
				vty_out(vty, " poll-interval %d",
					nbr_nbma->v_poll);

			vty_out(vty, "\n");
		}

	return 0;
}

static int config_write_virtual_link(struct vty *vty, struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_vl_data *vl_data;
	char buf[INET_ADDRSTRLEN];
	char buf2[BUFSIZ];
	int ret = 0;

	/* Virtual-Link print */
	for (ALL_LIST_ELEMENTS_RO(ospf->vlinks, node, vl_data)) {
		struct listnode *n2;
		struct crypt_key *ck;
		struct ospf_interface *oi;

		if (vl_data != NULL) {
			area_id2str(buf, sizeof(buf), &vl_data->vl_area_id,
				    vl_data->vl_area_id_fmt);
			oi = vl_data->vl_oi;

			/* timers */
			if (OSPF_IF_PARAM(oi, v_hello) !=
				    OSPF_HELLO_INTERVAL_DEFAULT ||
			    OSPF_IF_PARAM(oi, v_wait) !=
				    OSPF_ROUTER_DEAD_INTERVAL_DEFAULT ||
			    OSPF_IF_PARAM(oi, retransmit_interval) !=
				    OSPF_RETRANSMIT_INTERVAL_DEFAULT ||
			    OSPF_IF_PARAM(oi, retransmit_window) !=
				    OSPF_RETRANSMIT_WINDOW_DEFAULT ||
			    OSPF_IF_PARAM(oi, transmit_delay) !=
				    OSPF_TRANSMIT_DELAY_DEFAULT)
				vty_out(vty,
					" area %s virtual-link %pI4 hello-interval %d retransmit-interval %d retransmit-window %d transmit-delay %d dead-interval %d\n",
					buf, &vl_data->vl_peer,
					OSPF_IF_PARAM(oi, v_hello),
					OSPF_IF_PARAM(oi, retransmit_interval),
					OSPF_IF_PARAM(oi, retransmit_window),
					OSPF_IF_PARAM(oi, transmit_delay),
					OSPF_IF_PARAM(oi, v_wait));
			else
				vty_out(vty, " area %s virtual-link %pI4\n", buf,
					&vl_data->vl_peer);
			/* Auth type */
			ret = interface_config_auth_str(
				IF_DEF_PARAMS(oi->ifp), buf2);
			if (ret)
				vty_out(vty,
					" area %s virtual-link %pI4 authentication%s\n",
					buf, &vl_data->vl_peer, buf2);
			/* Auth key */
			if (IF_DEF_PARAMS(vl_data->vl_oi->ifp)->auth_simple[0]
			    != '\0')
				vty_out(vty,
					" area %s virtual-link %pI4 authentication-key %s\n",
					buf, &vl_data->vl_peer,
					IF_DEF_PARAMS(vl_data->vl_oi->ifp)
						->auth_simple);
			/* md5 keys */
			for (ALL_LIST_ELEMENTS_RO(
				     IF_DEF_PARAMS(vl_data->vl_oi->ifp)
					     ->auth_crypt,
				     n2, ck))
				vty_out(vty,
					" area %s virtual-link %pI4 message-digest-key %d md5 %s\n",
					buf, &vl_data->vl_peer,
					ck->key_id, ck->auth_key);
		}
	}

	return 0;
}


static int config_write_ospf_redistribute(struct vty *vty, struct ospf *ospf)
{
	int type;

	/* redistribute print. */
	for (type = 0; type < ZEBRA_ROUTE_MAX; type++) {
		struct list *red_list;
		struct listnode *node;
		struct ospf_redist *red;

		red_list = ospf->redist[type];
		if (!red_list)
			continue;

		for (ALL_LIST_ELEMENTS_RO(red_list, node, red)) {
			vty_out(vty, " redistribute %s",
				zebra_route_string(type));
			if (red->instance)
				vty_out(vty, " %d", red->instance);

			if (red->dmetric.value >= 0)
				vty_out(vty, " metric %d", red->dmetric.value);

			if (red->dmetric.type == EXTERNAL_METRIC_TYPE_1)
				vty_out(vty, " metric-type 1");

			if (ROUTEMAP_NAME(red))
				vty_out(vty, " route-map %s",
					ROUTEMAP_NAME(red));

			vty_out(vty, "\n");
		}
	}

	return 0;
}

static int ospf_cfg_write_helper_dis_rtr_walkcb(struct hash_bucket *bucket,
						void *arg)
{
	struct advRtr *rtr = bucket->data;
	struct vty *vty = (struct vty *)arg;

	vty_out(vty, " graceful-restart helper enable %pI4\n",
		&rtr->advRtrAddr);
	return HASHWALK_CONTINUE;
}

static void config_write_ospf_gr(struct vty *vty, struct ospf *ospf)
{
	if (!ospf->gr_info.restart_support)
		return;

	if (ospf->gr_info.grace_period == OSPF_DFLT_GRACE_INTERVAL)
		vty_out(vty, " graceful-restart\n");
	else
		vty_out(vty, " graceful-restart grace-period %u\n",
			ospf->gr_info.grace_period);
}

static int config_write_ospf_gr_helper(struct vty *vty, struct ospf *ospf)
{
	if (ospf->is_helper_supported)
		vty_out(vty, " graceful-restart helper enable\n");

	if (!ospf->strict_lsa_check)
		vty_out(vty,
			" no graceful-restart helper strict-lsa-checking\n");

	if (ospf->only_planned_restart)
		vty_out(vty, " graceful-restart helper planned-only\n");

	if (ospf->supported_grace_time != OSPF_MAX_GRACE_INTERVAL)
		vty_out(vty,
			" graceful-restart helper supported-grace-time %d\n",
			ospf->supported_grace_time);

	if (OSPF_HELPER_ENABLE_RTR_COUNT(ospf)) {
		hash_walk(ospf->enable_rtr_list,
			  ospf_cfg_write_helper_dis_rtr_walkcb, vty);
	}
	return 0;
}

static int config_write_ospf_external_aggregator(struct vty *vty,
						 struct ospf *ospf)
{
	struct route_node *rn;

	if (ospf->aggr_delay_interval != OSPF_EXTL_AGGR_DEFAULT_DELAY)
		vty_out(vty, " aggregation timer %u\n",
			ospf->aggr_delay_interval);

	/* print 'summary-address A.B.C.D/M' */
	for (rn = route_top(ospf->rt_aggr_tbl); rn; rn = route_next(rn))
		if (rn->info) {
			struct ospf_external_aggr_rt *aggr = rn->info;

			vty_out(vty, " summary-address %pI4/%d",
				&aggr->p.prefix, aggr->p.prefixlen);
			if (aggr->tag)
				vty_out(vty, " tag %u", aggr->tag);

			if (CHECK_FLAG(aggr->flags,
				       OSPF_EXTERNAL_AGGRT_NO_ADVERTISE))
				vty_out(vty, " no-advertise");

			vty_out(vty, "\n");
		}

	return 0;
}

static int config_write_ospf_default_metric(struct vty *vty, struct ospf *ospf)
{
	if (ospf->default_metric != -1)
		vty_out(vty, " default-metric %d\n", ospf->default_metric);
	return 0;
}

static int config_write_ospf_distribute(struct vty *vty, struct ospf *ospf)
{
	int type;
	struct ospf_redist *red;

	if (ospf) {
		/* distribute-list print. */
		for (type = 0; type < ZEBRA_ROUTE_MAX; type++)
			if (DISTRIBUTE_NAME(ospf, type))
				vty_out(vty, " distribute-list %s out %s\n",
					DISTRIBUTE_NAME(ospf, type),
					zebra_route_string(type));

		/* default-information print. */
		if (ospf->default_originate != DEFAULT_ORIGINATE_NONE) {
			vty_out(vty, " default-information originate");
			if (ospf->default_originate == DEFAULT_ORIGINATE_ALWAYS)
				vty_out(vty, " always");

			red = ospf_redist_lookup(ospf, DEFAULT_ROUTE, 0);
			if (red) {
				if (red->dmetric.value >= 0)
					vty_out(vty, " metric %d",
						red->dmetric.value);

				if (red->dmetric.type == EXTERNAL_METRIC_TYPE_1)
					vty_out(vty, " metric-type 1");

				if (ROUTEMAP_NAME(red))
					vty_out(vty, " route-map %s",
						ROUTEMAP_NAME(red));
			}

			vty_out(vty, "\n");
		}
	}

	return 0;
}

static int config_write_ospf_distance(struct vty *vty, struct ospf *ospf)
{
	struct route_node *rn;
	struct ospf_distance *odistance;

	if (ospf->distance_all)
		vty_out(vty, " distance %d\n", ospf->distance_all);

	if (ospf->distance_intra || ospf->distance_inter
	    || ospf->distance_external) {
		vty_out(vty, " distance ospf");

		if (ospf->distance_intra)
			vty_out(vty, " intra-area %d", ospf->distance_intra);
		if (ospf->distance_inter)
			vty_out(vty, " inter-area %d", ospf->distance_inter);
		if (ospf->distance_external)
			vty_out(vty, " external %d", ospf->distance_external);

		vty_out(vty, "\n");
	}

	for (rn = route_top(ospf->distance_table); rn; rn = route_next(rn))
		if ((odistance = rn->info) != NULL) {
			vty_out(vty, " distance %d %pFX %s\n",
				odistance->distance, &rn->p,
				odistance->access_list ? odistance->access_list
						       : "");
		}
	return 0;
}

static int ospf_config_write_one(struct vty *vty, struct ospf *ospf)
{
	int write = 0;

	/* `router ospf' print. */
	if (ospf->instance && strcmp(ospf->name, VRF_DEFAULT_NAME)) {
		vty_out(vty, "router ospf %d vrf %s\n", ospf->instance,
			ospf->name);
	} else if (ospf->instance) {
		vty_out(vty, "router ospf %d\n", ospf->instance);
	} else if (strcmp(ospf->name, VRF_DEFAULT_NAME)) {
		vty_out(vty, "router ospf vrf %s\n", ospf->name);
	} else
		vty_out(vty, "router ospf\n");

	if (!ospf->networks) {
		write++;
		return write;
	}

	/* Router ID print. */
	if (ospf->router_id_static.s_addr != INADDR_ANY)
		vty_out(vty, " ospf router-id %pI4\n",
			&ospf->router_id_static);

	/* zebra opaque attributes configuration. */
	if (CHECK_FLAG(ospf->config, OSPF_SEND_EXTRA_DATA_TO_ZEBRA))
		vty_out(vty, " ospf send-extra-data zebra\n");

	/* ABR type print. */
	if (ospf->abr_type != OSPF_ABR_DEFAULT)
		vty_out(vty, " ospf abr-type %s\n",
			ospf_abr_type_str[ospf->abr_type]);

	/* log-adjacency-changes flag print. */
	if (CHECK_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES)) {
		if (CHECK_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
			vty_out(vty, " log-adjacency-changes detail\n");
		else if (!SAVE_OSPF_LOG_ADJACENCY_CHANGES)
			vty_out(vty, " log-adjacency-changes\n");
	} else if (SAVE_OSPF_LOG_ADJACENCY_CHANGES) {
		vty_out(vty, " no log-adjacency-changes\n");
	}

	/* RFC1583 compatibility flag print -- Compatible with CISCO
	 * 12.1. */
	if (CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE))
		vty_out(vty, " compatible rfc1583\n");

	/* auto-cost reference-bandwidth configuration.  */
	if (ospf->ref_bandwidth != OSPF_DEFAULT_REF_BANDWIDTH) {
		vty_out(vty,
			"! Important: ensure reference bandwidth is consistent across all routers\n");
		vty_out(vty, " auto-cost reference-bandwidth %d\n",
			ospf->ref_bandwidth);
	}

	/* SPF timers print. */
	if (ospf->spf_delay != OSPF_SPF_DELAY_DEFAULT
	    || ospf->spf_holdtime != OSPF_SPF_HOLDTIME_DEFAULT
	    || ospf->spf_max_holdtime != OSPF_SPF_MAX_HOLDTIME_DEFAULT)
		vty_out(vty, " timers throttle spf %d %d %d\n", ospf->spf_delay,
			ospf->spf_holdtime, ospf->spf_max_holdtime);

	/* LSA timers print. */
	if (ospf->min_ls_interval != OSPF_MIN_LS_INTERVAL)
		vty_out(vty, " timers throttle lsa all %d\n",
			ospf->min_ls_interval);
	if (ospf->min_ls_arrival != OSPF_MIN_LS_ARRIVAL)
		vty_out(vty, " timers lsa min-arrival %d\n",
			ospf->min_ls_arrival);

	/* Write multiplier print. */
	if (ospf->write_oi_count != OSPF_WRITE_INTERFACE_COUNT_DEFAULT)
		vty_out(vty, " ospf write-multiplier %d\n",
			ospf->write_oi_count);

	if (ospf->max_multipath != MULTIPATH_NUM)
		vty_out(vty, " maximum-paths %d\n", ospf->max_multipath);

	/* Max-metric router-lsa print */
	config_write_stub_router(vty, ospf);

	/* SPF refresh parameters print. */
	if (ospf->lsa_refresh_interval != OSPF_LSA_REFRESH_INTERVAL_DEFAULT)
		vty_out(vty, " refresh timer %d\n", ospf->lsa_refresh_interval);

	if (ospf->fr_configured)
		vty_out(vty, " flood-reduction\n");

	if (!ospf->intf_socket_enabled)
		vty_out(vty, " no socket-per-interface\n");

	/* Redistribute information print. */
	config_write_ospf_redistribute(vty, ospf);

	/* Graceful Restart print */
	config_write_ospf_gr(vty, ospf);
	config_write_ospf_gr_helper(vty, ospf);

	/* Print external route aggregation. */
	config_write_ospf_external_aggregator(vty, ospf);

	/* passive-interface print. */
	if (ospf->passive_interface_default == OSPF_IF_PASSIVE)
		vty_out(vty, " passive-interface default\n");

	/* proactive-arp print. */
	if (ospf->proactive_arp != OSPF_PROACTIVE_ARP_DEFAULT) {
		if (ospf->proactive_arp)
			vty_out(vty, " proactive-arp\n");
		else
			vty_out(vty, " no proactive-arp\n");
	}

	/* TI-LFA print. */
	if (ospf->ti_lfa_enabled) {
		if (ospf->ti_lfa_protection_type == OSPF_TI_LFA_NODE_PROTECTION)
			vty_out(vty, " fast-reroute ti-lfa node-protection\n");
		else
			vty_out(vty, " fast-reroute ti-lfa\n");
	}

	/* Network area print. */
	config_write_network_area(vty, ospf);

	/* Area config print. */
	config_write_ospf_area(vty, ospf);

	/* static neighbor print. */
	config_write_ospf_nbr_nbma(vty, ospf);

	/* Virtual-Link print. */
	config_write_virtual_link(vty, ospf);

	/* Default metric configuration.  */
	config_write_ospf_default_metric(vty, ospf);

	/* Distribute-list and default-information print. */
	config_write_ospf_distribute(vty, ospf);

	/* Distance configuration. */
	config_write_ospf_distance(vty, ospf);

	ospf_opaque_config_write_router(vty, ospf);

	/* LDP-Sync print */
	ospf_ldp_sync_write_config(vty, ospf);

	/* Socket buffer sizes */
	if (ospf->recv_sock_bufsize != OSPF_DEFAULT_SOCK_BUFSIZE) {
		if (ospf->send_sock_bufsize == ospf->recv_sock_bufsize)
			vty_out(vty, " socket buffer all %u\n",
				ospf->recv_sock_bufsize);
		else
			vty_out(vty, " socket buffer recv %u\n",
				ospf->recv_sock_bufsize);
	}

	if (ospf->send_sock_bufsize != OSPF_DEFAULT_SOCK_BUFSIZE &&
	    ospf->send_sock_bufsize != ospf->recv_sock_bufsize)
		vty_out(vty, " socket buffer send %u\n",
			ospf->send_sock_bufsize);


	vty_out(vty, "exit\n");

	write++;
	return write;
}

/* OSPF configuration write function. */
static int ospf_config_write(struct vty *vty)
{
	struct ospf *ospf;
	struct listnode *ospf_node = NULL;
	int write = 0;

	if (listcount(om->ospf) == 0)
		return write;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, ospf_node, ospf)) {
		/* VRF Default check if it is running.
		 * Upon daemon start, there could be default instance
		 * in absence of 'router ospf'/oi_running is disabled. */
		if (ospf->vrf_id == VRF_DEFAULT && ospf->oi_running)
			write += ospf_config_write_one(vty, ospf);
		/* For Non-Default VRF simply display the configuration,
		 * even if it is not oi_running. */
		else if (ospf->vrf_id != VRF_DEFAULT)
			write += ospf_config_write_one(vty, ospf);
	}
	return write;
}

void ospf_vty_show_init(void)
{
	/* "show ip ospf" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_cmd);

	install_element(VIEW_NODE, &show_ip_ospf_instance_cmd);

	/* "show ip ospf database" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_database_cmd);

	/* "show ip ospf interface" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_interface_cmd);

	install_element(VIEW_NODE, &show_ip_ospf_instance_interface_cmd);
	/* "show ip ospf interface traffic */
	install_element(VIEW_NODE, &show_ip_ospf_interface_traffic_cmd);

	/* "show ip ospf neighbor" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_int_detail_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_int_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_id_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_detail_all_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_detail_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_neighbor_all_cmd);

	install_element(VIEW_NODE,
			&show_ip_ospf_instance_neighbor_int_detail_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_neighbor_int_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_neighbor_id_cmd);
	install_element(VIEW_NODE,
			&show_ip_ospf_instance_neighbor_detail_all_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_neighbor_detail_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_neighbor_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_neighbor_all_cmd);

	/* "show ip ospf route" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_route_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_border_routers_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_reachable_routers_cmd);

	install_element(VIEW_NODE, &show_ip_ospf_instance_route_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_border_routers_cmd);
	install_element(VIEW_NODE,
			&show_ip_ospf_instance_reachable_routers_cmd);

	/* "show ip ospf vrfs" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_vrfs_cmd);

	/* "show ip ospf gr-helper details" command */
	install_element(VIEW_NODE, &show_ip_ospf_gr_helper_cmd);

	/* "show ip ospf summary-address" command */
	install_element(VIEW_NODE, &show_ip_ospf_external_aggregator_cmd);
}

/* Initialization of OSPF interface. */
static void ospf_vty_if_init(void)
{
	/* Install interface node. */
	if_cmd_init(config_write_interface);

	/* "ip ospf authentication" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_authentication_args_addr_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_authentication_addr_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_ospf_authentication_args_addr_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_authentication_addr_cmd);
	install_element(INTERFACE_NODE, &ip_ospf_authentication_key_addr_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_ospf_authentication_key_authkey_addr_cmd);
	install_element(INTERFACE_NODE,
			&no_ospf_authentication_key_authkey_addr_cmd);

	/* "ip ospf message-digest-key" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_message_digest_key_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_message_digest_key_cmd);

	/* "ip ospf cost" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_cost_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_cost_cmd);

	/* "ip ospf mtu-ignore" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_mtu_ignore_addr_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_mtu_ignore_addr_cmd);

	/* "ip ospf dead-interval" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_dead_interval_cmd);
	install_element(INTERFACE_NODE,
			&ip_ospf_dead_interval_minimal_addr_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_dead_interval_cmd);

	/* "ip ospf hello-interval" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_hello_interval_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_hello_interval_cmd);

	/* "ip ospf graceful-restart" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_gr_hdelay_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_gr_hdelay_cmd);

	/* "ip ospf network" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_network_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_network_cmd);

	/* "ip ospf priority" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_priority_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_priority_cmd);

	/* "ip ospf retransmit-interval" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_retransmit_interval_addr_cmd);
	install_element(INTERFACE_NODE,
			&no_ip_ospf_retransmit_interval_addr_cmd);

	/* "ip ospf retransmit-window" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_retransmit_window_addr_cmd);

	/* "ip ospf transmit-delay" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_transmit_delay_addr_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_transmit_delay_addr_cmd);

	/* "ip ospf area" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_area_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_area_cmd);

	/* "ip ospf passive" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_passive_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_passive_cmd);

	/* "ip ospf capability opaque" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_capability_opaque_addr_cmd);

	/* "ip ospf prefix-suppression" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_prefix_suppression_addr_cmd);

	/* "ip ospf neighbor-filter" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_neighbor_filter_addr_cmd);

	/* These commands are compatibitliy for previous version. */
	install_element(INTERFACE_NODE, &ospf_authentication_key_cmd);
	install_element(INTERFACE_NODE, &ospf_message_digest_key_cmd);
	install_element(INTERFACE_NODE, &no_ospf_message_digest_key_cmd);
	install_element(INTERFACE_NODE, &ospf_dead_interval_cmd);
	install_element(INTERFACE_NODE, &no_ospf_dead_interval_cmd);
	install_element(INTERFACE_NODE, &ospf_hello_interval_cmd);
	install_element(INTERFACE_NODE, &no_ospf_hello_interval_cmd);
	install_element(INTERFACE_NODE, &ospf_cost_cmd);
	install_element(INTERFACE_NODE, &no_ospf_cost_cmd);
	install_element(INTERFACE_NODE, &ospf_network_cmd);
	install_element(INTERFACE_NODE, &no_ospf_network_cmd);
	install_element(INTERFACE_NODE, &ospf_priority_cmd);
	install_element(INTERFACE_NODE, &no_ospf_priority_cmd);
	install_element(INTERFACE_NODE, &ospf_retransmit_interval_cmd);
	install_element(INTERFACE_NODE, &no_ospf_retransmit_interval_cmd);
	install_element(INTERFACE_NODE, &ospf_transmit_delay_cmd);
	install_element(INTERFACE_NODE, &no_ospf_transmit_delay_cmd);
}

static void ospf_vty_zebra_init(void)
{
	install_element(OSPF_NODE, &ospf_redistribute_source_cmd);
	install_element(OSPF_NODE, &no_ospf_redistribute_source_cmd);
	install_element(OSPF_NODE, &ospf_redistribute_instance_source_cmd);
	install_element(OSPF_NODE, &no_ospf_redistribute_instance_source_cmd);

	install_element(OSPF_NODE, &ospf_distribute_list_out_cmd);
	install_element(OSPF_NODE, &no_ospf_distribute_list_out_cmd);

	install_element(OSPF_NODE, &ospf_default_information_originate_cmd);
	install_element(OSPF_NODE, &no_ospf_default_information_originate_cmd);

	install_element(OSPF_NODE, &ospf_default_metric_cmd);
	install_element(OSPF_NODE, &no_ospf_default_metric_cmd);

	install_element(OSPF_NODE, &ospf_distance_cmd);
	install_element(OSPF_NODE, &no_ospf_distance_cmd);
	install_element(OSPF_NODE, &no_ospf_distance_ospf_cmd);
	install_element(OSPF_NODE, &ospf_distance_ospf_cmd);

	/*Ospf garcefull restart helper configurations */
	install_element(OSPF_NODE, &ospf_gr_helper_enable_cmd);
	install_element(OSPF_NODE, &no_ospf_gr_helper_enable_cmd);
	install_element(OSPF_NODE, &ospf_gr_helper_enable_lsacheck_cmd);
	install_element(OSPF_NODE, &no_ospf_gr_helper_enable_lsacheck_cmd);
	install_element(OSPF_NODE, &ospf_gr_helper_supported_grace_time_cmd);
	install_element(OSPF_NODE, &no_ospf_gr_helper_supported_grace_time_cmd);
	install_element(OSPF_NODE, &ospf_gr_helper_planned_only_cmd);
	install_element(OSPF_NODE, &no_ospf_gr_helper_planned_only_cmd);

	/* External LSA summarisation config commands.*/
	install_element(OSPF_NODE, &ospf_external_route_aggregation_cmd);
	install_element(OSPF_NODE, &no_ospf_external_route_aggregation_cmd);
	install_element(OSPF_NODE,
			&ospf_external_route_aggregation_no_adrvertise_cmd);
	install_element(OSPF_NODE,
			&no_ospf_external_route_aggregation_no_adrvertise_cmd);
	install_element(OSPF_NODE, &ospf_route_aggregation_timer_cmd);
	install_element(OSPF_NODE, &no_ospf_route_aggregation_timer_cmd);
}

static int ospf_config_write(struct vty *vty);
static struct cmd_node ospf_node = {
	.name = "ospf",
	.node = OSPF_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-router)# ",
	.config_write = ospf_config_write,
};

static void ospf_interface_clear(struct interface *ifp)
{
	if (!if_is_operative(ifp))
		return;

	if (IS_DEBUG_OSPF(ism, ISM_EVENTS))
		zlog_debug("ISM[%s]: clear by reset", ifp->name);

	ospf_if_reset(ifp);
}

DEFUN (clear_ip_ospf_interface,
       clear_ip_ospf_interface_cmd,
       "clear ip ospf [vrf NAME] interface [IFNAME]",
       CLEAR_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "Interface information\n"
       "Interface name\n")
{
	int idx_ifname = 0;
	int idx_vrf = 0;
	struct interface *ifp;
	struct listnode *node;
	struct ospf *ospf = NULL;
	char *vrf_name = NULL;
	vrf_id_t vrf_id = VRF_DEFAULT;
	struct vrf *vrf = NULL;

	if (argv_find(argv, argc, "vrf", &idx_vrf))
		vrf_name = argv[idx_vrf + 1]->arg;
	if (vrf_name && strmatch(vrf_name, VRF_DEFAULT_NAME))
		vrf_name = NULL;
	if (vrf_name) {
		vrf = vrf_lookup_by_name(vrf_name);
		if (vrf)
			vrf_id = vrf->vrf_id;
	}
	if (!argv_find(argv, argc, "IFNAME", &idx_ifname)) {
		/* Clear all the ospfv2 interfaces. */
		for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
			if (vrf_id != ospf->vrf_id)
				continue;
			if (!vrf)
				vrf = vrf_lookup_by_id(ospf->vrf_id);
			FOR_ALL_INTERFACES (vrf, ifp)
				ospf_interface_clear(ifp);
		}
	} else {
		/* Interface name is specified. */
		ifp = if_lookup_by_name(argv[idx_ifname]->arg, vrf_id);
		if (ifp == NULL)
			vty_out(vty, "No such interface name\n");
		else
			ospf_interface_clear(ifp);
	}

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(ospf_lsa_refresh_timer, ospf_lsa_refresh_timer_cmd,
	     "[no$no] ospf lsa-refresh [(120-1800)]$value",
	     NO_STR OSPF_STR
	     "OSPF lsa refresh timer\n"
	     "timer value in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf)

	if (no)
		ospf->lsa_refresh_timer = OSPF_LS_REFRESH_TIME;
	else
		ospf->lsa_refresh_timer = value;

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(ospf_maxage_delay_timer, ospf_maxage_delay_timer_cmd,
	     "[no$no] ospf maxage-delay [(0-60)]$value",
	     NO_STR OSPF_STR
	     "OSPF lsa maxage delay timer\n"
	     "timer value in seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf)

	if (no)
		ospf->maxage_delay = OSPF_LSA_MAXAGE_REMOVE_DELAY_DEFAULT;
	else
		ospf->maxage_delay = value;

	EVENT_OFF(ospf->t_maxage);
	OSPF_TIMER_ON(ospf->t_maxage, ospf_maxage_lsa_remover,
		      ospf->maxage_delay);

	return CMD_SUCCESS;
}

/*
 * ------------------------------------------------------------------------*
 * Following is (vty) configuration functions for flood-reduction handling.
 * ------------------------------------------------------------------------
 */

DEFPY(flood_reduction, flood_reduction_cmd, "flood-reduction",
      "flood reduction feature\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf)
	struct ospf_area *area;
	struct listnode *node;

	/* Turn on the Flood Reduction feature for the router. */
	if (!ospf->fr_configured) {
		ospf->fr_configured = true;
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
			       "Flood Reduction: OFF -> ON");
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
			if (area) {
				ospf_area_update_fr_state(area);
				ospf_refresh_area_self_lsas(area);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFPY(flood_reduction_area, flood_reduction_area_cmd,
      "area <A.B.C.D|(0-4294967295)> flood-reduction",
      "OSPF area parameters\n"
      "OSPF area ID in IP address format\n"
      "OSPF area ID as a decimal value\n"
      "Enable flood reduction for area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf)
	struct ospf_area *oa;
	int idx = 1;
	int format;
	int ret;
	const char *areaid;
	struct in_addr area_id;

	areaid = argv[idx]->arg;

	ret = str2area_id(areaid, &area_id, &format);
	if (ret < 0) {
		vty_out(vty, "Please specify area by A.B.C.D|<0-4294967295>\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	oa = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!oa) {
		vty_out(vty, "OSPF area ID not present\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Turn on the Flood Reduction feature for the area. */
	if (!oa->fr_info.configured) {
		oa->fr_info.configured = true;
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
			       "Flood Reduction area %pI4 : OFF -> ON",
			       &oa->area_id);
		ospf_area_update_fr_state(oa);
		ospf_refresh_area_self_lsas(oa);
	}

	return CMD_SUCCESS;
}

DEFPY(no_flood_reduction, no_flood_reduction_cmd, "no flood-reduction",
      NO_STR "flood reduction feature\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf)
	struct listnode *node;
	struct ospf_area *area;

	/* Turn off the Flood Reduction feature for the router. */
	if (ospf->fr_configured) {
		ospf->fr_configured = false;
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
			       "Flood Reduction: ON -> OFF");
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
			if (area) {
				ospf_area_update_fr_state(area);
				ospf_refresh_area_self_lsas(area);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFPY(no_flood_reduction_area, no_flood_reduction_area_cmd,
      "no area <A.B.C.D|(0-4294967295)> flood-reduction",
      NO_STR
      "OSPF area parameters\n"
      "OSPF area ID in IP address format\n"
      "OSPF area ID as a decimal value\n"
      "Disable flood reduction for area\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf)
	struct ospf_area *oa;
	int idx = 2;
	int format;
	int ret;
	const char *areaid;
	struct in_addr area_id;

	areaid = argv[idx]->arg;

	ret = str2area_id(areaid, &area_id, &format);
	if (ret < 0) {
		vty_out(vty, "Please specify area by A.B.C.D|<0-4294967295>\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	oa = ospf_area_lookup_by_area_id(ospf, area_id);
	if (!oa) {
		vty_out(vty, "OSPF area ID not present\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Turn off the Flood Reduction feature for the area. */
	if (oa->fr_info.configured) {
		oa->fr_info.configured = false;
		OSPF_LOG_DEBUG(IS_DEBUG_OSPF_EVENT,
			       "Flood Reduction area %pI4 : ON -> OFF",
			       &oa->area_id);
		ospf_area_update_fr_state(oa);
		ospf_refresh_area_self_lsas(oa);
	}

	return CMD_SUCCESS;
}

DEFPY(ospf_socket_bufsizes,
      ospf_socket_bufsizes_cmd,
      "[no] socket buffer <send$send_val | recv$recv_val | all$all_val> \
	  ![(1-4000000000)$bufsize]",
      NO_STR
      "Socket parameters\n"
      "Buffer size configuration\n"
      "Send buffer size\n"
      "Receive buffer size\n"
      "Both send and receive buffer sizes\n"
      "Buffer size, in bytes\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	uint32_t recvsz, sendsz;

	if (no)
		bufsize = OSPF_DEFAULT_SOCK_BUFSIZE;

	if (all_val) {
		recvsz = bufsize;
		sendsz = bufsize;
	} else if (send_val) {
		sendsz = bufsize;
		recvsz = ospf->recv_sock_bufsize;
	} else if (recv_val) {
		recvsz = bufsize;
		sendsz = ospf->send_sock_bufsize;
	} else
		return CMD_SUCCESS;

	/* React to a change by modifying existing sockets */
	ospf_update_bufsize(ospf, recvsz, sendsz);

	return CMD_SUCCESS;
}

DEFPY (per_intf_socket,
       per_intf_socket_cmd,
       "[no] socket-per-interface",
       NO_STR
       "Use write socket per interface\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct listnode *node;
	struct ospf_interface *oi;

	if (no) {
		if (ospf->intf_socket_enabled) {
			ospf->intf_socket_enabled = false;

			/* Iterate and close any sockets */
			for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
				ospf_ifp_sock_close(oi->ifp);
		}
	} else if (!ospf->intf_socket_enabled) {
		ospf->intf_socket_enabled = true;

		/* Iterate and open sockets */
		for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi))
			ospf_ifp_sock_init(oi->ifp);
	}

	return CMD_SUCCESS;
}

void ospf_vty_clear_init(void)
{
	install_element(ENABLE_NODE, &clear_ip_ospf_interface_cmd);
	install_element(ENABLE_NODE, &clear_ip_ospf_process_cmd);
	install_element(ENABLE_NODE, &clear_ip_ospf_neighbor_cmd);
}


/* Install OSPF related vty commands. */
void ospf_vty_init(void)
{
	/* Install ospf top node. */
	install_node(&ospf_node);

	/* "router ospf" commands. */
	install_element(CONFIG_NODE, &router_ospf_cmd);
	install_element(CONFIG_NODE, &no_router_ospf_cmd);


	install_default(OSPF_NODE);

	/* "ospf router-id" commands. */
	install_element(OSPF_NODE, &ospf_router_id_cmd);
	install_element(OSPF_NODE, &ospf_router_id_old_cmd);
	install_element(OSPF_NODE, &no_ospf_router_id_cmd);
	install_element(OSPF_NODE, &no_router_id_cmd);

	/* "passive-interface" commands. */
	install_element(OSPF_NODE, &ospf_passive_interface_default_cmd);
	install_element(OSPF_NODE, &ospf_passive_interface_addr_cmd);
	install_element(OSPF_NODE, &no_ospf_passive_interface_default_cmd);
	install_element(OSPF_NODE, &no_ospf_passive_interface_addr_cmd);

	/* "ospf abr-type" commands. */
	install_element(OSPF_NODE, &ospf_abr_type_cmd);
	install_element(OSPF_NODE, &no_ospf_abr_type_cmd);

	/* "ospf log-adjacency-changes" commands. */
	install_element(OSPF_NODE, &ospf_log_adjacency_changes_cmd);
	install_element(OSPF_NODE, &ospf_log_adjacency_changes_detail_cmd);
	install_element(OSPF_NODE, &no_ospf_log_adjacency_changes_cmd);
	install_element(OSPF_NODE, &no_ospf_log_adjacency_changes_detail_cmd);

	/* "ospf rfc1583-compatible" commands. */
	install_element(OSPF_NODE, &ospf_compatible_rfc1583_cmd);
	install_element(OSPF_NODE, &no_ospf_compatible_rfc1583_cmd);
	install_element(OSPF_NODE, &ospf_rfc1583_flag_cmd);
	install_element(OSPF_NODE, &no_ospf_rfc1583_flag_cmd);

	/* "ospf send-extra-data zebra" commands. */
	install_element(OSPF_NODE, &ospf_send_extra_data_cmd);

	/* "network area" commands. */
	install_element(OSPF_NODE, &ospf_network_area_cmd);
	install_element(OSPF_NODE, &no_ospf_network_area_cmd);

	/* "area authentication" commands. */
	install_element(OSPF_NODE,
			&ospf_area_authentication_message_digest_cmd);
	install_element(OSPF_NODE, &ospf_area_authentication_cmd);
	install_element(OSPF_NODE, &no_ospf_area_authentication_cmd);

	/* "area range" commands.  */
	install_element(OSPF_NODE, &ospf_area_range_cmd);
	install_element(OSPF_NODE, &ospf_area_range_cost_cmd);
	install_element(OSPF_NODE, &ospf_area_range_not_advertise_cmd);
	install_element(OSPF_NODE, &no_ospf_area_range_cmd);
	install_element(OSPF_NODE, &no_ospf_area_range_substitute_cmd);

	/* "area virtual-link" commands. */
	install_element(OSPF_NODE, &ospf_area_vlink_cmd);
	install_element(OSPF_NODE, &ospf_area_vlink_intervals_cmd);
	install_element(OSPF_NODE, &no_ospf_area_vlink_cmd);
	install_element(OSPF_NODE, &no_ospf_area_vlink_intervals_cmd);


	/* "area stub" commands. */
	install_element(OSPF_NODE, &ospf_area_stub_no_summary_cmd);
	install_element(OSPF_NODE, &ospf_area_stub_cmd);
	install_element(OSPF_NODE, &no_ospf_area_stub_no_summary_cmd);
	install_element(OSPF_NODE, &no_ospf_area_stub_cmd);

	/* "area nssa" commands. */
	install_element(OSPF_NODE, &ospf_area_nssa_cmd);
	install_element(OSPF_NODE, &no_ospf_area_nssa_cmd);
	install_element(OSPF_NODE, &ospf_area_nssa_range_cmd);
	install_element(OSPF_NODE, &no_ospf_area_nssa_range_cmd);

	install_element(OSPF_NODE, &ospf_area_default_cost_cmd);
	install_element(OSPF_NODE, &no_ospf_area_default_cost_cmd);

	install_element(OSPF_NODE, &ospf_area_shortcut_cmd);
	install_element(OSPF_NODE, &no_ospf_area_shortcut_cmd);

	install_element(OSPF_NODE, &ospf_area_export_list_cmd);
	install_element(OSPF_NODE, &no_ospf_area_export_list_cmd);

	install_element(OSPF_NODE, &ospf_area_filter_list_cmd);
	install_element(OSPF_NODE, &no_ospf_area_filter_list_cmd);

	install_element(OSPF_NODE, &ospf_area_import_list_cmd);
	install_element(OSPF_NODE, &no_ospf_area_import_list_cmd);

	/* SPF timer commands */
	install_element(OSPF_NODE, &ospf_timers_throttle_spf_cmd);
	install_element(OSPF_NODE, &no_ospf_timers_throttle_spf_cmd);

	/* LSA timers commands */
	install_element(OSPF_NODE, &ospf_timers_min_ls_interval_cmd);
	install_element(OSPF_NODE, &ospf_timers_lsa_min_arrival_cmd);
	install_element(OSPF_NODE, &ospf_timers_lsa_min_arrival_deprecated_cmd);

	/* refresh timer commands */
	install_element(OSPF_NODE, &ospf_refresh_timer_cmd);
	install_element(OSPF_NODE, &no_ospf_refresh_timer_val_cmd);

	/* max-metric commands */
	install_element(OSPF_NODE, &ospf_max_metric_router_lsa_admin_cmd);
	install_element(OSPF_NODE, &no_ospf_max_metric_router_lsa_admin_cmd);
	install_element(OSPF_NODE, &ospf_max_metric_router_lsa_startup_cmd);
	install_element(OSPF_NODE, &no_ospf_max_metric_router_lsa_startup_cmd);
	install_element(OSPF_NODE, &ospf_max_metric_router_lsa_shutdown_cmd);
	install_element(OSPF_NODE, &no_ospf_max_metric_router_lsa_shutdown_cmd);

	/* reference bandwidth commands */
	install_element(OSPF_NODE, &ospf_auto_cost_reference_bandwidth_cmd);
	install_element(OSPF_NODE, &no_ospf_auto_cost_reference_bandwidth_cmd);

	/* "neighbor" command. */
	install_element(OSPF_NODE, &ospf_neighbor_cmd);

	/* write multiplier commands */
	install_element(OSPF_NODE, &ospf_write_multiplier_cmd);
	install_element(OSPF_NODE, &write_multiplier_cmd);
	install_element(OSPF_NODE, &no_ospf_write_multiplier_cmd);
	install_element(OSPF_NODE, &no_write_multiplier_cmd);

	/* "proactive-arp" commands. */
	install_element(OSPF_NODE, &ospf_proactive_arp_cmd);
	install_element(OSPF_NODE, &no_ospf_proactive_arp_cmd);

	/* TI-LFA commands */
	install_element(OSPF_NODE, &ospf_ti_lfa_cmd);
	install_element(OSPF_NODE, &no_ospf_ti_lfa_cmd);

	/* Max path configurations */
	install_element(OSPF_NODE, &ospf_max_multipath_cmd);
	install_element(OSPF_NODE, &no_ospf_max_multipath_cmd);

	vrf_cmd_init(NULL);

	install_element(OSPF_NODE, &ospf_lsa_refresh_timer_cmd);
	install_element(OSPF_NODE, &ospf_maxage_delay_timer_cmd);

	/* Flood Reduction commands */
	install_element(OSPF_NODE, &flood_reduction_cmd);
	install_element(OSPF_NODE, &no_flood_reduction_cmd);
	install_element(OSPF_NODE, &flood_reduction_area_cmd);
	install_element(OSPF_NODE, &no_flood_reduction_area_cmd);

	install_element(OSPF_NODE, &ospf_socket_bufsizes_cmd);
	install_element(OSPF_NODE, &per_intf_socket_cmd);

	/* Init interface related vty commands. */
	ospf_vty_if_init();

	/* Init zebra related vty commands. */
	ospf_vty_zebra_init();
}
