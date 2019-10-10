/* OSPF VTY interface.
 * Copyright (C) 2005 6WIND <alain.ritoux@6wind.com>
 * Copyright (C) 2000 Toshiaki Takada
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
#include <string.h>

#include "monotime.h"
#include "memory.h"
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include <lib/json.h>
#include "defaults.h"

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
/*#include "ospfd/ospf_routemap.h" */
#include "ospfd/ospf_vty.h"
#include "ospfd/ospf_dump.h"
#include "ospfd/ospf_bfd.h"

static const char *ospf_network_type_str[] = {
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
		sprintf(buf, "%lu", (unsigned long)ntohl(area_id->s_addr));
}

static int str2metric(const char *str, int *metric)
{
	/* Sanity check. */
	if (str == NULL)
		return 0;

	*metric = strtol(str, NULL, 10);
	if (*metric < 0 && *metric > 16777214) {
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

static struct ospf *ospf_cmd_lookup_ospf(struct vty *vty,
					 struct cmd_token *argv[],
					 const int argc, uint32_t enable,
					 unsigned short *instance)
{
	struct ospf *ospf = NULL;
	int idx_vrf = 0, idx_inst = 0;
	const char *vrf_name = NULL;

	*instance = 0;
	if (argv_find(argv, argc, "(1-65535)", &idx_inst))
		*instance = strtoul(argv[idx_inst]->arg, NULL, 10);

	if (argv_find(argv, argc, "vrf", &idx_vrf)) {
		vrf_name = argv[idx_vrf + 1]->arg;
		if (vrf_name == NULL || strmatch(vrf_name, VRF_DEFAULT_NAME))
			vrf_name = NULL;
		if (enable) {
			/* Allocate VRF aware instance */
			ospf = ospf_get(*instance, vrf_name);
		} else {
			ospf = ospf_lookup_by_inst_name(*instance, vrf_name);
		}
	} else {
		if (enable) {
			ospf = ospf_get(*instance, NULL);
		} else {
			ospf = ospf_lookup_instance(*instance);
		}
	}

	return ospf;
}

static void ospf_show_vrf_name(struct ospf *ospf, struct vty *vty,
			       json_object *json, uint8_t use_vrf)
{
	if (use_vrf) {
		if (json) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_string_add(json, "vrfName",
						       "default");
			else
				json_object_string_add(json, "vrfName",
						       ospf->name);
			json_object_int_add(json, "vrfId", ospf->vrf_id);
		} else {
			if (ospf->vrf_id == VRF_DEFAULT)
				vty_out(vty, "VRF Name: %s\n", "default");
			else if (ospf->name)
				vty_out(vty, "VRF Name: %s\n", ospf->name);
		}
	}
}

#ifndef VTYSH_EXTRACT_PL
#include "ospfd/ospf_vty_clippy.c"
#endif

DEFUN_NOSH (router_ospf,
       router_ospf_cmd,
       "router ospf [{(1-65535)|vrf NAME}]",
       "Enable a routing process\n"
       "Start OSPF configuration\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR)
{
	struct ospf *ospf = NULL;
	int ret = CMD_SUCCESS;
	unsigned short instance = 0;
	struct vrf *vrf = NULL;
	struct route_node *rn;
	struct interface *ifp;

	ospf = ospf_cmd_lookup_ospf(vty, argv, argc, 1, &instance);
	if (!ospf)
		return CMD_WARNING_CONFIG_FAILED;

	/* The following logic to set the vty qobj index is in place to be able
	   to ignore the commands which dont belong to this instance. */
	if (ospf->instance != instance) {
		VTY_PUSH_CONTEXT_NULL(OSPF_NODE);
		ret = CMD_NOT_MY_INSTANCE;
	} else {
		if (ospf->vrf_id != VRF_UNKNOWN)
			ospf->oi_running = 1;
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"Config command 'router ospf %d' received, vrf %s id %u oi_running %u",
				instance, ospf->name ? ospf->name : "NIL",
				ospf->vrf_id, ospf->oi_running);
		VTY_PUSH_CONTEXT(OSPF_NODE, ospf);

		/* Activate 'ip ospf area x' configured interfaces for given
		 * vrf. Activate area on vrf x aware interfaces.
		 * vrf_enable callback calls router_id_update which
		 * internally will call ospf_if_update to trigger
		 * network_run_state
		 */
		vrf = vrf_lookup_by_id(ospf->vrf_id);

		FOR_ALL_INTERFACES (vrf, ifp) {
			struct ospf_if_params *params;

			params = IF_DEF_PARAMS(ifp);
			if (OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
				for (rn = route_top(ospf->networks); rn;
				     rn = route_next(rn)) {
					if (rn->info != NULL) {
						vty_out(vty,
							"Interface %s has area config but please remove all network commands first.\n",
							ifp->name);
						return ret;
					}
				}
				if (!ospf_interface_area_is_already_set(ospf,
									ifp)) {
					ospf_interface_area_set(ospf, ifp);
					ospf->if_ospf_cli_count++;
				}
			}
		}

		ospf_router_id_update(ospf);
	}

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
	struct ospf *ospf;
	unsigned short instance = 0;

	ospf = ospf_cmd_lookup_ospf(vty, argv, argc, 0, &instance);
	if (ospf == NULL) {
		if (instance)
			return CMD_NOT_MY_INSTANCE;
		else
			return CMD_WARNING;
	}
	ospf_finish(ospf);

	return CMD_SUCCESS;
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
				"For this router-id change to take effect,"
				" save config and restart ospfd\n");
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
				"For this router-id change to take effect,"
				" save config and restart ospfd\n");
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
				"For this router-id change to take effect,"
				" save config and restart ospfd\n");
			return CMD_SUCCESS;
		}

	ospf_router_id_update(ospf);

	return CMD_SUCCESS;
}


static void ospf_passive_interface_default(struct ospf *ospf, uint8_t newval)
{
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct listnode *ln;
	struct interface *ifp;
	struct ospf_interface *oi;

	ospf->passive_interface_default = newval;

	FOR_ALL_INTERFACES (vrf, ifp) {
		if (ifp && OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(ifp),
						    passive_interface))
			UNSET_IF_PARAM(IF_DEF_PARAMS(ifp), passive_interface);
	}
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, ln, oi)) {
		if (OSPF_IF_PARAM_CONFIGURED(oi->params, passive_interface))
			UNSET_IF_PARAM(oi->params, passive_interface);
		/* update multicast memberships */
		ospf_if_set_multicast(oi);
	}
}

static void ospf_passive_interface_update_addr(struct ospf *ospf,
					       struct interface *ifp,
					       struct ospf_if_params *params,
					       uint8_t value,
					       struct in_addr addr)
{
	uint8_t dflt;

	params->passive_interface = value;
	if (params != IF_DEF_PARAMS(ifp)) {
		if (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(ifp),
					     passive_interface))
			dflt = IF_DEF_PARAMS(ifp)->passive_interface;
		else
			dflt = ospf->passive_interface_default;

		if (value != dflt)
			SET_IF_PARAM(params, passive_interface);
		else
			UNSET_IF_PARAM(params, passive_interface);

		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}
}

static void ospf_passive_interface_update(struct ospf *ospf,
					  struct interface *ifp,
					  struct ospf_if_params *params,
					  uint8_t value)
{
	params->passive_interface = value;
	if (params == IF_DEF_PARAMS(ifp)) {
		if (value != ospf->passive_interface_default)
			SET_IF_PARAM(params, passive_interface);
		else
			UNSET_IF_PARAM(params, passive_interface);
	}
}

DEFUN (ospf_passive_interface,
       ospf_passive_interface_addr_cmd,
       "passive-interface <IFNAME [A.B.C.D]|default>",
       "Suppress routing updates on an interface\n"
       "Interface's name\n"
       "IPv4 address\n"
       "Suppress routing updates on interfaces by default\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 2;
	struct interface *ifp = NULL;
	struct in_addr addr = {.s_addr = INADDR_ANY};
	int ret;
	struct ospf_if_params *params;
	struct route_node *rn;

	if (strmatch(argv[1]->text, "default")) {
		ospf_passive_interface_default(ospf, OSPF_IF_PASSIVE);
		return CMD_SUCCESS;
	}
	if (ospf->vrf_id != VRF_UNKNOWN)
		ifp = if_get_by_name(argv[1]->arg, ospf->vrf_id);

	if (ifp == NULL) {
		vty_out(vty, "interface %s not found.\n", (char *)argv[1]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	params = IF_DEF_PARAMS(ifp);

	if (argc == 3) {
		ret = inet_aton(argv[idx_ipv4]->arg, &addr);
		if (!ret) {
			vty_out(vty,
				"Please specify interface address by A.B.C.D\n");
			return CMD_WARNING_CONFIG_FAILED;
		}

		params = ospf_get_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
		ospf_passive_interface_update_addr(ospf, ifp, params,
						   OSPF_IF_PASSIVE, addr);
	}

	ospf_passive_interface_update(ospf, ifp, params, OSPF_IF_PASSIVE);

	/* XXX We should call ospf_if_set_multicast on exactly those
	 * interfaces for which the passive property changed.  It is too much
	 * work to determine this set, so we do this for every interface.
	 * This is safe and reasonable because ospf_if_set_multicast uses a
	 * record of joined groups to avoid systems calls if the desired
	 * memberships match the current memership.
	 */

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi && (OSPF_IF_PARAM(oi, passive_interface)
			   == OSPF_IF_PASSIVE))
			ospf_if_set_multicast(oi);
	}
	/*
	 * XXX It is not clear what state transitions the interface needs to
	 * undergo when going from active to passive.  Fixing this will
	 * require precise identification of interfaces having such a
	 * transition.
	 */

	return CMD_SUCCESS;
}

DEFUN (no_ospf_passive_interface,
       no_ospf_passive_interface_addr_cmd,
       "no passive-interface <IFNAME [A.B.C.D]|default>",
       NO_STR
       "Allow routing updates on an interface\n"
       "Interface's name\n"
       "IPv4 address\n"
       "Allow routing updates on interfaces by default\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 3;
	struct interface *ifp = NULL;
	struct in_addr addr = {.s_addr = INADDR_ANY};
	struct ospf_if_params *params;
	int ret;
	struct route_node *rn;

	if (strmatch(argv[2]->text, "default")) {
		ospf_passive_interface_default(ospf, OSPF_IF_ACTIVE);
		return CMD_SUCCESS;
	}

	if (ospf->vrf_id != VRF_UNKNOWN)
		ifp = if_get_by_name(argv[2]->arg, ospf->vrf_id);

	if (ifp == NULL) {
		vty_out(vty, "interface %s not found.\n", (char *)argv[2]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	params = IF_DEF_PARAMS(ifp);

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
		ospf_passive_interface_update_addr(ospf, ifp, params,
						   OSPF_IF_ACTIVE, addr);
	}
	ospf_passive_interface_update(ospf, ifp, params, OSPF_IF_ACTIVE);

	/* XXX We should call ospf_if_set_multicast on exactly those
	 * interfaces for which the passive property changed.  It is too much
	 * work to determine this set, so we do this for every interface.
	 * This is safe and reasonable because ospf_if_set_multicast uses a
	 * record of joined groups to avoid systems calls if the desired
	 * memberships match the current memership.
	 */
	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (oi
		    && (OSPF_IF_PARAM(oi, passive_interface) == OSPF_IF_ACTIVE))
			ospf_if_set_multicast(oi);
	}

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

	if (ospf->instance) {
		vty_out(vty,
			"The network command is not supported in multi-instance ospf\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (ospf->if_ospf_cli_count > 0) {
		vty_out(vty,
			"Please remove all ip ospf area x.x.x.x commands first.\n");
		if (IS_DEBUG_OSPF_EVENT)
			zlog_debug(
				"%s ospf vrf %s num of %u ip osp area x config",
				__PRETTY_FUNCTION__,
				ospf->name ? ospf->name : "NIL",
				ospf->if_ospf_cli_count);
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
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	int idx_cost = 6;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;
	uint32_t cost;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	ospf_area_range_set(ospf, area_id, &p, OSPF_AREA_RANGE_ADVERTISE);
	if (argc > 5) {
		cost = strtoul(argv[idx_cost]->arg, NULL, 10);
		ospf_area_range_cost_set(ospf, area_id, &p, cost);
	}

	return CMD_SUCCESS;
}

DEFUN (ospf_area_range_cost,
       ospf_area_range_cost_cmd,
       "area <A.B.C.D|(0-4294967295)> range A.B.C.D/M cost (0-16777215)",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "User specified metric for this range\n"
       "Advertised metric for this range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	int idx_cost = 5;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;
	uint32_t cost;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	ospf_area_range_set(ospf, area_id, &p, OSPF_AREA_RANGE_ADVERTISE);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);

	cost = strtoul(argv[idx_cost]->arg, NULL, 10);
	ospf_area_range_cost_set(ospf, area_id, &p, cost);

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
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	ospf_area_range_set(ospf, area_id, &p, 0);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	ospf_area_range_substitute_unset(ospf, area_id, &p);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_range,
       no_ospf_area_range_cmd,
       "no area <A.B.C.D|(0-4294967295)> range A.B.C.D/M [<cost (0-16777215)|advertise [cost (0-16777215)]|not-advertise>]",
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
	int idx_ipv4_number = 2;
	int idx_ipv4_prefixlen = 4;
	struct prefix_ipv4 p;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);

	ospf_area_range_unset(ospf, area_id, &p);

	return CMD_SUCCESS;
}

DEFUN (ospf_area_range_substitute,
       ospf_area_range_substitute_cmd,
       "area <A.B.C.D|(0-4294967295)> range A.B.C.D/M substitute A.B.C.D/M",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Summarize routes matching address/mask (border routers only)\n"
       "Area range prefix\n"
       "Announce area range as another prefix\n"
       "Network prefix to be announced instead of range\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 1;
	int idx_ipv4_prefixlen = 3;
	int idx_ipv4_prefixlen_2 = 5;
	struct prefix_ipv4 p, s;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen_2]->arg, &s);

	ospf_area_range_substitute_set(ospf, area_id, &p, &s);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);

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
	int idx_ipv4_number = 2;
	int idx_ipv4_prefixlen = 4;
	int idx_ipv4_prefixlen_2 = 6;
	struct prefix_ipv4 p, s;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID(area_id, format, argv[idx_ipv4_number]->arg);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen]->arg, &p);
	str2prefix_ipv4(argv[idx_ipv4_prefixlen_2]->arg, &s);

	ospf_area_range_substitute_unset(ospf, area_id, &p);

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
	int hello_interval;     /* Obvious what these are... */
	int retransmit_interval;
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
			vty_out(vty, "Area %s is %s\n", inet_ntoa(area_id),
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

#define VLINK_HELPSTR_TIME_PARAM                                               \
	"Time between HELLO packets\n"                                         \
	"Seconds\n"                                                            \
	"Time between retransmitting lost link state advertisements\n"         \
	"Seconds\n"                                                            \
	"Link state transmit delay\n"                                          \
	"Seconds\n"                                                            \
	"Interval time after which a neighbor is declared down\n"              \
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
       "area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D [authentication [<message-digest|null>]] [<message-digest-key (1-255) md5 KEY|authentication-key AUTH_KEY>]",
       VLINK_HELPSTR_IPADDR
       "Enable authentication on this virtual link\n"
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

	if (argv_find(argv, argc, "message-digest", &idx)) {
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
       "no area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D [authentication [<message-digest|null>]] [<message-digest-key (1-255) md5 KEY|authentication-key AUTH_KEY>]",
       NO_STR
       VLINK_HELPSTR_IPADDR
       "Enable authentication on this virtual link\n" \
       "Use message-digest authentication\n" \
       "Use null authentication\n" \
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
       "area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D {hello-interval (1-65535)|retransmit-interval (1-65535)|transmit-delay (1-65535)|dead-interval (1-65535)}",
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
       "no area <A.B.C.D|(0-4294967295)> virtual-link A.B.C.D {hello-interval (1-65535)|retransmit-interval (1-65535)|transmit-delay (1-65535)|dead-interval (1-65535)}",
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
			"Shortcut area setting will take effect "
			"only when the router is configured as Shortcut ABR\n");

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_shortcut,
       no_ospf_area_shortcut_cmd,
       "no area <A.B.C.D|(0-4294967295)> shortcut <enable|disable>",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Deconfigure the area's shortcutting mode\n"
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

static int ospf_area_nssa_cmd_handler(struct vty *vty, int argc,
				      struct cmd_token **argv, int cfg_nosum,
				      int nosum)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	struct in_addr area_id;
	int ret, format;

	VTY_GET_OSPF_AREA_ID_NO_BB("NSSA", area_id, format, argv[1]->arg);

	ret = ospf_area_nssa_set(ospf, area_id);
	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	if (ret == 0) {
		vty_out(vty,
			"%% Area cannot be nssa as it contains a virtual link\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc > 3) {
		if (strncmp(argv[3]->text, "translate-c", 11) == 0)
			ospf_area_nssa_translator_role_set(
				ospf, area_id, OSPF_NSSA_ROLE_CANDIDATE);
		else if (strncmp(argv[3]->text, "translate-n", 11) == 0)
			ospf_area_nssa_translator_role_set(
				ospf, area_id, OSPF_NSSA_ROLE_NEVER);
		else if (strncmp(argv[3]->text, "translate-a", 11) == 0)
			ospf_area_nssa_translator_role_set(
				ospf, area_id, OSPF_NSSA_ROLE_ALWAYS);
	} else {
		ospf_area_nssa_translator_role_set(ospf, area_id,
						   OSPF_NSSA_ROLE_CANDIDATE);
	}

	if (cfg_nosum) {
		if (nosum)
			ospf_area_no_summary_set(ospf, area_id);
		else
			ospf_area_no_summary_unset(ospf, area_id);
	}

	ospf_schedule_abr_task(ospf);

	return CMD_SUCCESS;
}


DEFUN (ospf_area_nssa_translate,
       ospf_area_nssa_translate_cmd,
       "area <A.B.C.D|(0-4294967295)> nssa <translate-candidate|translate-never|translate-always>",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Configure NSSA-ABR for translate election (default)\n"
       "Configure NSSA-ABR to never translate\n"
       "Configure NSSA-ABR to always translate\n")
{
	return ospf_area_nssa_cmd_handler(vty, argc, argv, 0, 0);
}

DEFUN (ospf_area_nssa,
       ospf_area_nssa_cmd,
       "area <A.B.C.D|(0-4294967295)> nssa",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n")
{
	return ospf_area_nssa_cmd_handler(vty, argc, argv, 0, 0);
}

DEFUN (ospf_area_nssa_no_summary,
       ospf_area_nssa_no_summary_cmd,
       "area <A.B.C.D|(0-4294967295)> nssa no-summary",
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")
{
	int idx_ipv4_number = 1;
	struct in_addr area_id;
	int format;

	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	VTY_GET_OSPF_AREA_ID_NO_BB("NSSA", area_id, format,
				   argv[idx_ipv4_number]->arg);

	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	ospf_area_nssa_no_summary_set(ospf, area_id);

	ospf_schedule_abr_task(ospf);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_nssa_no_summary,
       no_ospf_area_nssa_no_summary_cmd,
       "no area <A.B.C.D|(0-4294967295)> nssa no-summary",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Do not inject inter-area routes into nssa\n")
{
	int idx_ipv4_number = 2;
	struct in_addr area_id;
	int format;

	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	VTY_GET_OSPF_AREA_ID_NO_BB("nssa", area_id, format,
				   argv[idx_ipv4_number]->arg);

	ospf_area_display_format_set(ospf, ospf_area_get(ospf, area_id),
				     format);
	ospf_area_no_summary_unset(ospf, area_id);

	ospf_schedule_abr_task(ospf);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_nssa,
       no_ospf_area_nssa_cmd,
       "no area <A.B.C.D|(0-4294967295)> nssa [<translate-candidate|translate-never|translate-always>]",
       NO_STR
       "OSPF area parameters\n"
       "OSPF area ID in IP address format\n"
       "OSPF area ID as a decimal value\n"
       "Configure OSPF area as nssa\n"
       "Configure NSSA-ABR for translate election (default)\n"
       "Configure NSSA-ABR to never translate\n"
       "Configure NSSA-ABR to always translate\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4_number = 2;
	struct in_addr area_id;
	int format;

	VTY_GET_OSPF_AREA_ID_NO_BB("NSSA", area_id, format,
				   argv[idx_ipv4_number]->arg);

	ospf_area_nssa_unset(ospf, area_id, argc);

	ospf_schedule_abr_task(ospf);

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
			"ospf_abr_announce_stub_defaults(): "
			"announcing 0.0.0.0/0 to area %s",
			inet_ntoa(area->area_id));
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_area_default_cost,
       no_ospf_area_default_cost_cmd,
       "no area <A.B.C.D|(0-4294967295)> default-cost (0-16777215)",
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
			"ospf_abr_announce_stub_defaults(): "
			"announcing 0.0.0.0/0 to area %s",
			inet_ntoa(area->area_id));
	ospf_abr_announce_network_to_area(&p, area->default_cost, area);


	ospf_area_check_free(ospf, area_id);

	return CMD_SUCCESS;
}

DEFUN (ospf_area_export_list,
       ospf_area_export_list_cmd,
       "area <A.B.C.D|(0-4294967295)> export-list NAME",
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
       "no area <A.B.C.D|(0-4294967295)> export-list NAME",
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
       "area <A.B.C.D|(0-4294967295)> import-list NAME",
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
       "no area <A.B.C.D|(0-4294967295)> import-list NAME",
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
       "area <A.B.C.D|(0-4294967295)> filter-list prefix WORD <in|out>",
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
       "no area <A.B.C.D|(0-4294967295)> filter-list prefix WORD <in|out>",
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
	}

	return CMD_SUCCESS;
}

DEFUN (no_ospf_abr_type,
       no_ospf_abr_type_cmd,
       "no ospf abr-type <cisco|ibm|shortcut|standard>",
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

static int ospf_timers_spf_set(struct vty *vty, unsigned int delay,
			       unsigned int hold, unsigned int max)
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->spf_delay = delay;
	ospf->spf_holdtime = hold;
	ospf->spf_max_holdtime = max;

	return CMD_SUCCESS;
}

DEFUN (ospf_timers_min_ls_interval,
       ospf_timers_min_ls_interval_cmd,
       "timers throttle lsa all (0-5000)",
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "LSA delay between transmissions\n"
       "All LSA types\n"
       "Delay (msec) between sending LSAs\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_number = 4;
	unsigned int interval;

	if (argc < 5) {
		vty_out(vty, "Insufficient arguments\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	interval = strtoul(argv[idx_number]->arg, NULL, 10);

	ospf->min_ls_interval = interval;

	return CMD_SUCCESS;
}

DEFUN (no_ospf_timers_min_ls_interval,
       no_ospf_timers_min_ls_interval_cmd,
       "no timers throttle lsa all [(0-5000)]",
       NO_STR
       "Adjust routing timers\n"
       "Throttling adaptive timer\n"
       "LSA delay between transmissions\n"
       "All LSA types\n"
       "Delay (msec) between sending LSAs\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	ospf->min_ls_interval = OSPF_MIN_LS_INTERVAL;

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


DEFUN (ospf_timers_lsa_min_arrival,
       ospf_timers_lsa_min_arrival_cmd,
       "timers lsa min-arrival (0-600000)",
       "Adjust routing timers\n"
       "OSPF LSA timers\n"
       "Minimum delay in receiving new version of a LSA\n"
       "Delay in milliseconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	ospf->min_ls_arrival = strtoul(argv[argc - 1]->arg, NULL, 10);
	return CMD_SUCCESS;
}

DEFUN (no_ospf_timers_lsa_min_arrival,
       no_ospf_timers_lsa_min_arrival_cmd,
       "no timers lsa min-arrival [(0-600000)]",
       NO_STR
       "Adjust routing timers\n"
       "OSPF LSA timers\n"
       "Minimum delay in receiving new version of a LSA\n"
       "Delay in milliseconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	unsigned int minarrival;

	if (argc > 4) {
		minarrival = strtoul(argv[argc - 1]->arg, NULL, 10);

		if (ospf->min_ls_arrival != minarrival
		    || minarrival == OSPF_MIN_LS_ARRIVAL)
			return CMD_SUCCESS;
	}

	ospf->min_ls_arrival = OSPF_MIN_LS_ARRIVAL;

	return CMD_SUCCESS;
}

DEFUN (ospf_neighbor,
       ospf_neighbor_cmd,
       "neighbor A.B.C.D [priority (0-255) [poll-interval (1-65535)]]",
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 1;
	int idx_pri = 3;
	int idx_poll = 5;
	struct in_addr nbr_addr;
	unsigned int priority = OSPF_NEIGHBOR_PRIORITY_DEFAULT;
	unsigned int interval = OSPF_POLL_INTERVAL_DEFAULT;

	if (!inet_aton(argv[idx_ipv4]->arg, &nbr_addr)) {
		vty_out(vty, "Please specify Neighbor ID by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argc > 2)
		priority = strtoul(argv[idx_pri]->arg, NULL, 10);

	if (argc > 4)
		interval = strtoul(argv[idx_poll]->arg, NULL, 10);

	ospf_nbr_nbma_set(ospf, nbr_addr);

	if (argc > 2)
		ospf_nbr_nbma_priority_set(ospf, nbr_addr, priority);

	if (argc > 4)
		ospf_nbr_nbma_poll_interval_set(ospf, nbr_addr, interval);

	return CMD_SUCCESS;
}

DEFUN (ospf_neighbor_poll_interval,
       ospf_neighbor_poll_interval_cmd,
       "neighbor A.B.C.D poll-interval (1-65535) [priority (0-255)]",
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n"
       "OSPF priority of non-broadcast neighbor\n"
       "Priority\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 1;
	int idx_poll = 3;
	int idx_pri = 5;
	struct in_addr nbr_addr;
	unsigned int priority;
	unsigned int interval;

	if (!inet_aton(argv[idx_ipv4]->arg, &nbr_addr)) {
		vty_out(vty, "Please specify Neighbor ID by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	interval = strtoul(argv[idx_poll]->arg, NULL, 10);

	priority = argc > 4 ? strtoul(argv[idx_pri]->arg, NULL, 10)
			    : OSPF_NEIGHBOR_PRIORITY_DEFAULT;

	ospf_nbr_nbma_set(ospf, nbr_addr);
	ospf_nbr_nbma_poll_interval_set(ospf, nbr_addr, interval);

	if (argc > 4)
		ospf_nbr_nbma_priority_set(ospf, nbr_addr, priority);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_neighbor,
       no_ospf_neighbor_cmd,
       "no neighbor A.B.C.D [priority (0-255) [poll-interval (1-65525)]]",
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Neighbor Priority\n"
       "Priority\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 2;
	struct in_addr nbr_addr;

	if (!inet_aton(argv[idx_ipv4]->arg, &nbr_addr)) {
		vty_out(vty, "Please specify Neighbor ID by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	(void)ospf_nbr_nbma_unset(ospf, nbr_addr);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_neighbor_poll,
       no_ospf_neighbor_poll_cmd,
       "no neighbor A.B.C.D poll-interval (1-65535) [priority (0-255)]",
       NO_STR
       NEIGHBOR_STR
       "Neighbor IP address\n"
       "Dead Neighbor Polling interval\n"
       "Seconds\n"
       "Neighbor Priority\n"
       "Priority\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);
	int idx_ipv4 = 2;
	struct in_addr nbr_addr;

	if (!inet_aton(argv[idx_ipv4]->arg, &nbr_addr)) {
		vty_out(vty, "Please specify Neighbor ID by A.B.C.D\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	(void)ospf_nbr_nbma_unset(ospf, nbr_addr);

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
       "no ospf write-multiplier (1-100)",
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
      "no write-multiplier (1-100)", NO_STR
      "Write multiplier\n"
      "Maximum number of interface serviced per write\n")

const char *ospf_abr_type_descr_str[] = {"Unknown", "Standard (RFC2328)",
					 "Alternative IBM", "Alternative Cisco",
					 "Alternative Shortcut"};

const char *ospf_shortcut_mode_descr_str[] = {"Default", "Enabled", "Disabled"};

static void show_ip_ospf_area(struct vty *vty, struct ospf_area *area,
			      json_object *json_areas, bool use_json)
{
	json_object *json_area = NULL;

	if (use_json)
		json_area = json_object_new_object();

	/* Show Area ID. */
	if (!use_json)
		vty_out(vty, " Area ID: %s", inet_ntoa(area->area_id));

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
			"   Number of interfaces in this area: Total: %d, "
			"Active: %d\n",
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
				"   It is an NSSA configuration. \n   Elected NSSA/ABR performs type-7/type-5 LSA translation. \n");
			if (!IS_OSPF_ABR(area->ospf))
				vty_out(vty,
					"   It is not ABR, therefore not Translator. \n");
			else if (area->NSSATranslatorState) {
				vty_out(vty, "   We are an ABR and ");
				if (area->NSSATranslatorRole
				    == OSPF_NSSA_ROLE_CANDIDATE)
					vty_out(vty,
						"the NSSA Elected Translator. \n");
				else if (area->NSSATranslatorRole
					 == OSPF_NSSA_ROLE_ALWAYS)
					vty_out(vty,
						"always an NSSA Translator. \n");
			} else {
				vty_out(vty, "   We are an ABR, but ");
				if (area->NSSATranslatorRole
				    == OSPF_NSSA_ROLE_CANDIDATE)
					vty_out(vty,
						"not the NSSA Elected Translator. \n");
				else
					vty_out(vty,
						"never an NSSA Translator. \n");
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
			"   Number of fully adjacent neighbors in this area:"
			" %d\n",
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
				"   Number of full virtual adjacencies going through"
				" this area: %d\n",
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

	if (use_json)
		json_object_object_add(json_areas, inet_ntoa(area->area_id),
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
		json_object_string_add(json_vrf, "routerId",
				       inet_ntoa(ospf->router_id));
	} else {
		vty_out(vty, " OSPF Routing Process, Router ID: %s\n",
			inet_ntoa(ospf->router_id));
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
				" This router is an ASBR "
				"(injecting external routing information)\n");
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
	/* Show each area status. */
	for (ALL_LIST_ELEMENTS(ospf->areas, node, nnode, area))
		show_ip_ospf_area(vty, area, json_areas, json ? 1 : 0);

	if (json) {
		if (use_vrf) {
			json_object_object_add(json_vrf, "areas", json_areas);
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
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
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else if (!ospf_output)
				vty_out(vty, "%% OSPF instance not found\n");
			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if ((ospf == NULL) || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

			return CMD_SUCCESS;
		}
	} else {
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		/* Display default ospf (instance 0) info */
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_common(vty, ospf, json, 0);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return ret;
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
				json_object_string_add(
					json_interface_sub, "ipAddress",
					inet_ntoa(oi->address->u.prefix4));
				json_object_int_add(json_interface_sub,
						    "ipAddressPrefixlen",
						    oi->address->prefixlen);
			} else
				vty_out(vty, "  Internet Address %s/%d,",
					inet_ntoa(oi->address->u.prefix4),
					oi->address->prefixlen);

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
				json_object_string_add(
					json_interface_sub,
					"ospfIfType", dstr);
				if (oi->type == OSPF_IFTYPE_VIRTUALLINK)
					json_object_string_add(
						json_interface_sub,
						"vlinkPeer",
						inet_ntoa(dest));
				else
					json_object_string_add(
						json_interface_sub,
						"localIfUsed",
						inet_ntoa(dest));
			} else
				vty_out(vty, " %s %s,", dstr,
					inet_ntoa(dest));
		}
		if (use_json) {
			json_object_string_add(json_interface_sub, "area",
					       ospf_area_desc_string(oi->area));
			if (OSPF_IF_PARAM(oi, mtu_ignore))
				json_object_boolean_true_add(
					json_interface_sub,
					"mtuMismatchDetect");
			json_object_string_add(json_interface_sub, "routerId",
					       inet_ntoa(ospf->router_id));
			json_object_string_add(json_interface_sub,
					       "networkType",
					       ospf_network_type_str[oi->type]);
			json_object_int_add(json_interface_sub, "cost",
					    oi->output_cost);
			json_object_int_add(
				json_interface_sub, "transmitDelaySecs",
				OSPF_IF_PARAM(oi, transmit_delay));
			json_object_string_add(json_interface_sub, "state",
					       lookup_msg(ospf_ism_state_msg,
							  oi->state, NULL));
			json_object_int_add(json_interface_sub, "priority",
					    PRIORITY(oi));
		} else {
			vty_out(vty, " Area %s\n",
				ospf_area_desc_string(oi->area));

			vty_out(vty, "  MTU mismatch detection: %s\n",
				OSPF_IF_PARAM(oi, mtu_ignore) ? "disabled"
							      : "enabled");

			vty_out(vty,
				"  Router ID %s, Network Type %s, Cost: %d\n",
				inet_ntoa(ospf->router_id),
				ospf_network_type_str[oi->type],
				oi->output_cost);

			vty_out(vty,
				"  Transmit Delay is %d sec, State %s, Priority %d\n",
				OSPF_IF_PARAM(oi, transmit_delay),
				lookup_msg(ospf_ism_state_msg, oi->state, NULL),
				PRIORITY(oi));
		}

		/* Show DR information. */
		if (DR(oi).s_addr == 0) {
			if (!use_json)
				vty_out(vty,
					"  No backup designated router on this network\n");
		} else {
			nbr = ospf_nbr_lookup_by_addr(oi->nbrs, &BDR(oi));
			if (nbr == NULL) {
				if (!use_json)
					vty_out(vty,
						"  No backup designated router on this network\n");
			} else {
				if (use_json) {
					json_object_string_add(
						json_interface_sub, "bdrId",
						inet_ntoa(nbr->router_id));
					json_object_string_add(
						json_interface_sub,
						"bdrAddress",
						inet_ntoa(nbr->address.u
								  .prefix4));
				} else {
					vty_out(vty,
						"  Backup Designated Router (ID) %s,",
						inet_ntoa(nbr->router_id));
					vty_out(vty, " Interface Address %s\n",
						inet_ntoa(nbr->address.u
								  .prefix4));
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
			json_object_int_add(json_interface_sub,
					    "timerDeadSecs",
					    OSPF_IF_PARAM(oi, v_wait));
			json_object_int_add(json_interface_sub,
					    "timerWaitSecs",
					    OSPF_IF_PARAM(oi, v_wait));
			json_object_int_add(
				json_interface_sub, "timerRetransmitSecs",
				OSPF_IF_PARAM(oi, retransmit_interval));
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
		ospf_bfd_interface_show(vty, ifp, json_interface_sub, use_json);
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
			if (use_json)
				json_object_boolean_true_add(json_vrf,
							     "noSuchIface");
			else
				vty_out(vty, "No such interface name\n");
		} else {
			if (use_json) {
				json_interface_sub = json_object_new_object();
				json_interface = json_object_new_object();
			}

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
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
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
	} else {
		vty_out(vty,
			"%-10s %8u/%-8u %7u/%-7u %7u/%-7u %7u/%-7u %7u/%-7u\n",
			oi->ifp->name, oi->hello_in, oi->hello_out,
			oi->db_desc_in, oi->db_desc_out, oi->ls_req_in,
			oi->ls_req_out, oi->ls_upd_in, oi->ls_upd_out,
			oi->ls_ack_in, oi->ls_ack_out);
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
		vty_out(vty, "%-12s%-17s%-17s%-17s%-17s%-17s\n", "Interface",
			"    HELLO", "    DB-Desc", "   LS-Req", "   LS-Update",
			"   LS-Ack");
		vty_out(vty, "%-10s%-18s%-18s%-17s%-17s%-17s\n", "",
			"      Rx/Tx", "     Rx/Tx", "    Rx/Tx", "    Rx/Tx",
			"    Rx/Tx");
		vty_out(vty,
			"--------------------------------------------------------------------------------------------\n");
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
		if (use_vrf) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
						       json_vrf);
		}
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

			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else if (!ospf)
				vty_out(vty, "%% OSPF instance not found\n");

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

			return CMD_SUCCESS;
		}
		ret = show_ip_ospf_interface_common(vty, ospf, intf_name,
						    use_vrf, json, uj);

	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

			return CMD_SUCCESS;
		}
		ret = show_ip_ospf_interface_common(vty, ospf, intf_name,
						    use_vrf, json, uj);
	}

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	if (argv_find(argv, argc, "INTERFACE", &idx_intf))
		intf_name = argv[idx_intf]->arg;

	ret = show_ip_ospf_interface_common(vty, ospf, intf_name, 0, json, uj);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

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

			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			}

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

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return ret;
}


static void show_ip_ospf_neighbour_header(struct vty *vty)
{
	vty_out(vty, "\n%-15s %3s %-15s %9s %-15s %-20s %5s %5s %5s\n",
		"Neighbor ID", "Pri", "State", "Dead Time", "Address",
		"Interface", "RXmtL", "RqstL", "DBsmL");
}

static void show_ip_ospf_neighbor_sub(struct vty *vty,
				      struct ospf_interface *oi,
				      json_object *json, bool use_json)
{
	struct route_node *rn;
	struct ospf_neighbor *nbr, *prev_nbr = NULL;
	char msgbuf[16];
	char timebuf[OSPF_TIME_DUMP_SIZE];
	json_object *json_neighbor = NULL, *json_neigh_array = NULL;

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn)) {
		if ((nbr = rn->info)) {
			/* Do not show myself. */
			if (nbr == oi->nbr_self)
				continue;
			/* Down state is not shown. */
			if (nbr->state == NSM_Down)
				continue;
			if (use_json) {
				char neigh_str[INET_ADDRSTRLEN];

				if (prev_nbr
				    && !IPV4_ADDR_SAME(&prev_nbr->src,
						       &nbr->src)) {
					/* Start new neigh list */
					json_neigh_array = NULL;
				}

				if (nbr->state == NSM_Attempt
				    && nbr->router_id.s_addr == 0)
					strlcpy(neigh_str, "neighbor",
						sizeof(neigh_str));
				else
					strlcpy(neigh_str,
						inet_ntoa(nbr->router_id),
						sizeof(neigh_str));

				json_object_object_get_ex(json, neigh_str,
							  &json_neigh_array);

				if (!json_neigh_array) {
					json_neigh_array =
						json_object_new_array();
					json_object_object_add(
						json, neigh_str,
						json_neigh_array);
				}

				json_neighbor = json_object_new_object();

				ospf_nbr_state_message(nbr, msgbuf, 16);

				long time_store;

				time_store =
					monotime_until(
						&nbr->t_inactivity->u.sands,
						NULL)
					/ 1000LL;

				json_object_int_add(json_neighbor, "priority",
						    nbr->priority);
				json_object_string_add(json_neighbor, "state",
						       msgbuf);
				json_object_int_add(json_neighbor,
						    "deadTimeMsecs",
						    time_store);
				json_object_string_add(json_neighbor, "address",
						       inet_ntoa(nbr->src));
				json_object_string_add(json_neighbor,
						       "ifaceName",
						       IF_NAME(oi));
				json_object_int_add(
					json_neighbor, "retransmitCounter",
					ospf_ls_retransmit_count(nbr));
				json_object_int_add(json_neighbor,
						    "requestCounter",
						    ospf_ls_request_count(nbr));
				json_object_int_add(json_neighbor,
						    "dbSummaryCounter",
						    ospf_db_summary_count(nbr));

				json_object_array_add(json_neigh_array,
						      json_neighbor);
			} else {
				ospf_nbr_state_message(nbr, msgbuf, 16);

				if (nbr->state == NSM_Attempt
				    && nbr->router_id.s_addr == 0)
					vty_out(vty, "%-15s %3d %-15s ", "-",
						nbr->priority, msgbuf);
				else
					vty_out(vty, "%-15s %3d %-15s ",
						inet_ntoa(nbr->router_id),
						nbr->priority, msgbuf);

				vty_out(vty, "%9s ",
					ospf_timer_dump(nbr->t_inactivity,
							timebuf,
							sizeof(timebuf)));
				vty_out(vty, "%-15s ", inet_ntoa(nbr->src));
				vty_out(vty, "%-20s %5ld %5ld %5d\n",
					IF_NAME(oi),
					ospf_ls_retransmit_count(nbr),
					ospf_ls_request_count(nbr),
					ospf_db_summary_count(nbr));
			}
			prev_nbr = nbr;
		}
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
		if (use_vrf) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
						       json_vrf);
		}
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

			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else if (!ospf)
				vty_out(vty, "OSPF instance not found\n");

			return ret;
		}

		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_common(vty, ospf, json, uj, 0);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return ret;
}

static int show_ip_ospf_neighbor_all_common(struct vty *vty, struct ospf *ospf,
					    json_object *json, bool use_json,
					    uint8_t use_vrf)
{
	struct listnode *node;
	struct ospf_interface *oi;
	json_object *json_vrf = NULL;
	json_object *json_neighbor_sub = NULL;

	if (use_json) {
		if (use_vrf)
			json_vrf = json_object_new_object();
		else
			json_vrf = json;
		json_neighbor_sub = json_object_new_object();
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
						inet_ntoa(nbr_nbma->addr),
						json_neighbor_sub);
				} else {
					vty_out(vty, "%-15s %3d %-15s %9s ",
						"-", nbr_nbma->priority, "Down",
						"-");
					vty_out(vty,
						"%-15s %-20s %5d %5d %5d\n",
						inet_ntoa(nbr_nbma->addr),
						IF_NAME(oi), 0, 0, 0);
				}
			}
		}
	}

	if (use_json) {
		if (use_vrf) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
						       json_vrf);
		}
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

			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			}

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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;
	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_all_common(vty, ospf, json, uj, 0);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return ret;
}

static int show_ip_ospf_neighbor_int_common(struct vty *vty, struct ospf *ospf,
					    int arg_base,
					    struct cmd_token **argv,
					    bool use_json, uint8_t use_vrf)
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

	ifp = if_lookup_by_name(argv[arg_base]->arg, ospf->vrf_id);
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

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_int,
       show_ip_ospf_neighbor_int_cmd,
       "show ip ospf [vrf <NAME>] neighbor IFNAME [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "Neighbor list\n"
       "Interface name\n"
       JSON_STR)
{
	struct ospf *ospf;
	int idx_ifname = 0;
	int idx_vrf = 0;
	bool uj = use_json(argc, argv);
	int ret = CMD_SUCCESS;
	struct interface *ifp = NULL;
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
	ospf = ospf_lookup_by_vrf_id(vrf_id);

	if (!ospf || !ospf->oi_running)
		return ret;

	if (!uj)
		show_ip_ospf_neighbour_header(vty);

	argv_find(argv, argc, "IFNAME", &idx_ifname);

	ifp = if_lookup_by_name(argv[idx_ifname]->arg, vrf_id);
	if (!ifp)
		return ret;

	ret = show_ip_ospf_neighbor_int_common(vty, ospf, idx_ifname,
					       argv, uj, 0);
	return ret;
}

DEFUN (show_ip_ospf_instance_neighbor_int,
       show_ip_ospf_instance_neighbor_int_cmd,
       "show ip ospf (1-65535) neighbor IFNAME [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       "Interface name\n"
       JSON_STR)
{
	int idx_number = 3;
	int idx_ifname = 5;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);

	if (!uj)
		show_ip_ospf_neighbour_header(vty);

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	if (!uj)
		show_ip_ospf_neighbour_header(vty);

	return show_ip_ospf_neighbor_int_common(vty, ospf, idx_ifname, argv, uj,
						0);
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
		json_object_string_add(json_sub, "ifaceAddress",
				       inet_ntoa(nbr_nbma->addr));
	else
		vty_out(vty, " interface address %s\n",
			inet_ntoa(nbr_nbma->addr));

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

	if (use_json) {
		if (prev_nbr &&
		    !IPV4_ADDR_SAME(&prev_nbr->src, &nbr->src)) {
			json_neigh_array = NULL;
		}

		if (nbr->state == NSM_Attempt && nbr->router_id.s_addr == 0)
			strlcpy(neigh_str, "noNbrId", sizeof(neigh_str));
		else
			strlcpy(neigh_str, inet_ntoa(nbr->router_id),
				sizeof(neigh_str));

		json_object_object_get_ex(json, neigh_str, &json_neigh_array);

		if (!json_neigh_array) {
			json_neigh_array = json_object_new_array();
			json_object_object_add(json, neigh_str,
					       json_neigh_array);
		}

		json_neigh = json_object_new_object();

	} else {
		/* Show neighbor ID. */
		if (nbr->state == NSM_Attempt && nbr->router_id.s_addr == 0)
			vty_out(vty, " Neighbor %s,", "-");
		else
			vty_out(vty, " Neighbor %s,",
				inet_ntoa(nbr->router_id));
	}

	/* Show interface address. */
	if (use_json)
		json_object_string_add(json_neigh, "ifaceAddress",
				       inet_ntoa(nbr->address.u.prefix4));
	else
		vty_out(vty, " interface address %s\n",
			inet_ntoa(nbr->address.u.prefix4));

	/* Show Area ID. */
	if (use_json) {
		json_object_string_add(json_neigh, "areaId",
				       ospf_area_desc_string(oi->area));
		json_object_string_add(json_neigh, "ifaceName", oi->ifp->name);
	} else
		vty_out(vty, "    In the area %s via interface %s\n",
			ospf_area_desc_string(oi->area), oi->ifp->name);

	/* Show neighbor priority and state. */
	if (use_json) {
		json_object_int_add(json_neigh, "nbrPriority", nbr->priority);
		json_object_string_add(
			json_neigh, "nbrState",
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL));
	} else
		vty_out(vty, "    Neighbor priority is %d, State is %s,",
			nbr->priority,
			lookup_msg(ospf_nsm_state_msg, nbr->state, NULL));

	/* Show state changes. */
	if (use_json)
		json_object_int_add(json_neigh, "stateChangeCounter",
				    nbr->state_change);
	else
		vty_out(vty, " %d state changes\n", nbr->state_change);

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

	/* Show Designated Rotuer ID. */
	if (use_json)
		json_object_string_add(json_neigh, "routerDesignatedId",
				       inet_ntoa(nbr->d_router));
	else
		vty_out(vty, "    DR is %s,", inet_ntoa(nbr->d_router));

	/* Show Backup Designated Rotuer ID. */
	if (use_json)
		json_object_string_add(json_neigh, "routerDesignatedBackupId",
				       inet_ntoa(nbr->bd_router));
	else
		vty_out(vty, " BDR is %s\n", inet_ntoa(nbr->bd_router));

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
		if (nbr->t_ls_upd != NULL)
			json_object_string_add(
				json_neigh,
				"threadLinkStateUpdateRetransmission",
				"on");
	} else
		vty_out(vty,
			"    Thread Link State Update Retransmission %s\n\n",
			nbr->t_ls_upd != NULL ? "on" : "off");

	ospf_bfd_show_info(vty, nbr->bfd_info, json_neigh, use_json, 0);

	if (use_json)
		json_object_array_add(json_neigh_array, json_neigh);

}

static int show_ip_ospf_neighbor_id_common(struct vty *vty, struct ospf *ospf,
					   struct in_addr *router_id,
					   bool use_json, uint8_t use_vrf)
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
		if ((nbr = ospf_nbr_lookup_by_routerid(oi->nbrs, router_id))) {
			show_ip_ospf_neighbor_detail_sub(vty, oi, nbr, NULL,
							 json, use_json);
		}
	}

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFPY (show_ip_ospf_neighbor_id,
       show_ip_ospf_neighbor_id_cmd,
       "show ip ospf neighbor A.B.C.D$router_id [json$json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Neighbor ID\n"
       JSON_STR)
{
	struct ospf *ospf;
	struct listnode *node;
	int ret = CMD_SUCCESS;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		if (!ospf->oi_running)
			continue;
		ret = show_ip_ospf_neighbor_id_common(vty, ospf, &router_id,
						      !!json, 0);
	}

	return ret;
}

DEFPY (show_ip_ospf_instance_neighbor_id,
       show_ip_ospf_instance_neighbor_id_cmd,
       "show ip ospf (1-65535)$instance neighbor A.B.C.D$router_id [json$json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       "Neighbor ID\n"
       JSON_STR)
{
	struct ospf *ospf;

	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_neighbor_id_common(vty, ospf, &router_id, !!json,
					       0);
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
			if ((nbr = rn->info)) {
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
	}

	if (use_json) {
		json_object_object_add(json_vrf, "neighbors",
				       json_nbr_sub);
		if (use_vrf) {
			if (ospf->vrf_id == VRF_DEFAULT)
				json_object_object_add(json, "default",
						       json_vrf);
			else
				json_object_object_add(json, ospf->name,
						       json_vrf);
		}
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_detail,
       show_ip_ospf_neighbor_detail_cmd,
       "show ip ospf [vrf <NAME|all>] neighbor detail [json]",
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
				ret = show_ip_ospf_neighbor_detail_common(
					vty, ospf, json, uj, use_vrf);
			}
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			}

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
		ret = show_ip_ospf_neighbor_detail_common(vty, ospf, json, uj,
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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_detail_common(vty, ospf, json, uj, 0);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

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
			if ((nbr = rn->info)) {
				if (nbr != oi->nbr_self)
					if (nbr->state != NSM_Down)
						show_ip_ospf_neighbor_detail_sub(
							vty, oi, rn->info,
							prev_nbr,
							json_vrf, use_json);
				prev_nbr = nbr;
			}
		}

		if (oi->type == OSPF_IFTYPE_NBMA) {
			struct listnode *nd;

			for (ALL_LIST_ELEMENTS_RO(oi->nbr_nbma, nd, nbr_nbma)) {
				if (nbr_nbma->nbr == NULL
				    || nbr_nbma->nbr->state == NSM_Down)
					show_ip_ospf_nbr_nbma_detail_sub(
						vty, oi, nbr_nbma, use_json,
						json_vrf);
			}
		}
	}

	if (use_json) {
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

			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			}

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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	if (uj)
		json = json_object_new_object();

	ret = show_ip_ospf_neighbor_detail_all_common(vty, ospf, json, uj, 0);

	if (uj) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	}

	return ret;
}

static int show_ip_ospf_neighbor_int_detail_common(struct vty *vty,
						   struct ospf *ospf,
						   int arg_base,
						   struct cmd_token **argv,
						   bool use_json)
{
	struct ospf_interface *oi;
	struct interface *ifp;
	struct route_node *rn, *nrn;
	struct ospf_neighbor *nbr;
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

	ifp = if_lookup_by_name(argv[arg_base]->arg, ospf->vrf_id);
	if (!ifp) {
		if (!use_json)
			vty_out(vty, "No such interface.\n");
		else {
			vty_out(vty, "{}\n");
			json_object_free(json);
		}
		return CMD_WARNING;
	}

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		if ((oi = rn->info)) {
			for (nrn = route_top(oi->nbrs); nrn;
			     nrn = route_next(nrn)) {
				if ((nbr = nrn->info)) {
					if (nbr != oi->nbr_self) {
						if (nbr->state != NSM_Down)
							show_ip_ospf_neighbor_detail_sub(
								vty, oi, nbr,
								NULL,
								json, use_json);
					}
				}
			}
		}
	}

	if (use_json) {
		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else
		vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_neighbor_int_detail,
       show_ip_ospf_neighbor_int_detail_cmd,
       "show ip ospf neighbor IFNAME detail [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Neighbor list\n"
       "Interface name\n"
       "detail of all neighbors\n"
       JSON_STR)
{
	struct ospf *ospf;
	bool uj = use_json(argc, argv);
	struct listnode *node = NULL;
	int ret = CMD_SUCCESS;
	bool ospf_output = false;

	for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
		if (!ospf->oi_running)
			continue;
		ospf_output = true;
		ret = show_ip_ospf_neighbor_int_detail_common(vty, ospf, 4,
							      argv, uj);
	}

	if (!ospf_output)
		vty_out(vty, "%% OSPF instance not found\n");

	return ret;
}

DEFUN (show_ip_ospf_instance_neighbor_int_detail,
       show_ip_ospf_instance_neighbor_int_detail_cmd,
       "show ip ospf (1-65535) neighbor IFNAME detail [json]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Neighbor list\n"
       "Interface name\n"
       "detail of all neighbors\n"
       JSON_STR)
{
	int idx_number = 3;
	int idx_ifname = 5;
	struct ospf *ospf;
	unsigned short instance = 0;
	bool uj = use_json(argc, argv);

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_neighbor_int_detail_common(vty, ospf, idx_ifname,
						       argv, uj);
}

/* Show functions */
static int show_lsa_summary(struct vty *vty, struct ospf_lsa *lsa, int self)
{
	struct router_lsa *rl;
	struct summary_lsa *sl;
	struct as_external_lsa *asel;
	struct prefix_ipv4 p;

	if (lsa != NULL)
		/* If self option is set, check LSA self flag. */
		if (self == 0 || IS_LSA_SELF(lsa)) {
			/* LSA common part show. */
			vty_out(vty, "%-15s ", inet_ntoa(lsa->data->id));
			vty_out(vty, "%-15s %4d 0x%08lx 0x%04x",
				inet_ntoa(lsa->data->adv_router), LS_AGE(lsa),
				(unsigned long)ntohl(lsa->data->ls_seqnum),
				ntohs(lsa->data->checksum));
			/* LSA specific part show. */
			switch (lsa->data->type) {
			case OSPF_ROUTER_LSA:
				rl = (struct router_lsa *)lsa->data;
				vty_out(vty, " %-d", ntohs(rl->links));
				break;
			case OSPF_SUMMARY_LSA:
				sl = (struct summary_lsa *)lsa->data;

				p.family = AF_INET;
				p.prefix = sl->header.id;
				p.prefixlen = ip_masklen(sl->mask);
				apply_mask_ipv4(&p);

				vty_out(vty, " %s/%d", inet_ntoa(p.prefix),
					p.prefixlen);
				break;
			case OSPF_AS_EXTERNAL_LSA:
			case OSPF_AS_NSSA_LSA:
				asel = (struct as_external_lsa *)lsa->data;

				p.family = AF_INET;
				p.prefix = asel->header.id;
				p.prefixlen = ip_masklen(asel->mask);
				apply_mask_ipv4(&p);

				vty_out(vty, " %s %s/%d [0x%lx]",
					IS_EXTERNAL_METRIC(asel->e[0].tos)
						? "E2"
						: "E1",
					inet_ntoa(p.prefix), p.prefixlen,
					(unsigned long)ntohl(
						asel->e[0].route_tag));
				break;
			case OSPF_NETWORK_LSA:
			case OSPF_ASBR_SUMMARY_LSA:
			case OSPF_OPAQUE_LINK_LSA:
			case OSPF_OPAQUE_AREA_LSA:
			case OSPF_OPAQUE_AS_LSA:
			default:
				break;
			}
			vty_out(vty, "\n");
		}

	return 0;
}

static const char *show_database_desc[] = {
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

static const char *show_database_header[] = {
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

static void show_ip_ospf_database_header(struct vty *vty, struct ospf_lsa *lsa)
{
	struct router_lsa *rlsa = (struct router_lsa *)lsa->data;

	vty_out(vty, "  LS age: %d\n", LS_AGE(lsa));
	vty_out(vty, "  Options: 0x%-2x : %s\n", lsa->data->options,
		ospf_options_dump(lsa->data->options));
	vty_out(vty, "  LS Flags: 0x%-2x %s\n", lsa->flags,
		((lsa->flags & OSPF_LSA_LOCAL_XLT) ? "(Translated from Type-7)"
						   : ""));

	if (lsa->data->type == OSPF_ROUTER_LSA) {
		vty_out(vty, "  Flags: 0x%x", rlsa->flags);

		if (rlsa->flags)
			vty_out(vty, " :%s%s%s%s",
				IS_ROUTER_LSA_BORDER(rlsa) ? " ABR" : "",
				IS_ROUTER_LSA_EXTERNAL(rlsa) ? " ASBR" : "",
				IS_ROUTER_LSA_VIRTUAL(rlsa) ? " VL-endpoint"
							    : "",
				IS_ROUTER_LSA_SHORTCUT(rlsa) ? " Shortcut"
							     : "");

		vty_out(vty, "\n");
	}
	vty_out(vty, "  LS Type: %s\n",
		lookup_msg(ospf_lsa_type_msg, lsa->data->type, NULL));
	vty_out(vty, "  Link State ID: %s %s\n", inet_ntoa(lsa->data->id),
		lookup_msg(ospf_link_state_id_type_msg, lsa->data->type, NULL));
	vty_out(vty, "  Advertising Router: %s\n",
		inet_ntoa(lsa->data->adv_router));
	vty_out(vty, "  LS Seq Number: %08lx\n",
		(unsigned long)ntohl(lsa->data->ls_seqnum));
	vty_out(vty, "  Checksum: 0x%04x\n", ntohs(lsa->data->checksum));
	vty_out(vty, "  Length: %d\n\n", ntohs(lsa->data->length));
}

const char *link_type_desc[] = {
	"(null)",
	"another Router (point-to-point)",
	"a Transit Network",
	"Stub Network",
	"a Virtual Link",
};

const char *link_id_desc[] = {
	"(null)", "Neighboring Router ID", "Designated Router address",
	"Net",    "Neighboring Router ID",
};

const char *link_data_desc[] = {
	"(null)",       "Router Interface address", "Router Interface address",
	"Network Mask", "Router Interface address",
};

/* Show router-LSA each Link information. */
static void show_ip_ospf_database_router_links(struct vty *vty,
					       struct router_lsa *rl)
{
	int len, type;
	unsigned int i;

	len = ntohs(rl->header.length) - 4;
	for (i = 0; i < ntohs(rl->links) && len > 0; len -= 12, i++) {
		type = rl->link[i].type;

		vty_out(vty, "    Link connected to: %s\n",
			link_type_desc[type]);
		vty_out(vty, "     (Link ID) %s: %s\n", link_id_desc[type],
			inet_ntoa(rl->link[i].link_id));
		vty_out(vty, "     (Link Data) %s: %s\n", link_data_desc[type],
			inet_ntoa(rl->link[i].link_data));
		vty_out(vty, "      Number of TOS metrics: 0\n");
		vty_out(vty, "       TOS 0 Metric: %d\n",
			ntohs(rl->link[i].metric));
		vty_out(vty, "\n");
	}
}

/* Show router-LSA detail information. */
static int show_router_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	if (lsa != NULL) {
		struct router_lsa *rl = (struct router_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa);

		vty_out(vty, "   Number of Links: %d\n\n", ntohs(rl->links));

		show_ip_ospf_database_router_links(vty, rl);
		vty_out(vty, "\n");
	}

	return 0;
}

/* Show network-LSA detail information. */
static int show_network_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	int length, i;

	if (lsa != NULL) {
		struct network_lsa *nl = (struct network_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa);

		vty_out(vty, "  Network Mask: /%d\n", ip_masklen(nl->mask));

		length = ntohs(lsa->data->length) - OSPF_LSA_HEADER_SIZE - 4;

		for (i = 0; length > 0; i++, length -= 4)
			vty_out(vty, "        Attached Router: %s\n",
				inet_ntoa(nl->routers[i]));

		vty_out(vty, "\n");
	}

	return 0;
}

/* Show summary-LSA detail information. */
static int show_summary_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	if (lsa != NULL) {
		struct summary_lsa *sl = (struct summary_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa);

		vty_out(vty, "  Network Mask: /%d\n", ip_masklen(sl->mask));
		vty_out(vty, "        TOS: 0  Metric: %d\n",
			GET_METRIC(sl->metric));
		vty_out(vty, "\n");
	}

	return 0;
}

/* Show summary-ASBR-LSA detail information. */
static int show_summary_asbr_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	if (lsa != NULL) {
		struct summary_lsa *sl = (struct summary_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa);

		vty_out(vty, "  Network Mask: /%d\n", ip_masklen(sl->mask));
		vty_out(vty, "        TOS: 0  Metric: %d\n",
			GET_METRIC(sl->metric));
		vty_out(vty, "\n");
	}

	return 0;
}

/* Show AS-external-LSA detail information. */
static int show_as_external_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	if (lsa != NULL) {
		struct as_external_lsa *al =
			(struct as_external_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa);

		vty_out(vty, "  Network Mask: /%d\n", ip_masklen(al->mask));
		vty_out(vty, "        Metric Type: %s\n",
			IS_EXTERNAL_METRIC(al->e[0].tos)
				? "2 (Larger than any link state path)"
				: "1");
		vty_out(vty, "        TOS: 0\n");
		vty_out(vty, "        Metric: %d\n",
			GET_METRIC(al->e[0].metric));
		vty_out(vty, "        Forward Address: %s\n",
			inet_ntoa(al->e[0].fwd_addr));

		vty_out(vty,
			"        External Route Tag: %" ROUTE_TAG_PRI "\n\n",
			(route_tag_t)ntohl(al->e[0].route_tag));
	}

	return 0;
}
#if 0
static int
show_as_external_lsa_stdvty (struct ospf_lsa *lsa)
{
  struct as_external_lsa *al = (struct as_external_lsa *) lsa->data;

  /* show_ip_ospf_database_header (vty, lsa); */

  zlog_debug( "  Network Mask: /%d%s",
	     ip_masklen (al->mask), "\n");
  zlog_debug( "        Metric Type: %s%s",
	     IS_EXTERNAL_METRIC (al->e[0].tos) ?
	     "2 (Larger than any link state path)" : "1", "\n");
  zlog_debug( "        TOS: 0%s", "\n");
  zlog_debug( "        Metric: %d%s",
	     GET_METRIC (al->e[0].metric), "\n");
  zlog_debug( "        Forward Address: %s%s",
	     inet_ntoa (al->e[0].fwd_addr), "\n");

  zlog_debug( "        External Route Tag: %"ROUTE_TAG_PRI"%s%s",
	     (route_tag_t)ntohl (al->e[0].route_tag), "\n", "\n");

  return 0;
}
#endif
/* Show AS-NSSA-LSA detail information. */
static int show_as_nssa_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	if (lsa != NULL) {
		struct as_external_lsa *al =
			(struct as_external_lsa *)lsa->data;

		show_ip_ospf_database_header(vty, lsa);

		vty_out(vty, "  Network Mask: /%d\n", ip_masklen(al->mask));
		vty_out(vty, "        Metric Type: %s\n",
			IS_EXTERNAL_METRIC(al->e[0].tos)
				? "2 (Larger than any link state path)"
				: "1");
		vty_out(vty, "        TOS: 0\n");
		vty_out(vty, "        Metric: %d\n",
			GET_METRIC(al->e[0].metric));
		vty_out(vty, "        NSSA: Forward Address: %s\n",
			inet_ntoa(al->e[0].fwd_addr));

		vty_out(vty,
			"        External Route Tag: %" ROUTE_TAG_PRI "\n\n",
			(route_tag_t)ntohl(al->e[0].route_tag));
	}

	return 0;
}

static int show_func_dummy(struct vty *vty, struct ospf_lsa *lsa)
{
	return 0;
}

static int show_opaque_lsa_detail(struct vty *vty, struct ospf_lsa *lsa)
{
	if (lsa != NULL) {
		show_ip_ospf_database_header(vty, lsa);
		show_opaque_info_detail(vty, lsa);

		vty_out(vty, "\n");
	}
	return 0;
}

int (*show_function[])(struct vty *, struct ospf_lsa *) = {
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
	lp->family = 0;
	if (id == NULL)
		lp->prefixlen = 0;
	else if (adv_router == NULL) {
		lp->prefixlen = 32;
		lp->id = *id;
	} else {
		lp->prefixlen = 64;
		lp->id = *id;
		lp->adv_router = *adv_router;
	}
}

static void show_lsa_detail_proc(struct vty *vty, struct route_table *rt,
				 struct in_addr *id, struct in_addr *adv_router)
{
	struct prefix_ls lp;
	struct route_node *rn, *start;
	struct ospf_lsa *lsa;

	show_lsa_prefix_set(vty, &lp, id, adv_router);
	start = route_node_get(rt, (struct prefix *)&lp);
	if (start) {
		route_lock_node(start);
		for (rn = start; rn; rn = route_next_until(rn, start))
			if ((lsa = rn->info)) {
				if (show_function[lsa->data->type] != NULL)
					show_function[lsa->data->type](vty,
								       lsa);
			}
		route_unlock_node(start);
	}
}

/* Show detail LSA information
   -- if id is NULL then show all LSAs. */
static void show_lsa_detail(struct vty *vty, struct ospf *ospf, int type,
			    struct in_addr *id, struct in_addr *adv_router)
{
	struct listnode *node;
	struct ospf_area *area;

	switch (type) {
	case OSPF_AS_EXTERNAL_LSA:
	case OSPF_OPAQUE_AS_LSA:
		vty_out(vty, "                %s \n\n",
			show_database_desc[type]);
		show_lsa_detail_proc(vty, AS_LSDB(ospf, type), id, adv_router);
		break;
	default:
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
			vty_out(vty, "\n                %s (Area %s)\n\n",
				show_database_desc[type],
				ospf_area_desc_string(area));
			show_lsa_detail_proc(vty, AREA_LSDB(area, type), id,
					     adv_router);
		}
		break;
	}
}

static void show_lsa_detail_adv_router_proc(struct vty *vty,
					    struct route_table *rt,
					    struct in_addr *adv_router)
{
	struct route_node *rn;
	struct ospf_lsa *lsa;

	for (rn = route_top(rt); rn; rn = route_next(rn))
		if ((lsa = rn->info))
			if (IPV4_ADDR_SAME(adv_router,
					   &lsa->data->adv_router)) {
				if (CHECK_FLAG(lsa->flags, OSPF_LSA_LOCAL_XLT))
					continue;
				if (show_function[lsa->data->type] != NULL)
					show_function[lsa->data->type](vty,
								       lsa);
			}
}

/* Show detail LSA information. */
static void show_lsa_detail_adv_router(struct vty *vty, struct ospf *ospf,
				       int type, struct in_addr *adv_router)
{
	struct listnode *node;
	struct ospf_area *area;

	switch (type) {
	case OSPF_AS_EXTERNAL_LSA:
	case OSPF_OPAQUE_AS_LSA:
		vty_out(vty, "                %s \n\n",
			show_database_desc[type]);
		show_lsa_detail_adv_router_proc(vty, AS_LSDB(ospf, type),
						adv_router);
		break;
	default:
		for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
			vty_out(vty, "\n                %s (Area %s)\n\n",
				show_database_desc[type],
				ospf_area_desc_string(area));
			show_lsa_detail_adv_router_proc(
				vty, AREA_LSDB(area, type), adv_router);
		}
		break;
	}
}

static void show_ip_ospf_database_summary(struct vty *vty, struct ospf *ospf,
					  int self)
{
	struct ospf_lsa *lsa;
	struct route_node *rn;
	struct ospf_area *area;
	struct listnode *node;
	int type;

	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		for (type = OSPF_MIN_LSA; type < OSPF_MAX_LSA; type++) {
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
				vty_out(vty, "                %s (Area %s)\n\n",
					show_database_desc[type],
					ospf_area_desc_string(area));
				vty_out(vty, "%s\n",
					show_database_header[type]);

				LSDB_LOOP (AREA_LSDB(area, type), rn, lsa)
					show_lsa_summary(vty, lsa, self);

				vty_out(vty, "\n");
			}
		}
	}

	for (type = OSPF_MIN_LSA; type < OSPF_MAX_LSA; type++) {
		switch (type) {
		case OSPF_AS_EXTERNAL_LSA:
		case OSPF_OPAQUE_AS_LSA:
			break;
		default:
			continue;
		}
		if (ospf_lsdb_count_self(ospf->lsdb, type)
		    || (!self && ospf_lsdb_count(ospf->lsdb, type))) {
			vty_out(vty, "                %s\n\n",
				show_database_desc[type]);
			vty_out(vty, "%s\n", show_database_header[type]);

			LSDB_LOOP (AS_LSDB(ospf, type), rn, lsa)
				show_lsa_summary(vty, lsa, self);

			vty_out(vty, "\n");
		}
	}

	vty_out(vty, "\n");
}

static void show_ip_ospf_database_maxage(struct vty *vty, struct ospf *ospf)
{
	struct route_node *rn;

	vty_out(vty, "\n                MaxAge Link States:\n\n");

	for (rn = route_top(ospf->maxage_lsa); rn; rn = route_next(rn)) {
		struct ospf_lsa *lsa;

		if ((lsa = rn->info) != NULL) {
			vty_out(vty, "Link type: %d\n", lsa->data->type);
			vty_out(vty, "Link State ID: %s\n",
				inet_ntoa(lsa->data->id));
			vty_out(vty, "Advertising Router: %s\n",
				inet_ntoa(lsa->data->adv_router));
			vty_out(vty, "LSA lock count: %d\n", lsa->lock);
			vty_out(vty, "\n");
		}
	}
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

static int show_ip_ospf_database_common(struct vty *vty, struct ospf *ospf,
					int arg_base, int argc,
					struct cmd_token **argv,
					uint8_t use_vrf)
{
	int idx_type = 4;
	int type, ret;
	struct in_addr id, adv_router;

	if (ospf->instance)
		vty_out(vty, "\nOSPF Instance: %d\n", ospf->instance);

	ospf_show_vrf_name(ospf, vty, NULL, use_vrf);

	vty_out(vty, "\n       OSPF Router with ID (%s)\n\n",
		inet_ntoa(ospf->router_id));

	/* Show all LSA. */
	if (argc == arg_base + 4) {
		show_ip_ospf_database_summary(vty, ospf, 0);
		return CMD_SUCCESS;
	}

	/* Set database type to show. */
	if (strncmp(argv[arg_base + idx_type]->text, "r", 1) == 0)
		type = OSPF_ROUTER_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "ne", 2) == 0)
		type = OSPF_NETWORK_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "ns", 2) == 0)
		type = OSPF_AS_NSSA_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "su", 2) == 0)
		type = OSPF_SUMMARY_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "a", 1) == 0)
		type = OSPF_ASBR_SUMMARY_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "e", 1) == 0)
		type = OSPF_AS_EXTERNAL_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "se", 2) == 0) {
		show_ip_ospf_database_summary(vty, ospf, 1);
		return CMD_SUCCESS;
	} else if (strncmp(argv[arg_base + idx_type]->text, "m", 1) == 0) {
		show_ip_ospf_database_maxage(vty, ospf);
		return CMD_SUCCESS;
	} else if (strncmp(argv[arg_base + idx_type]->text, "opaque-l", 8) == 0)
		type = OSPF_OPAQUE_LINK_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "opaque-ar", 9) == 0)
		type = OSPF_OPAQUE_AREA_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "opaque-as", 9) == 0)
		type = OSPF_OPAQUE_AS_LSA;
	else
		return CMD_WARNING;

	/* `show ip ospf database LSA'. */
	if (argc == arg_base + 5)
		show_lsa_detail(vty, ospf, type, NULL, NULL);
	else if (argc >= arg_base + 6) {
		ret = inet_aton(argv[arg_base + 5]->arg, &id);
		if (!ret)
			return CMD_WARNING;

		/* `show ip ospf database LSA ID'. */
		if (argc == arg_base + 6)
			show_lsa_detail(vty, ospf, type, &id, NULL);
		/* `show ip ospf database LSA ID adv-router ADV_ROUTER'. */
		else if (argc == arg_base + 7) {
			if (strncmp(argv[arg_base + 6]->text, "s", 1) == 0)
				adv_router = ospf->router_id;
			else {
				ret = inet_aton(argv[arg_base + 7]->arg,
						&adv_router);
				if (!ret)
					return CMD_WARNING;
			}
			show_lsa_detail(vty, ospf, type, &id, &adv_router);
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_database_max,
       show_ip_ospf_database_max_cmd,
       "show ip ospf [vrf <NAME|all>] database <max-age|self-originate>",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Database summary\n"
       "LSAs in MaxAge list\n"
       "Self-originated link states\n")
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
				ret = show_ip_ospf_database_common(
					vty, ospf, idx_vrf ? 2 : 0, argc, argv,
					use_vrf);
			}

			if (!ospf_output)
				vty_out(vty, "%% OSPF instance not found\n");
		} else {
			ospf = ospf_lookup_by_inst_name(inst, vrf_name);
			if (ospf == NULL || !ospf->oi_running) {
				vty_out(vty, "%% OSPF instance not found\n");
				return CMD_SUCCESS;
			}
			ret = (show_ip_ospf_database_common(
				vty, ospf, idx_vrf ? 2 : 0, argc, argv,
				use_vrf));
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}

		ret = show_ip_ospf_database_common(vty, ospf, 0, argc, argv,
						   use_vrf);
	}

	return ret;
}

DEFUN (show_ip_ospf_instance_database,
       show_ip_ospf_instance_database_cmd,
       "show ip ospf [{(1-65535)|vrf NAME}] database [<asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as> [A.B.C.D [<self-originate|adv-router A.B.C.D>]]]",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR
       "Database summary\n"
        OSPF_LSA_TYPES_DESC
       "Link State ID (as an IP address)\n"
       "Self-originated link states\n"
       "Advertising Router link states\n"
       "Advertising Router (as an IP address)\n")
{
	struct ospf *ospf;
	unsigned short instance = 0;
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx = 0;
	uint8_t use_vrf = 0;

	if (argv_find(argv, argc, "(1-65535)", &idx)) {
		instance = strtoul(argv[idx]->arg, NULL, 10);
		ospf = ospf_lookup_instance(instance);
		if (ospf == NULL)
			return CMD_NOT_MY_INSTANCE;
		if (!ospf->oi_running)
			return CMD_SUCCESS;

		return (show_ip_ospf_database_common(vty, ospf, idx ? 1 : 0,
						     argc, argv, use_vrf));
	} else if (argv_find(argv, argc, "vrf", &idx)) {
		vrf_name = argv[++idx]->arg;
		all_vrf = strmatch(vrf_name, "all");
	}

	if (vrf_name) {
		use_vrf = 1;
		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ret = (show_ip_ospf_database_common(
					vty, ospf, idx ? 2 : 0, argc, argv,
					use_vrf));
			}
		} else {
			ospf = ospf_lookup_by_inst_name(inst, vrf_name);
			if ((ospf == NULL) || !ospf->oi_running) {
				vty_out(vty, "%% OSPF instance not found\n");
				return CMD_SUCCESS;
			}

			ret = (show_ip_ospf_database_common(
				vty, ospf, idx ? 2 : 0, argc, argv, use_vrf));
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}

		ret = (show_ip_ospf_database_common(vty, ospf, 0, argc, argv,
						    use_vrf));
	}

	return ret;
}

DEFUN (show_ip_ospf_instance_database_max,
       show_ip_ospf_instance_database_max_cmd,
       "show ip ospf (1-65535) database <max-age|self-originate>",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "Database summary\n"
       "LSAs in MaxAge list\n"
       "Self-originated link states\n")
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);

	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running) {
		vty_out(vty, "%% OSPF instance not found\n");
		return CMD_SUCCESS;
	}

	return show_ip_ospf_database_common(vty, ospf, 1, argc, argv, 0);
}


static int show_ip_ospf_database_type_adv_router_common(struct vty *vty,
							struct ospf *ospf,
							int arg_base, int argc,
							struct cmd_token **argv,
							uint8_t use_vrf)
{
	int idx_type = 4;
	int type, ret;
	struct in_addr adv_router;

	if (ospf->instance)
		vty_out(vty, "\nOSPF Instance: %d\n", ospf->instance);

	ospf_show_vrf_name(ospf, vty, NULL, use_vrf);

	vty_out(vty, "\n       OSPF Router with ID (%s)\n\n",
		inet_ntoa(ospf->router_id));

	/* Set database type to show. */
	if (strncmp(argv[arg_base + idx_type]->text, "r", 1) == 0)
		type = OSPF_ROUTER_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "ne", 2) == 0)
		type = OSPF_NETWORK_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "ns", 2) == 0)
		type = OSPF_AS_NSSA_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "s", 1) == 0)
		type = OSPF_SUMMARY_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "a", 1) == 0)
		type = OSPF_ASBR_SUMMARY_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "e", 1) == 0)
		type = OSPF_AS_EXTERNAL_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "opaque-l", 8) == 0)
		type = OSPF_OPAQUE_LINK_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "opaque-ar", 9) == 0)
		type = OSPF_OPAQUE_AREA_LSA;
	else if (strncmp(argv[arg_base + idx_type]->text, "opaque-as", 9) == 0)
		type = OSPF_OPAQUE_AS_LSA;
	else
		return CMD_WARNING;

	/* `show ip ospf database LSA adv-router ADV_ROUTER'. */
	if (strncmp(argv[arg_base + 5]->text, "s", 1) == 0)
		adv_router = ospf->router_id;
	else {
		ret = inet_aton(argv[arg_base + 6]->arg, &adv_router);
		if (!ret)
			return CMD_WARNING;
	}

	show_lsa_detail_adv_router(vty, ospf, type, &adv_router);

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_instance_database_type_adv_router,
       show_ip_ospf_instance_database_type_adv_router_cmd,
       "show ip ospf [{(1-65535)|vrf NAME}] database <asbr-summary|external|network|router|summary|nssa-external|opaque-link|opaque-area|opaque-as> <adv-router A.B.C.D|self-originate>",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       VRF_CMD_HELP_STR
       "Database summary\n"
       OSPF_LSA_TYPES_DESC
       "Advertising Router link states\n"
       "Advertising Router (as an IP address)\n"
       "Self-originated link states\n")
{
	struct ospf *ospf = NULL;
	unsigned short instance = 0;
	struct listnode *node = NULL;
	char *vrf_name = NULL;
	bool all_vrf = false;
	int ret = CMD_SUCCESS;
	int inst = 0;
	int idx = 0, idx_vrf = 0;
	uint8_t use_vrf = 0;

	if (argv_find(argv, argc, "(1-65535)", &idx)) {
		instance = strtoul(argv[idx]->arg, NULL, 10);
		ospf = ospf_lookup_instance(instance);
		if (ospf == NULL)
			return CMD_NOT_MY_INSTANCE;
		if (!ospf->oi_running) {
			vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}

		return (show_ip_ospf_database_type_adv_router_common(
			vty, ospf, idx ? 1 : 0, argc, argv, use_vrf));
	}

	OSPF_FIND_VRF_ARGS(argv, argc, idx_vrf, vrf_name, all_vrf);

	if (vrf_name) {
		bool ospf_output = false;

		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ospf_output = true;
				ret = show_ip_ospf_database_type_adv_router_common(
					vty, ospf, idx ? 1 : 0, argc, argv,
					use_vrf);
			}
			if (!ospf_output)
				vty_out(vty, "%% OSPF instance not found\n");
		} else {
			ospf = ospf_lookup_by_inst_name(inst, vrf_name);
			if ((ospf == NULL) || !ospf->oi_running) {
				vty_out(vty, "%% OSPF instance not found\n");
				return CMD_SUCCESS;
			}

			ret = show_ip_ospf_database_type_adv_router_common(
				vty, ospf, idx ? 1 : 0, argc, argv, use_vrf);
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}

		ret = show_ip_ospf_database_type_adv_router_common(
			vty, ospf, idx ? 1 : 0, argc, argv, use_vrf);
	}
	return ret;
	/*return (show_ip_ospf_database_type_adv_router_common(
		vty, ospf, idx ? 1 : 0, argc, argv));*/
}

DEFUN (ip_ospf_authentication_args,
       ip_ospf_authentication_args_addr_cmd,
       "ip ospf authentication <null|message-digest> [A.B.C.D]",
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable authentication on this interface\n"
       "Use null authentication\n"
       "Use message-digest authentication\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_encryption = 3;
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
       "no ip ospf authentication <null|message-digest> [A.B.C.D]",
       NO_STR
       "IP Information\n"
       "OSPF interface commands\n"
       "Enable authentication on this interface\n"
       "Use null authentication\n"
       "Use message-digest authentication\n"
       "Address of interface\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx_encryption = 4;
	int idx_ipv4 = 5;
	struct in_addr addr;
	int ret;
	struct ospf_if_params *params;
	struct route_node *rn;
	int auth_type;

	params = IF_DEF_PARAMS(ifp);

	if (argc == 6) {
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
		if (argv[idx_encryption]->arg[0] == 'n') {
			auth_type = OSPF_AUTH_NULL;
		} else if (argv[idx_encryption]->arg[0] == 'm') {
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
		}

		for (rn = route_top(IF_OIFS_PARAMS(ifp)); rn;
		     rn = route_next(rn)) {
			if ((params = rn->info)) {
				if (params->auth_type == auth_type) {
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
	if (ospf_crypt_key_lookup(params->auth_crypt, key_id) != NULL) {
		vty_out(vty, "OSPF: Key %d already exists\n", key_id);
		return CMD_WARNING;
	}

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

	for (rn = route_top(oi->nbrs); rn; rn = route_next(rn))
		if ((nbr = rn->info)) {
			nbr->v_inactivity = OSPF_IF_PARAM(oi, v_wait);
			nbr->v_db_desc = OSPF_IF_PARAM(oi, retransmit_interval);
			nbr->v_ls_req = OSPF_IF_PARAM(oi, retransmit_interval);
			nbr->v_ls_upd = OSPF_IF_PARAM(oi, retransmit_interval);
		}
}

static int ospf_vty_dead_interval_set(struct vty *vty, const char *interval_str,
				      const char *nbr_str,
				      const char *fast_hello_str)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	uint32_t seconds;
	uint8_t hellomult;
	struct in_addr addr;
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

	/* Update timer values in neighbor structure. */
	if (nbr_str) {
		struct ospf *ospf = NULL;

		ospf = ospf_lookup_by_vrf_id(ifp->vrf_id);
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
       "ip ospf dead-interval minimal hello-multiplier (1-10) [A.B.C.D]",
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
       "no ip ospf dead-interval [<(1-65535)|minimal hello-multiplier (1-10)> [A.B.C.D]]",
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

	UNSET_IF_PARAM(params, fast_hello);
	params->fast_hello = OSPF_FAST_HELLO_DEFAULT;

	if (params != IF_DEF_PARAMS(ifp)) {
		ospf_free_if_params(ifp, addr);
		ospf_if_update_params(ifp, addr);
	}

	/* Update timer values in neighbor structure. */
	if (argc == 1) {
		struct ospf *ospf = NULL;

		ospf = ospf_lookup_by_vrf_id(ifp->vrf_id);
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
              "no ospf dead-interval [<(1-65535)|minimal hello-multiplier (1-10)> [A.B.C.D]]",
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
	struct in_addr addr;
	struct ospf_if_params *params;
	params = IF_DEF_PARAMS(ifp);
	uint32_t seconds = 0;

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

	SET_IF_PARAM(params, v_hello);
	params->v_hello = seconds;

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

	UNSET_IF_PARAM(params, v_hello);
	params->v_hello = OSPF_HELLO_INTERVAL_DEFAULT;

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

DEFUN (ip_ospf_network,
       ip_ospf_network_cmd,
       "ip ospf network <broadcast|non-broadcast|point-to-multipoint|point-to-point>",
       "IP Information\n"
       "OSPF interface commands\n"
       "Network type\n"
       "Specify OSPF broadcast multi-access network\n"
       "Specify OSPF NBMA network\n"
       "Specify OSPF point-to-multipoint network\n"
       "Specify OSPF point-to-point network\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	int idx = 0;
	int old_type = IF_DEF_PARAMS(ifp)->type;
	struct route_node *rn;

	if (old_type == OSPF_IFTYPE_LOOPBACK) {
		vty_out(vty,
			"This is a loopback interface. Can't set network type.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (argv_find(argv, argc, "broadcast", &idx))
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_BROADCAST;
	else if (argv_find(argv, argc, "non-broadcast", &idx))
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_NBMA;
	else if (argv_find(argv, argc, "point-to-multipoint", &idx))
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_POINTOMULTIPOINT;
	else if (argv_find(argv, argc, "point-to-point", &idx))
		IF_DEF_PARAMS(ifp)->type = OSPF_IFTYPE_POINTOPOINT;

	if (IF_DEF_PARAMS(ifp)->type == old_type)
		return CMD_SUCCESS;

	SET_IF_PARAM(IF_DEF_PARAMS(ifp), type);

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->type = IF_DEF_PARAMS(ifp)->type;

		if (oi->state > ISM_Down) {
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceDown);
			OSPF_ISM_EVENT_EXECUTE(oi, ISM_InterfaceUp);
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

	if (IF_DEF_PARAMS(ifp)->type == old_type)
		return CMD_SUCCESS;

	for (rn = route_top(IF_OIFS(ifp)); rn; rn = route_next(rn)) {
		struct ospf_interface *oi = rn->info;

		if (!oi)
			continue;

		oi->type = IF_DEF_PARAMS(ifp)->type;

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
       "ip ospf retransmit-interval (3-65535) [A.B.C.D]",
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

	argv_find(argv, argc, "(3-65535)", &idx);
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
              "ospf retransmit-interval (3-65535) [A.B.C.D]",
              "OSPF interface commands\n"
              "Time between retransmitting lost link state advertisements\n"
              "Seconds\n"
              "Address of interface\n")
{
	return ip_ospf_retransmit_interval(self, vty, argc, argv);
}

DEFUN (no_ip_ospf_retransmit_interval,
       no_ip_ospf_retransmit_interval_addr_cmd,
       "no ip ospf retransmit-interval [(3-65535)] [A.B.C.D]",
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
       "no ospf retransmit-interval [(3-65535)] [A.B.C.D]",
       NO_STR
       "OSPF interface commands\n"
       "Time between retransmitting lost link state advertisements\n"
       "Seconds\n"
       "Address of interface\n")
{
	return no_ip_ospf_retransmit_interval(self, vty, argc, argv);
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

	if (argv_find(argv, argc, "(1-65535)", &idx))
		instance = strtol(argv[idx]->arg, NULL, 10);

	argv_find(argv, argc, "area", &idx);
	areaid = argv[idx + 1]->arg;

	if (ifp->vrf_id && !instance)
		ospf = ospf_lookup_by_vrf_id(ifp->vrf_id);
	else
		ospf = ospf_lookup_instance(instance);

	if (instance && ospf == NULL) {
		params = IF_DEF_PARAMS(ifp);
		if (OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
			UNSET_IF_PARAM(params, if_area);
			ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
			ospf_interface_area_unset(ospf, ifp);
			ospf->if_ospf_cli_count--;
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
			vty_out(vty,
				"Must remove previous area/address config before changing ospf area");
			return CMD_WARNING_CONFIG_FAILED;
		}
		ospf_if_update_params((ifp), (addr));
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

	/* enable ospf on this interface with area_id */
	if (params) {
		SET_IF_PARAM(params, if_area);
		params->if_area = area_id;
		params->if_area_id_fmt = format;
	}

	if (ospf) {
		ospf_interface_area_set(ospf, ifp);
		ospf->if_ospf_cli_count++;
	}

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

	if (argv_find(argv, argc, "(1-65535)", &idx))
		instance = strtol(argv[idx]->arg, NULL, 10);

	if (ifp->vrf_id && !instance)
		ospf = ospf_lookup_by_vrf_id(ifp->vrf_id);
	else
		ospf = ospf_lookup_instance(instance);

	if (ospf == NULL)
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

	ospf_interface_area_unset(ospf, ifp);
	ospf->if_ospf_cli_count--;
	return CMD_SUCCESS;
}

DEFUN (ospf_redistribute_source,
       ospf_redistribute_source_cmd,
       "redistribute " FRR_REDIST_STR_OSPFD " [{metric (0-16777214)|metric-type (1-2)|route-map WORD}]",
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

	/* Get distribute source. */
	source = proto_redistnum(AFI_IP, argv[idx_protocol]->text);
	if (source < 0)
		return CMD_WARNING_CONFIG_FAILED;

	red = ospf_redist_add(ospf, source, 0);

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
	/* Get route-map */
	if (argv_find(argv, argc, "WORD", &idx)) {
		ospf_routemap_set(red, argv[idx]->arg);
	} else
		ospf_routemap_unset(red);

	return ospf_redistribute_set(ospf, source, 0, type, metric);
}

DEFUN (no_ospf_redistribute_source,
       no_ospf_redistribute_source_cmd,
       "no redistribute " FRR_REDIST_STR_OSPFD " [{metric (0-16777214)|metric-type (1-2)|route-map WORD}]",
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
       "redistribute <ospf|table> (1-65535) [{metric (0-16777214)|metric-type (1-2)|route-map WORD}]",
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

	red = ospf_redist_add(ospf, source, instance);

	idx = 3;
	if (argv_find(argv, argc, "route-map", &idx))
		ospf_routemap_set(red, argv[idx + 1]->arg);
	else
		ospf_routemap_unset(red);

	return ospf_redistribute_set(ospf, source, instance, type, metric);
}

DEFUN (no_ospf_redistribute_instance_source,
       no_ospf_redistribute_instance_source_cmd,
       "no redistribute <ospf|table> (1-65535) [{metric (0-16777214)|metric-type (1-2)|route-map WORD}]",
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
       "distribute-list WORD out " FRR_REDIST_STR_OSPFD,
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
       "no distribute-list WORD out " FRR_REDIST_STR_OSPFD,
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
       "default-information originate [{always|metric (0-16777214)|metric-type (1-2)|route-map WORD}]",
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
	int sameRtmap = 0;
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
	if (argv_find(argv, argc, "WORD", &idx))
		rtmap = argv[idx]->arg;

	/* To check ,if user is providing same route map */
	if ((rtmap == ROUTEMAP_NAME(red)) ||
	    (rtmap && ROUTEMAP_NAME(red)
	    && (strcmp(rtmap, ROUTEMAP_NAME(red)) == 0)))
		sameRtmap = 1;

	/* Don't allow if the same lsa is aleardy originated. */
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
       "no default-information originate [{always|metric (0-16777214)|metric-type (1-2)|route-map WORD}]",
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

	ospf->distance_all = atoi(argv[idx_number]->arg);

	return CMD_SUCCESS;
}

DEFUN (no_ospf_distance,
       no_ospf_distance_cmd,
       "no distance (1-255)",
       NO_STR
       "Administrative distance\n"
       "OSPF Administrative distance\n")
{
	VTY_DECLVAR_INSTANCE_CONTEXT(ospf, ospf);

	ospf->distance_all = 0;

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

#if 0
DEFUN (ospf_distance_source,
       ospf_distance_source_cmd,
       "distance (1-255) A.B.C.D/M",
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n")
{
  VTY_DECLVAR_CONTEXT(ospf, ospf);
  int idx_number = 1;
  int idx_ipv4_prefixlen = 2;

  ospf_distance_set (vty, ospf, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, NULL);

  return CMD_SUCCESS;
}

DEFUN (no_ospf_distance_source,
       no_ospf_distance_source_cmd,
       "no distance (1-255) A.B.C.D/M",
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n")
{
  VTY_DECLVAR_CONTEXT(ospf, ospf);
  int idx_number = 2;
  int idx_ipv4_prefixlen = 3;

  ospf_distance_unset (vty, ospf, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, NULL);

  return CMD_SUCCESS;
}

DEFUN (ospf_distance_source_access_list,
       ospf_distance_source_access_list_cmd,
       "distance (1-255) A.B.C.D/M WORD",
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
  VTY_DECLVAR_CONTEXT(ospf, ospf);
  int idx_number = 1;
  int idx_ipv4_prefixlen = 2;
  int idx_word = 3;

  ospf_distance_set (vty, ospf, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, argv[idx_word]->arg);

  return CMD_SUCCESS;
}

DEFUN (no_ospf_distance_source_access_list,
       no_ospf_distance_source_access_list_cmd,
       "no distance (1-255) A.B.C.D/M WORD",
       NO_STR
       "Administrative distance\n"
       "Distance value\n"
       "IP source prefix\n"
       "Access list name\n")
{
  VTY_DECLVAR_CONTEXT(ospf, ospf);
  int idx_number = 2;
  int idx_ipv4_prefixlen = 3;
  int idx_word = 4;

  ospf_distance_unset (vty, ospf, argv[idx_number]->arg, argv[idx_ipv4_prefixlen]->arg, argv[idx_word]->arg);

  return CMD_SUCCESS;
}
#endif

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
		vty_out(vty, "%% Must supply stub-router period");
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
		OSPF_TIMER_OFF(area->t_stub_router);

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
		vty_out(vty, "%% Must supply stub-router shutdown period");
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

static void config_write_stub_router(struct vty *vty, struct ospf *ospf)
{
	struct listnode *ln;
	struct ospf_area *area;

	if (ospf->stub_router_startup_time != OSPF_STUB_ROUTER_UNCONFIGURED)
		vty_out(vty, " max-metric router-lsa on-startup %u\n",
			ospf->stub_router_startup_time);
	if (ospf->stub_router_shutdown_time != OSPF_STUB_ROUTER_UNCONFIGURED)
		vty_out(vty, " max-metric router-lsa on-shutdown %u\n",
			ospf->stub_router_shutdown_time);
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, ln, area)) {
		if (CHECK_FLAG(area->stub_router_state,
			       OSPF_AREA_ADMIN_STUB_ROUTED)) {
			vty_out(vty, " max-metric router-lsa administrative\n");
			break;
		}
	}
	return;
}

static void show_ip_ospf_route_network(struct vty *vty, struct ospf *ospf,
				       struct route_table *rt,
				       json_object *json)
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
		if ((or = rn->info) == NULL)
			continue;
		char buf1[PREFIX2STR_BUFFER];

		memset(buf1, 0, sizeof(buf1));
		prefix2str(&rn->p, buf1, sizeof(buf1));

		json_route = json_object_new_object();
		if (json) {
			json_object_object_add(json, buf1, json_route);
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_NOSLASHESCAPE);
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
					json_object_string_add(
						json_route, "area",
						inet_ntoa(or->u.std.area_id));
				} else {
					vty_out(vty,
						"N IA %-18s    [%d] area: %s\n",
						buf1, or->cost,
						inet_ntoa(or->u.std.area_id));
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
				json_object_int_add(json_route, "cost",
						    or->cost);
				json_object_string_add(
					json_route, "area",
					inet_ntoa(or->u.std.area_id));
			} else {
				vty_out(vty, "N    %-18s    [%d] area: %s\n",
					buf1, or->cost,
					inet_ntoa(or->u.std.area_id));
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

					if (path->nexthop.s_addr == 0) {
						if (json) {
							json_object_string_add(
								json_nexthop,
								"ip", " ");
							json_object_string_add(
								json_nexthop,
								"directly attached to",
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
							json_object_string_add(
								json_nexthop,
								"ip",
								inet_ntoa(
									path->nexthop));
							json_object_string_add(
								json_nexthop,
								"via",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						} else {
							vty_out(vty,
								"%24s   via %s, %s\n",
								"",
								inet_ntoa(
									path->nexthop),
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						}
					}
				}
			}
		}
		if (!json)
			json_object_free(json_route);
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
	json_object *json_route = NULL, *json_nexthop_array = NULL,
		    *json_nexthop = NULL;

	if (!json)
		vty_out(vty,
			"============ OSPF router routing table =============\n");

	for (rn = route_top(rtrs); rn; rn = route_next(rn)) {
		if (rn->info == NULL)
			continue;
		int flag = 0;

		json_route = json_object_new_object();
		if (json) {
			json_object_object_add(json, inet_ntoa(rn->p.u.prefix4),
					       json_route);
			json_object_string_add(json_route, "routeType", "R ");
		} else {
			vty_out(vty, "R    %-15s    ",
				inet_ntoa(rn->p.u.prefix4));
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
				json_object_string_add(
					json_route, "area",
					inet_ntoa(or->u.std.area_id));
				if (or->path_type == OSPF_PATH_INTER_AREA)
					json_object_boolean_true_add(json_route,
								     "IA");
				if (or->u.std.flags & ROUTER_LSA_BORDER)
					json_object_string_add(json_route,
							       "routerType",
							       "abr");
				else if (or->u.std.flags & ROUTER_LSA_EXTERNAL)
					json_object_string_add(json_route,
							       "routerType",
							       "asbr");
			} else {
				vty_out(vty, "%s [%d] area: %s",
					(or->path_type == OSPF_PATH_INTER_AREA
						 ? "IA"
						 : "  "),
					or->cost, inet_ntoa(or->u.std.area_id));
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
					if (path->nexthop.s_addr == 0) {
						if (json) {
							json_object_string_add(
								json_nexthop,
								"ip", " ");
							json_object_string_add(
								json_nexthop,
								"directly attached to",
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
							json_object_string_add(
								json_nexthop,
								"ip",
								inet_ntoa(
									path->nexthop));
							json_object_string_add(
								json_nexthop,
								"via",
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						} else {
							vty_out(vty,
								"%24s   via %s, %s\n",
								"",
								inet_ntoa(
									path->nexthop),
								ifindex2ifname(
									path->ifindex,
									ospf->vrf_id));
						}
					}
				}
			}
		}
		if (!json)
			json_object_free(json_route);
	}
	if (!json)
		vty_out(vty, "\n");
}

static void show_ip_ospf_route_external(struct vty *vty, struct ospf *ospf,
					struct route_table *rt,
					json_object *json)
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

		snprintf(buf1, 19, "%s/%d", inet_ntoa(rn->p.u.prefix4),
			 rn->p.prefixlen);
		json_route = json_object_new_object();
		if (json) {
			json_object_object_add(json, buf1, json_route);
			json_object_to_json_string_ext(
				json, JSON_C_TO_STRING_NOSLASHESCAPE);
		}

		switch (er->path_type) {
		case OSPF_PATH_TYPE1_EXTERNAL:
			if (json) {
				json_object_string_add(json_route, "routeType",
						       "N E1");
				json_object_int_add(json_route, "cost",
						    er->cost);
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
				if (path->nexthop.s_addr == 0) {
					if (json) {
						json_object_string_add(
							json_nexthop, "ip",
							" ");
						json_object_string_add(
							json_nexthop,
							"directly attached to",
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
						json_object_string_add(
							json_nexthop, "ip",
							inet_ntoa(
								path->nexthop));
						json_object_string_add(
							json_nexthop, "via",
							ifindex2ifname(
								path->ifindex,
								ospf->vrf_id));
					} else {
						vty_out(vty,
							"%24s   via %s, %s\n",
							"",
							inet_ntoa(
								path->nexthop),
							ifindex2ifname(
								path->ifindex,
								ospf->vrf_id));
					}
				}
			}
		}
		if (!json)
			json_object_free(json_route);
	}
	if (!json)
		vty_out(vty, "\n");
}

static int show_ip_ospf_border_routers_common(struct vty *vty,
					      struct ospf *ospf,
					      uint8_t use_vrf)
{
	if (ospf->instance)
		vty_out(vty, "\nOSPF Instance: %d\n\n", ospf->instance);

	ospf_show_vrf_name(ospf, vty, NULL, use_vrf);

	if (ospf->new_table == NULL) {
		vty_out(vty, "No OSPF routing information exist\n");
		return CMD_SUCCESS;
	}

	/* Show Network routes.
	show_ip_ospf_route_network (vty, ospf->new_table);   */

	/* Show Router routes. */
	show_ip_ospf_route_router(vty, ospf, ospf->new_rtrs, NULL);

	vty_out(vty, "\n");

	return CMD_SUCCESS;
}

DEFUN (show_ip_ospf_border_routers,
       show_ip_ospf_border_routers_cmd,
       "show ip ospf [vrf <NAME|all>] border-routers",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       VRF_CMD_HELP_STR
       "All VRFs\n"
       "Show all the ABR's and ASBR's\n")
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
				ret = show_ip_ospf_border_routers_common(
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

			ret = show_ip_ospf_border_routers_common(vty, ospf,
								 use_vrf);
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			vty_out(vty, "%% OSPF instance not found\n");
			return CMD_SUCCESS;
		}

		ret = show_ip_ospf_border_routers_common(vty, ospf, use_vrf);
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
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_border_routers_common(vty, ospf, 0);
}

static int show_ip_ospf_route_common(struct vty *vty, struct ospf *ospf,
				     json_object *json, uint8_t use_vrf)
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
		vty_out(vty, "No OSPF routing information exist\n");
		return CMD_SUCCESS;
	}

	/* Show Network routes. */
	show_ip_ospf_route_network(vty, ospf, ospf->new_table, json_vrf);

	/* Show Router routes. */
	show_ip_ospf_route_router(vty, ospf, ospf->new_rtrs, json_vrf);

	/* Show AS External routes. */
	show_ip_ospf_route_external(vty, ospf, ospf->old_external_route,
				    json_vrf);

	if (json) {
		if (use_vrf) {
			// json_object_object_add(json_vrf, "areas",
			// json_areas);
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

DEFUN (show_ip_ospf_route,
       show_ip_ospf_route_cmd,
	"show ip ospf [vrf <NAME|all>] route [json]",
	SHOW_STR
	IP_STR
	"OSPF information\n"
	VRF_CMD_HELP_STR
	"All VRFs\n"
	"OSPF routing table\n"
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

	/* vrf input is provided could be all or specific vrf*/
	if (vrf_name) {
		bool ospf_output = false;

		use_vrf = 1;

		if (all_vrf) {
			for (ALL_LIST_ELEMENTS_RO(om->ospf, node, ospf)) {
				if (!ospf->oi_running)
					continue;
				ospf_output = true;
				ret = show_ip_ospf_route_common(vty, ospf, json,
								use_vrf);
			}

			if (uj) {
				/* Keep Non-pretty format */
				vty_out(vty, "%s\n",
					json_object_to_json_string(json));
				json_object_free(json);
			} else if (!ospf_output)
				vty_out(vty, "%% OSPF instance not found\n");

			return ret;
		}
		ospf = ospf_lookup_by_inst_name(inst, vrf_name);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

			return CMD_SUCCESS;
		}
	} else {
		/* Display default ospf (instance 0) info */
		ospf = ospf_lookup_by_vrf_id(VRF_DEFAULT);
		if (ospf == NULL || !ospf->oi_running) {
			if (uj) {
				vty_out(vty, "%s\n",
					json_object_to_json_string_ext(
						json, JSON_C_TO_STRING_PRETTY));
				json_object_free(json);
			} else
				vty_out(vty, "%% OSPF instance not found\n");

			return CMD_SUCCESS;
		}
	}

	if (ospf) {
		ret = show_ip_ospf_route_common(vty, ospf, json, use_vrf);
		/* Keep Non-pretty format */
		if (uj)
			vty_out(vty, "%s\n", json_object_to_json_string(json));
	}

	if (uj)
		json_object_free(json);

	return ret;
}

DEFUN (show_ip_ospf_instance_route,
       show_ip_ospf_instance_route_cmd,
       "show ip ospf (1-65535) route",
       SHOW_STR
       IP_STR
       "OSPF information\n"
       "Instance ID\n"
       "OSPF routing table\n")
{
	int idx_number = 3;
	struct ospf *ospf;
	unsigned short instance = 0;

	instance = strtoul(argv[idx_number]->arg, NULL, 10);
	ospf = ospf_lookup_instance(instance);
	if (ospf == NULL)
		return CMD_NOT_MY_INSTANCE;

	if (!ospf->oi_running)
		return CMD_SUCCESS;

	return show_ip_ospf_route_common(vty, ospf, NULL, 0);
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
	static char header[] = "Name                       Id     RouterId  ";

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

		if (ospf->vrf_id == 0)
			name = VRF_DEFAULT_NAME;
		else
			name = ospf->name;

		vrf_id_ui = (ospf->vrf_id == VRF_UNKNOWN)
				    ? -1
				    : (int64_t)ospf->vrf_id;

		if (uj) {
			json_object_int_add(json_vrf, "vrfId", vrf_id_ui);
			json_object_string_add(json_vrf, "routerId",
					       inet_ntoa(ospf->router_id));

			json_object_object_add(json_vrfs, name, json_vrf);

		} else {
			vty_out(vty, "%-25s  %-5d  %-16s  \n", name,
				ospf->vrf_id, inet_ntoa(ospf->router_id));
		}
	}

	if (uj) {
		json_object_object_add(json, "vrfs", json_vrfs);
		json_object_int_add(json, "totalVrfs", count);

		vty_out(vty, "%s\n", json_object_to_json_string_ext(
					     json, JSON_C_TO_STRING_PRETTY));
		json_object_free(json);
	} else {
		if (count)
			vty_out(vty, "\nTotal number of OSPF VRFs: %d\n",
				count);
	}

	return CMD_SUCCESS;
}

const char *ospf_abr_type_str[] = {"unknown", "standard", "ibm", "cisco",
				   "shortcut"};

const char *ospf_shortcut_mode_str[] = {"default", "enable", "disable"};

const char *ospf_int_type_str[] = {"unknown", /* should never be used. */
				   "point-to-point", "broadcast",
				   "non-broadcast",  "point-to-multipoint",
				   "virtual-link", /* should never be used. */
				   "loopback"};

static int config_write_interface_one(struct vty *vty, struct vrf *vrf)
{
	struct listnode *node;
	struct interface *ifp;
	struct crypt_key *ck;
	struct route_node *rn = NULL;
	struct ospf_if_params *params;
	int write = 0;
	struct ospf *ospf = vrf->info;

	FOR_ALL_INTERFACES (vrf, ifp) {

		if (memcmp(ifp->name, "VLINK", 5) == 0)
			continue;

		vty_frame(vty, "!\n");
		if (ifp->vrf_id == VRF_DEFAULT)
			vty_frame(vty, "interface %s\n", ifp->name);
		else
			vty_frame(vty, "interface %s vrf %s\n", ifp->name,
				  vrf->name);
		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);

		write++;

		params = IF_DEF_PARAMS(ifp);

		do {
			/* Interface Network print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, type)
			    && params->type != OSPF_IFTYPE_LOOPBACK) {
				if (params->type != ospf_default_iftype(ifp)) {
					vty_out(vty, " ip ospf network %s",
						ospf_int_type_str
							[params->type]);
					if (params != IF_DEF_PARAMS(ifp) && rn)
						vty_out(vty, " %s",
							inet_ntoa(
								rn->p.u.prefix4));
					vty_out(vty, "\n");
				}
			}

			/* OSPF interface authentication print */
			if (OSPF_IF_PARAM_CONFIGURED(params, auth_type)
			    && params->auth_type != OSPF_AUTH_NOTSET) {
				const char *auth_str;

				/* Translation tables are not that much help
				* here due to syntax
				* of the simple option */
				switch (params->auth_type) {

				case OSPF_AUTH_NULL:
					auth_str = " null";
					break;

				case OSPF_AUTH_SIMPLE:
					auth_str = "";
					break;

				case OSPF_AUTH_CRYPTOGRAPHIC:
					auth_str = " message-digest";
					break;

				default:
					auth_str = "";
					break;
				}

				vty_out(vty, " ip ospf authentication%s",
					auth_str);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}

			/* Simple Authentication Password print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, auth_simple)
			    && params->auth_simple[0] != '\0') {
				vty_out(vty, " ip ospf authentication-key %s",
					params->auth_simple);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
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
						vty_out(vty, " %s",
							inet_ntoa(
								rn->p.u.prefix4));
					vty_out(vty, "\n");
				}
			}

			/* Interface Output Cost print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, output_cost_cmd)) {
				vty_out(vty, " ip ospf cost %u",
					params->output_cost_cmd);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}

			/* Hello Interval print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, v_hello)
			    && params->v_hello != OSPF_HELLO_INTERVAL_DEFAULT) {
				vty_out(vty, " ip ospf hello-interval %u",
					params->v_hello);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}


			/* Router Dead Interval print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, v_wait)
			    && params->v_wait
				       != OSPF_ROUTER_DEAD_INTERVAL_DEFAULT) {
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
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}

			/* Router Priority print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, priority)
			    && params->priority
				       != OSPF_ROUTER_PRIORITY_DEFAULT) {
				vty_out(vty, " ip ospf priority %u",
					params->priority);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
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
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}

			/* Transmit Delay print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, transmit_delay)
			    && params->transmit_delay
				       != OSPF_TRANSMIT_DELAY_DEFAULT) {
				vty_out(vty, " ip ospf transmit-delay %u",
					params->transmit_delay);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}

			/* Area  print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, if_area)) {
				if (ospf && ospf->instance)
					vty_out(vty, " ip ospf %d",
						ospf->instance);
				else
					vty_out(vty, " ip ospf");

				char buf[INET_ADDRSTRLEN];

				area_id2str(buf, sizeof(buf), &params->if_area,
					    params->if_area_id_fmt);
				vty_out(vty, " area %s", buf);
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
				vty_out(vty, "\n");
			}

			/* bfd  print. */
			if (params && params->bfd_info)
				ospf_bfd_write_config(vty, params);

			/* MTU ignore print. */
			if (OSPF_IF_PARAM_CONFIGURED(params, mtu_ignore)
			    && params->mtu_ignore != OSPF_MTU_IGNORE_DEFAULT) {
				if (params->mtu_ignore == 0)
					vty_out(vty, " no ip ospf mtu-ignore");
				else
					vty_out(vty, " ip ospf mtu-ignore");
				if (params != IF_DEF_PARAMS(ifp) && rn)
					vty_out(vty, " %s",
						inet_ntoa(rn->p.u.prefix4));
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

		vty_endframe(vty, NULL);
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
	uint8_t buf[INET_ADDRSTRLEN];

	/* `network area' print. */
	for (rn = route_top(ospf->networks); rn; rn = route_next(rn))
		if (rn->info) {
			struct ospf_network *n = rn->info;

			/* Create Area ID string by specified Area ID format. */
			if (n->area_id_fmt == OSPF_AREA_ID_FMT_DOTTEDQUAD)
				inet_ntop(AF_INET, &n->area_id, (char *)buf,
					  sizeof(buf));
			else
				sprintf((char *)buf, "%lu",
					(unsigned long int)ntohl(
						n->area_id.s_addr));

			/* Network print. */
			vty_out(vty, " network %s/%d area %s\n",
				inet_ntoa(rn->p.u.prefix4), rn->p.prefixlen,
				buf);
		}

	return 0;
}

static int config_write_ospf_area(struct vty *vty, struct ospf *ospf)
{
	struct listnode *node;
	struct ospf_area *area;
	uint8_t buf[INET_ADDRSTRLEN];

	/* Area configuration print. */
	for (ALL_LIST_ELEMENTS_RO(ospf->areas, node, area)) {
		struct route_node *rn1;

		area_id2str((char *)buf, sizeof(buf), &area->area_id,
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
				switch (area->NSSATranslatorRole) {
				case OSPF_NSSA_ROLE_NEVER:
					vty_out(vty,
						" area %s nssa translate-never\n",
						buf);
					break;
				case OSPF_NSSA_ROLE_ALWAYS:
					vty_out(vty,
						" area %s nssa translate-always\n",
						buf);
					break;
				case OSPF_NSSA_ROLE_CANDIDATE:
					vty_out(vty, " area %s nssa \n", buf);
					break;
				}
				if (area->no_summary)
					vty_out(vty,
						" area %s nssa no-summary\n",
						buf);
			}

			if (area->default_cost != 1)
				vty_out(vty, " area %s default-cost %d\n", buf,
					area->default_cost);
		}

		for (rn1 = route_top(area->ranges); rn1; rn1 = route_next(rn1))
			if (rn1->info) {
				struct ospf_area_range *range = rn1->info;

				vty_out(vty, " area %s range %s/%d", buf,
					inet_ntoa(rn1->p.u.prefix4),
					rn1->p.prefixlen);

				if (range->cost_config
				    != OSPF_AREA_RANGE_COST_UNSPEC)
					vty_out(vty, " cost %d",
						range->cost_config);

				if (!CHECK_FLAG(range->flags,
						OSPF_AREA_RANGE_ADVERTISE))
					vty_out(vty, " not-advertise");

				if (CHECK_FLAG(range->flags,
					       OSPF_AREA_RANGE_SUBSTITUTE))
					vty_out(vty, " substitute %s/%d",
						inet_ntoa(range->subst_addr),
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
			vty_out(vty, " neighbor %s", inet_ntoa(nbr_nbma->addr));

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
			if (OSPF_IF_PARAM(oi, v_hello)
				    != OSPF_HELLO_INTERVAL_DEFAULT
			    || OSPF_IF_PARAM(oi, v_wait)
				       != OSPF_ROUTER_DEAD_INTERVAL_DEFAULT
			    || OSPF_IF_PARAM(oi, retransmit_interval)
				       != OSPF_RETRANSMIT_INTERVAL_DEFAULT
			    || OSPF_IF_PARAM(oi, transmit_delay)
				       != OSPF_TRANSMIT_DELAY_DEFAULT)
				vty_out(vty,
					" area %s virtual-link %s hello-interval %d retransmit-interval %d transmit-delay %d dead-interval %d\n",
					buf, inet_ntoa(vl_data->vl_peer),
					OSPF_IF_PARAM(oi, v_hello),
					OSPF_IF_PARAM(oi, retransmit_interval),
					OSPF_IF_PARAM(oi, transmit_delay),
					OSPF_IF_PARAM(oi, v_wait));
			else
				vty_out(vty, " area %s virtual-link %s\n", buf,
					inet_ntoa(vl_data->vl_peer));
			/* Auth key */
			if (IF_DEF_PARAMS(vl_data->vl_oi->ifp)->auth_simple[0]
			    != '\0')
				vty_out(vty,
					" area %s virtual-link %s authentication-key %s\n",
					buf, inet_ntoa(vl_data->vl_peer),
					IF_DEF_PARAMS(vl_data->vl_oi->ifp)
						->auth_simple);
			/* md5 keys */
			for (ALL_LIST_ELEMENTS_RO(
				     IF_DEF_PARAMS(vl_data->vl_oi->ifp)
					     ->auth_crypt,
				     n2, ck))
				vty_out(vty,
					" area %s virtual-link %s"
					" message-digest-key %d md5 %s\n",
					buf, inet_ntoa(vl_data->vl_peer),
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
			vty_out(vty, " distance %d %s/%d %s\n",
				odistance->distance, inet_ntoa(rn->p.u.prefix4),
				rn->p.prefixlen,
				odistance->access_list ? odistance->access_list
						       : "");
		}
	return 0;
}

static int ospf_config_write_one(struct vty *vty, struct ospf *ospf)
{
	struct vrf *vrf = vrf_lookup_by_id(ospf->vrf_id);
	struct interface *ifp;
	struct ospf_interface *oi;
	struct listnode *node = NULL;
	int write = 0;

	/* `router ospf' print. */
	if (ospf->instance && ospf->name) {
		vty_out(vty, "router ospf %d vrf %s\n", ospf->instance,
			ospf->name);
	} else if (ospf->instance) {
		vty_out(vty, "router ospf %d\n", ospf->instance);
	} else if (ospf->name) {
		vty_out(vty, "router ospf vrf %s\n", ospf->name);
	} else
		vty_out(vty, "router ospf\n");

	if (!ospf->networks) {
		write++;
		return write;
	}

	/* Router ID print. */
	if (ospf->router_id_static.s_addr != 0)
		vty_out(vty, " ospf router-id %s\n",
			inet_ntoa(ospf->router_id_static));

	/* ABR type print. */
	if (ospf->abr_type != OSPF_ABR_DEFAULT)
		vty_out(vty, " ospf abr-type %s\n",
			ospf_abr_type_str[ospf->abr_type]);

	/* log-adjacency-changes flag print. */
	if (CHECK_FLAG(ospf->config, OSPF_LOG_ADJACENCY_CHANGES)) {
		if (CHECK_FLAG(ospf->config, OSPF_LOG_ADJACENCY_DETAIL))
			vty_out(vty, " log-adjacency-changes detail\n");
		else if (!DFLT_OSPF_LOG_ADJACENCY_CHANGES)
			vty_out(vty, " log-adjacency-changes\n");
	} else if (DFLT_OSPF_LOG_ADJACENCY_CHANGES) {
		vty_out(vty, " no log-adjacency-changes\n");
	}

	/* RFC1583 compatibility flag print -- Compatible with CISCO
	 * 12.1. */
	if (CHECK_FLAG(ospf->config, OSPF_RFC1583_COMPATIBLE))
		vty_out(vty, " compatible rfc1583\n");

	/* auto-cost reference-bandwidth configuration.  */
	if (ospf->ref_bandwidth != OSPF_DEFAULT_REF_BANDWIDTH) {
		vty_out(vty,
			"! Important: ensure reference bandwidth "
			"is consistent across all routers\n");
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

	/* Max-metric router-lsa print */
	config_write_stub_router(vty, ospf);

	/* SPF refresh parameters print. */
	if (ospf->lsa_refresh_interval != OSPF_LSA_REFRESH_INTERVAL_DEFAULT)
		vty_out(vty, " refresh timer %d\n", ospf->lsa_refresh_interval);

	/* Redistribute information print. */
	config_write_ospf_redistribute(vty, ospf);

	/* passive-interface print. */
	if (ospf->passive_interface_default == OSPF_IF_PASSIVE)
		vty_out(vty, " passive-interface default\n");

	FOR_ALL_INTERFACES (vrf, ifp)
		if (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(ifp),
					     passive_interface)
		    && IF_DEF_PARAMS(ifp)->passive_interface
			       != ospf->passive_interface_default) {
			vty_out(vty, " %spassive-interface %s\n",
				IF_DEF_PARAMS(ifp)->passive_interface ? ""
								      : "no ",
				ifp->name);
		}
	for (ALL_LIST_ELEMENTS_RO(ospf->oiflist, node, oi)) {
		if (!OSPF_IF_PARAM_CONFIGURED(oi->params, passive_interface))
			continue;
		if (OSPF_IF_PARAM_CONFIGURED(IF_DEF_PARAMS(oi->ifp),
					     passive_interface)) {
			if (oi->params->passive_interface
			    == IF_DEF_PARAMS(oi->ifp)->passive_interface)
				continue;
		} else if (oi->params->passive_interface
			   == ospf->passive_interface_default)
			continue;

		vty_out(vty, " %spassive-interface %s %s\n",
			oi->params->passive_interface ? "" : "no ",
			oi->ifp->name, inet_ntoa(oi->address->u.prefix4));
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
	install_element(VIEW_NODE, &show_ip_ospf_database_max_cmd);

	install_element(VIEW_NODE,
			&show_ip_ospf_instance_database_type_adv_router_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_database_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_database_max_cmd);

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

	install_element(VIEW_NODE, &show_ip_ospf_instance_route_cmd);
	install_element(VIEW_NODE, &show_ip_ospf_instance_border_routers_cmd);

	/* "show ip ospf vrfs" commands. */
	install_element(VIEW_NODE, &show_ip_ospf_vrfs_cmd);
}


/* ospfd's interface node. */
static struct cmd_node interface_node = {INTERFACE_NODE, "%s(config-if)# ", 1};

/* Initialization of OSPF interface. */
static void ospf_vty_if_init(void)
{
	/* Install interface node. */
	install_node(&interface_node, config_write_interface);
	if_cmd_init();

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

	/* "ip ospf transmit-delay" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_transmit_delay_addr_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_transmit_delay_addr_cmd);

	/* "ip ospf area" commands. */
	install_element(INTERFACE_NODE, &ip_ospf_area_cmd);
	install_element(INTERFACE_NODE, &no_ip_ospf_area_cmd);

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
#if 0
  install_element (OSPF_NODE, &ospf_distance_source_cmd);
  install_element (OSPF_NODE, &no_ospf_distance_source_cmd);
  install_element (OSPF_NODE, &ospf_distance_source_access_list_cmd);
  install_element (OSPF_NODE, &no_ospf_distance_source_access_list_cmd);
#endif /* 0 */
}

static struct cmd_node ospf_node = {OSPF_NODE, "%s(config-router)# ", 1};

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

void ospf_vty_clear_init(void)
{
	install_element(ENABLE_NODE, &clear_ip_ospf_interface_cmd);
}


/* Install OSPF related vty commands. */
void ospf_vty_init(void)
{
	/* Install ospf top node. */
	install_node(&ospf_node, ospf_config_write);

	/* "router ospf" commands. */
	install_element(CONFIG_NODE, &router_ospf_cmd);
	install_element(CONFIG_NODE, &no_router_ospf_cmd);


	install_default(OSPF_NODE);

	/* "ospf router-id" commands. */
	install_element(OSPF_NODE, &ospf_router_id_cmd);
	install_element(OSPF_NODE, &ospf_router_id_old_cmd);
	install_element(OSPF_NODE, &no_ospf_router_id_cmd);

	/* "passive-interface" commands. */
	install_element(OSPF_NODE, &ospf_passive_interface_addr_cmd);
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
	install_element(OSPF_NODE, &ospf_area_range_substitute_cmd);
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
	install_element(OSPF_NODE, &ospf_area_nssa_translate_cmd);
	install_element(OSPF_NODE, &ospf_area_nssa_no_summary_cmd);
	install_element(OSPF_NODE, &no_ospf_area_nssa_no_summary_cmd);
	install_element(OSPF_NODE, &no_ospf_area_nssa_cmd);

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
	install_element(OSPF_NODE, &no_ospf_timers_min_ls_interval_cmd);
	install_element(OSPF_NODE, &ospf_timers_lsa_min_arrival_cmd);
	install_element(OSPF_NODE, &no_ospf_timers_lsa_min_arrival_cmd);

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

	/* "neighbor" commands. */
	install_element(OSPF_NODE, &ospf_neighbor_cmd);
	install_element(OSPF_NODE, &ospf_neighbor_poll_interval_cmd);
	install_element(OSPF_NODE, &no_ospf_neighbor_cmd);
	install_element(OSPF_NODE, &no_ospf_neighbor_poll_cmd);

	/* write multiplier commands */
	install_element(OSPF_NODE, &ospf_write_multiplier_cmd);
	install_element(OSPF_NODE, &write_multiplier_cmd);
	install_element(OSPF_NODE, &no_ospf_write_multiplier_cmd);
	install_element(OSPF_NODE, &no_write_multiplier_cmd);

	/* Init interface related vty commands. */
	ospf_vty_if_init();

	/* Init zebra related vty commands. */
	ospf_vty_zebra_init();
}
