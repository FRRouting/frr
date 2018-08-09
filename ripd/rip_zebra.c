/* RIPd and zebra interface.
 * Copyright (C) 1997, 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
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

#include "command.h"
#include "prefix.h"
#include "table.h"
#include "stream.h"
#include "memory.h"
#include "routemap.h"
#include "zclient.h"
#include "log.h"
#include "vrf.h"
#include "ripd/ripd.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

DEFINE_MTYPE_STATIC(RIPD, RIP_REDISTRIBUTE, "RIP Redistriute")

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Send ECMP routes to zebra. */
static void rip_zebra_ipv4_send(struct route_node *rp,
				uint8_t cmd, vrf_id_t vrf_id)
{
	struct list *list = (struct list *)rp->info;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct listnode *listnode = NULL;
	struct rip_info *rinfo = NULL;
	int count = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = vrf_id;
	api.type = ZEBRA_ROUTE_RIP;
	api.safi = SAFI_UNICAST;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = vrf_id;
		api_nh->gate = rinfo->nh.gate;
		api_nh->type = NEXTHOP_TYPE_IPV4;
		if (cmd == ZEBRA_ROUTE_ADD)
			SET_FLAG(rinfo->flags, RIP_RTF_FIB);
		else
			UNSET_FLAG(rinfo->flags, RIP_RTF_FIB);
		count++;
	}

	api.prefix = rp->p;
	api.nexthop_num = count;

	rinfo = listgetdata(listhead(list));

	SET_FLAG(api.message, ZAPI_MESSAGE_METRIC);
	api.metric = rinfo->metric;

	if (rinfo->distance && rinfo->distance != ZEBRA_RIP_DISTANCE_DEFAULT) {
		SET_FLAG(api.message, ZAPI_MESSAGE_DISTANCE);
		api.distance = rinfo->distance;
	}

	if (rinfo->tag) {
		SET_FLAG(api.message, ZAPI_MESSAGE_TAG);
		api.tag = rinfo->tag;
	}

	zclient_route_send(cmd, zclient, &api);

	if (IS_RIP_DEBUG_ZEBRA) {
		if (rip_global->ecmp)
			zlog_debug("%s: %s/%d nexthops %d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   inet_ntoa(rp->p.u.prefix4), rp->p.prefixlen,
				   count);
		else
			zlog_debug("%s: %s/%d",
				   (cmd == ZEBRA_ROUTE_ADD)
					   ? "Install into zebra"
					   : "Delete from zebra",
				   inet_ntoa(rp->p.u.prefix4), rp->p.prefixlen);
	}

	rip_global_route_changes++;
}

/* Add/update ECMP routes to zebra. */
void rip_zebra_ipv4_add(struct route_node *rp, vrf_id_t vrf_id)
{
	rip_zebra_ipv4_send(rp, ZEBRA_ROUTE_ADD, vrf_id);
}

/* Delete ECMP routes from zebra. */
void rip_zebra_ipv4_delete(struct route_node *rp, vrf_id_t vrf_id)
{
	rip_zebra_ipv4_send(rp, ZEBRA_ROUTE_DELETE, vrf_id);
}

/* Zebra route add and delete treatment. */
static int rip_zebra_read_route(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;
	struct nexthop nh;

	if (!rip_global)
		return 0;

	if (zapi_route_decode(zclient->ibuf, &api) < 0)
		return -1;

	memset(&nh, 0, sizeof(nh));
	nh.type = api.nexthops[0].type;
	nh.gate.ipv4 = api.nexthops[0].gate.ipv4;
	nh.ifindex = api.nexthops[0].ifindex;

	/* Then fetch IPv4 prefixes. */
	if (command == ZEBRA_REDISTRIBUTE_ROUTE_ADD)
		rip_redistribute_add(api.type, RIP_ROUTE_REDISTRIBUTE,
				     (struct prefix_ipv4 *)&api.prefix, &nh,
				     api.metric, api.distance, api.tag);
	else if (command == ZEBRA_REDISTRIBUTE_ROUTE_DEL)
		rip_redistribute_delete(api.type, RIP_ROUTE_REDISTRIBUTE,
					(struct prefix_ipv4 *)&api.prefix,
					nh.ifindex);

	return 0;
}

void rip_zclient_reset(void)
{
	zclient_reset(zclient);
}

/* RIP route-map set for redistribution */
static void rip_routemap_set(struct rip_redist *red, const char *name)
{
	if (red->route_map.name)
		free(red->route_map.name);

	red->route_map.name = strdup(name);
	red->route_map.map = route_map_lookup_by_name(name);
}

static void rip_redistribute_metric_set(struct rip_redist *red,
					unsigned int metric)
{
	red->dmetric.metric_config = 1;
	red->dmetric.metric = metric;
}

static int rip_metric_unset(struct rip_redist *red, unsigned int metric)
{
#define DONT_CARE_METRIC_RIP 17
	if (metric != DONT_CARE_METRIC_RIP
	    && red->dmetric.metric != metric)
		return 1;
	red->dmetric.metric_config = 0;
	red->dmetric.metric = 0;
	return 0;
}

/* Redistribution types */
static struct {
	int type;
	int str_min_len;
	const char *str;
} redist_type[] = {{ZEBRA_ROUTE_KERNEL, 1, "kernel"},
		   {ZEBRA_ROUTE_CONNECT, 1, "connected"},
		   {ZEBRA_ROUTE_STATIC, 1, "static"},
		   {ZEBRA_ROUTE_OSPF, 1, "ospf"},
		   {ZEBRA_ROUTE_BGP, 2, "bgp"},
		   {ZEBRA_ROUTE_VNC, 1, "vnc"},
		   {0, 0, NULL}};

static int str2metric(const char *str, int *metric)
{
	/* Sanity check. */
	if (str == NULL)
		return 0;
	*metric = strtol(str, NULL, 10);
	if (*metric < 0 && *metric > 16)
		return 0;
	return 1;
}

static int rip_redistribute_unset(struct rip *rip, int type,
				  struct rip_redist *red)
{
	if (rip->vrf_id == VRF_UNKNOWN) {
		/* only remove from config */
		rip_redist_del(rip, type);
		return CMD_SUCCESS;
	}

	if (!vrf_bitmap_check(zclient->redist[AFI_IP][type], rip->vrf_id))
		return CMD_SUCCESS;

	vrf_bitmap_unset(zclient->redist[AFI_IP][type], rip->vrf_id);

	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, type, 0, rip->vrf_id);

	/* Remove the routes from RIP table. */
	rip_redistribute_withdraw(type, rip);
	rip_redist_del(rip, type);
	return CMD_SUCCESS;
}

static struct rip_redist *rip_redist_add(struct rip *rip, uint8_t type)
{
	struct list *red_list;
	struct rip_redist *red;

	red = rip_redist_lookup(rip, type);
	if (red)
		return red;

	if (!rip->redist[type])
		rip->redist[type] = list_new();

	red_list = rip->redist[type];
	red = (struct rip_redist *)XCALLOC(MTYPE_RIP_REDISTRIBUTE,
					    sizeof(struct rip_redist));

	listnode_add(red_list, red);

	return red;
}

int rip_redistribute_set(struct rip *rip, int type, struct rip_redist *red)
{
	if (rip->vrf_id == VRF_UNKNOWN)
		return CMD_SUCCESS;

	zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
			      AFI_IP, type, 0, rip->vrf_id);

	return CMD_SUCCESS;
}

/* RIP route-map unset for redistribution */
int rip_routemap_unset(struct rip_redist *red, const char *name)
{
	if (!rip_global)
		return 0;

	if (!red->route_map.name
	    || (name != NULL && strcmp(red->route_map.name, name)))
		return 1;

	free(red->route_map.name);
	red->route_map.name = NULL;
	red->route_map.map = NULL;

	return 0;
}

struct rip_redist *rip_redist_lookup(struct rip *rip, uint8_t type)
{
	struct list *red_list;
	struct listnode *node;
	struct rip_redist *red;

	red_list = rip->redist[type];
	if (!red_list)
		return (NULL);
	/* return first instance */
	for (ALL_LIST_ELEMENTS_RO(red_list, node, red))
		return red;
	return NULL;
}

void rip_redist_del(struct rip *rip, uint8_t type)
{
	struct rip_redist *red;

	red = rip_redist_lookup(rip, type);
	if (red)
		listnode_delete(rip->redist[type], red);
	if (rip->redist[type])
		list_delete_and_null(&rip->redist[type]);
	if (red) {
		rip_routemap_unset(red, NULL);
		XFREE(MTYPE_RIP_REDISTRIBUTE, red);
	}
}

int rip_redistribute_check(int type, struct rip *rip)
{
	return vrf_bitmap_check(zclient->redist[AFI_IP][type], rip->vrf_id);
}

void rip_redistribute_clean(vrf_id_t vrf_id)
{
	int i;

	if (vrf_id == VRF_UNKNOWN)
		return;

	for (i = 0; redist_type[i].str; i++) {
		if (vrf_bitmap_check(
			    zclient->redist[AFI_IP][redist_type[i].type],
			    vrf_id)) {
			if (zclient->sock > 0)
				zebra_redistribute_send(
					ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, redist_type[i].type, 0,
					vrf_id);

			vrf_bitmap_unset(
				zclient->redist[AFI_IP][redist_type[i].type],
				vrf_id);

			/* Remove the routes from RIP table. */
			rip_redistribute_withdraw(redist_type[i].type,
						  rip_global);
		}
	}
}

DEFUN (rip_redistribute_type,
	rip_redistribute_type_cmd,
	"redistribute " FRR_REDIST_STR_RIPD " [{metric (0-16)|route-map WORD}]",
	REDIST_STR
	FRR_REDIST_HELP_STR_RIPD
	"Metric\n"
	"Metric value\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")
{
	int idx_protocol = 1;
	int source;
	struct rip_redist *red;
	int idx = 0;
	int metric = 0;
	int metric_config = 0;
	char *rmap = NULL;

	source = proto_redistnum(AFI_IP, argv[idx_protocol]->text);

	VTY_DECLVAR_INSTANCE_CONTEXT(rip, rip);

	if (source < 0) {
		vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);
		return CMD_WARNING_CONFIG_FAILED;
	}
	if (argv_find(argv, argc, "(0-16)", &idx)) {
		if (!str2metric(argv[idx]->arg, &metric))
			return CMD_WARNING_CONFIG_FAILED;
		metric_config = 1;
	}
	/* Get route-map */
	if (argv_find(argv, argc, "WORD", &idx))
		rmap = argv[idx]->arg;
	red = rip_redist_add(rip, source);
	if (metric_config)
		rip_redistribute_metric_set(red, metric);
	if (rmap)
		rip_routemap_set(red, rmap);

	return rip_redistribute_set(rip, source, red);
}

DEFUN (no_rip_redistribute_type,
	no_rip_redistribute_type_cmd,
	"no redistribute " FRR_REDIST_STR_RIPD " [{metric (0-16)|route-map WORD}]",
	NO_STR
	REDIST_STR
	FRR_REDIST_HELP_STR_RIPD
	"Metric\n"
	"Metric value\n"
	"Route map reference\n"
	"Pointer to route-map entries\n")
{
	int idx_protocol = 2;
	int source;
	struct rip_redist *red;
	int idx;
	int metric = 0;
	int metric_config = 0;
	char *rmap = NULL;

	source = proto_redistnum(AFI_IP, argv[idx_protocol]->text);

	VTY_DECLVAR_INSTANCE_CONTEXT(rip, rip);

	if (source < 0) {
		vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);
		return CMD_WARNING_CONFIG_FAILED;
	}

	red = rip_redist_lookup(rip, source);
	if (!red)
		return CMD_SUCCESS;

	if (argv_find(argv, argc, "(0-16)", &idx)) {
		if (!str2metric(argv[idx]->arg, &metric))
			return CMD_WARNING_CONFIG_FAILED;
		metric_config = 1;
	}
	/* Get route-map */
	if (argv_find(argv, argc, "WORD", &idx))
		rmap = argv[idx]->arg;

	if (red) {
		if (metric_config) {
			if (rip_metric_unset(red,
					     metric))
				return CMD_WARNING_CONFIG_FAILED;
		} else
			rip_metric_unset(red,
					 DONT_CARE_METRIC_RIP);
		if (rmap && rip_routemap_unset(red, rmap)
		    &&  metric_config) {
			rip_redistribute_metric_set(
					red, metric);
			return CMD_WARNING_CONFIG_FAILED;
		} else if (rmap == NULL)
			rip_routemap_unset(red, NULL);
		rip_redistribute_unset(rip, source, red);
		return CMD_SUCCESS;
	}
	return CMD_WARNING_CONFIG_FAILED;
}

/* Default information originate. */

DEFUN (rip_default_information_originate,
       rip_default_information_originate_cmd,
       "default-information originate",
       "Control distribution of default route\n"
       "Distribute a default route\n")
{
	struct prefix_ipv4 p;
	struct nexthop nh;
	struct rip *rip = rip_global;

	if (!rip->default_information) {
		memset(&p, 0, sizeof(struct prefix_ipv4));
		memset(&nh, 0, sizeof(nh));

		p.family = AF_INET;
		nh.type = NEXTHOP_TYPE_IPV4;

		rip->default_information = 1;

		rip_redistribute_add(ZEBRA_ROUTE_RIP, RIP_ROUTE_DEFAULT, &p,
				     &nh, 0, 0, 0);
	}

	return CMD_SUCCESS;
}

DEFUN (no_rip_default_information_originate,
       no_rip_default_information_originate_cmd,
       "no default-information originate",
       NO_STR
       "Control distribution of default route\n"
       "Distribute a default route\n")
{
	struct prefix_ipv4 p;
	struct rip *rip = rip_global;

	if (rip->default_information) {
		memset(&p, 0, sizeof(struct prefix_ipv4));
		p.family = AF_INET;

		rip->default_information = 0;

		rip_redistribute_delete(ZEBRA_ROUTE_RIP, RIP_ROUTE_DEFAULT, &p,
					0);
	}

	return CMD_SUCCESS;
}

int config_write_rip_redistribute(struct vty *vty, int config_mode)
{
	int i;
	struct rip *rip = rip_global;
	struct rip_redist *red;

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		red = rip_redist_lookup(rip, i);
		if (!red)
			continue;
		if (!config_mode) {
			vty_out(vty, " %s", zebra_route_string(i));
			continue;
		}
		vty_out(vty, " redistribute %s",
			zebra_route_string(i));

		if (red->dmetric.metric_config)
			vty_out(vty, " metric %d", red->dmetric.metric);

		if (ROUTEMAP_NAME(red))
			vty_out(vty, " route-map %s",
				ROUTEMAP_NAME(red));

		vty_out(vty, "\n");
	}

	return 0;
}

static void rip_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
}

void rip_zebra_vrf_register(struct rip *rip_param)
{
	if (!zclient || zclient->sock < 0 || !rip_param)
		return;

	if (rip_param->vrf_id != VRF_UNKNOWN) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("%s: Register VRF %s id %u",
				   __PRETTY_FUNCTION__,
				   vrf_id_to_name(rip_param->vrf_id),
				   rip_param->vrf_id);
		zclient_send_reg_requests(zclient, rip_param->vrf_id);
	}
}

void rip_zebra_vrf_deregister(struct rip *rip_param)
{
	if (!zclient || zclient->sock < 0 || !rip_param)
		return;

	if (rip_param->vrf_id != VRF_DEFAULT &&
	    rip_param->vrf_id != VRF_UNKNOWN) {
		if (IS_RIP_DEBUG_EVENT)
			zlog_debug("%s: De-Register VRF %s id %u to Zebra.",
				   __PRETTY_FUNCTION__,
				   vrf_id_to_name(rip_param->vrf_id),
				   rip_param->vrf_id);
		/* Deregister for router-id, interfaces,
		 * redistributed routes.
		 */
		zclient_send_dereg_requests(zclient, rip_param->vrf_id);
	}
}

void rip_zclient_init(struct thread_master *master)
{
	/* Set default value to the zebra client structure. */
	zclient = zclient_new_notify(master, &zclient_options_default);
	zclient_init(zclient, ZEBRA_ROUTE_RIP, 0, &ripd_privs);
	zclient->zebra_connected = rip_zebra_connected;
	zclient->interface_add = rip_interface_add;
	zclient->interface_delete = rip_interface_delete;
	zclient->interface_address_add = rip_interface_address_add;
	zclient->interface_address_delete = rip_interface_address_delete;
	zclient->interface_up = rip_interface_up;
	zclient->interface_down = rip_interface_down;
	zclient->redistribute_route_add = rip_zebra_read_route;
	zclient->redistribute_route_del = rip_zebra_read_route;

	/* Install command elements to rip node. */
	install_element(RIP_NODE, &rip_redistribute_type_cmd);
	install_element(RIP_NODE, &no_rip_redistribute_type_cmd);
	install_element(RIP_NODE, &rip_default_information_originate_cmd);
	install_element(RIP_NODE, &no_rip_default_information_originate_cmd);
}

void rip_zclient_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}
