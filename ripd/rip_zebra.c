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

/* All information about zebra. */
struct zclient *zclient = NULL;

/* Send ECMP routes to zebra. */
static void rip_zebra_ipv4_send(struct route_node *rp, uint8_t cmd)
{
	struct list *list = (struct list *)rp->info;
	struct zapi_route api;
	struct zapi_nexthop *api_nh;
	struct listnode *listnode = NULL;
	struct rip_info *rinfo = NULL;
	int count = 0;

	memset(&api, 0, sizeof(api));
	api.vrf_id = VRF_DEFAULT;
	api.type = ZEBRA_ROUTE_RIP;
	api.safi = SAFI_UNICAST;

	SET_FLAG(api.message, ZAPI_MESSAGE_NEXTHOP);
	for (ALL_LIST_ELEMENTS_RO(list, listnode, rinfo)) {
		if (count >= MULTIPATH_NUM)
			break;
		api_nh = &api.nexthops[count];
		api_nh->vrf_id = VRF_DEFAULT;
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
		if (rip->ecmp)
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
void rip_zebra_ipv4_add(struct route_node *rp)
{
	rip_zebra_ipv4_send(rp, ZEBRA_ROUTE_ADD);
}

/* Delete ECMP routes from zebra. */
void rip_zebra_ipv4_delete(struct route_node *rp)
{
	rip_zebra_ipv4_send(rp, ZEBRA_ROUTE_DELETE);
}

/* Zebra route add and delete treatment. */
static int rip_zebra_read_route(int command, struct zclient *zclient,
				zebra_size_t length, vrf_id_t vrf_id)
{
	struct zapi_route api;
	struct nexthop nh;

	if (!rip)
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
static void rip_routemap_set(int type, const char *name)
{
	if (rip->route_map[type].name)
		free(rip->route_map[type].name);

	rip->route_map[type].name = strdup(name);
	rip->route_map[type].map = route_map_lookup_by_name(name);
}

static void rip_redistribute_metric_set(int type, unsigned int metric)
{
	rip->route_map[type].metric_config = 1;
	rip->route_map[type].metric = metric;
}

static int rip_metric_unset(int type, unsigned int metric)
{
#define DONT_CARE_METRIC_RIP 17  
	if (metric != DONT_CARE_METRIC_RIP
	    && rip->route_map[type].metric != metric)
		return 1;
	rip->route_map[type].metric_config = 0;
	rip->route_map[type].metric = 0;
	return 0;
}

/* RIP route-map unset for redistribution */
static int rip_routemap_unset(int type, const char *name)
{
	if (!rip->route_map[type].name
	    || (name != NULL && strcmp(rip->route_map[type].name, name)))
		return 1;

	free(rip->route_map[type].name);
	rip->route_map[type].name = NULL;
	rip->route_map[type].map = NULL;

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

static int rip_redistribute_unset(int type)
{
	if (!vrf_bitmap_check(zclient->redist[AFI_IP][type], VRF_DEFAULT))
		return CMD_SUCCESS;

	vrf_bitmap_unset(zclient->redist[AFI_IP][type], VRF_DEFAULT);

	if (zclient->sock > 0)
		zebra_redistribute_send(ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, type, 0, VRF_DEFAULT);

	/* Remove the routes from RIP table. */
	rip_redistribute_withdraw(type);

	return CMD_SUCCESS;
}

int rip_redistribute_check(int type)
{
	return vrf_bitmap_check(zclient->redist[AFI_IP][type], VRF_DEFAULT);
}

void rip_redistribute_clean(void)
{
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (vrf_bitmap_check(
			    zclient->redist[AFI_IP][redist_type[i].type],
			    VRF_DEFAULT)) {
			if (zclient->sock > 0)
				zebra_redistribute_send(
					ZEBRA_REDISTRIBUTE_DELETE, zclient,
					AFI_IP, redist_type[i].type, 0,
					VRF_DEFAULT);

			vrf_bitmap_unset(
				zclient->redist[AFI_IP][redist_type[i].type],
				VRF_DEFAULT);

			/* Remove the routes from RIP table. */
			rip_redistribute_withdraw(redist_type[i].type);
		}
	}
}

DEFUN (rip_redistribute_type,
       rip_redistribute_type_cmd,
       "redistribute " FRR_REDIST_STR_RIPD,
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD)
{
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (strncmp(redist_type[i].str, argv[1]->arg,
			    redist_type[i].str_min_len)
		    == 0) {
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
					     AFI_IP, redist_type[i].type, 0,
					     VRF_DEFAULT);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[1]->arg);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_rip_redistribute_type,
       no_rip_redistribute_type_cmd,
       "no redistribute " FRR_REDIST_STR_RIPD,
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD)
{
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (strncmp(redist_type[i].str, argv[2]->arg,
			    redist_type[i].str_min_len)
		    == 0) {
			rip_metric_unset(redist_type[i].type,
					 DONT_CARE_METRIC_RIP);
			rip_routemap_unset(redist_type[i].type, NULL);
			rip_redistribute_unset(redist_type[i].type);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[2]->arg);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (rip_redistribute_type_routemap,
       rip_redistribute_type_routemap_cmd,
       "redistribute " FRR_REDIST_STR_RIPD " route-map WORD",
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int idx_protocol = 1;
	int idx_word = 3;
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (strmatch(redist_type[i].str, argv[idx_protocol]->text)) {
			rip_routemap_set(redist_type[i].type,
					 argv[idx_word]->arg);
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
					     AFI_IP, redist_type[i].type, 0,
					     VRF_DEFAULT);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_rip_redistribute_type_routemap,
       no_rip_redistribute_type_routemap_cmd,
       "no redistribute " FRR_REDIST_STR_RIPD " route-map WORD",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int idx_protocol = 2;
	int idx_word = 4;
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (strmatch(redist_type[i].str, argv[idx_protocol]->text)) {
			if (rip_routemap_unset(redist_type[i].type,
					       argv[idx_word]->arg))
				return CMD_WARNING_CONFIG_FAILED;
			rip_redistribute_unset(redist_type[i].type);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (rip_redistribute_type_metric,
       rip_redistribute_type_metric_cmd,
       "redistribute " FRR_REDIST_STR_RIPD " metric (0-16)",
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n")
{
	int idx_protocol = 1;
	int idx_number = 3;
	int i;
	int metric;

	metric = atoi(argv[idx_number]->arg);

	for (i = 0; redist_type[i].str; i++) {
		if (strmatch(redist_type[i].str, argv[idx_protocol]->text)) {
			rip_redistribute_metric_set(redist_type[i].type,
						    metric);
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
					     AFI_IP, redist_type[i].type, 0,
					     VRF_DEFAULT);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (no_rip_redistribute_type_metric,
       no_rip_redistribute_type_metric_cmd,
       "no redistribute " FRR_REDIST_STR_RIPD " metric (0-16)",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n")
{
	int idx_protocol = 2;
	int idx_number = 4;
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (strmatch(redist_type[i].str, argv[idx_protocol]->text)) {
			if (rip_metric_unset(redist_type[i].type,
					     atoi(argv[idx_number]->arg)))
				return CMD_WARNING_CONFIG_FAILED;
			rip_redistribute_unset(redist_type[i].type);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (rip_redistribute_type_metric_routemap,
       rip_redistribute_type_metric_routemap_cmd,
       "redistribute " FRR_REDIST_STR_RIPD " metric (0-16) route-map WORD",
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int idx_protocol = 1;
	int idx_number = 3;
	int idx_word = 5;
	int i;
	int metric;

	metric = atoi(argv[idx_number]->arg);

	for (i = 0; redist_type[i].str; i++) {
		if (strmatch(redist_type[i].str, argv[idx_protocol]->text)) {
			rip_redistribute_metric_set(redist_type[i].type,
						    metric);
			rip_routemap_set(redist_type[i].type,
					 argv[idx_word]->arg);
			zclient_redistribute(ZEBRA_REDISTRIBUTE_ADD, zclient,
					     AFI_IP, redist_type[i].type, 0,
					     VRF_DEFAULT);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);

	return CMD_WARNING_CONFIG_FAILED;
}


DEFUN (no_rip_redistribute_type_metric_routemap,
       no_rip_redistribute_type_metric_routemap_cmd,
       "no redistribute " FRR_REDIST_STR_RIPD " metric (0-16) route-map WORD",
       NO_STR
       REDIST_STR
       FRR_REDIST_HELP_STR_RIPD
       "Metric\n"
       "Metric value\n"
       "Route map reference\n"
       "Pointer to route-map entries\n")
{
	int idx_protocol = 2;
	int idx_number = 4;
	int idx_word = 6;
	int i;

	for (i = 0; redist_type[i].str; i++) {
		if (strmatch(redist_type[i].str, argv[idx_protocol]->text)) {
			if (rip_metric_unset(redist_type[i].type,
					     atoi(argv[idx_number]->arg)))
				return CMD_WARNING_CONFIG_FAILED;
			if (rip_routemap_unset(redist_type[i].type,
					       argv[idx_word]->arg)) {
				rip_redistribute_metric_set(
					redist_type[i].type,
					atoi(argv[idx_number]->arg));
				return CMD_WARNING_CONFIG_FAILED;
			}
			rip_redistribute_unset(redist_type[i].type);
			return CMD_SUCCESS;
		}
	}

	vty_out(vty, "Invalid type %s\n", argv[idx_protocol]->text);

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

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++) {
		if (i == zclient->redist_default
		    || !vrf_bitmap_check(zclient->redist[AFI_IP][i],
					 VRF_DEFAULT))
			continue;

		if (!config_mode) {
			vty_out(vty, " %s", zebra_route_string(i));
			continue;
		}

		if (rip->route_map[i].metric_config) {
			if (rip->route_map[i].name)
				vty_out(vty,
					" redistribute %s metric %d route-map %s\n",
					zebra_route_string(i),
					rip->route_map[i].metric,
					rip->route_map[i].name);
			else
				vty_out(vty, " redistribute %s metric %d\n",
					zebra_route_string(i),
					rip->route_map[i].metric);
		} else {
			if (rip->route_map[i].name)
				vty_out(vty, " redistribute %s route-map %s\n",
					zebra_route_string(i),
					rip->route_map[i].name);
			else
				vty_out(vty, " redistribute %s\n",
					zebra_route_string(i));
		}
	}

	return 0;
}

static void rip_zebra_connected(struct zclient *zclient)
{
	zclient_send_reg_requests(zclient, VRF_DEFAULT);
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
	install_element(RIP_NODE, &rip_redistribute_type_routemap_cmd);
	install_element(RIP_NODE, &rip_redistribute_type_metric_cmd);
	install_element(RIP_NODE, &rip_redistribute_type_metric_routemap_cmd);
	install_element(RIP_NODE, &no_rip_redistribute_type_cmd);
	install_element(RIP_NODE, &no_rip_redistribute_type_routemap_cmd);
	install_element(RIP_NODE, &no_rip_redistribute_type_metric_cmd);
	install_element(RIP_NODE,
			&no_rip_redistribute_type_metric_routemap_cmd);
	install_element(RIP_NODE, &rip_default_information_originate_cmd);
	install_element(RIP_NODE, &no_rip_default_information_originate_cmd);
}

void rip_zclient_stop(void)
{
	zclient_stop(zclient);
	zclient_free(zclient);
}
