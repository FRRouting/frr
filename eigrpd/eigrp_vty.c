/*
 * EIGRP VTY Interface.
 * Copyright (C) 2013-2016
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
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
#include "thread.h"
#include "prefix.h"
#include "table.h"
#include "vty.h"
#include "command.h"
#include "plist.h"
#include "log.h"
#include "zclient.h"
#include "keychain.h"
#include "linklist.h"
#include "distribute.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_const.h"

static int config_write_network(struct vty *vty, struct eigrp *eigrp)
{
	struct route_node *rn;
	int i;

	/* `network area' print. */
	for (rn = route_top(eigrp->networks); rn; rn = route_next(rn))
		if (rn->info) {
			/* Network print. */
			vty_out(vty, " network %s/%d \n",
				inet_ntoa(rn->p.u.prefix4), rn->p.prefixlen);
		}

	if (eigrp->max_paths != EIGRP_MAX_PATHS_DEFAULT)
		vty_out(vty, " maximum-paths %d\n", eigrp->max_paths);

	if (eigrp->variance != EIGRP_VARIANCE_DEFAULT)
		vty_out(vty, " variance %d\n", eigrp->variance);

	for (i = 0; i < ZEBRA_ROUTE_MAX; i++)
		if (i != zclient->redist_default
		    && vrf_bitmap_check(zclient->redist[AFI_IP][i],
					VRF_DEFAULT))
			vty_out(vty, " redistribute %s\n",
				zebra_route_string(i));

	/*Separate EIGRP configuration from the rest of the config*/
	vty_out(vty, "!\n");

	return 0;
}

static int config_write_interfaces(struct vty *vty, struct eigrp *eigrp)
{
	struct eigrp_interface *ei;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		vty_frame(vty, "interface %s\n", ei->ifp->name);

		if (ei->params.auth_type == EIGRP_AUTH_TYPE_MD5) {
			vty_out(vty, " ip authentication mode eigrp %d md5\n",
				eigrp->AS);
		}

		if (ei->params.auth_type == EIGRP_AUTH_TYPE_SHA256) {
			vty_out(vty,
				" ip authentication mode eigrp %d hmac-sha-256\n",
				eigrp->AS);
		}

		if (ei->params.auth_keychain) {
			vty_out(vty,
				" ip authentication key-chain eigrp %d %s\n",
				eigrp->AS,
				ei->params.auth_keychain);
		}

		if (ei->params.v_hello != EIGRP_HELLO_INTERVAL_DEFAULT) {
			vty_out(vty, " ip hello-interval eigrp %d\n",
				ei->params.v_hello);
		}

		if (ei->params.v_wait != EIGRP_HOLD_INTERVAL_DEFAULT) {
			vty_out(vty, " ip hold-time eigrp %d\n",
				ei->params.v_wait);
		}

		/*Separate this EIGRP interface configuration from the others*/
		vty_endframe(vty, "!\n");
	}

	return 0;
}

static int eigrp_write_interface(struct vty *vty)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;
	struct eigrp_interface *ei;

	RB_FOREACH (ifp, if_name_head, &vrf->ifaces_by_name) {
		ei = ifp->info;
		if (!ei)
			continue;

		vty_frame(vty, "interface %s\n", ifp->name);

		if (ifp->desc)
			vty_out(vty, " description %s\n", ifp->desc);

		if (ei->params.bandwidth != EIGRP_BANDWIDTH_DEFAULT)
			vty_out(vty, " bandwidth %u\n",
				ei->params.bandwidth);
		if (ei->params.delay != EIGRP_DELAY_DEFAULT)
			vty_out(vty, " delay %u\n", ei->params.delay);
		if (ei->params.v_hello != EIGRP_HELLO_INTERVAL_DEFAULT)
			vty_out(vty, " ip hello-interval eigrp %u\n",
				ei->params.v_hello);
		if (ei->params.v_wait != EIGRP_HOLD_INTERVAL_DEFAULT)
			vty_out(vty, " ip hold-time eigrp %u\n",
				ei->params.v_wait);

		vty_endframe(vty, "!\n");
	}

	return 0;
}

/**
 * Writes distribute lists to config
 */
static int config_write_eigrp_distribute(struct vty *vty, struct eigrp *eigrp)
{
	int write = 0;

	/* Distribute configuration. */
	write += config_write_distribute(vty);

	return write;
}

/**
 * Writes 'router eigrp' section to config
 */
static int config_write_eigrp_router(struct vty *vty, struct eigrp *eigrp)
{
	int write = 0;

	/* `router eigrp' print. */
	vty_out(vty, "router eigrp %d\n", eigrp->AS);

	write++;

	if (!eigrp->networks)
		return write;

	/* Router ID print. */
	if (eigrp->router_id_static != 0) {
		struct in_addr router_id_static;
		router_id_static.s_addr = htonl(eigrp->router_id_static);
		vty_out(vty, " eigrp router-id %s\n",
			inet_ntoa(router_id_static));
	}

	/* Network area print. */
	config_write_network(vty, eigrp);

	/* Distribute-list and default-information print. */
	config_write_eigrp_distribute(vty, eigrp);

	/*Separate EIGRP configuration from the rest of the config*/
	vty_out(vty, "!\n");

	return write;
}

DEFUN_NOSH (router_eigrp,
            router_eigrp_cmd,
            "router eigrp (1-65535)",
            "Enable a routing process\n"
            "Start EIGRP configuration\n"
            "AS Number to use\n")
{
	struct eigrp *eigrp = eigrp_get(argv[2]->arg);
	VTY_PUSH_CONTEXT(EIGRP_NODE, eigrp);

	return CMD_SUCCESS;
}

DEFUN (no_router_eigrp,
       no_router_eigrp_cmd,
       "no router eigrp (1-65535)",
       NO_STR
       "Routing process\n"
       "EIGRP configuration\n"
       "AS number to use\n")
{
	vty->node = CONFIG_NODE;

	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (eigrp->AS != atoi(argv[3]->arg)) {
		vty_out(vty, "%% Attempting to deconfigure non-existent AS\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	eigrp_finish_final(eigrp);

	return CMD_SUCCESS;
}

DEFUN (eigrp_router_id,
       eigrp_router_id_cmd,
       "eigrp router-id A.B.C.D",
       "EIGRP specific commands\n"
       "Router ID for this EIGRP process\n"
       "EIGRP Router-ID in IP address format\n")
{
	// struct eigrp *eigrp = vty->index;
	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_router_id,
       no_eigrp_router_id_cmd,
       "no eigrp router-id A.B.C.D",
       NO_STR
       "EIGRP specific commands\n"
       "Router ID for this EIGRP process\n"
       "EIGRP Router-ID in IP address format\n")
{
	// struct eigrp *eigrp = vty->index;
	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (eigrp_passive_interface,
       eigrp_passive_interface_cmd,
       "passive-interface IFNAME",
       "Suppress routing updates on an interface\n"
       "Interface to suppress on\n")
{
	VTY_DECLVAR_CONTEXT(eigrp, eigrp);
	struct eigrp_interface *ei;
	struct listnode *node;
	char *ifname = argv[1]->arg;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (strcmp(ifname, ei->ifp->name) == 0) {
			ei->params.passive_interface = EIGRP_IF_PASSIVE;
			return CMD_SUCCESS;
		}
	}
	return CMD_SUCCESS;
}

DEFUN (no_eigrp_passive_interface,
       no_eigrp_passive_interface_cmd,
       "no passive-interface IFNAME",
       NO_STR
       "Suppress routing updates on an interface\n"
       "Interface to suppress on\n")
{
	VTY_DECLVAR_CONTEXT(eigrp, eigrp);
	struct eigrp_interface *ei;
	struct listnode *node;
	char *ifname = argv[2]->arg;

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (strcmp(ifname, ei->ifp->name) == 0) {
			ei->params.passive_interface = EIGRP_IF_ACTIVE;
			return CMD_SUCCESS;
		}
	}

	return CMD_SUCCESS;
}

DEFUN (eigrp_timers_active,
       eigrp_timers_active_cmd,
       "timers active-time <(1-65535)|disabled>",
       "Adjust routing timers\n"
       "Time limit for active state\n"
       "Active state time limit in minutes\n"
       "Disable time limit for active state\n")
{
	// struct eigrp *eigrp = vty->index;
	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_timers_active,
       no_eigrp_timers_active_cmd,
       "no timers active-time <(1-65535)|disabled>",
       NO_STR
       "Adjust routing timers\n"
       "Time limit for active state\n"
       "Active state time limit in minutes\n"
       "Disable time limit for active state\n")
{
	// struct eigrp *eigrp = vty->index;
	/*TODO: */

	return CMD_SUCCESS;
}


DEFUN (eigrp_metric_weights,
       eigrp_metric_weights_cmd,
       "metric weights (0-255) (0-255) (0-255) (0-255) (0-255) ",
       "Modify metrics and parameters for advertisement\n"
       "Modify metric coefficients\n"
       "K1\n"
       "K2\n"
       "K3\n"
       "K4\n"
       "K5\n")
{
	// struct eigrp *eigrp = vty->index;
	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_metric_weights,
       no_eigrp_metric_weights_cmd,
       "no metric weights <0-255> <0-255> <0-255> <0-255> <0-255>",
       NO_STR
       "Modify metrics and parameters for advertisement\n"
       "Modify metric coefficients\n"
       "K1\n"
       "K2\n"
       "K3\n"
       "K4\n"
       "K5\n")
{
	// struct eigrp *eigrp = vty->index;
	/*TODO: */

	return CMD_SUCCESS;
}


DEFUN (eigrp_network,
       eigrp_network_cmd,
       "network A.B.C.D/M",
       "Enable routing on an IP network\n"
       "EIGRP network prefix\n")
{
	VTY_DECLVAR_CONTEXT(eigrp, eigrp);
	struct prefix p;
	int ret;

	str2prefix(argv[1]->arg, &p);

	ret = eigrp_network_set(eigrp, &p);

	if (ret == 0) {
		vty_out(vty, "There is already same network statement.\n");
		return CMD_WARNING;
	}

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_network,
       no_eigrp_network_cmd,
       "no network A.B.C.D/M",
       NO_STR
       "Disable routing on an IP network\n"
       "EIGRP network prefix\n")
{
	VTY_DECLVAR_CONTEXT(eigrp, eigrp);
	struct prefix p;
	int ret;

	str2prefix(argv[2]->arg, &p);

	ret = eigrp_network_unset(eigrp, &p);

	if (ret == 0) {
		vty_out(vty, "Can't find specified network configuration.\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFUN (eigrp_neighbor,
       eigrp_neighbor_cmd,
       "neighbor A.B.C.D",
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	// struct eigrp *eigrp = vty->index;

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_neighbor,
       no_eigrp_neighbor_cmd,
       "no neighbor A.B.C.D",
       NO_STR
       "Specify a neighbor router\n"
       "Neighbor address\n")
{
	// struct eigrp *eigrp = vty->index;

	return CMD_SUCCESS;
}

DEFUN (show_ip_eigrp_topology,
       show_ip_eigrp_topology_cmd,
       "show ip eigrp topology [all-links]",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       "IP-EIGRP topology\n"
       "Show all links in topology table\n")
{
	struct eigrp *eigrp;
	struct listnode *node, *node2;
	struct eigrp_prefix_entry *tn;
	struct eigrp_nexthop_entry *te;
	int first;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	show_ip_eigrp_topology_header(vty, eigrp);

	for (ALL_LIST_ELEMENTS_RO(eigrp->topology_table, node, tn)) {
		first = 1;
		for (ALL_LIST_ELEMENTS_RO(tn->entries, node2, te)) {
			if (argc == 5
			    || (((te->flags
				  & EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)
				 == EIGRP_NEXTHOP_ENTRY_SUCCESSOR_FLAG)
				|| ((te->flags
				     & EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG)
				    == EIGRP_NEXTHOP_ENTRY_FSUCCESSOR_FLAG))) {
				show_ip_eigrp_nexthop_entry(vty, eigrp, te,
							     &first);
				first = 0;
			}
		}
	}

	return CMD_SUCCESS;
}

ALIAS(show_ip_eigrp_topology, show_ip_eigrp_topology_detail_cmd,
      "show ip eigrp topology <A.B.C.D|A.B.C.D/M|detail|summary>",
      SHOW_STR IP_STR
      "IP-EIGRP show commands\n"
      "IP-EIGRP topology\n"
      "Netwok to display information about\n"
      "IP prefix <network>/<length>, e.g., 192.168.0.0/16\n"
      "Show all links in topology table\n"
      "Show a summary of the topology table\n")

DEFUN (show_ip_eigrp_interfaces,
       show_ip_eigrp_interfaces_cmd,
       "show ip eigrp interfaces [IFNAME] [detail]",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       "IP-EIGRP interfaces\n"
       "Interface name to look at\n"
       "Detailed information\n")
{
	struct eigrp_interface *ei;
	struct eigrp *eigrp;
	struct listnode *node;
	int idx = 0;
	bool detail = false;
	const char *ifname = NULL;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "IFNAME", &idx))
		ifname = argv[idx]->arg;

	if (argv_find(argv, argc, "detail", &idx))
		detail = true;

	if (!ifname)
		show_ip_eigrp_interface_header(vty, eigrp);

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (!ifname || strcmp(ei->ifp->name, ifname) == 0) {
			show_ip_eigrp_interface_sub(vty, eigrp, ei);
			if (detail)
				show_ip_eigrp_interface_detail(vty, eigrp, ei);
		}
	}

	return CMD_SUCCESS;
}

DEFUN (show_ip_eigrp_neighbors,
       show_ip_eigrp_neighbors_cmd,
       "show ip eigrp neighbors [IFNAME] [detail]",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       "IP-EIGRP neighbors\n"
       "Interface to show on\n"
       "Detailed Information\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;
	bool detail = false;
	int idx = 0;
	const char *ifname = NULL;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (argv_find(argv, argc, "IFNAME", &idx))
		ifname = argv[idx]->arg;

	detail = (argv_find(argv, argc, "detail", &idx));

	show_ip_eigrp_neighbor_header(vty, eigrp);

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (!ifname || strcmp(ei->ifp->name, ifname) == 0) {
			for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
				if (detail || (nbr->state == EIGRP_NEIGHBOR_UP))
					show_ip_eigrp_neighbor_sub(vty, nbr,
								   detail);
			}
		}
	}

	return CMD_SUCCESS;
}

DEFUN (eigrp_if_delay,
       eigrp_if_delay_cmd,
       "delay (1-16777215)",
       "Specify interface throughput delay\n"
       "Throughput delay (tens of microseconds)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;
	u_int32_t delay;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");

		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}
	delay = atoi(argv[1]->arg);

	ei->params.delay = delay;
	eigrp_if_reset(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_if_delay,
       no_eigrp_if_delay_cmd,
       "no delay (1-16777215)",
       NO_STR
       "Specify interface throughput delay\n"
       "Throughput delay (tens of microseconds)\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");

		return CMD_SUCCESS;
	}
	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	ei->params.delay = EIGRP_DELAY_DEFAULT;
	eigrp_if_reset(ifp);

	return CMD_SUCCESS;
}

DEFUN (eigrp_if_bandwidth,
       eigrp_if_bandwidth_cmd,
       "eigrp bandwidth (1-10000000)",
       "EIGRP specific commands\n"
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	u_int32_t bandwidth;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	bandwidth = atoi(argv[1]->arg);

	ei->params.bandwidth = bandwidth;
	eigrp_if_reset(ifp);

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_if_bandwidth,
       no_eigrp_if_bandwidth_cmd,
       "no eigrp bandwidth [(1-10000000)]",
       NO_STR
       "EIGRP specific commands\n"
       "Set bandwidth informational parameter\n"
       "Bandwidth in kilobits\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	ei->params.bandwidth = EIGRP_BANDWIDTH_DEFAULT;
	eigrp_if_reset(ifp);

	return CMD_SUCCESS;
}

DEFUN (eigrp_if_ip_hellointerval,
       eigrp_if_ip_hellointerval_cmd,
       "ip hello-interval eigrp (1-65535)",
       "Interface Internet Protocol config commands\n"
       "Configures EIGRP hello interval\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Seconds between hello transmissions\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	u_int32_t hello;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	hello = atoi(argv[3]->arg);

	ei->params.v_hello = hello;

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_if_ip_hellointerval,
       no_eigrp_if_ip_hellointerval_cmd,
       "no ip hello-interval eigrp [(1-65535)]",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Configures EIGRP hello interval\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Seconds between hello transmissions\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	ei->params.v_hello = EIGRP_HELLO_INTERVAL_DEFAULT;

	THREAD_TIMER_OFF(ei->t_hello);
	thread_add_timer(master, eigrp_hello_timer, ei, 1,
			 &ei->t_hello);

	return CMD_SUCCESS;
}

DEFUN (eigrp_if_ip_holdinterval,
       eigrp_if_ip_holdinterval_cmd,
       "ip hold-time eigrp (1-65535)",
       "Interface Internet Protocol config commands\n"
       "Configures EIGRP IPv4 hold time\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Seconds before neighbor is considered down\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	u_int32_t hold;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	hold = atoi(argv[3]->arg);

	ei->params.v_wait = hold;

	return CMD_SUCCESS;
}

DEFUN (eigrp_ip_summary_address,
       eigrp_ip_summary_address_cmd,
       "ip summary-address eigrp (1-65535) A.B.C.D/M",
       "Interface Internet Protocol config commands\n"
       "Perform address summarization\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "AS number\n"
       "Summary <network>/<length>, e.g. 192.168.0.0/16\n")
{
	// VTY_DECLVAR_CONTEXT(interface, ifp);
	// u_int32_t AS;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	// AS = atoi (argv[3]->arg);

	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_ip_summary_address,
       no_eigrp_ip_summary_address_cmd,
       "no ip summary-address eigrp (1-65535) A.B.C.D/M",
       NO_STR
       "Interface Internet Protocol config commands\n"
       "Perform address summarization\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "AS number\n"
       "Summary <network>/<length>, e.g. 192.168.0.0/16\n")
{
	// VTY_DECLVAR_CONTEXT(interface, ifp);
	// u_int32_t AS;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	// AS = atoi (argv[4]->arg);

	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_if_ip_holdinterval,
       no_eigrp_if_ip_holdinterval_cmd,
       "no ip hold-time eigrp",
       "No"
       "Interface Internet Protocol config commands\n"
       "Configures EIGRP hello interval\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Seconds before neighbor is considered down\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	ei->params.v_wait = EIGRP_HOLD_INTERVAL_DEFAULT;

	return CMD_SUCCESS;
}

static int str2auth_type(const char *str, struct eigrp_interface *ei)
{
	/* Sanity check. */
	if (str == NULL)
		return CMD_WARNING_CONFIG_FAILED;

	if (strncmp(str, "md5", 3) == 0) {
		ei->params.auth_type = EIGRP_AUTH_TYPE_MD5;
		return CMD_SUCCESS;
	} else if (strncmp(str, "hmac-sha-256", 12) == 0) {
		ei->params.auth_type = EIGRP_AUTH_TYPE_SHA256;
		return CMD_SUCCESS;
	}

	return CMD_WARNING_CONFIG_FAILED;
}

DEFUN (eigrp_authentication_mode,
       eigrp_authentication_mode_cmd,
       "ip authentication mode eigrp (1-65535) <md5|hmac-sha-256>",
       "Interface Internet Protocol config commands\n"
       "Authentication subcommands\n"
       "Mode\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Autonomous system number\n"
       "Keyed message digest\n"
       "HMAC SHA256 algorithm \n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	//  if(strncmp(argv[2], "md5",3))
	//    IF_DEF_PARAMS (ifp)->auth_type = EIGRP_AUTH_TYPE_MD5;
	//  else if(strncmp(argv[2], "hmac-sha-256",12))
	//    IF_DEF_PARAMS (ifp)->auth_type = EIGRP_AUTH_TYPE_SHA256;

	return str2auth_type(argv[5]->arg, ei);
}

DEFUN (no_eigrp_authentication_mode,
       no_eigrp_authentication_mode_cmd,
       "no ip authentication mode eigrp (1-65535) <md5|hmac-sha-256>",
       "Disable\n"
       "Interface Internet Protocol config commands\n"
       "Authentication subcommands\n"
       "Mode\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Autonomous system number\n"
       "Keyed message digest\n"
       "HMAC SHA256 algorithm \n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	ei->params.auth_type = EIGRP_AUTH_TYPE_NONE;

	return CMD_SUCCESS;
}

DEFUN (eigrp_authentication_keychain,
       eigrp_authentication_keychain_cmd,
       "ip authentication key-chain eigrp (1-65535) WORD",
       "Interface Internet Protocol config commands\n"
       "Authentication subcommands\n"
       "Key-chain\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Autonomous system number\n"
       "Name of key-chain\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;
	struct keychain *keychain;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	keychain = keychain_lookup(argv[4]->arg);
	if (keychain != NULL) {
		if (ei->params.auth_keychain) {
			free(ei->params.auth_keychain);
			ei->params.auth_keychain =
				strdup(keychain->name);
		} else
			ei->params.auth_keychain =
				strdup(keychain->name);
	} else
		vty_out(vty, "Key chain with specified name not found\n");

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_authentication_keychain,
       no_eigrp_authentication_keychain_cmd,
       "no ip authentication key-chain eigrp (1-65535) WORD",
       "Disable\n"
       "Interface Internet Protocol config commands\n"
       "Authentication subcommands\n"
       "Key-chain\n"
       "Enhanced Interior Gateway Routing Protocol (EIGRP)\n"
       "Autonomous system number\n"
       "Name of key-chain\n")
{
	VTY_DECLVAR_CONTEXT(interface, ifp);
	struct eigrp_interface *ei = ifp->info;
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	if (!ei) {
		vty_out(vty, " EIGRP not configured on this interface\n");
		return CMD_SUCCESS;
	}

	if ((ei->params.auth_keychain != NULL)
	    && (strcmp(ei->params.auth_keychain, argv[5]->arg) == 0)) {
		free(ei->params.auth_keychain);
		ei->params.auth_keychain = NULL;
	} else
		vty_out(vty,
			"Key chain with specified name not configured on interface\n");

	return CMD_SUCCESS;
}

DEFUN (eigrp_redistribute_source_metric,
       eigrp_redistribute_source_metric_cmd,
       "redistribute " FRR_REDIST_STR_EIGRPD
       " [metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)]",
       REDIST_STR
       FRR_REDIST_HELP_STR_EIGRPD
       "Metric for redistributed routes\n"
       "Bandwidth metric in Kbits per second\n"
       "EIGRP delay metric, in 10 microsecond units\n"
       "EIGRP reliability metric where 255 is 100% reliable2 ?\n"
       "EIGRP Effective bandwidth metric (Loading) where 255 is 100% loaded\n"
       "EIGRP MTU of the path\n")
{
	VTY_DECLVAR_CONTEXT(eigrp, eigrp);
	struct eigrp_metrics metrics_from_command = {0};
	int source;
	int idx = 0;

	/* Get distribute source. */
	argv_find(argv, argc, "redistribute", &idx);
	source = proto_redistnum(AFI_IP, argv[idx + 1]->text);
	if (source < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get metrics values */

	return eigrp_redistribute_set(eigrp, source, metrics_from_command);
}

DEFUN (no_eigrp_redistribute_source_metric,
       no_eigrp_redistribute_source_metric_cmd,
       "no redistribute " FRR_REDIST_STR_EIGRPD
       " metric (1-4294967295) (0-4294967295) (0-255) (1-255) (1-65535)",
       "Disable\n"
       REDIST_STR
       FRR_REDIST_HELP_STR_EIGRPD
       "Metric for redistributed routes\n"
       "Bandwidth metric in Kbits per second\n"
       "EIGRP delay metric, in 10 microsecond units\n"
       "EIGRP reliability metric where 255 is 100% reliable2 ?\n"
       "EIGRP Effective bandwidth metric (Loading) where 255 is 100% loaded\n"
       "EIGRP MTU of the path\n")
{
	VTY_DECLVAR_CONTEXT(eigrp, eigrp);
	int source;
	int idx = 0;

	/* Get distribute source. */
	argv_find(argv, argc, "redistribute", &idx);
	source = proto_redistnum(AFI_IP, argv[idx + 1]->text);
	if (source < 0) {
		vty_out(vty, "%% Invalid route type\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	/* Get metrics values */

	return eigrp_redistribute_unset(eigrp, source);
}

DEFUN (eigrp_variance,
       eigrp_variance_cmd,
       "variance (1-128)",
       "Control load balancing variance\n"
       "Metric variance multiplier\n")
{
	struct eigrp *eigrp;
	u_char variance;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}
	variance = atoi(argv[1]->arg);

	eigrp->variance = variance;

	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_variance,
       no_eigrp_variance_cmd,
       "no variance (1-128)",
       "Disable\n"
       "Control load balancing variance\n"
       "Metric variance multiplier\n")
{
	struct eigrp *eigrp;
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	eigrp->variance = EIGRP_VARIANCE_DEFAULT;

	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (eigrp_maximum_paths,
       eigrp_maximum_paths_cmd,
       "maximum-paths (1-32)",
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
	struct eigrp *eigrp;
	u_char max;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	max = atoi(argv[1]->arg);

	eigrp->max_paths = max;

	/*TODO: */

	return CMD_SUCCESS;
}

DEFUN (no_eigrp_maximum_paths,
       no_eigrp_maximum_paths_cmd,
       "no maximum-paths <1-32>",
       NO_STR
       "Forward packets over multiple paths\n"
       "Number of paths\n")
{
	struct eigrp *eigrp;

	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, "EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	eigrp->max_paths = EIGRP_MAX_PATHS_DEFAULT;

	/*TODO: */

	return CMD_SUCCESS;
}

/*
 * Execute hard restart for all neighbors
 */
DEFUN (clear_ip_eigrp_neighbors,
       clear_ip_eigrp_neighbors_cmd,
       "clear ip eigrp neighbors",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       "Clear IP-EIGRP neighbors\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* iterate over all eigrp interfaces */
	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		/* send Goodbye Hello */
		eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);

		/* iterate over all neighbors on eigrp interface */
		for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
			if (nbr->state != EIGRP_NEIGHBOR_DOWN) {
				zlog_debug(
					"Neighbor %s (%s) is down: manually cleared",
					inet_ntoa(nbr->src),
					ifindex2ifname(nbr->ei->ifp->ifindex,
						       VRF_DEFAULT));
				vty_time_print(vty, 0);
				vty_out(vty,
					"Neighbor %s (%s) is down: manually cleared\n",
					inet_ntoa(nbr->src),
					ifindex2ifname(nbr->ei->ifp->ifindex,
						       VRF_DEFAULT));

				/* set neighbor to DOWN */
				nbr->state = EIGRP_NEIGHBOR_DOWN;
				/* delete neighbor */
				eigrp_nbr_delete(nbr);
			}
		}
	}

	return CMD_SUCCESS;
}

/*
 * Execute hard restart for all neighbors on interface
 */
DEFUN (clear_ip_eigrp_neighbors_int,
       clear_ip_eigrp_neighbors_int_cmd,
       "clear ip eigrp neighbors IFNAME",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       "Clear IP-EIGRP neighbors\n"
       "Interface's name\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct listnode *node2, *nnode2;
	struct eigrp_neighbor *nbr;
	int idx = 0;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* lookup interface by specified name */
	argv_find(argv, argc, "IFNAME", &idx);
	ei = eigrp_if_lookup_by_name(eigrp, argv[idx]->arg);
	if (ei == NULL) {
		vty_out(vty, " Interface (%s) doesn't exist\n", argv[idx]->arg);
		return CMD_WARNING;
	}

	/* send Goodbye Hello */
	eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);

	/* iterate over all neighbors on eigrp interface */
	for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
		if (nbr->state != EIGRP_NEIGHBOR_DOWN) {
			zlog_debug("Neighbor %s (%s) is down: manually cleared",
				   inet_ntoa(nbr->src),
				   ifindex2ifname(nbr->ei->ifp->ifindex,
						  VRF_DEFAULT));
			vty_time_print(vty, 0);
			vty_out(vty,
				"Neighbor %s (%s) is down: manually cleared\n",
				inet_ntoa(nbr->src),
				ifindex2ifname(nbr->ei->ifp->ifindex,
					       VRF_DEFAULT));

			/* set neighbor to DOWN */
			nbr->state = EIGRP_NEIGHBOR_DOWN;
			/* delete neighbor */
			eigrp_nbr_delete(nbr);
		}
	}

	return CMD_SUCCESS;
}

/*
 * Execute hard restart for neighbor specified by IP
 */
DEFUN (clear_ip_eigrp_neighbors_IP,
       clear_ip_eigrp_neighbors_IP_cmd,
       "clear ip eigrp neighbors A.B.C.D",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       "Clear IP-EIGRP neighbors\n"
       "IP-EIGRP neighbor address\n")
{
	struct eigrp *eigrp;
	struct eigrp_neighbor *nbr;
	struct in_addr nbr_addr;

	if (!inet_aton(argv[4]->arg, &nbr_addr)) {
		vty_out(vty, "Unable to parse %s",
			argv[4]->arg);
		return CMD_WARNING;
	}

	/* Check if eigrp process is enabled */
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* lookup neighbor in whole process */
	nbr = eigrp_nbr_lookup_by_addr_process(eigrp, nbr_addr);

	/* if neighbor doesn't exists, notify user and exit */
	if (nbr == NULL) {
		vty_out(vty, "Neighbor with entered address doesn't exists.\n");
		return CMD_WARNING;
	}

	/* execute hard reset on neighbor */
	eigrp_nbr_hard_restart(nbr, vty);

	return CMD_SUCCESS;
}

/*
 * Execute graceful restart for all neighbors
 */
DEFUN (clear_ip_eigrp_neighbors_soft,
       clear_ip_eigrp_neighbors_soft_cmd,
       "clear ip eigrp neighbors soft",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       "Clear IP-EIGRP neighbors\n"
       "Resync with peers without adjacency reset\n")
{
	struct eigrp *eigrp;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* execute graceful restart on all neighbors */
	eigrp_update_send_process_GR(eigrp, EIGRP_GR_MANUAL, vty);

	return CMD_SUCCESS;
}

/*
 * Execute graceful restart for all neighbors on interface
 */
DEFUN (clear_ip_eigrp_neighbors_int_soft,
       clear_ip_eigrp_neighbors_int_soft_cmd,
       "clear ip eigrp neighbors IFNAME soft",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       "Clear IP-EIGRP neighbors\n"
       "Interface's name\n"
       "Resync with peer without adjacency reset\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* lookup interface by specified name */
	ei = eigrp_if_lookup_by_name(eigrp, argv[4]->arg);
	if (ei == NULL) {
		vty_out(vty, " Interface (%s) doesn't exist\n", argv[4]->arg);
		return CMD_WARNING;
	}

	/* execute graceful restart for all neighbors on interface */
	eigrp_update_send_interface_GR(ei, EIGRP_GR_MANUAL, vty);
	return CMD_SUCCESS;
}

/*
 * Execute graceful restart for neighbor specified by IP
 */
DEFUN (clear_ip_eigrp_neighbors_IP_soft,
       clear_ip_eigrp_neighbors_IP_soft_cmd,
       "clear ip eigrp neighbors A.B.C.D soft",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       "Clear IP-EIGRP neighbors\n"
       "IP-EIGRP neighbor address\n"
       "Resync with peer without adjacency reset\n")
{
	struct eigrp *eigrp;
	struct eigrp_neighbor *nbr;
	struct in_addr nbr_addr;

	if (!inet_aton(argv[4]->arg, &nbr_addr)) {
		vty_out(vty, "Unable to parse: %s",
			argv[4]->arg);
		return CMD_WARNING;
	}

	/* Check if eigrp process is enabled */
	eigrp = eigrp_lookup();
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* lookup neighbor in whole process */
	nbr = eigrp_nbr_lookup_by_addr_process(eigrp, nbr_addr);

	/* if neighbor doesn't exists, notify user and exit */
	if (nbr == NULL) {
		vty_out(vty, "Neighbor with entered address doesn't exists.\n");
		return CMD_WARNING;
	}

	/* execute graceful restart on neighbor */
	eigrp_update_send_GR(nbr, EIGRP_GR_MANUAL, vty);

	return CMD_SUCCESS;
}

static struct cmd_node eigrp_node = {EIGRP_NODE, "%s(config-router)# ", 1};

/* Save EIGRP configuration */
static int eigrp_config_write(struct vty *vty)
{
	struct eigrp *eigrp;

	int write = 0;

	eigrp = eigrp_lookup();
	if (eigrp != NULL) {
		/* Writes 'router eigrp' section to config */
		config_write_eigrp_router(vty, eigrp);

		/* Interface config print */
		config_write_interfaces(vty, eigrp);
		//
		//      /* static neighbor print. */
		//      config_write_eigrp_nbr_nbma (vty, eigrp);
		//
		//      /* Virtual-Link print. */
		//      config_write_virtual_link (vty, eigrp);
		//
		//      /* Default metric configuration.  */
		//      config_write_eigrp_default_metric (vty, eigrp);
		//
		//      /* Distribute-list and default-information print. */
		//      config_write_eigrp_distribute (vty, eigrp);
		//
		//      /* Distance configuration. */
		//      config_write_eigrp_distance (vty, eigrp)
	}

	return write;
}

void eigrp_vty_show_init(void)
{
	install_element(VIEW_NODE, &show_ip_eigrp_interfaces_cmd);

	install_element(VIEW_NODE, &show_ip_eigrp_neighbors_cmd);

	install_element(VIEW_NODE, &show_ip_eigrp_topology_cmd);

	install_element(VIEW_NODE, &show_ip_eigrp_topology_detail_cmd);
}

/* eigrpd's interface node. */
static struct cmd_node eigrp_interface_node = {INTERFACE_NODE,
					       "%s(config-if)# ", 1};

void eigrp_vty_if_init(void)
{
	install_node(&eigrp_interface_node, eigrp_write_interface);
	if_cmd_init();

	/* Delay and bandwidth configuration commands*/
	install_element(INTERFACE_NODE, &eigrp_if_delay_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_delay_cmd);
	install_element(INTERFACE_NODE, &eigrp_if_bandwidth_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_bandwidth_cmd);

	/*Hello-interval and hold-time interval configuration commands*/
	install_element(INTERFACE_NODE, &eigrp_if_ip_holdinterval_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_ip_holdinterval_cmd);
	install_element(INTERFACE_NODE, &eigrp_if_ip_hellointerval_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_if_ip_hellointerval_cmd);

	/* "Authentication configuration commands */
	install_element(INTERFACE_NODE, &eigrp_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_authentication_mode_cmd);
	install_element(INTERFACE_NODE, &eigrp_authentication_keychain_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_authentication_keychain_cmd);

	/*EIGRP Summarization commands*/
	install_element(INTERFACE_NODE, &eigrp_ip_summary_address_cmd);
	install_element(INTERFACE_NODE, &no_eigrp_ip_summary_address_cmd);
}

static void eigrp_vty_zebra_init(void)
{
	install_element(EIGRP_NODE, &eigrp_redistribute_source_metric_cmd);
	install_element(EIGRP_NODE, &no_eigrp_redistribute_source_metric_cmd);
}

/* Install EIGRP related vty commands. */
void eigrp_vty_init(void)
{
	install_node(&eigrp_node, eigrp_config_write);

	install_default(EIGRP_NODE);

	install_element(CONFIG_NODE, &router_eigrp_cmd);
	install_element(CONFIG_NODE, &no_router_eigrp_cmd);
	install_element(EIGRP_NODE, &eigrp_network_cmd);
	install_element(EIGRP_NODE, &no_eigrp_network_cmd);
	install_element(EIGRP_NODE, &eigrp_variance_cmd);
	install_element(EIGRP_NODE, &no_eigrp_variance_cmd);
	install_element(EIGRP_NODE, &eigrp_router_id_cmd);
	install_element(EIGRP_NODE, &no_eigrp_router_id_cmd);
	install_element(EIGRP_NODE, &eigrp_passive_interface_cmd);
	install_element(EIGRP_NODE, &no_eigrp_passive_interface_cmd);
	install_element(EIGRP_NODE, &eigrp_timers_active_cmd);
	install_element(EIGRP_NODE, &no_eigrp_timers_active_cmd);
	install_element(EIGRP_NODE, &eigrp_metric_weights_cmd);
	install_element(EIGRP_NODE, &no_eigrp_metric_weights_cmd);
	install_element(EIGRP_NODE, &eigrp_maximum_paths_cmd);
	install_element(EIGRP_NODE, &no_eigrp_maximum_paths_cmd);
	install_element(EIGRP_NODE, &eigrp_neighbor_cmd);
	install_element(EIGRP_NODE, &no_eigrp_neighbor_cmd);

	/* commands for manual hard restart */
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_int_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_IP_cmd);
	/* commands for manual graceful restart */
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_soft_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_int_soft_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_IP_soft_cmd);

	eigrp_vty_zebra_init();
}
