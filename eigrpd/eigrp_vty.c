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

#include "eigrpd/eigrp_vty_clippy.c"

static void eigrp_vty_display_prefix_entry(struct vty *vty, struct eigrp *eigrp,
					   struct eigrp_prefix_descriptor *pe,
					   bool all)
{
	bool first = true;
	struct eigrp_route_descriptor *te;
	struct listnode *node;

	for (ALL_LIST_ELEMENTS_RO(pe->entries, node, te)) {
		if (all
		    || (((te->flags & EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)
			 == EIGRP_ROUTE_DESCRIPTOR_SUCCESSOR_FLAG)
			|| ((te->flags & EIGRP_ROUTE_DESCRIPTOR_FSUCCESSOR_FLAG)
			    == EIGRP_ROUTE_DESCRIPTOR_FSUCCESSOR_FLAG))) {
			show_ip_eigrp_route_descriptor(vty, eigrp, te, &first);
			first = false;
		}
	}
}

static struct eigrp *eigrp_vty_get_eigrp(struct vty *vty, const char *vrf_name)
{
	struct vrf *vrf;

	if (vrf_name)
		vrf = vrf_lookup_by_name(vrf_name);
	else
		vrf = vrf_lookup_by_id(VRF_DEFAULT);

	if (!vrf) {
		vty_out(vty, "VRF %s specified does not exist",
			vrf_name ? vrf_name : VRF_DEFAULT_NAME);
		return NULL;
	}

	return eigrp_lookup(vrf->vrf_id);
}

static void eigrp_topology_helper(struct vty *vty, struct eigrp *eigrp,
				  const char *all)
{
	struct eigrp_prefix_descriptor *tn;
	struct route_node *rn;

	show_ip_eigrp_topology_header(vty, eigrp);

	for (rn = route_top(eigrp->topology_table); rn; rn = route_next(rn)) {
		if (!rn->info)
			continue;

		tn = rn->info;
		eigrp_vty_display_prefix_entry(vty, eigrp, tn,
					       all ? true : false);
	}
}

DEFPY (show_ip_eigrp_topology_all,
       show_ip_eigrp_topology_all_cmd,
       "show ip eigrp [vrf NAME] topology [all-links$all]",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       VRF_CMD_HELP_STR
       "IP-EIGRP topology\n"
       "Show all links in topology table\n")
{
	struct eigrp *eigrp;

	if (vrf && strncmp(vrf, "all", sizeof("all")) == 0) {
		struct vrf *v;

		RB_FOREACH (v, vrf_name_head, &vrfs_by_name) {
			eigrp = eigrp_lookup(v->vrf_id);
			if (!eigrp)
				continue;

			vty_out(vty, "VRF %s:\n", v->name);

			eigrp_topology_helper(vty, eigrp, all);
		}
	} else {
		eigrp = eigrp_vty_get_eigrp(vty, vrf);
		if (eigrp == NULL) {
			vty_out(vty, " EIGRP Routing Process not enabled\n");
			return CMD_SUCCESS;
		}

		eigrp_topology_helper(vty, eigrp, all);
	}

	return CMD_SUCCESS;
}

DEFPY (show_ip_eigrp_topology,
       show_ip_eigrp_topology_cmd,
       "show ip eigrp [vrf NAME] topology <A.B.C.D$address|A.B.C.D/M$prefix>",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       VRF_CMD_HELP_STR
       "IP-EIGRP topology\n"
       "For a specific address\n"
       "For a specific prefix\n")
{
	struct eigrp *eigrp;
	struct eigrp_prefix_descriptor *tn;
	struct route_node *rn;
	struct prefix cmp;

	if (vrf && strncmp(vrf, "all", sizeof("all")) == 0) {
		vty_out(vty, "Specifying vrf `all` for a particular address/prefix makes no sense\n");
		return CMD_SUCCESS;
	}

	eigrp = eigrp_vty_get_eigrp(vty, vrf);
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	show_ip_eigrp_topology_header(vty, eigrp);

	if (address_str)
		prefix_str = address_str;

	if (str2prefix(prefix_str, &cmp) < 0) {
		vty_out(vty, "%% Malformed address\n");
		return CMD_WARNING;
	}

	rn = route_node_match(eigrp->topology_table, &cmp);
	if (!rn) {
		vty_out(vty, "%% Network not in table\n");
		return CMD_WARNING;
	}

	if (!rn->info) {
		vty_out(vty, "%% Network not in table\n");
		route_unlock_node(rn);
		return CMD_WARNING;
	}

	tn = rn->info;
	eigrp_vty_display_prefix_entry(vty, eigrp, tn, argc == 5);

	route_unlock_node(rn);
	return CMD_SUCCESS;
}

static void eigrp_interface_helper(struct vty *vty, struct eigrp *eigrp,
				   const char *ifname, const char *detail)
{
	struct eigrp_interface *ei;
	struct listnode *node;

	if (!ifname)
		show_ip_eigrp_interface_header(vty, eigrp);

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (!ifname || strcmp(ei->ifp->name, ifname) == 0) {
			show_ip_eigrp_interface_sub(vty, eigrp, ei);
			if (detail)
				show_ip_eigrp_interface_detail(vty, eigrp, ei);
		}
	}
}

DEFPY (show_ip_eigrp_interfaces,
       show_ip_eigrp_interfaces_cmd,
       "show ip eigrp [vrf NAME] interfaces [IFNAME] [detail]$detail",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       VRF_CMD_HELP_STR
       "IP-EIGRP interfaces\n"
       "Interface name to look at\n"
       "Detailed information\n")
{
	struct eigrp *eigrp;

	if (vrf && strncmp(vrf, "all", sizeof("all")) == 0) {
		struct vrf *v;

		RB_FOREACH (v, vrf_name_head, &vrfs_by_name) {
			eigrp = eigrp_lookup(v->vrf_id);
			if (!eigrp)
				continue;

			vty_out(vty, "VRF %s:\n", v->name);

			eigrp_interface_helper(vty, eigrp, ifname, detail);
		}
	} else {
		eigrp = eigrp_vty_get_eigrp(vty, vrf);
		if (eigrp == NULL) {
			vty_out(vty, "EIGRP Routing Process not enabled\n");
			return CMD_SUCCESS;
		}

		eigrp_interface_helper(vty, eigrp, ifname, detail);
	}


	return CMD_SUCCESS;
}

static void eigrp_neighbors_helper(struct vty *vty, struct eigrp *eigrp,
				   const char *ifname, const char *detail)
{
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	show_ip_eigrp_neighbor_header(vty, eigrp);

	for (ALL_LIST_ELEMENTS_RO(eigrp->eiflist, node, ei)) {
		if (!ifname || strcmp(ei->ifp->name, ifname) == 0) {
			for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
				if (detail || (nbr->state == EIGRP_NEIGHBOR_UP))
					show_ip_eigrp_neighbor_sub(vty, nbr,
								   !!detail);
			}
		}
	}
}

DEFPY (show_ip_eigrp_neighbors,
       show_ip_eigrp_neighbors_cmd,
       "show ip eigrp [vrf NAME] neighbors [IFNAME] [detail]$detail",
       SHOW_STR
       IP_STR
       "IP-EIGRP show commands\n"
       VRF_CMD_HELP_STR
       "IP-EIGRP neighbors\n"
       "Interface to show on\n"
       "Detailed Information\n")
{
	struct eigrp *eigrp;

	if (vrf && strncmp(vrf, "all", sizeof("all")) == 0) {
		struct vrf *vrf;

		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			eigrp = eigrp_lookup(vrf->vrf_id);
			if (!eigrp)
				continue;

			vty_out(vty, "VRF %s:\n", vrf->name);

			eigrp_neighbors_helper(vty, eigrp, ifname, detail);
		}
	} else {
		eigrp = eigrp_vty_get_eigrp(vty, vrf);
		if (eigrp == NULL) {
			vty_out(vty, " EIGRP Routing Process not enabled\n");
			return CMD_SUCCESS;
		}

		eigrp_neighbors_helper(vty, eigrp, ifname, detail);
	}

	return CMD_SUCCESS;
}

/*
 * Execute hard restart for all neighbors
 */
DEFPY (clear_ip_eigrp_neighbors,
       clear_ip_eigrp_neighbors_cmd,
       "clear ip eigrp [vrf NAME] neighbors",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       VRF_CMD_HELP_STR
       "Clear IP-EIGRP neighbors\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct listnode *node, *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_vty_get_eigrp(vty, vrf);
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
					"Neighbor %pI4 (%s) is down: manually cleared",
					&nbr->src,
					ifindex2ifname(nbr->ei->ifp->ifindex,
						       eigrp->vrf_id));
				vty_time_print(vty, 0);
				vty_out(vty,
					"Neighbor %pI4 (%s) is down: manually cleared\n",
					&nbr->src,
					ifindex2ifname(nbr->ei->ifp->ifindex,
						       eigrp->vrf_id));

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
DEFPY (clear_ip_eigrp_neighbors_int,
       clear_ip_eigrp_neighbors_int_cmd,
       "clear ip eigrp [vrf NAME] neighbors IFNAME",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       VRF_CMD_HELP_STR
       "Clear IP-EIGRP neighbors\n"
       "Interface's name\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;
	struct listnode *node2, *nnode2;
	struct eigrp_neighbor *nbr;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_vty_get_eigrp(vty, vrf);
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* lookup interface by specified name */
	ei = eigrp_if_lookup_by_name(eigrp, ifname);
	if (ei == NULL) {
		vty_out(vty, " Interface (%s) doesn't exist\n", ifname);
		return CMD_WARNING;
	}

	/* send Goodbye Hello */
	eigrp_hello_send(ei, EIGRP_HELLO_GRACEFUL_SHUTDOWN, NULL);

	/* iterate over all neighbors on eigrp interface */
	for (ALL_LIST_ELEMENTS(ei->nbrs, node2, nnode2, nbr)) {
		if (nbr->state != EIGRP_NEIGHBOR_DOWN) {
			zlog_debug(
				"Neighbor %pI4 (%s) is down: manually cleared",
				&nbr->src,
				ifindex2ifname(nbr->ei->ifp->ifindex,
					       eigrp->vrf_id));
			vty_time_print(vty, 0);
			vty_out(vty,
				"Neighbor %pI4 (%s) is down: manually cleared\n",
				&nbr->src,
				ifindex2ifname(nbr->ei->ifp->ifindex,
					       eigrp->vrf_id));

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
DEFPY (clear_ip_eigrp_neighbors_IP,
       clear_ip_eigrp_neighbors_IP_cmd,
       "clear ip eigrp [vrf NAME] neighbors A.B.C.D$nbr_addr",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       VRF_CMD_HELP_STR
       "Clear IP-EIGRP neighbors\n"
       "IP-EIGRP neighbor address\n")
{
	struct eigrp *eigrp;
	struct eigrp_neighbor *nbr;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_vty_get_eigrp(vty, vrf);
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
DEFPY (clear_ip_eigrp_neighbors_soft,
       clear_ip_eigrp_neighbors_soft_cmd,
       "clear ip eigrp [vrf NAME] neighbors soft",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       VRF_CMD_HELP_STR
       "Clear IP-EIGRP neighbors\n"
       "Resync with peers without adjacency reset\n")
{
	struct eigrp *eigrp;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_vty_get_eigrp(vty, vrf);
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
DEFPY (clear_ip_eigrp_neighbors_int_soft,
       clear_ip_eigrp_neighbors_int_soft_cmd,
       "clear ip eigrp [vrf NAME] neighbors IFNAME soft",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       VRF_CMD_HELP_STR
       "Clear IP-EIGRP neighbors\n"
       "Interface's name\n"
       "Resync with peer without adjacency reset\n")
{
	struct eigrp *eigrp;
	struct eigrp_interface *ei;

	/* Check if eigrp process is enabled */
	eigrp = eigrp_vty_get_eigrp(vty, vrf);
	if (eigrp == NULL) {
		vty_out(vty, " EIGRP Routing Process not enabled\n");
		return CMD_SUCCESS;
	}

	/* lookup interface by specified name */
	ei = eigrp_if_lookup_by_name(eigrp, ifname);
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
DEFPY (clear_ip_eigrp_neighbors_IP_soft,
       clear_ip_eigrp_neighbors_IP_soft_cmd,
       "clear ip eigrp [vrf NAME] neighbors A.B.C.D$nbr_addr soft",
       CLEAR_STR
       IP_STR
       "Clear IP-EIGRP\n"
       VRF_CMD_HELP_STR
       "Clear IP-EIGRP neighbors\n"
       "IP-EIGRP neighbor address\n"
       "Resync with peer without adjacency reset\n")
{
	struct eigrp *eigrp;
	struct eigrp_neighbor *nbr;


	/* Check if eigrp process is enabled */
	eigrp = eigrp_vty_get_eigrp(vty, vrf);
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

void eigrp_vty_show_init(void)
{
	install_element(VIEW_NODE, &show_ip_eigrp_interfaces_cmd);

	install_element(VIEW_NODE, &show_ip_eigrp_neighbors_cmd);

	install_element(VIEW_NODE, &show_ip_eigrp_topology_cmd);
	install_element(VIEW_NODE, &show_ip_eigrp_topology_all_cmd);
}

/* Install EIGRP related vty commands. */
void eigrp_vty_init(void)
{
	/* commands for manual hard restart */
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_int_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_IP_cmd);
	/* commands for manual graceful restart */
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_soft_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_int_soft_cmd);
	install_element(ENABLE_NODE, &clear_ip_eigrp_neighbors_IP_soft_cmd);
}
