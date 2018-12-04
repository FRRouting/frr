/*
 * VRRP commands
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "command.h"
#include "vty.h"
#include "if.h"
#include "termtable.h"
#include "prefix.h"

#include "vrrp.h"
#include "vrrp_vty.h"
#include "vrrp_memory.h"
#ifndef VTYSH_EXTRACT_PL
#include "vrrpd/vrrp_vty_clippy.c"
#endif


#define VRRP_STR "Virtual Router Redundancy Protocol\n"
#define VRRP_VRID_STR "Virtual Router ID\n"
#define VRRP_PRIORITY_STR "Virtual Router Priority\n"
#define VRRP_IP_STR "Virtual Router IPv4 address\n"

#define VROUTER_GET_VTY(_vty, _vrid, _vr)                                      \
	do {                                                                   \
		_vr = vrrp_lookup(_vrid);                                      \
		if (!_vr) {                                                    \
			vty_out(_vty,                                          \
				"%% Please configure VRRP instance %u\n",      \
				(unsigned int)_vrid);                          \
			return CMD_WARNING_CONFIG_FAILED;                      \
		}                                                              \
	} while (0);

DEFUN_NOSH (show_debugging_vrrpd,
	    show_debugging_vrrpd_cmd,
	    "show debugging [vrrp]",
	    SHOW_STR
	    DEBUG_STR
	    "VRRP information\n")
{
	vty_out(vty, "VRRP debugging status\n");

	return CMD_SUCCESS;
}

DEFPY(vrrp_vrid,
      vrrp_vrid_cmd,
      "[no] vrrp (1-255)$vrid",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR)
{
	VTY_DECLVAR_CONTEXT(interface, ifp);

	struct vrrp_vrouter *vr = vrrp_vrouter_create(ifp, vrid);
	int ret = vrrp_event(vr, VRRP_EVENT_STARTUP);
	if (ret < 0) {
		vty_out(vty, "%% Failed to start VRRP instance\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	return CMD_SUCCESS;
}

DEFPY(vrrp_priority,
      vrrp_priority_cmd,
      "[no] vrrp (1-255)$vrid priority (1-254)",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      VRRP_PRIORITY_STR
      "Priority value\n")
{
	struct vrrp_vrouter *vr;

	VROUTER_GET_VTY(vty, vrid, vr);
	vrrp_update_priority(vr, priority);

	return CMD_SUCCESS;
}

DEFPY(vrrp_ip,
      vrrp_ip_cmd,
      "[no] vrrp (1-255)$vrid ip A.B.C.D$ip",
      NO_STR
      VRRP_STR
      VRRP_VRID_STR
      "Add IP address\n"
      VRRP_IP_STR)
{
	struct vrrp_vrouter *vr;

	VROUTER_GET_VTY(vty, vrid, vr);
	vrrp_add_ip(vr, ip);

	return CMD_SUCCESS;
}

DEFPY(vrrp_vrid_show,
      vrrp_vrid_show_cmd,
      "show vrrp [(1-255)$vrid]",
      SHOW_STR
      VRRP_STR
      VRRP_VRID_STR)
{
	struct vrrp_vrouter *vr;
	char ethstr[ETHER_ADDR_STRLEN];
	char ipstr[INET_ADDRSTRLEN];
	const char *stastr;

	VROUTER_GET_VTY(vty, vrid, vr);

	switch (vr->fsm.state) {
	case VRRP_STATE_INITIALIZE:
		stastr = "Initialize";
		break;
	case VRRP_STATE_MASTER:
		stastr = "Master";
		break;
	case VRRP_STATE_BACKUP:
		stastr = "Backup";
		break;
	}

	struct ttable *tt = ttable_new(&ttable_styles[TTSTYLE_BLANK]);

	ttable_add_row(tt, "%s|%" PRIu32, "Virtual Router ID", vr->vrid);
	prefix_mac2str(&vr->vr_mac_v4, ethstr, sizeof(ethstr));
	ttable_add_row(tt, "%s|%s", "Virtual MAC", ethstr);
	ttable_add_row(tt, "%s|%s", "Status", stastr);
	ttable_add_row(tt, "%s|%" PRIu8, "Priority", vr->priority);
	ttable_add_row(tt, "%s|%s", "Preempt Mode",
		       vr->preempt_mode ? "Yes" : "No");
	ttable_add_row(tt, "%s|%s", "Accept Mode",
		       vr->accept_mode ? "Yes" : "No");
	ttable_add_row(tt, "%s|%" PRIu16, "Advertisement Interval",
		       vr->advertisement_interval);
	ttable_add_row(tt, "%s|%" PRIu16, "Master Advertisement Interval",
		       vr->master_adver_interval);
	ttable_add_row(tt, "%s|%" PRIu16, "Skew Time", vr->skew_time);
	ttable_add_row(tt, "%s|%" PRIu16, "Master Down Interval",
		       vr->master_down_interval);
	ttable_add_row(tt, "%s|%u", "IPv4 Addresses", vr->v4->count);

	char *table = ttable_dump(tt, "\n");
	vty_out(vty, "\n%s\n", table);
	XFREE(MTYPE_TMP, table);
	ttable_del(tt);

	/* Dump IPv4 Addresses */
	if (vr->v4->count) {
		vty_out(vty, " IPv4 Addresses\n");
		vty_out(vty, " --------------\n");
		struct listnode *ln;
		struct in_addr *v4;
		for (ALL_LIST_ELEMENTS_RO(vr->v4, ln, v4)) {
			inet_ntop(AF_INET, v4, ipstr, sizeof(ipstr));
			vty_out(vty, " %s\n", ipstr);
		}
		vty_out(vty, "\n");
	}

	return CMD_SUCCESS;
}

static struct cmd_node interface_node = {
	INTERFACE_NODE,
	"%s(config-if)# ", 1
};

void vrrp_vty_init(void)
{
	install_node(&interface_node, NULL);
	if_cmd_init();
	install_element(VIEW_NODE, &show_debugging_vrrpd_cmd);
	install_element(VIEW_NODE, &vrrp_vrid_show_cmd);
	install_element(INTERFACE_NODE, &vrrp_vrid_cmd);
	install_element(INTERFACE_NODE, &vrrp_priority_cmd);
	install_element(INTERFACE_NODE, &vrrp_ip_cmd);
}
