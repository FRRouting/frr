/*
 * VTY library for Path Monitoring Daemon
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "prefix.h"
#include "sockunion.h"
#include <hash.h>
#include "nexthop.h"
#include "log.h"
#include "vrf.h"
#include "zclient.h"
#include "nexthop_group.h"

#include "pmd/pm_memory.h"
#include "pmd/pm_zebra.h"
#include "pmd/pm_vty.h"

#include "pmd/pm.h"

#ifndef VTYSH_EXTRACT_PL
#include "pmd/pm_vty_clippy.c"
#endif

#define SESSION_STR "Configure session\n"
#define SESSION_IPV4_STR "IPv4 peer address\n"
#define SESSION_IPV6_STR "IPv6 peer address\n"
#define REMOTE_STR "Configure remote address\n"
#define LOCAL_STR "Configure local address\n"
#define LOCAL_IPV4_STR "IPv4 local address\n"
#define LOCAL_IPV6_STR "IPv6 local address\n"
#define LOCAL_INTF_STR "Configure local interface name to use\n"
#define VRF_STR "Configure VRF\n"
#define VRF_NAME_STR "Configure VRF name\n"

/*
 * Prototypes
 */
static int pm_write_config(struct vty *vty);
static int pm_session_walk_write_config(struct vty *vty);
static void pm_session_write_config_walker(struct hash_bucket *b, void *data);

static int pm_write_config(struct vty *vty)
{
	vty_out(vty, "pm\n");
	vty_out(vty, "!\n");
	return 0;
}

struct pm_session_walk_ctxt {
	struct vty *vty;
	struct pm_session *pm;
};

static void pm_session_write_config_walker(struct hash_bucket *b, void *data)
{
	struct vty *vty = data;
	char buf[SU_ADDRSTRLEN];
	struct pm_session *pm = (struct pm_session *)b->data;

	vty_out(vty, " session %s", sockunion2str(&pm->key.peer, buf, sizeof(buf)));
	if (sockunion_family(&pm->key.local) == AF_INET ||
	    sockunion_family(&pm->key.local) == AF_INET6)
		vty_out(vty, " local-address %s",
			sockunion2str(&pm->key.local, buf, sizeof(buf)));
	if (pm->key.ifname[0])
		vty_out(vty, " interface %s", pm->key.ifname);
	if (pm->key.vrfname[0])
		vty_out(vty, " vrf %s", pm->key.vrfname);
	vty_out(vty, "\n");
	if (pm->interval != PM_INTERVAL_DEFAULT)
		vty_out(vty, "  interval %u\n", pm->interval);
	if (pm->tos_val != PM_PACKET_TOS_DEFAULT)
		vty_out(vty, "  packet-tos %u\n", pm->tos_val);
	if (pm->packet_size != pm_get_default_packet_size(pm))
		vty_out(vty, "  packet-size %u\n", pm->packet_size);
	if (pm->timeout != PM_TIMEOUT_DEFAULT)
		vty_out(vty, "  timeout %u\n", pm->timeout);
	if (pm->flags & PM_SESS_FLAG_SHUTDOWN)
		vty_out(vty, "  shutdown\n");
	else
		vty_out(vty, "  no shutdown\n");
	vty_out(vty, " !\n");
	return;
}

static int pm_session_walk_write_config(struct vty *vty)
{
	hash_iterate(pm_session_list,
		     pm_session_write_config_walker, (void *)vty);
	return 1;
}

/*
 * Commands definition.
 */
DEFUN_NOSH(pm_enter, pm_enter_cmd, "pm", "Configure Path Monitoring sessions\n")
{
	vty->node = PM_NODE;
	return CMD_SUCCESS;
}

DEFUN_NOSH(
	pm_peer_enter, pm_peer_enter_cmd,
	"session <A.B.C.D|X:X::X:X> [{local-address <A.B.C.D|X:X::X:X>|interface IFNAME|vrf NAME}]",
	SESSION_STR SESSION_IPV4_STR SESSION_IPV6_STR
	LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR VRF_NAME_STR)
{
	struct pm_session *pm = NULL;
	const char *peer = argv[1]->arg;
	int idx;
	const char *ifname = NULL, *local = NULL, *vrfname = NULL;
	union sockunion psa;
	char errormsg[128];

	idx = 0;
	if (argv_find(argv, argc, "interface", &idx))
		ifname = argv[idx + 1]->arg;

	idx = 0;
	if (argv_find(argv, argc, "local-address", &idx))
		local = argv[idx + 1]->arg;

	idx = 0;
	if (argv_find(argv, argc, "vrf", &idx))
		vrfname = argv[idx + 1]->arg;

	str2sockunion(peer, &psa);
	pm = pm_lookup_session(&psa, local, ifname, vrfname, true,
			       errormsg, sizeof(errormsg));
	if (!pm) {
		vty_out(vty, "%% Invalid session configuration: %s\n",
			errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	pm_initialise(pm, false, errormsg, sizeof(errormsg));
	VTY_PUSH_CONTEXT(PM_SESSION_NODE, pm);
	return CMD_SUCCESS;
}

DEFPY(
	pm_remove_session, pm_remove_session_cmd,
	"no session <A.B.C.D|X:X::X:X>$peer [{local-address <A.B.C.D|X:X::X:X>$local|interface IFNAME$ifname|vrf NAME$vrfname}]",
	NO_STR
	SESSION_STR SESSION_IPV4_STR SESSION_IPV6_STR
	LOCAL_STR LOCAL_IPV4_STR LOCAL_IPV6_STR
	INTERFACE_STR
	LOCAL_INTF_STR
	VRF_STR VRF_NAME_STR)
{
	union sockunion psa;
	struct pm_session *pm = NULL;
	char errormsg[128];

	str2sockunion(peer_str, &psa);
	pm = pm_lookup_session(&psa, local_str, ifname, vrfname, false,
			       errormsg, sizeof(errormsg));
	if (!pm) {
		vty_out(vty, "%% Invalid session configuration: %s\n",
			errormsg);
		return CMD_WARNING_CONFIG_FAILED;
	}
	hash_release(pm_session_list, pm);
	XFREE(MTYPE_PM_SESSION, pm);
	return CMD_SUCCESS;
}

DEFPY(pm_packet_interval, pm_packet_interval_cmd, "[no] interval [(1-65535)$freq]",
      NO_STR
      "Interval between each emission\n"
      "Interval in milliseconds\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->interval = PM_INTERVAL_DEFAULT;
	else if (freq)
		pm->interval = freq;
	return CMD_SUCCESS;
}

DEFPY(pm_packet_size, pm_packet_size_cmd, "[no] packet-size [(1-65535)$psize]",
      NO_STR "Packet size in bytes\n" "Size of packet to send\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->packet_size = pm_get_default_packet_size(pm);
	else if (psize)
		pm->packet_size = psize;
	return CMD_SUCCESS;
}

DEFPY(pm_packet_tos, pm_packet_tos_cmd, "[no] packet-tos (1-255)$tosval",
      NO_STR "TOS to apply to packet\n"
      "Packet TOS val in decimal format\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->tos_val = PM_PACKET_TOS_DEFAULT;
	else if (tosval)
		pm->tos_val = tosval;
	return CMD_SUCCESS;
}

DEFPY(pm_packet_timeout, pm_packet_timeout_cmd, "[no] timeout [(1-65535)$tmo]",
      NO_STR
      "Timeout where response considered as lost\n"
      "Timeout in milliseconds\n")
{
	struct pm_session *pm;

	pm = VTY_GET_CONTEXT(pm_session);

	if (no)
		pm->timeout = PM_TIMEOUT_DEFAULT;
	else if (tmo)
		pm->timeout = tmo;
	return CMD_SUCCESS;
}

DEFPY(pm_session_shutdown, pm_session_shutdown_cmd, "[no] shutdown",
      NO_STR "Disable PM session\n")
{
	struct pm_session *pm;
	char errormsg[128];

	pm = VTY_GET_CONTEXT(pm_session);
	if (no) {
		if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN))
			return CMD_SUCCESS;

		PM_UNSET_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN);

		pm_initialise(pm, true, errormsg, sizeof(errormsg));
		if (!PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_VALIDATE))
			vty_out(vty, "%% session could not be started: %s",
				errormsg);
		else {
			/* Change and notify state change. */
			/* Enable all timers. */
		}
	} else {
		if (PM_CHECK_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN))
			return CMD_SUCCESS;

		PM_SET_FLAG(pm->flags, PM_SESS_FLAG_SHUTDOWN);

		/* Disable all events. */
		/* Change and notify state change. */
	}
	return CMD_SUCCESS;
}

DEFUN_NOSH (show_debugging_pmd,
	    show_debugging_pmd_cmd,
	    "show debugging [pm]",
	    SHOW_STR
	    DEBUG_STR
	    "Pm Information\n")
{
	vty_out(vty, "Pm debugging status\n");

	return CMD_SUCCESS;
}

struct cmd_node pm_node = {
	.name = "pm",
	.node = PM_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-pm)# ",
	.config_write = pm_write_config
};

struct cmd_node pm_session_node = {
	.name = "pm-session",
	.node = PM_SESSION_NODE,
	.parent_node = PM_NODE,
	.prompt = "%s(config-pm-session)# ",
	.config_write = pm_session_walk_write_config
};

void pm_vty_init(void)
{
	install_element(VIEW_NODE, &show_debugging_pmd_cmd);

	/* Install PM node and commands. */
	install_element(CONFIG_NODE, &pm_enter_cmd);
	install_node(&pm_node);
	install_default(PM_NODE);
	install_element(PM_NODE, &pm_peer_enter_cmd);
	install_element(PM_NODE, &pm_remove_session_cmd);


	/* Install PM session node. */
	install_node(&pm_session_node);
	install_default(PM_SESSION_NODE);

	install_element(PM_SESSION_NODE, &pm_session_shutdown_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_timeout_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_interval_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_size_cmd);
	install_element(PM_SESSION_NODE, &pm_packet_tos_cmd);
}
