/*
 * Zebra debug related function
 * Copyright (C) 1999 Kunihiro Ishiguro
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
#include "debug.h"

/* For debug statement. */
unsigned long zebra_debug_event;
unsigned long zebra_debug_packet;
unsigned long zebra_debug_kernel;
unsigned long zebra_debug_rib;
unsigned long zebra_debug_fpm;
unsigned long zebra_debug_nht;
unsigned long zebra_debug_mpls;
unsigned long zebra_debug_vxlan;
unsigned long zebra_debug_pw;

DEFINE_HOOK(zebra_debug_show_debugging, (struct vty *vty), (vty));

DEFUN_NOSH (show_debugging_zebra,
	    show_debugging_zebra_cmd,
	    "show debugging [zebra]",
	    SHOW_STR
	    "Debugging information\n"
	    "Zebra configuration\n")
{
	vty_out(vty, "Zebra debugging status:\n");

	if (IS_ZEBRA_DEBUG_EVENT)
		vty_out(vty, "  Zebra event debugging is on\n");

	if (IS_ZEBRA_DEBUG_PACKET) {
		if (IS_ZEBRA_DEBUG_SEND && IS_ZEBRA_DEBUG_RECV) {
			vty_out(vty, "  Zebra packet%s debugging is on\n",
				IS_ZEBRA_DEBUG_DETAIL ? " detail" : "");
		} else {
			if (IS_ZEBRA_DEBUG_SEND)
				vty_out(vty,
					"  Zebra packet send%s debugging is on\n",
					IS_ZEBRA_DEBUG_DETAIL ? " detail" : "");
			else
				vty_out(vty,
					"  Zebra packet receive%s debugging is on\n",
					IS_ZEBRA_DEBUG_DETAIL ? " detail" : "");
		}
	}

	if (IS_ZEBRA_DEBUG_KERNEL)
		vty_out(vty, "  Zebra kernel debugging is on\n");
	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
		vty_out(vty,
			"  Zebra kernel netlink message dumps (send) are on\n");
	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV)
		vty_out(vty,
			"  Zebra kernel netlink message dumps (recv) are on\n");

	/* Check here using flags as the 'macro' does an OR */
	if (CHECK_FLAG(zebra_debug_rib, ZEBRA_DEBUG_RIB_DETAILED))
		vty_out(vty, "  Zebra RIB detailed debugging is on\n");
	else if (CHECK_FLAG(zebra_debug_rib, ZEBRA_DEBUG_RIB))
		vty_out(vty, "  Zebra RIB debugging is on\n");

	if (IS_ZEBRA_DEBUG_FPM)
		vty_out(vty, "  Zebra FPM debugging is on\n");
	if (IS_ZEBRA_DEBUG_NHT)
		vty_out(vty, "  Zebra next-hop tracking debugging is on\n");
	if (IS_ZEBRA_DEBUG_MPLS)
		vty_out(vty, "  Zebra MPLS debugging is on\n");
	if (IS_ZEBRA_DEBUG_VXLAN)
		vty_out(vty, "  Zebra VXLAN debugging is on\n");
	if (IS_ZEBRA_DEBUG_PW)
		vty_out(vty, "  Zebra pseudowire debugging is on\n");

	hook_call(zebra_debug_show_debugging, vty);
	return CMD_SUCCESS;
}

DEFUN (debug_zebra_events,
       debug_zebra_events_cmd,
       "debug zebra events",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra events\n")
{
	zebra_debug_event = ZEBRA_DEBUG_EVENT;
	return CMD_SUCCESS;
}

DEFUN (debug_zebra_nht,
       debug_zebra_nht_cmd,
       "debug zebra nht",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra next hop tracking\n")
{
	zebra_debug_nht = ZEBRA_DEBUG_NHT;
	return CMD_SUCCESS;
}

DEFUN (debug_zebra_mpls,
       debug_zebra_mpls_cmd,
       "debug zebra mpls",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra MPLS LSPs\n")
{
	zebra_debug_mpls = ZEBRA_DEBUG_MPLS;
	return CMD_SUCCESS;
}

DEFUN (debug_zebra_vxlan,
       debug_zebra_vxlan_cmd,
       "debug zebra vxlan",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra VxLAN (EVPN)\n")
{
	zebra_debug_vxlan = ZEBRA_DEBUG_VXLAN;
	return CMD_SUCCESS;
}

DEFUN (debug_zebra_pw,
       debug_zebra_pw_cmd,
       "[no] debug zebra pseudowires",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra pseudowires\n")
{
	if (strmatch(argv[0]->text, "no"))
		UNSET_FLAG(zebra_debug_pw, ZEBRA_DEBUG_PW);
	else
		SET_FLAG(zebra_debug_pw, ZEBRA_DEBUG_PW);
	return CMD_SUCCESS;
}

DEFUN (debug_zebra_packet,
       debug_zebra_packet_cmd,
       "debug zebra packet [<recv|send>] [detail]",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n"
       "Debug option set for detailed info\n")
{
	int idx = 0;
	zebra_debug_packet = ZEBRA_DEBUG_PACKET;

	if (argv_find(argv, argc, "send", &idx))
		SET_FLAG(zebra_debug_packet, ZEBRA_DEBUG_SEND);
	else if (argv_find(argv, argc, "recv", &idx))
		SET_FLAG(zebra_debug_packet, ZEBRA_DEBUG_RECV);
	else {
		SET_FLAG(zebra_debug_packet, ZEBRA_DEBUG_SEND);
		SET_FLAG(zebra_debug_packet, ZEBRA_DEBUG_RECV);
	}

	if (argv_find(argv, argc, "detail", &idx))
		SET_FLAG(zebra_debug_packet, ZEBRA_DEBUG_DETAIL);

	return CMD_SUCCESS;
}

DEFUN (debug_zebra_kernel,
       debug_zebra_kernel_cmd,
       "debug zebra kernel",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra between kernel interface\n")
{
	SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL);

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV)
		UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);

	if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
		UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);

	return CMD_SUCCESS;
}

DEFUN (debug_zebra_kernel_msgdump,
       debug_zebra_kernel_msgdump_cmd,
       "debug zebra kernel msgdump [<recv|send>]",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra between kernel interface\n"
       "Dump raw netlink messages, sent and received\n"
       "Dump raw netlink messages received\n"
       "Dump raw netlink messages sent\n")
{
	int idx = 0;

	if (argv_find(argv, argc, "recv", &idx)) {
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);

		if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND)
			UNSET_FLAG(zebra_debug_kernel,
				   ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);

	} else if (argv_find(argv, argc, "send", &idx)) {
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);

		if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV)
			UNSET_FLAG(zebra_debug_kernel,
				   ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);

	} else {
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);
	}

	return CMD_SUCCESS;
}

DEFUN (debug_zebra_rib,
       debug_zebra_rib_cmd,
       "debug zebra rib [detailed]",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug RIB events\n"
       "Detailed debugs\n")
{
	int idx = 0;
	SET_FLAG(zebra_debug_rib, ZEBRA_DEBUG_RIB);

	if (argv_find(argv, argc, "detailed", &idx))
		SET_FLAG(zebra_debug_rib, ZEBRA_DEBUG_RIB_DETAILED);

	return CMD_SUCCESS;
}

DEFUN (debug_zebra_fpm,
       debug_zebra_fpm_cmd,
       "debug zebra fpm",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra FPM events\n")
{
	SET_FLAG(zebra_debug_fpm, ZEBRA_DEBUG_FPM);
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_events,
       no_debug_zebra_events_cmd,
       "no debug zebra events",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra events\n")
{
	zebra_debug_event = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_nht,
       no_debug_zebra_nht_cmd,
       "no debug zebra nht",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra next hop tracking\n")
{
	zebra_debug_nht = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_mpls,
       no_debug_zebra_mpls_cmd,
       "no debug zebra mpls",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra MPLS LSPs\n")
{
	zebra_debug_mpls = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_vxlan,
       no_debug_zebra_vxlan_cmd,
       "no debug zebra vxlan",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra VxLAN (EVPN)\n")
{
	zebra_debug_vxlan = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_packet,
       no_debug_zebra_packet_cmd,
       "no debug zebra packet [<recv|send>] [detail]",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n"
       "Debug option set for detailed info\n")
{
	zebra_debug_packet = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_kernel,
       no_debug_zebra_kernel_cmd,
       "no debug zebra kernel",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra between kernel interface\n")
{
	zebra_debug_kernel = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_kernel_msgdump,
       no_debug_zebra_kernel_msgdump_cmd,
       "no debug zebra kernel msgdump [<recv|send>]",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra between kernel interface\n"
       "Dump raw netlink messages, sent and received\n"
       "Dump raw netlink messages received\n"
       "Dump raw netlink messages sent\n")
{
	zebra_debug_kernel = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_rib,
       no_debug_zebra_rib_cmd,
       "no debug zebra rib [detailed]",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra RIB\n"
       "Detailed debugs\n")
{
	zebra_debug_rib = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_fpm,
       no_debug_zebra_fpm_cmd,
       "no debug zebra fpm",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra FPM events\n")
{
	zebra_debug_fpm = 0;
	return CMD_SUCCESS;
}

/* Debug node. */
struct cmd_node debug_node = {DEBUG_NODE, "", /* Debug node has no interface. */
			      1};

static int config_write_debug(struct vty *vty)
{
	int write = 0;

	if (IS_ZEBRA_DEBUG_EVENT) {
		vty_out(vty, "debug zebra events\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_PACKET) {
		if (IS_ZEBRA_DEBUG_SEND && IS_ZEBRA_DEBUG_RECV) {
			vty_out(vty, "debug zebra packet%s\n",
				IS_ZEBRA_DEBUG_DETAIL ? " detail" : "");
			write++;
		} else {
			if (IS_ZEBRA_DEBUG_SEND)
				vty_out(vty, "debug zebra packet send%s\n",
					IS_ZEBRA_DEBUG_DETAIL ? " detail" : "");
			else
				vty_out(vty, "debug zebra packet recv%s\n",
					IS_ZEBRA_DEBUG_DETAIL ? " detail" : "");
			write++;
		}
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND
		    && IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV) {
			vty_out(vty, "debug zebra kernel msgdump\n");
			write++;
		} else if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV) {
			vty_out(vty, "debug zebra kernel msgdump recv\n");
			write++;
		} else if (IS_ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND) {
			vty_out(vty, "debug zebra kernel msgdump send\n");
			write++;
		} else {
			vty_out(vty, "debug zebra kernel\n");
			write++;
		}
	}

	if (CHECK_FLAG(zebra_debug_rib, ZEBRA_DEBUG_RIB_DETAILED)) {
		vty_out(vty, "debug zebra rib detailed\n");
		write++;
	} else if (CHECK_FLAG(zebra_debug_rib, ZEBRA_DEBUG_RIB)) {
		vty_out(vty, "debug zebra rib\n");
		write++;
	}

	if (IS_ZEBRA_DEBUG_FPM) {
		vty_out(vty, "debug zebra fpm\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_NHT) {
		vty_out(vty, "debug zebra nht\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_MPLS) {
		vty_out(vty, "debug zebra mpls\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_VXLAN) {
		vty_out(vty, "debug zebra vxlan\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_PW) {
		vty_out(vty, "debug zebra pseudowires\n");
		write++;
	}
	return write;
}

void zebra_debug_init(void)
{
	zebra_debug_event = 0;
	zebra_debug_packet = 0;
	zebra_debug_kernel = 0;
	zebra_debug_rib = 0;
	zebra_debug_fpm = 0;
	zebra_debug_mpls = 0;
	zebra_debug_vxlan = 0;
	zebra_debug_pw = 0;

	install_node(&debug_node, config_write_debug);

	install_element(VIEW_NODE, &show_debugging_zebra_cmd);

	install_element(ENABLE_NODE, &debug_zebra_events_cmd);
	install_element(ENABLE_NODE, &debug_zebra_nht_cmd);
	install_element(ENABLE_NODE, &debug_zebra_mpls_cmd);
	install_element(ENABLE_NODE, &debug_zebra_vxlan_cmd);
	install_element(ENABLE_NODE, &debug_zebra_pw_cmd);
	install_element(ENABLE_NODE, &debug_zebra_packet_cmd);
	install_element(ENABLE_NODE, &debug_zebra_kernel_cmd);
	install_element(ENABLE_NODE, &debug_zebra_kernel_msgdump_cmd);
	install_element(ENABLE_NODE, &debug_zebra_rib_cmd);
	install_element(ENABLE_NODE, &debug_zebra_fpm_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_events_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_nht_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_mpls_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_vxlan_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_packet_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_kernel_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_kernel_msgdump_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_rib_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_fpm_cmd);

	install_element(CONFIG_NODE, &debug_zebra_events_cmd);
	install_element(CONFIG_NODE, &debug_zebra_nht_cmd);
	install_element(CONFIG_NODE, &debug_zebra_mpls_cmd);
	install_element(CONFIG_NODE, &debug_zebra_vxlan_cmd);
	install_element(CONFIG_NODE, &debug_zebra_pw_cmd);
	install_element(CONFIG_NODE, &debug_zebra_packet_cmd);
	install_element(CONFIG_NODE, &debug_zebra_kernel_cmd);
	install_element(CONFIG_NODE, &debug_zebra_kernel_msgdump_cmd);
	install_element(CONFIG_NODE, &debug_zebra_rib_cmd);
	install_element(CONFIG_NODE, &debug_zebra_fpm_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_events_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_nht_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_mpls_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_vxlan_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_packet_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_kernel_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_kernel_msgdump_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_rib_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_fpm_cmd);
}
