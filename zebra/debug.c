// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra debug related function
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>
#include "command.h"
#include "debug.h"
#include "mgmt_be_client.h"

#include "zebra/debug_clippy.c"

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
unsigned long zebra_debug_dplane;
unsigned long zebra_debug_dplane_dpdk;
unsigned long zebra_debug_mlag;
unsigned long zebra_debug_nexthop;
unsigned long zebra_debug_evpn_mh;
unsigned long zebra_debug_pbr;
unsigned long zebra_debug_neigh;
unsigned long zebra_debug_tc;
unsigned long zebra_debug_srv6;

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
	if (IS_ZEBRA_DEBUG_NHT_DETAILED)
		vty_out(vty, "  Zebra detailed next-hop tracking debugging is on\n");
	else if (IS_ZEBRA_DEBUG_NHT)
		vty_out(vty, "  Zebra next-hop tracking debugging is on\n");
	if (IS_ZEBRA_DEBUG_MPLS_DETAIL)
		vty_out(vty, "  Zebra detailed MPLS debugging is on\n");
	else if (IS_ZEBRA_DEBUG_MPLS)
		vty_out(vty, "  Zebra MPLS debugging is on\n");

	if (IS_ZEBRA_DEBUG_VXLAN)
		vty_out(vty, "  Zebra VXLAN debugging is on\n");
	if (IS_ZEBRA_DEBUG_PW)
		vty_out(vty, "  Zebra pseudowire debugging is on\n");
	if (IS_ZEBRA_DEBUG_DPLANE_DETAIL)
		vty_out(vty, "  Zebra detailed dataplane debugging is on\n");
	else if (IS_ZEBRA_DEBUG_DPLANE)
		vty_out(vty, "  Zebra dataplane debugging is on\n");
	if (IS_ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)
		vty_out(vty,
			"  Zebra detailed dpdk dataplane debugging is on\n");
	else if (IS_ZEBRA_DEBUG_DPLANE_DPDK)
		vty_out(vty, "  Zebra dataplane dpdk debugging is on\n");
	if (IS_ZEBRA_DEBUG_MLAG)
		vty_out(vty, "  Zebra mlag debugging is on\n");
	if (IS_ZEBRA_DEBUG_NHG_DETAIL)
		vty_out(vty, "  Zebra detailed nexthop debugging is on\n");
	else if (IS_ZEBRA_DEBUG_NHG)
		vty_out(vty, "  Zebra nexthop debugging is on\n");

	if (IS_ZEBRA_DEBUG_EVPN_MH_ES)
		vty_out(vty, "  Zebra EVPN-MH ethernet segment debugging is on\n");

	if (IS_ZEBRA_DEBUG_EVPN_MH_NH)
		vty_out(vty, "  Zebra EVPN-MH nexthop debugging is on\n");

	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC)
		vty_out(vty, "  Zebra EVPN-MH MAC debugging is on\n");

	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH)
		vty_out(vty, "  Zebra EVPN-MH Neigh debugging is on\n");

	if (IS_ZEBRA_DEBUG_PBR)
		vty_out(vty, "  Zebra PBR debugging is on\n");

	if (IS_ZEBRA_DEBUG_SRV6)
		vty_out(vty, "  Zebra SRv6 is on\n");

	hook_call(zebra_debug_show_debugging, vty);

	cmd_show_lib_debugs(vty);

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
       "debug zebra nht [detailed]",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra next hop tracking\n"
       "Debug option set for detailed info\n")
{
	int idx = 0;

	zebra_debug_nht = ZEBRA_DEBUG_NHT;

	if (argv_find(argv, argc, "detailed", &idx))
		zebra_debug_nht |= ZEBRA_DEBUG_NHT_DETAILED;

	return CMD_SUCCESS;
}

DEFPY (debug_zebra_mpls,
       debug_zebra_mpls_cmd,
       "debug zebra mpls [detailed$detail]",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra MPLS LSPs\n"
       "Debug option for detailed info\n")
{
	zebra_debug_mpls = ZEBRA_DEBUG_MPLS;

	if (detail)
		zebra_debug_mpls |= ZEBRA_DEBUG_MPLS_DETAILED;

	return CMD_SUCCESS;
}

DEFPY (debug_zebra_vxlan,
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

	return CMD_SUCCESS;
}

#if defined(HAVE_NETLINK)
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

	if (argv_find(argv, argc, "recv", &idx))
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);
	else if (argv_find(argv, argc, "send", &idx))
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);
	else {
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);
		SET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);
	}

	return CMD_SUCCESS;
}
#endif

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

DEFUN (debug_zebra_dplane,
       debug_zebra_dplane_cmd,
       "debug zebra dplane [detailed]",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra dataplane events\n"
       "Detailed debug information\n")
{
	int idx = 0;

	SET_FLAG(zebra_debug_dplane, ZEBRA_DEBUG_DPLANE);

	if (argv_find(argv, argc, "detailed", &idx))
		SET_FLAG(zebra_debug_dplane, ZEBRA_DEBUG_DPLANE_DETAILED);

	return CMD_SUCCESS;
}

DEFPY(debug_zebra_dplane_dpdk, debug_zebra_dplane_dpdk_cmd,
      "[no$no] debug zebra dplane dpdk [detailed$detail]",
      NO_STR DEBUG_STR
      "Zebra configuration\n"
      "Debug zebra dataplane events\n"
      "Debug zebra DPDK offload events\n"
      "Detailed debug information\n")
{
	if (no) {
		UNSET_FLAG(zebra_debug_dplane_dpdk, ZEBRA_DEBUG_DPLANE_DPDK);
		UNSET_FLAG(zebra_debug_dplane_dpdk,
			   ZEBRA_DEBUG_DPLANE_DPDK_DETAIL);
	} else {
		SET_FLAG(zebra_debug_dplane_dpdk, ZEBRA_DEBUG_DPLANE_DPDK);

		if (detail)
			SET_FLAG(zebra_debug_dplane_dpdk,
				 ZEBRA_DEBUG_DPLANE_DPDK_DETAIL);
	}

	return CMD_SUCCESS;
}

DEFUN (debug_zebra_pbr,
       debug_zebra_pbr_cmd,
       "debug zebra pbr",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra pbr events\n")
{
	SET_FLAG(zebra_debug_pbr, ZEBRA_DEBUG_PBR);
	return CMD_SUCCESS;
}

DEFPY (debug_zebra_neigh,
       debug_zebra_neigh_cmd,
       "[no$no] debug zebra neigh",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra neigh events\n")
{
	if (no)
		UNSET_FLAG(zebra_debug_neigh, ZEBRA_DEBUG_NEIGH);
	else
		SET_FLAG(zebra_debug_neigh, ZEBRA_DEBUG_NEIGH);

	return CMD_SUCCESS;
}

DEFUN (debug_zebra_tc,
       debug_zebra_tc_cmd,
       "debug zebra tc",
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra tc events\n")
{
	SET_FLAG(zebra_debug_tc, ZEBRA_DEBUG_TC);
	return CMD_SUCCESS;
}

DEFPY(debug_zebra_srv6,
      debug_zebra_srv6_cmd,
      "[no$no] debug zebra srv6",
      NO_STR
      DEBUG_STR
      "Zebra configuration\n"
      "Debug zebra SRv6 events\n")
{
	if (no)
		UNSET_FLAG(zebra_debug_srv6, ZEBRA_DEBUG_SRV6);
	else
		SET_FLAG(zebra_debug_srv6, ZEBRA_DEBUG_SRV6);
	return CMD_SUCCESS;
}

DEFPY (debug_zebra_mlag,
       debug_zebra_mlag_cmd,
       "[no$no] debug zebra mlag",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for mlag events\n")
{
	if (no)
		UNSET_FLAG(zebra_debug_mlag, ZEBRA_DEBUG_MLAG);
	else
		SET_FLAG(zebra_debug_mlag, ZEBRA_DEBUG_MLAG);
	return CMD_SUCCESS;
}

DEFPY (debug_zebra_evpn_mh,
       debug_zebra_evpn_mh_cmd,
       "[no$no] debug zebra evpn mh <es$es|mac$mac|neigh$neigh|nh$nh>",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "EVPN\n"
       "Multihoming\n"
       "Ethernet Segment Debugging\n"
       "MAC Debugging\n"
       "Neigh Debugging\n"
       "Nexthop Debugging\n")
{
	if (es) {
		if (no)
			UNSET_FLAG(zebra_debug_evpn_mh, ZEBRA_DEBUG_EVPN_MH_ES);
		else
			SET_FLAG(zebra_debug_evpn_mh, ZEBRA_DEBUG_EVPN_MH_ES);
	}

	if (mac) {
		if (no)
			UNSET_FLAG(zebra_debug_evpn_mh,
					ZEBRA_DEBUG_EVPN_MH_MAC);
		else
			SET_FLAG(zebra_debug_evpn_mh, ZEBRA_DEBUG_EVPN_MH_MAC);
	}

	if (neigh) {
		if (no)
			UNSET_FLAG(zebra_debug_evpn_mh,
					ZEBRA_DEBUG_EVPN_MH_NEIGH);
		else
			SET_FLAG(zebra_debug_evpn_mh,
					ZEBRA_DEBUG_EVPN_MH_NEIGH);
	}

	if (nh) {
		if (no)
			UNSET_FLAG(zebra_debug_evpn_mh, ZEBRA_DEBUG_EVPN_MH_NH);
		else
			SET_FLAG(zebra_debug_evpn_mh, ZEBRA_DEBUG_EVPN_MH_NH);
	}

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
       "no debug zebra nht [detailed]",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra next hop tracking\n"
       "Debug option set for detailed info\n")
{
	zebra_debug_nht = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_mpls,
       no_debug_zebra_mpls_cmd,
       "no debug zebra mpls [detailed]",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug option set for zebra MPLS LSPs\n"
       "Debug option for zebra detailed info\n")
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
	UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL);

	return CMD_SUCCESS;
}

#if defined(HAVE_NETLINK)
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
	int idx = 0;

	if (argv_find(argv, argc, "recv", &idx))
		UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);
	else if (argv_find(argv, argc, "send", &idx))
		UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);
	else {
		UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_RECV);
		UNSET_FLAG(zebra_debug_kernel, ZEBRA_DEBUG_KERNEL_MSGDUMP_SEND);
	}

	return CMD_SUCCESS;
}
#endif

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

DEFUN (no_debug_zebra_dplane,
       no_debug_zebra_dplane_cmd,
       "no debug zebra dplane",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra dataplane events\n")
{
	zebra_debug_dplane = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_zebra_pbr,
       no_debug_zebra_pbr_cmd,
       "no debug zebra pbr",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra pbr events\n")
{
	zebra_debug_pbr = 0;
	return CMD_SUCCESS;
}

DEFPY (debug_zebra_nexthop,
       debug_zebra_nexthop_cmd,
       "[no$no] debug zebra nexthop [detail$detail]",
       NO_STR
       DEBUG_STR
       "Zebra configuration\n"
       "Debug zebra nexthop events\n"
       "Detailed information\n")
{
	if (no)
		zebra_debug_nexthop = 0;
	else {
		SET_FLAG(zebra_debug_nexthop, ZEBRA_DEBUG_NHG);

		if (detail)
			SET_FLAG(zebra_debug_nexthop,
				 ZEBRA_DEBUG_NHG_DETAILED);
	}

	return CMD_SUCCESS;
}

/* Debug node. */
static int config_write_debug(struct vty *vty);
struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_debug,
};

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
	}

	if (IS_ZEBRA_DEBUG_KERNEL) {
		vty_out(vty, "debug zebra kernel\n");
		write++;
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

	if (IS_ZEBRA_DEBUG_NHT_DETAILED) {
		vty_out(vty, "debug zebra nht detailed\n");
		write++;
	} else if (IS_ZEBRA_DEBUG_NHT) {
		vty_out(vty, "debug zebra nht\n");
		write++;
	}

	if (IS_ZEBRA_DEBUG_MPLS_DETAIL) {
		vty_out(vty, "debug zebra mpls detailed\n");
		write++;
	} else if (IS_ZEBRA_DEBUG_MPLS) {
		vty_out(vty, "debug zebra mpls\n");
		write++;
	}

	if (IS_ZEBRA_DEBUG_VXLAN) {
		vty_out(vty, "debug zebra vxlan\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_MLAG) {
		vty_out(vty, "debug zebra mlag\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_EVPN_MH_ES) {
		vty_out(vty, "debug zebra evpn mh es\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_EVPN_MH_NH) {
		vty_out(vty, "debug zebra evpn mh nh\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_EVPN_MH_MAC) {
		vty_out(vty, "debug zebra evpn mh mac\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_EVPN_MH_NEIGH) {
		vty_out(vty, "debug zebra evpn mh neigh\n");
		write++;
	}
	if (IS_ZEBRA_DEBUG_PW) {
		vty_out(vty, "debug zebra pseudowires\n");
		write++;
	}

	if (CHECK_FLAG(zebra_debug_dplane, ZEBRA_DEBUG_DPLANE_DETAILED)) {
		vty_out(vty, "debug zebra dplane detailed\n");
		write++;
	} else if (CHECK_FLAG(zebra_debug_dplane, ZEBRA_DEBUG_DPLANE)) {
		vty_out(vty, "debug zebra dplane\n");
		write++;
	}

	if (CHECK_FLAG(zebra_debug_dplane_dpdk,
		       ZEBRA_DEBUG_DPLANE_DPDK_DETAIL)) {
		vty_out(vty, "debug zebra dplane dpdk detailed\n");
		write++;
	} else if (CHECK_FLAG(zebra_debug_dplane_dpdk,
			      ZEBRA_DEBUG_DPLANE_DPDK)) {
		vty_out(vty, "debug zebra dplane dpdk\n");
		write++;
	}

	if (CHECK_FLAG(zebra_debug_nexthop, ZEBRA_DEBUG_NHG_DETAILED)) {
		vty_out(vty, "debug zebra nexthop detail\n");
		write++;
	} else if (CHECK_FLAG(zebra_debug_nexthop, ZEBRA_DEBUG_NHG)) {
		vty_out(vty, "debug zebra nexthop\n");
		write++;
	}

	if (IS_ZEBRA_DEBUG_PBR) {
		vty_out(vty, "debug zebra pbr\n");
		write++;
	}

	if (IS_ZEBRA_DEBUG_NEIGH) {
		vty_out(vty, "debug zebra neigh\n");
		write++;
	}

	if (IS_ZEBRA_DEBUG_SRV6) {
		vty_out(vty, "debug zebra srv6\n");
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
	zebra_debug_dplane = 0;
	zebra_debug_dplane_dpdk = 0;
	zebra_debug_mlag = 0;
	zebra_debug_evpn_mh = 0;
	zebra_debug_nht = 0;
	zebra_debug_nexthop = 0;
	zebra_debug_pbr = 0;
	zebra_debug_neigh = 0;

	install_node(&debug_node);

	install_element(ENABLE_NODE, &show_debugging_zebra_cmd);

	install_element(ENABLE_NODE, &debug_zebra_events_cmd);
	install_element(ENABLE_NODE, &debug_zebra_nht_cmd);
	install_element(ENABLE_NODE, &debug_zebra_mpls_cmd);
	install_element(ENABLE_NODE, &debug_zebra_vxlan_cmd);
	install_element(ENABLE_NODE, &debug_zebra_pw_cmd);
	install_element(ENABLE_NODE, &debug_zebra_packet_cmd);
	install_element(ENABLE_NODE, &debug_zebra_kernel_cmd);
#if defined(HAVE_NETLINK)
	install_element(ENABLE_NODE, &debug_zebra_kernel_msgdump_cmd);
#endif
	install_element(ENABLE_NODE, &debug_zebra_rib_cmd);
	install_element(ENABLE_NODE, &debug_zebra_fpm_cmd);
	install_element(ENABLE_NODE, &debug_zebra_dplane_cmd);
	install_element(ENABLE_NODE, &debug_zebra_srv6_cmd);
	install_element(ENABLE_NODE, &debug_zebra_mlag_cmd);
	install_element(ENABLE_NODE, &debug_zebra_nexthop_cmd);
	install_element(ENABLE_NODE, &debug_zebra_pbr_cmd);
	install_element(ENABLE_NODE, &debug_zebra_neigh_cmd);
	install_element(ENABLE_NODE, &debug_zebra_tc_cmd);
	install_element(ENABLE_NODE, &debug_zebra_dplane_dpdk_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_events_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_nht_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_mpls_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_vxlan_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_packet_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_kernel_cmd);
#if defined(HAVE_NETLINK)
	install_element(ENABLE_NODE, &no_debug_zebra_kernel_msgdump_cmd);
#endif
	install_element(ENABLE_NODE, &no_debug_zebra_rib_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_fpm_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_dplane_cmd);
	install_element(ENABLE_NODE, &no_debug_zebra_pbr_cmd);
	install_element(ENABLE_NODE, &debug_zebra_evpn_mh_cmd);

	install_element(CONFIG_NODE, &debug_zebra_events_cmd);
	install_element(CONFIG_NODE, &debug_zebra_nht_cmd);
	install_element(CONFIG_NODE, &debug_zebra_mpls_cmd);
	install_element(CONFIG_NODE, &debug_zebra_vxlan_cmd);
	install_element(CONFIG_NODE, &debug_zebra_pw_cmd);
	install_element(CONFIG_NODE, &debug_zebra_packet_cmd);
	install_element(CONFIG_NODE, &debug_zebra_kernel_cmd);
#if defined(HAVE_NETLINK)
	install_element(CONFIG_NODE, &debug_zebra_kernel_msgdump_cmd);
#endif
	install_element(CONFIG_NODE, &debug_zebra_rib_cmd);
	install_element(CONFIG_NODE, &debug_zebra_fpm_cmd);
	install_element(CONFIG_NODE, &debug_zebra_dplane_cmd);
	install_element(CONFIG_NODE, &debug_zebra_dplane_dpdk_cmd);
	install_element(CONFIG_NODE, &debug_zebra_nexthop_cmd);
	install_element(CONFIG_NODE, &debug_zebra_pbr_cmd);
	install_element(CONFIG_NODE, &debug_zebra_neigh_cmd);

	install_element(CONFIG_NODE, &no_debug_zebra_events_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_nht_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_mpls_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_vxlan_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_packet_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_kernel_cmd);
#if defined(HAVE_NETLINK)
	install_element(CONFIG_NODE, &no_debug_zebra_kernel_msgdump_cmd);
#endif
	install_element(CONFIG_NODE, &no_debug_zebra_rib_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_fpm_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_dplane_cmd);
	install_element(CONFIG_NODE, &no_debug_zebra_pbr_cmd);
	install_element(CONFIG_NODE, &debug_zebra_srv6_cmd);
	install_element(CONFIG_NODE, &debug_zebra_mlag_cmd);
	install_element(CONFIG_NODE, &debug_zebra_evpn_mh_cmd);

	/* Init mgmtd backend client debug commands. */
	mgmt_be_client_lib_vty_init();
}
