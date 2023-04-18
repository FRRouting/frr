// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIPng debug output routines
 * Copyright (C) 1998 Kunihiro Ishiguro
 */

#include <zebra.h>
#include "command.h"
#include "ripngd/ripng_debug.h"

/* For debug statement. */
unsigned long ripng_debug_event = 0;
unsigned long ripng_debug_packet = 0;
unsigned long ripng_debug_zebra = 0;

DEFUN_NOSH (show_debugging_ripng,
	    show_debugging_ripng_cmd,
	    "show debugging [ripng]",
	    SHOW_STR
	    DEBUG_STR
	    "RIPng configuration\n")
{
	vty_out(vty, "RIPng debugging status:\n");

	if (IS_RIPNG_DEBUG_EVENT)
		vty_out(vty, "  RIPng event debugging is on\n");

	if (IS_RIPNG_DEBUG_PACKET) {
		if (IS_RIPNG_DEBUG_SEND && IS_RIPNG_DEBUG_RECV) {
			vty_out(vty, "  RIPng packet debugging is on\n");
		} else {
			if (IS_RIPNG_DEBUG_SEND)
				vty_out(vty,
					"  RIPng packet send debugging is on\n");
			else
				vty_out(vty,
					"  RIPng packet receive debugging is on\n");
		}
	}

	if (IS_RIPNG_DEBUG_ZEBRA)
		vty_out(vty, "  RIPng zebra debugging is on\n");

	cmd_show_lib_debugs(vty);

	return CMD_SUCCESS;
}

DEFUN (debug_ripng_events,
       debug_ripng_events_cmd,
       "debug ripng events",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng events\n")
{
	ripng_debug_event = RIPNG_DEBUG_EVENT;
	return CMD_SUCCESS;
}

DEFUN (debug_ripng_packet,
       debug_ripng_packet_cmd,
       "debug ripng packet",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n")
{
	ripng_debug_packet = RIPNG_DEBUG_PACKET;
	ripng_debug_packet |= RIPNG_DEBUG_SEND;
	ripng_debug_packet |= RIPNG_DEBUG_RECV;
	return CMD_SUCCESS;
}

DEFUN (debug_ripng_packet_direct,
       debug_ripng_packet_direct_cmd,
       "debug ripng packet <recv|send>",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")
{
	int idx_recv_send = 3;
	ripng_debug_packet |= RIPNG_DEBUG_PACKET;
	if (strcmp("send", argv[idx_recv_send]->text) == 0)
		ripng_debug_packet |= RIPNG_DEBUG_SEND;
	if (strcmp("recv", argv[idx_recv_send]->text) == 0)
		ripng_debug_packet |= RIPNG_DEBUG_RECV;

	return CMD_SUCCESS;
}

DEFUN (debug_ripng_zebra,
       debug_ripng_zebra_cmd,
       "debug ripng zebra",
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng and zebra communication\n")
{
	ripng_debug_zebra = RIPNG_DEBUG_ZEBRA;
	return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_events,
       no_debug_ripng_events_cmd,
       "no debug ripng events",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng events\n")
{
	ripng_debug_event = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_packet,
       no_debug_ripng_packet_cmd,
       "no debug ripng packet",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n")
{
	ripng_debug_packet = 0;
	return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_packet_direct,
       no_debug_ripng_packet_direct_cmd,
       "no debug ripng packet <recv|send>",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng packet\n"
       "Debug option set for receive packet\n"
       "Debug option set for send packet\n")
{
	int idx_recv_send = 4;
	if (strcmp("send", argv[idx_recv_send]->text) == 0) {
		if (IS_RIPNG_DEBUG_RECV)
			ripng_debug_packet &= ~RIPNG_DEBUG_SEND;
		else
			ripng_debug_packet = 0;
	} else if (strcmp("recv", argv[idx_recv_send]->text) == 0) {
		if (IS_RIPNG_DEBUG_SEND)
			ripng_debug_packet &= ~RIPNG_DEBUG_RECV;
		else
			ripng_debug_packet = 0;
	}
	return CMD_SUCCESS;
}

DEFUN (no_debug_ripng_zebra,
       no_debug_ripng_zebra_cmd,
       "no debug ripng zebra",
       NO_STR
       DEBUG_STR
       "RIPng configuration\n"
       "Debug option set for ripng and zebra communication\n")
{
	ripng_debug_zebra = 0;
	return CMD_SUCCESS;
}

static int config_write_debug(struct vty *vty);
/* Debug node. */
static struct cmd_node debug_node = {
	.name = "debug",
	.node = DEBUG_NODE,
	.prompt = "",
	.config_write = config_write_debug,
};

static int config_write_debug(struct vty *vty)
{
	int write = 0;

	if (IS_RIPNG_DEBUG_EVENT) {
		vty_out(vty, "debug ripng events\n");
		write++;
	}
	if (IS_RIPNG_DEBUG_PACKET) {
		if (IS_RIPNG_DEBUG_SEND && IS_RIPNG_DEBUG_RECV) {
			vty_out(vty, "debug ripng packet\n");
			write++;
		} else {
			if (IS_RIPNG_DEBUG_SEND)
				vty_out(vty, "debug ripng packet send\n");
			else
				vty_out(vty, "debug ripng packet recv\n");
			write++;
		}
	}
	if (IS_RIPNG_DEBUG_ZEBRA) {
		vty_out(vty, "debug ripng zebra\n");
		write++;
	}
	return write;
}

void ripng_debug_init(void)
{
	ripng_debug_event = 0;
	ripng_debug_packet = 0;
	ripng_debug_zebra = 0;

	install_node(&debug_node);

	install_element(ENABLE_NODE, &show_debugging_ripng_cmd);

	install_element(ENABLE_NODE, &debug_ripng_events_cmd);
	install_element(ENABLE_NODE, &debug_ripng_packet_cmd);
	install_element(ENABLE_NODE, &debug_ripng_packet_direct_cmd);
	install_element(ENABLE_NODE, &debug_ripng_zebra_cmd);
	install_element(ENABLE_NODE, &no_debug_ripng_events_cmd);
	install_element(ENABLE_NODE, &no_debug_ripng_packet_cmd);
	install_element(ENABLE_NODE, &no_debug_ripng_packet_direct_cmd);
	install_element(ENABLE_NODE, &no_debug_ripng_zebra_cmd);

	install_element(CONFIG_NODE, &debug_ripng_events_cmd);
	install_element(CONFIG_NODE, &debug_ripng_packet_cmd);
	install_element(CONFIG_NODE, &debug_ripng_packet_direct_cmd);
	install_element(CONFIG_NODE, &debug_ripng_zebra_cmd);
	install_element(CONFIG_NODE, &no_debug_ripng_events_cmd);
	install_element(CONFIG_NODE, &no_debug_ripng_packet_cmd);
	install_element(CONFIG_NODE, &no_debug_ripng_packet_direct_cmd);
	install_element(CONFIG_NODE, &no_debug_ripng_zebra_cmd);
}
