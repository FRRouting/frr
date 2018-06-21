/*
 * Copyright (C) 2016 by Open Source Routing.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "vty.h"

#include "ldpd.h"
#include "ldp_debug.h"
#include "ldp_vty.h"

struct ldp_debug conf_ldp_debug;
struct ldp_debug ldp_debug;

/* Debug node. */
struct cmd_node ldp_debug_node =
{
	DEBUG_NODE,
	"",
	1
};

int
ldp_vty_debug(struct vty *vty, const char *negate, const char *type_str,
    const char *dir_str, const char *all)
{
	if (type_str == NULL)
		return (CMD_WARNING_CONFIG_FAILED);

	if (strcmp(type_str, "discovery") == 0) {
		if (dir_str == NULL)
			return (CMD_WARNING_CONFIG_FAILED);

		if (dir_str[0] == 'r') {
			if (negate)
				DEBUG_OFF(hello, LDP_DEBUG_HELLO_RECV);
			else
				DEBUG_ON(hello, LDP_DEBUG_HELLO_RECV);
		} else {
			if (negate)
				DEBUG_OFF(hello, LDP_DEBUG_HELLO_SEND);
			else
				DEBUG_ON(hello, LDP_DEBUG_HELLO_SEND);
		}
	} else if (strcmp(type_str, "errors") == 0) {
		if (negate)
			DEBUG_OFF(errors, LDP_DEBUG_ERRORS);
		else
			DEBUG_ON(errors, LDP_DEBUG_ERRORS);
	} else if (strcmp(type_str, "event") == 0) {
		if (negate)
			DEBUG_OFF(event, LDP_DEBUG_EVENT);
		else
			DEBUG_ON(event, LDP_DEBUG_EVENT);
	} else if (strcmp(type_str, "labels") == 0) {
		if (negate)
			DEBUG_OFF(labels, LDP_DEBUG_LABELS);
		else
			DEBUG_ON(labels, LDP_DEBUG_LABELS);
	} else if (strcmp(type_str, "messages") == 0) {
		if (dir_str == NULL)
			return (CMD_WARNING_CONFIG_FAILED);

		if (dir_str[0] == 'r') {
			if (negate) {
				DEBUG_OFF(msg, LDP_DEBUG_MSG_RECV);
				DEBUG_OFF(msg, LDP_DEBUG_MSG_RECV_ALL);
			} else {
				DEBUG_ON(msg, LDP_DEBUG_MSG_RECV);
				if (all)
					DEBUG_ON(msg, LDP_DEBUG_MSG_RECV_ALL);
			}
		} else {
			if (negate) {
				DEBUG_OFF(msg, LDP_DEBUG_MSG_SEND);
				DEBUG_OFF(msg, LDP_DEBUG_MSG_SEND_ALL);
			} else {
				DEBUG_ON(msg, LDP_DEBUG_MSG_SEND);
				if (all)
					DEBUG_ON(msg, LDP_DEBUG_MSG_SEND_ALL);
			}
		}
	} else if (strcmp(type_str, "zebra") == 0) {
		if (negate)
			DEBUG_OFF(zebra, LDP_DEBUG_ZEBRA);
		else
			DEBUG_ON(zebra, LDP_DEBUG_ZEBRA);
	}

	main_imsg_compose_both(IMSG_DEBUG_UPDATE, &ldp_debug,
	    sizeof(ldp_debug));

	return (CMD_SUCCESS);
}

int
ldp_vty_show_debugging(struct vty *vty)
{
	vty_out (vty, "LDP debugging status:\n");

	if (LDP_DEBUG(hello, LDP_DEBUG_HELLO_RECV))
		vty_out (vty,"  LDP discovery debugging is on (inbound)\n");
	if (LDP_DEBUG(hello, LDP_DEBUG_HELLO_SEND))
		vty_out (vty,"  LDP discovery debugging is on (outbound)\n");
	if (LDP_DEBUG(errors, LDP_DEBUG_ERRORS))
		vty_out (vty, "  LDP errors debugging is on\n");
	if (LDP_DEBUG(event, LDP_DEBUG_EVENT))
		vty_out (vty, "  LDP events debugging is on\n");
	if (LDP_DEBUG(labels, LDP_DEBUG_LABELS))
		vty_out (vty, "  LDP labels debugging is on\n");
	if (LDP_DEBUG(msg, LDP_DEBUG_MSG_RECV_ALL))
		vty_out (vty,
			  "  LDP detailed messages debugging is on (inbound)\n");
	else if (LDP_DEBUG(msg, LDP_DEBUG_MSG_RECV))
		vty_out (vty,"  LDP messages debugging is on (inbound)\n");
	if (LDP_DEBUG(msg, LDP_DEBUG_MSG_SEND_ALL))
		vty_out (vty,
			  "  LDP detailed messages debugging is on (outbound)\n");
	else if (LDP_DEBUG(msg, LDP_DEBUG_MSG_SEND))
		vty_out (vty,"  LDP messages debugging is on (outbound)\n");
	if (LDP_DEBUG(zebra, LDP_DEBUG_ZEBRA))
		vty_out (vty, "  LDP zebra debugging is on\n");
	vty_out (vty, "\n");

	return (CMD_SUCCESS);
}

int
ldp_debug_config_write(struct vty *vty)
{
	int write = 0;

	if (CONF_LDP_DEBUG(hello, LDP_DEBUG_HELLO_RECV)) {
		vty_out (vty,"debug mpls ldp discovery hello recv\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(hello, LDP_DEBUG_HELLO_SEND)) {
		vty_out (vty,"debug mpls ldp discovery hello sent\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(errors, LDP_DEBUG_ERRORS)) {
		vty_out (vty, "debug mpls ldp errors\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(event, LDP_DEBUG_EVENT)) {
		vty_out (vty, "debug mpls ldp event\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(labels, LDP_DEBUG_LABELS)) {
		vty_out (vty, "debug mpls ldp labels\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(msg, LDP_DEBUG_MSG_RECV_ALL)) {
		vty_out (vty, "debug mpls ldp messages recv all\n");
		write = 1;
	} else if (CONF_LDP_DEBUG(msg, LDP_DEBUG_MSG_RECV)) {
		vty_out (vty, "debug mpls ldp messages recv\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(msg, LDP_DEBUG_MSG_SEND_ALL)) {
		vty_out (vty, "debug mpls ldp messages sent all\n");
		write = 1;
	} else if (CONF_LDP_DEBUG(msg, LDP_DEBUG_MSG_SEND)) {
		vty_out (vty, "debug mpls ldp messages sent\n");
		write = 1;
	}

	if (CONF_LDP_DEBUG(zebra, LDP_DEBUG_ZEBRA)) {
		vty_out (vty, "debug mpls ldp zebra\n");
		write = 1;
	}

	return (write);
}
