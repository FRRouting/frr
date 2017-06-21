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
ldp_vty_debug(struct vty *vty, int disable, const char *type_str,
    const char *dir_str, int all)
{
	if (strcmp(type_str, "discovery") == 0) {
		if (dir_str == NULL)
			return (CMD_WARNING);

		if (dir_str[0] == 'r') {
			if (disable)
				DEBUG_OFF(hello, HELLO_RECV);
			else
				DEBUG_ON(hello, HELLO_RECV);
		} else {
			if (disable)
				DEBUG_OFF(hello, HELLO_SEND);
			else
				DEBUG_ON(hello, HELLO_SEND);
		}
	} else if (strcmp(type_str, "errors") == 0) {
		if (disable)
			DEBUG_OFF(errors, ERRORS);
		else
			DEBUG_ON(errors, ERRORS);
	} else if (strcmp(type_str, "event") == 0) {
		if (disable)
			DEBUG_OFF(event, EVENT);
		else
			DEBUG_ON(event, EVENT);
	} else if (strcmp(type_str, "messages") == 0) {
		if (dir_str == NULL)
			return (CMD_WARNING);

		if (dir_str[0] == 'r') {
			if (disable) {
				DEBUG_OFF(msg, MSG_RECV);
				DEBUG_OFF(msg, MSG_RECV_ALL);
			} else {
				DEBUG_ON(msg, MSG_RECV);
				if (all)
					DEBUG_ON(msg, MSG_RECV_ALL);
			}
		} else {
			if (disable) {
				DEBUG_OFF(msg, MSG_SEND);
				DEBUG_OFF(msg, MSG_SEND_ALL);
			} else {
				DEBUG_ON(msg, MSG_SEND);
				if (all)
					DEBUG_ON(msg, MSG_SEND_ALL);
			}
		}
	} else if (strcmp(type_str, "zebra") == 0) {
		if (disable)
			DEBUG_OFF(zebra, ZEBRA);
		else
			DEBUG_ON(zebra, ZEBRA);
	}

	main_imsg_compose_both(IMSG_DEBUG_UPDATE, &ldp_debug,
	    sizeof(ldp_debug));

	return (CMD_SUCCESS);
}

int
ldp_vty_show_debugging(struct vty *vty)
{
	vty_outln (vty, "LDP debugging status:");

	if (LDP_DEBUG(hello, HELLO_RECV))
		vty_outln (vty,"  LDP discovery debugging is on (inbound)");
	if (LDP_DEBUG(hello, HELLO_SEND))
		vty_outln (vty,"  LDP discovery debugging is on (outbound)");
	if (LDP_DEBUG(errors, ERRORS))
		vty_outln (vty, "  LDP errors debugging is on");
	if (LDP_DEBUG(event, EVENT))
		vty_outln (vty, "  LDP events debugging is on");
	if (LDP_DEBUG(msg, MSG_RECV_ALL))
		vty_outln (vty,
			  "  LDP detailed messages debugging is on " "(inbound)");
	else if (LDP_DEBUG(msg, MSG_RECV))
		vty_outln (vty,"  LDP messages debugging is on (inbound)");
	if (LDP_DEBUG(msg, MSG_SEND_ALL))
		vty_outln (vty,
			  "  LDP detailed messages debugging is on " "(outbound)");
	else if (LDP_DEBUG(msg, MSG_SEND))
		vty_outln (vty,"  LDP messages debugging is on (outbound)");
	if (LDP_DEBUG(zebra, ZEBRA))
		vty_outln (vty, "  LDP zebra debugging is on");
	vty_outln (vty, "");

	return (CMD_SUCCESS);
}

int
ldp_debug_config_write(struct vty *vty)
{
	int write = 0;

	if (CONF_LDP_DEBUG(hello, HELLO_RECV)) {
		vty_outln (vty,"debug mpls ldp discovery hello recv");
		write = 1;
	}

	if (CONF_LDP_DEBUG(hello, HELLO_SEND)) {
		vty_outln (vty,"debug mpls ldp discovery hello sent");
		write = 1;
	}

	if (CONF_LDP_DEBUG(errors, ERRORS)) {
		vty_outln (vty, "debug mpls ldp errors");
		write = 1;
	}

	if (CONF_LDP_DEBUG(event, EVENT)) {
		vty_outln (vty, "debug mpls ldp event");
		write = 1;
	}

	if (CONF_LDP_DEBUG(msg, MSG_RECV_ALL)) {
		vty_outln (vty, "debug mpls ldp messages recv all");
		write = 1;
	} else if (CONF_LDP_DEBUG(msg, MSG_RECV)) {
		vty_outln (vty, "debug mpls ldp messages recv");
		write = 1;
	}

	if (CONF_LDP_DEBUG(msg, MSG_SEND_ALL)) {
		vty_outln (vty, "debug mpls ldp messages sent all");
		write = 1;
	} else if (CONF_LDP_DEBUG(msg, MSG_SEND)) {
		vty_outln (vty, "debug mpls ldp messages sent");
		write = 1;
	}

	if (CONF_LDP_DEBUG(zebra, ZEBRA)) {
		vty_outln (vty, "debug mpls ldp zebra");
		write = 1;
	}

	return (write);
}
