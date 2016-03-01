/*
 * Copyright (C) 2016 by Open Source Routing.
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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
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
ldp_vty_debug(struct vty *vty, struct vty_arg *args[])
{
 	const char		*type_str, *dir_str;
	int			 disable, all;

	disable = (vty_get_arg_value(args, "no")) ? 1 : 0;
	type_str = vty_get_arg_value(args, "type");

	if (strcmp(type_str, "discovery") == 0) {
		dir_str = vty_get_arg_value(args, "dir");
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
	} else 	if (strcmp(type_str, "messages") == 0) {
		all = (vty_get_arg_value(args, "all")) ? 1 : 0;
		dir_str = vty_get_arg_value(args, "dir");
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
	} else 	if (strcmp(type_str, "zebra") == 0) {
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
ldp_vty_show_debugging(struct vty *vty, struct vty_arg *args[])
{
	vty_out(vty, "LDP debugging status:%s", VTY_NEWLINE);

	if (LDP_DEBUG(hello, HELLO_RECV))
		vty_out(vty, "  LDP discovery debugging is on (inbound)%s",
		    VTY_NEWLINE);
	if (LDP_DEBUG(hello, HELLO_SEND))
		vty_out(vty, "  LDP discovery debugging is on (outbound)%s",
		    VTY_NEWLINE);
	if (LDP_DEBUG(errors, ERRORS))
		vty_out(vty, "  LDP errors debugging is on%s", VTY_NEWLINE);
	if (LDP_DEBUG(event, EVENT))
		vty_out(vty, "  LDP events debugging is on%s", VTY_NEWLINE);
	if (LDP_DEBUG(msg, MSG_RECV_ALL))
		vty_out(vty, "  LDP detailed messages debugging is on "
		    "(inbound)%s", VTY_NEWLINE);
	else if (LDP_DEBUG(msg, MSG_RECV))
		vty_out(vty, "  LDP messages debugging is on (inbound)%s",
		    VTY_NEWLINE);
	if (LDP_DEBUG(msg, MSG_SEND_ALL))
		vty_out(vty, "  LDP detailed messages debugging is on "
		    "(outbound)%s", VTY_NEWLINE);
	else if (LDP_DEBUG(msg, MSG_SEND))
		vty_out(vty, "  LDP messages debugging is on (outbound)%s",
		    VTY_NEWLINE);
	if (LDP_DEBUG(zebra, ZEBRA))
		vty_out(vty, "  LDP zebra debugging is on%s", VTY_NEWLINE);
	vty_out (vty, "%s", VTY_NEWLINE);

	return (CMD_SUCCESS);
}

int
ldp_debug_config_write(struct vty *vty)
{
	int write = 0;

	if (CONF_LDP_DEBUG(hello, HELLO_RECV)) {
		vty_out(vty, "debug mpls ldp discovery hello recv%s",
		    VTY_NEWLINE);
		write = 1;
	}

	if (CONF_LDP_DEBUG(hello, HELLO_SEND)) {
		vty_out(vty, "debug mpls ldp discovery hello sent%s",
		    VTY_NEWLINE);
		write = 1;
	}

	if (CONF_LDP_DEBUG(errors, ERRORS)) {
		vty_out(vty, "debug mpls ldp errors%s", VTY_NEWLINE);
		write = 1;
	}

	if (CONF_LDP_DEBUG(event, EVENT)) {
		vty_out(vty, "debug mpls ldp event%s", VTY_NEWLINE);
		write = 1;
	}

	if (CONF_LDP_DEBUG(msg, MSG_RECV_ALL)) {
		vty_out(vty, "debug mpls ldp messages recv all%s", VTY_NEWLINE);
		write = 1;
	} else if (CONF_LDP_DEBUG(msg, MSG_RECV)) {
		vty_out(vty, "debug mpls ldp messages recv%s", VTY_NEWLINE);
		write = 1;
	}

	if (CONF_LDP_DEBUG(msg, MSG_SEND_ALL)) {
		vty_out(vty, "debug mpls ldp messages sent all%s", VTY_NEWLINE);
		write = 1;
	} else if (CONF_LDP_DEBUG(msg, MSG_SEND)) {
		vty_out(vty, "debug mpls ldp messages sent%s", VTY_NEWLINE);
		write = 1;
	}

	if (CONF_LDP_DEBUG(zebra, ZEBRA)) {
		vty_out(vty, "debug mpls ldp zebra%s", VTY_NEWLINE);
		write = 1;
	}

	return (write);
}
