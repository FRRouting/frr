/*
 * Copyright (C) 2018  NetDEF, Inc.
 *                     Renato Westphal
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

#include "if.h"
#include "vrf.h"
#include "log.h"
#include "prefix.h"
#include "table.h"
#include "command.h"
#include "routemap.h"
#include "northbound.h"
#include "libfrr.h"

#include "ripd/ripd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_debug.h"
#include "ripd/rip_interface.h"

/*
 * XPath: /frr-ripd:authentication-type-failure
 */
void ripd_notif_send_auth_type_failure(const char *ifname)
{
	const char *xpath = "/frr-ripd:authentication-type-failure";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	arguments = yang_data_list_new();

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
	data = yang_data_new_string(xpath_arg, ifname);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}

/*
 * XPath: /frr-ripd:authentication-failure
 */
void ripd_notif_send_auth_failure(const char *ifname)
{
	const char *xpath = "/frr-ripd:authentication-failure";
	struct list *arguments;
	char xpath_arg[XPATH_MAXLEN];
	struct yang_data *data;

	arguments = yang_data_list_new();

	snprintf(xpath_arg, sizeof(xpath_arg), "%s/interface-name", xpath);
	data = yang_data_new_string(xpath_arg, ifname);
	listnode_add(arguments, data);

	nb_notification_send(xpath, arguments);
}
