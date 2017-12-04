/*
 * SHARP - vty code
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
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
#include "nexthop.h"
#include "log.h"

#include "sharpd/sharp_zebra.h"
#include "sharpd/sharp_vty.h"
#ifndef VTYSH_EXTRACT_PL
#include "sharpd/sharp_vty_clippy.c"
#endif

extern uint32_t total_routes;
extern uint32_t installed_routes;
extern uint32_t removed_routes;

DEFPY (install_routes,
       install_routes_cmd,
       "install routes A.B.C.D$start nexthop A.B.C.D$nexthop (1-1000000)$routes",
       "install some routes\n"
       "Routes to install\n"
       "Address to start /32 generation at\n"
       "Nexthop to use\n"
       "Nexthop address\n"
       "How many to create\n")
{
	int i;
	struct prefix p;
	struct nexthop nhop;
	uint32_t temp;

	total_routes = routes;
	installed_routes = 0;

	memset(&p, 0, sizeof(p));
	memset(&nhop, 0, sizeof(nhop));

	p.family = AF_INET;
	p.prefixlen = 32;
	p.u.prefix4 = start;

	nhop.gate.ipv4 = nexthop;
	nhop.type = NEXTHOP_TYPE_IPV4;

	zlog_debug("Inserting %ld routes", routes);

	temp = ntohl(p.u.prefix4.s_addr);
	for (i = 0 ; i < routes ; i++) {
		route_add(&p, &nhop);
		p.u.prefix4.s_addr = htonl(++temp);
	}

	return CMD_SUCCESS;
}

DEFPY (remove_routes,
       remove_routes_cmd,
       "remove routes A.B.C.D$start (1-1000000)$routes",
       "Remove some routes\n"
       "Routes to remove\n"
       "Starting spot\n"
       "Routes to uniinstall\n")
{
	int i;
	struct prefix p;
	uint32_t temp;

	total_routes = routes;
	removed_routes = 0;

	memset(&p, 0, sizeof(p));

	p.family = AF_INET;
	p.prefixlen = 32;
	p.u.prefix4 = start;

	zlog_debug("Removing %ld routes", routes);

	temp = ntohl(p.u.prefix4.s_addr);
	for (i = 0; i < routes ; i++) {
		route_delete(&p);
		p.u.prefix4.s_addr = htonl(++temp);
	}

	return CMD_SUCCESS;
}

void sharp_vty_init(void)
{
	install_element(ENABLE_NODE, &install_routes_cmd);
	install_element(ENABLE_NODE, &remove_routes_cmd);
	return;
}
