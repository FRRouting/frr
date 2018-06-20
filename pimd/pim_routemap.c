/* PIM Route-map Code
 * Copyright (C) 2016 Cumulus Networks <sharpd@cumulusnetworks.com>
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "if.h"
#include "vty.h"
#include "routemap.h"

#include "pimd.h"

static void pim_route_map_add(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

static void pim_route_map_delete(const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_DELETED);
}

static void pim_route_map_event(route_map_event_t event, const char *rmap_name)
{
	route_map_notify_dependencies(rmap_name, RMAP_EVENT_MATCH_ADDED);
}

void pim_route_map_init(void)
{
	route_map_init();

	route_map_add_hook(pim_route_map_add);
	route_map_delete_hook(pim_route_map_delete);
	route_map_event_hook(pim_route_map_event);
}

void pim_route_map_terminate(void)
{
	route_map_add_hook(NULL);
	route_map_delete_hook(NULL);
	route_map_event_hook(NULL);
	route_map_finish();
}
