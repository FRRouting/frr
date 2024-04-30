// SPDX-License-Identifier: GPL-2.0-or-later
/* PIM Route-map Code
 * Copyright (C) 2016 Cumulus Networks <sharpd@cumulusnetworks.com>
 * Copyright (C) 1999 Kunihiro Ishiguro <kunihiro@zebra.org>
 *
 * This file is part of Quagga
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

static void pim_route_map_event(const char *rmap_name)
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
	route_map_finish();
}
