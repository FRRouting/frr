// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PBR - debugging
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Quentin Young
 */
#include <zebra.h>

#include "debug.h"
#include "command.h"
#include "vector.h"

#include "pbrd/pbr_debug_clippy.c"
#include "pbrd/pbr_debug.h"

struct debug pbr_dbg_map = { 0, "debug pbr map", "PBR map" };
struct debug pbr_dbg_zebra = { 0, "debug pbr zebra",
			       "PBR Zebra communications" };
struct debug pbr_dbg_nht = { 0, "debug pbr nht", "PBR nexthop tracking" };
struct debug pbr_dbg_event = { 0, "debug pbr events", "PBR events" };

void pbr_debug_init(void)
{
	debug_install(&pbr_dbg_map);
	debug_install(&pbr_dbg_zebra);
	debug_install(&pbr_dbg_nht);
	debug_install(&pbr_dbg_event);
}
