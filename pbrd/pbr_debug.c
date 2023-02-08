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

struct debug pbr_dbg_map = {0, "PBR map"};
struct debug pbr_dbg_zebra = {0, "PBR Zebra communications"};
struct debug pbr_dbg_nht = {0, "PBR nexthop tracking"};
struct debug pbr_dbg_event = {0, "PBR events"};

struct debug *pbr_debugs[] = {&pbr_dbg_map, &pbr_dbg_zebra, &pbr_dbg_nht,
			      &pbr_dbg_event};

const char *pbr_debugs_conflines[] = {
	"debug pbr map",
	"debug pbr zebra",
	"debug pbr nht",
	"debug pbr events",
};

void pbr_debug_set_all(uint32_t flags, bool set)
{
	for (unsigned int i = 0; i < array_size(pbr_debugs); i++) {
		DEBUG_FLAGS_SET(pbr_debugs[i], flags, set);

		/* if all modes have been turned off, don't preserve options */
		if (!DEBUG_MODE_CHECK(pbr_debugs[i], DEBUG_MODE_ALL))
			DEBUG_CLEAR(pbr_debugs[i]);
	}
}

int pbr_debug_config_write_helper(struct vty *vty, bool config)
{
	uint32_t mode = DEBUG_MODE_ALL;

	if (config)
		mode = DEBUG_MODE_CONF;

	for (unsigned int i = 0; i < array_size(pbr_debugs); i++)
		if (DEBUG_MODE_CHECK(pbr_debugs[i], mode))
			vty_out(vty, "%s\n", pbr_debugs_conflines[i]);
	return 0;
}

int pbr_debug_config_write(struct vty *vty)
{
	return pbr_debug_config_write_helper(vty, true);
}

struct debug_callbacks pbr_dbg_cbs = {.debug_set_all = pbr_debug_set_all};

void pbr_debug_init(void)
{
	debug_init(&pbr_dbg_cbs);
}
