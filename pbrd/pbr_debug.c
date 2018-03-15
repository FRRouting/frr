/*
 * PBR - debugging
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Quentin Young
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

#include "debug.h"
#include "command.h"
#include "vector.h"

#ifndef VTYSH_EXTRACT_PL
#include "pbrd/pbr_debug_clippy.c"
#endif
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

/*
 * Set or unset flags on all debugs for pbrd.
 *
 * flags
 *    The flags to set
 *
 * set
 *    Whether to set or unset the specified flags
 */
static void pbr_debug_set_all(uint32_t flags, bool set)
{
	for (unsigned int i = 0; i < array_size(pbr_debugs); i++) {
		DEBUG_FLAGS_SET(pbr_debugs[i], flags, set);

		/* if all modes have been turned off, don't preserve options */
		if (!DEBUG_MODE_CHECK(pbr_debugs[i], DEBUG_MODE_ALL))
			DEBUG_CLEAR(pbr_debugs[i]);
	}
}

/*
 * Check flags on all debugs for pbrd.
 *
 * flags
 *    The flags to set
 *
 * Returns:
 *    The subset of the given flags that were set in all pbrd debugs
 */
static uint32_t pbr_debug_check_all(uint32_t flags)
{
	uint32_t mode = DEBUG_MODE_ALL;

	for (unsigned int i = 0; i < array_size(pbr_debugs); i++)
		mode &= DEBUG_MODE_CHECK(pbr_debugs[i], flags);
	return mode;
}

static int pbr_debug_config_write_helper(struct vty *vty, bool config)
{
	uint32_t mode = DEBUG_MODE_ALL;

	if (config)
		mode = DEBUG_MODE_CONF;

	if (pbr_debug_check_all(DEBUG_MODE_CONF) == mode) {
		vty_out(vty, "debug pbr\n");
		return 0;
	}

	for (unsigned int i = 0; i < array_size(pbr_debugs); i++)
		if (DEBUG_MODE_CHECK(pbr_debugs[i], mode))
			vty_out(vty, "%s\n", pbr_debugs_conflines[i]);
	return 0;
}

int pbr_debug_config_write(struct vty *vty)
{
	return pbr_debug_config_write_helper(vty, true);
}

/* PBR debugging CLI ------------------------------------------------------- */
/* clang-format off */

DEFPY(debug_pbr,
      debug_pbr_cmd,
      "[no] debug pbr [{map$map|zebra$zebra|nht$nht|events$events}]",
      NO_STR
      DEBUG_STR
      "Policy Based Routing\n"
      "Policy maps\n"
      "PBRD <-> Zebra communications\n"
      "Nexthop tracking\n"
      "Events\n")
{
	uint32_t mode = DEBUG_NODE2MODE(vty->node);

	if (map)
		DEBUG_MODE_SET(&pbr_dbg_map, mode, !no);
	if (zebra)
		DEBUG_MODE_SET(&pbr_dbg_zebra, mode, !no);
	if (nht)
		DEBUG_MODE_SET(&pbr_dbg_nht, mode, !no);
	if (events)
		DEBUG_MODE_SET(&pbr_dbg_event, mode, !no);

	/* no specific debug --> act on all of them */
	if (strmatch(argv[argc - 1]->text, "pbr"))
		pbr_debug_set_all(mode, !no);

	return CMD_SUCCESS;
}

DEFUN_NOSH(show_debugging_pbr,
	   show_debugging_pbr_cmd,
	   "show debugging [pbr]",
	   SHOW_STR
	   DEBUG_STR
	   "Policy Based Routing\n")
{
	vty_out(vty, "PBR debugging status:\n");

	pbr_debug_config_write_helper(vty, false);

	return CMD_SUCCESS;
}

/* clang-format on */
/* ------------------------------------------------------------------------- */

static struct cmd_node debug_node = {DEBUG_NODE, "", 1};

struct debug_callbacks pbr_dbg_cbs = {.debug_set_all = pbr_debug_set_all};

void pbr_debug_init(void)
{
	debug_init(&pbr_dbg_cbs);
}

void pbr_debug_init_vty(void)
{
	install_node(&debug_node, pbr_debug_config_write);

	install_element(VIEW_NODE, &debug_pbr_cmd);
	install_element(CONFIG_NODE, &debug_pbr_cmd);

	install_element(VIEW_NODE, &show_debugging_pbr_cmd);
}
