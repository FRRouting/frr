/*
 * Logging - VTY code
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
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

#include "lib/log_vty.h"
#include "command.h"
#include "lib/vty.h"
#include "lib/log.h"
#ifndef VTYSH_EXTRACT_PL
#include "lib/log_vty_clippy.c"
#endif

DEFPY (log_filter,
       log_filter_cmd,
       "[no] log-filter WORD$filter",
       NO_STR
       FILTER_LOG_STR
       "String to filter by\n")
{
	int ret = 0;

	if (no)
		ret = zlog_filter_del(filter);
	else
		ret = zlog_filter_add(filter);

	if (ret == 1) {
		vty_out(vty, "%% filter table full\n");
		return CMD_WARNING;
	} else if (ret != 0) {
		vty_out(vty, "%% failed to %s log filter\n",
			(no ? "remove" : "apply"));
		return CMD_WARNING;
	}

	vty_out(vty, " %s\n", filter);
	return CMD_SUCCESS;
}

/* Clear all log filters */
DEFPY (log_filter_clear,
       log_filter_clear_cmd,
       "clear log-filter",
       CLEAR_STR
       FILTER_LOG_STR)
{
	zlog_filter_clear();
	return CMD_SUCCESS;
}

/* Show log filter */
DEFPY (show_log_filter,
       show_log_filter_cmd,
       "show log-filter",
       SHOW_STR
       FILTER_LOG_STR)
{
	char log_filters[ZLOG_FILTERS_MAX * (ZLOG_FILTER_LENGTH_MAX + 3)] = "";
	int len = 0;

	len = zlog_filter_dump(log_filters, sizeof(log_filters));

	if (len == -1) {
		vty_out(vty, "%% failed to get filters\n");
		return CMD_WARNING;
	}

	if (len != 0)
		vty_out(vty, "%s", log_filters);

	return CMD_SUCCESS;
}

void log_filter_cmd_init(void)
{
	install_element(VIEW_NODE, &show_log_filter_cmd);
	install_element(CONFIG_NODE, &log_filter_cmd);
	install_element(CONFIG_NODE, &log_filter_clear_cmd);
}
