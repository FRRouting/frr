/*
 * MGMTD VTY interface.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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

#ifndef _MGMTD_VTY_H
#define _MGMTD_VTY_H

#include "lib/command.h"
#include "lib/vty.h"
#include "lib/northbound.h"
#include "lib/northbound_cli.h"
#include "mgmtd/mgmt_defines.h"

extern void mgmt_enqueue_vty_nb_command(struct vty *vty, const char *xpath,
					enum nb_operation operation,
					const char *value);
extern int mgmt_apply_vty_nb_commands(struct vty *vty,
				      const char *xpath_base_fmt, ...);
extern int mgmt_hndl_bknd_cmd(const struct cmd_element *cmd, struct vty *vty,
			      int argc, struct cmd_token *argv[]);

#define DEF_MGMTD_CMD(dmn, cmdname, cmdstr, helpstr)                           \
	DEFUN_CMD_ELEMENT(mgmt_hndl_bknd_cmd, cmdname, cmdstr, helpstr,        \
			  CMD_ATTR_YANG, 0)

#define DEF_MGMTD_HIDDEN_CMD(dmn, cmdname, cmdstr, helpstr)                    \
	DEFUN_CMD_ELEMENT(mgmt_hndl_bknd_cmd, cmdname, cmdstr, helpstr,        \
			  CMD_ATTR_YANG | CMD_ATTR_HIDDEN, 0)

static inline LYD_FORMAT mgmt_str2format(const char *format_str)
{
	if (!strncmp("json", format_str, sizeof("json")))
		return LYD_JSON;
	else if (!strncmp("xml", format_str, sizeof("xml")))
		return LYD_XML;
	return LYD_UNKNOWN;
}

#ifdef INCLUDE_MGMTD_CMDDEFS_ONLY

#define NB_ENQEUE_CLI_COMMAND(vty, xpath, op, val)                             \
	mgmt_enqueue_vty_nb_command(vty, xpath, op, val)
#define NB_APPLY_CLI_COMMANDS(vty, xpath...)                                   \
	mgmt_apply_vty_nb_commands(vty, xpath)

#else /* INCLUDE_MGMTD_CMDDEFS_ONLY */

#define NB_ENQEUE_CLI_COMMAND(vty, xpath, op, val)                             \
	nb_cli_enqueue_change(vty, xpath, op, val)
#define NB_APPLY_CLI_COMMANDS(vty, xpath...) nb_cli_apply_changes(vty, xpath)

#endif /* INCLUDE_MGMTD_CMDDEFS_ONLY */

extern void mgmt_vty_init(void);
extern void mgmt_init_bcknd_cmd(void);

#endif /* _MGMTD_VTY_H */
