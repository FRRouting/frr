/*
 * CMGD VTY interface.
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

#ifndef _CMGD_VTY_H
#define _CMGD_VTY_H

#include "lib/command.h"
#include "lib/vty.h"
#include "lib/northbound.h"
#include "lib/northbound_cli.h"
#include "cmgd/cmgd_defines.h"

extern void cmgd_enqueue_nb_commands(struct vty *vty, const char *xpath,
				enum nb_operation operation,
				const char *value);
extern int cmgd_apply_nb_commands(struct vty *vty, const char *xpath_base_fmt, ...);
extern int cmgd_hndl_bknd_cmd(const struct cmd_element *, struct vty *, int,
				struct cmd_token *[]);

#define DEF_CMGD_CMD(dmn, cmdname, cmdstr, helpstr)					\
	DEFUN_CMD_ELEMENT(cmgd_hndl_bknd_cmd, cmdname, cmdstr, helpstr, CMD_ATTR_YANG, 0)

#define DEF_CMGD_HIDDEN_CMD(dmn, cmdname, cmdstr, helpstr)				\
	DEFUN_CMD_ELEMENT(cmgd_hndl_bknd_cmd, cmdname, cmdstr, helpstr, 		\
	CMD_ATTR_YANG|CMD_ATTR_HIDDEN, 0)

#ifdef INCLUDE_CMGD_CMDDEFS_ONLY

#define NB_ENQEUE_CLI_COMMAND(vty, xpath, op, val)					\
	cmgd_enqueue_nb_commands(vty, xpath, op, val)
#define NB_APPLY_CLI_COMMANDS(vty, xpath...)						\
	cmgd_apply_nb_commands(vty, xpath)

#else /* INCLUDE_CMGD_CMDDEFS_ONLY */

#define NB_ENQEUE_CLI_COMMAND(vty, xpath, op, val)					\
	nb_cli_enqueue_change(vty, xpath, op, val)
#define NB_APPLY_CLI_COMMANDS(vty, xpath...)						\
	nb_cli_apply_changes(vty, xpath)

#endif /* INCLUDE_CMGD_CMDDEFS_ONLY */

extern void cmgd_vty_init(void);
extern void cmgd_init_bcknd_cmd(void);

#endif /* _CMGD_VTY_H */
