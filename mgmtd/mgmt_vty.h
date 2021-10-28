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

#include "northbound_cli.h"

/*
 * Declare prototypes for command initialization routines defined by
 * backend components that have been moved to new MGMTD infra here
 * one by one. These are supposed to be compiled into
 * mgmt/ibmgmt_be_nb.la first and then called from mgmt_vty_init()
 * below to load all backend client command handlers on MGMTd
 * process context.
 */
extern void static_vty_init(void);

extern void mgmt_enqueue_vty_nb_command(struct vty *vty, const char *xpath,
					enum nb_operation operation,
					const char *value);
extern int mgmt_apply_vty_nb_commands(struct vty *vty,
				      const char *xpath_base_fmt, ...);

static inline LYD_FORMAT mgmt_str2format(const char *format_str)
{
	if (!strncmp("json", format_str, sizeof("json")))
		return LYD_JSON;
	else if (!strncmp("xml", format_str, sizeof("xml")))
		return LYD_XML;
	return LYD_UNKNOWN;
}

extern void mgmt_vty_init(void);

#endif /* _MGMTD_VTY_H */
