/*
 * Logging - VTY library
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

#ifndef __LOG_VTY_H__
#define __LOG_VTY_H__

#include "lib/hook.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vty;

extern void log_cmd_init(void);
extern void log_config_write(struct vty *vty);
extern int log_level_match(const char *s);
extern void log_show_syslog(struct vty *vty);

extern int facility_match(const char *str);
extern const char *facility_name(int facility);

DECLARE_HOOK(zlog_rotate, (), ());
extern void zlog_rotate(void);

DECLARE_HOOK(zlog_cli_show, (struct vty * vty), (vty));

#ifdef __cplusplus
}
#endif

#endif /* __LOG_VTY_H__ */
