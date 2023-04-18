// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Logging - VTY library
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
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
