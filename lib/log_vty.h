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
extern const char *log_lev2sev(const char *level);

extern int facility_match(const char *str);
extern const char *facility_name(int facility);

DECLARE_HOOK(zlog_rotate, (), ());
extern void zlog_rotate(void);

DECLARE_HOOK(zlog_cli_show, (struct vty * vty), (vty));

/* Default logging level in the YANG model */
extern const int log_default_lvl;

/* Internal logging state */
extern uint logmsgs_with_persist_bt;
extern int log_config_stdout_lvl;
extern int log_config_syslog_lvl;
extern int log_cmdline_stdout_lvl;
extern int log_cmdline_syslog_lvl;
extern struct zlog_cfg_file zt_file_cmdline;
extern struct zlog_cfg_file zt_file;
extern struct zlog_cfg_filterfile zt_filterfile;
extern struct zlog_cfg_file zt_stdout_file;
extern struct zlog_cfg_5424 zt_stdout_journald;
extern bool stdout_journald_in_use;

void log_stdout_apply_level(void);

extern struct frr_yang_module_info frr_logging_cli_info;

#ifdef __cplusplus
}
#endif

#endif /* __LOG_VTY_H__ */
