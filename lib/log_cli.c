// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 8 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 */
#include <zebra.h>
#include <pwd.h>
#include <grp.h>
#include "command.h"
#include "log.h"
#include "log_vty.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "lib/vtysh_daemons.h"

#include "lib/log_cli_clippy.c"

/* ======================= */
/* Basic logging CLI code. */
/* ======================= */

DEFPY_YANG (config_log_stdout,
	    config_log_stdout_cmd,
	    "[no] log stdout [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
	    NO_STR
	    "Logging control\n"
	    "Set stdout logging level\n"
	    LOG_LEVEL_DESC)
{
	if (no)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout", NB_OP_CREATE, NULL);
		if (levelarg)
			nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout/level",
					      NB_OP_MODIFY, log_lev2sev(levelarg));
		else
			nb_cli_enqueue_change(vty, "/frr-logging:logging/stdout/level",
					      NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_HIDDEN (config_log_monitor,
       config_log_monitor_cmd,
       "[no] log monitor [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Set terminal line (monitor) logging level\n"
       LOG_LEVEL_DESC)
{
	vty_out(vty, "%% \"log monitor\" is deprecated and does nothing.\n");
	return CMD_SUCCESS;
}

DEFPY_YANG_NOSH (debug_uid_backtrace,
            debug_uid_backtrace_cmd,
            "[no] debug unique-id UID backtrace",
            NO_STR
            DEBUG_STR
            "Options per individual log message, by unique ID\n"
            "Log message unique ID (XXXXX-XXXXX)\n"
            "Add backtrace to log when message is printed\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/uid-backtrace[uid='%s']", uid);
	nb_cli_enqueue_change(vty, xpath, no ? NB_OP_DESTROY : NB_OP_CREATE, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Per-daemon log file config */
DEFUN_YANG (config_log_dmn_file,
	    config_log_dmn_file_cmd,
            "log daemon " DAEMONS_LIST " file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
	    "Logging control\n"
	    "Specific daemon\n"
	    DAEMONS_STR
	    "Logging to file\n"
	    "Logging filename\n"
	    LOG_LEVEL_DESC)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/daemon-file[daemon='%s']/filename",
		 argv[2]->text);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, argv[4]->arg);
	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/daemon-file[daemon='%s']/level",
		 argv[2]->text);
	if (argc < 6)
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	else
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, log_lev2sev(argv[5]->text));
	return nb_cli_apply_changes(vty, NULL);
}

/* Per-daemon no log file */
DEFUN_YANG (no_config_log_dmn_file,
	    no_config_log_dmn_file_cmd,
	    "no log daemon " DAEMONS_LIST " file [FILENAME [LEVEL]]",
	    NO_STR
	    "Logging control\n"
	    "Specific daemon\n"
	    DAEMONS_STR
	    "Cancel logging to file\n"
	    "Logging file name\n"
	    "Logging level\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/frr-logging:logging/daemon-file[daemon='%s']",
		 argv[3]->text);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_file,
	    config_log_file_cmd,
	    "[no] log file ![FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]]",
	    NO_STR
	    "Logging control\n"
	    "Logging to file\n"
	    "Logging filename\n"
	    LOG_LEVEL_DESC)
{
	if (no)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/file", NB_OP_DESTROY, NULL);
	else {
		nb_cli_enqueue_change(vty, "/frr-logging:logging/file/filename", NB_OP_MODIFY,
				      filename);
		if (levelarg)
			nb_cli_enqueue_change(vty, "/frr-logging:logging/file/level", NB_OP_MODIFY,
					      log_lev2sev(levelarg));
		else
			nb_cli_enqueue_change(vty, "/frr-logging:logging/file/level",
					      NB_OP_DESTROY, NULL);
	}
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_syslog,
	    config_log_syslog_cmd,
       "log syslog [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Set syslog logging level\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog", NB_OP_CREATE, NULL);
	if (levelarg)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog/level", NB_OP_MODIFY,
				      log_lev2sev(levelarg));
	else
		nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog/level", NB_OP_DESTROY,
				      NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_syslog,
       no_config_log_syslog_cmd,
       "no log syslog [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Cancel logging to syslog\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/syslog", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_facility,
       config_log_facility_cmd,
       "log facility <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>$facilityarg",
       "Logging control\n"
       "Facility parameter for syslog messages\n"
       LOG_FACILITY_DESC)
{
	char buf[64];

	snprintf(buf, sizeof(buf), "ietf-syslog-types:%s", facilityarg);
	nb_cli_enqueue_change(vty, "/frr-logging:logging/facility", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_facility,
       no_config_log_facility_cmd,
       "no log facility [<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>] [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Reset syslog facility to default (daemon)\n"
       LOG_FACILITY_DESC
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/facility", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_record_priority,
       config_log_record_priority_cmd,
       "[no] log record-priority",
	NO_STR
       "Logging control\n"
       "Log the priority of the message within the message\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/record-priority", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_timestamp_precision,
       config_log_timestamp_precision_cmd,
       "log timestamp precision (0-6)",
       "Logging control\n"
       "Timestamp configuration\n"
       "Set the timestamp precision\n"
       "Number of subsecond digits\n")
{
	char buf[8];

	snprintf(buf, sizeof(buf), "%u", (uint)precision);
	nb_cli_enqueue_change(vty, "/frr-logging:logging/timestamp-precision", NB_OP_MODIFY, buf);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_timestamp_precision,
       no_config_log_timestamp_precision_cmd,
       "no log timestamp precision [(0-6)]",
       NO_STR
       "Logging control\n"
       "Timestamp configuration\n"
       "Reset the timestamp precision to the default value of 0\n"
       "Number of subsecond digits\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/timestamp-precision", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_ec,
       config_log_ec_cmd,
       "[no] log error-category",
       NO_STR
       "Logging control\n"
       "Prefix log message text with [EC 9999] code\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/error-category", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_xid,
       config_log_xid_cmd,
       "[no] log unique-id",
       NO_STR
       "Logging control\n"
       "Prefix log message text with [XXXXX-XXXXX] identifier\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/unique-id", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (config_log_filterfile,
       config_log_filterfile_cmd,
       "log filtered-file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Logging to file with string filter\n"
       "Logging filename\n"
       LOG_LEVEL_DESC)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file", NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file/filename", NB_OP_MODIFY,
			      filename);
	if (levelarg)
		nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file/level",
				      NB_OP_MODIFY, log_lev2sev(levelarg));
	else
		nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file/level",
				      NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_config_log_filterfile,
       no_config_log_filterfile_cmd,
       "no log filtered-file [FILENAME [LEVEL]]",
       NO_STR
       "Logging control\n"
       "Cancel logging to file with string filter\n"
       "Logging file name\n"
       "Logging level\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filtered-file", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (log_filter,
       log_filter_cmd,
       "[no] log filter-text WORD$filter",
       NO_STR
       "Logging control\n"
       FILTER_LOG_STR
       "String to filter by\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filter-text",
			      no ? NB_OP_DESTROY : NB_OP_CREATE, filter);
	return nb_cli_apply_changes(vty, NULL);
}

/* Clear all log filters */
DEFPY_YANG (log_filter_clear,
       log_filter_clear_cmd,
       "clear log filter-text",
       CLEAR_STR
       "Logging control\n"
       FILTER_LOG_STR)
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/filter-text", NB_OP_DESTROY, NULL);
	return nb_cli_apply_changes(vty, NULL);
	/* zlog_filter_clear(); */
	return CMD_SUCCESS;
}

/* Enable/disable 'immediate' mode, with no output buffering */
DEFPY_YANG (log_immediate_mode,
       log_immediate_mode_cmd,
       "[no] log immediate-mode",
       NO_STR
       "Logging control\n"
       "Output immediately, without buffering\n")
{
	nb_cli_enqueue_change(vty, "/frr-logging:logging/immediate-mode", NB_OP_MODIFY,
			      no ? "false" : "true");
	return nb_cli_apply_changes(vty, NULL);
}

void log_cli_init(void)
{
	install_element(CONFIG_NODE, &config_log_stdout_cmd);
	install_element(CONFIG_NODE, &config_log_monitor_cmd);
	install_element(CONFIG_NODE, &config_log_file_cmd);
	install_element(CONFIG_NODE, &config_log_dmn_file_cmd);
	install_element(CONFIG_NODE, &no_config_log_dmn_file_cmd);
	install_element(CONFIG_NODE, &config_log_syslog_cmd);
	install_element(CONFIG_NODE, &no_config_log_syslog_cmd);
	install_element(CONFIG_NODE, &config_log_facility_cmd);
	install_element(CONFIG_NODE, &no_config_log_facility_cmd);
	install_element(CONFIG_NODE, &config_log_record_priority_cmd);
	install_element(CONFIG_NODE, &config_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &no_config_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &config_log_ec_cmd);
	install_element(CONFIG_NODE, &config_log_xid_cmd);

	install_element(CONFIG_NODE, &log_filter_cmd);
	install_element(CONFIG_NODE, &log_filter_clear_cmd);
	install_element(CONFIG_NODE, &config_log_filterfile_cmd);
	install_element(CONFIG_NODE, &no_config_log_filterfile_cmd);
	install_element(CONFIG_NODE, &log_immediate_mode_cmd);

	install_element(CONFIG_NODE, &debug_uid_backtrace_cmd);
}


/* clang-format off */
static void logging_stdout_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	int level = log_level_match(yang_dnode_get_string(dnode, "level"));

	if (level != LOG_DEBUG || show_defaults)
		vty_out(vty, "log stdout %s\n", zlog_priority_str(level));
	else
		vty_out(vty, "log stdout\n");
}

static void logging_syslog_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	int level = log_level_match(yang_dnode_get_string(dnode, "level"));

	if (level != LOG_DEBUG || show_defaults)
		vty_out(vty, "log syslog %s\n", zlog_priority_str(level));
	else
		vty_out(vty, "log syslog\n");
}

static void logging_file_filename_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *fname = yang_dnode_get_string(dnode, NULL);
	int level = log_level_match(yang_dnode_get_string(dnode, "../level"));

	if (level != LOG_DEBUG  || show_defaults)
		vty_out(vty, "log file %s %s\n", fname, zlog_priority_str(level));
	else
		vty_out(vty, "log file %s\n", fname);
}

static void logging_filtered_file_filename_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *fname = yang_dnode_get_string(dnode, NULL);
	int level = log_level_match(yang_dnode_get_string(dnode, "../level"));

	if (level != LOG_DEBUG || show_defaults)
		vty_out(vty, "log filtered-file %s %s\n", fname, zlog_priority_str(level));
	else
		vty_out(vty, "log filtered-file %s\n", fname);
}

static void logging_daemon_file_filename_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *fname = yang_dnode_get_string(dnode, NULL);
	const char *daemon = yang_dnode_get_string(dnode, "../daemon");
	int level = log_level_match(yang_dnode_get_string(dnode, "../level"));

	if (level != LOG_DEBUG || show_defaults)
		vty_out(vty, "log daemon %s file %s %s\n", daemon, fname, zlog_priority_str(level));
	else
		vty_out(vty, "log daemon %s file %s\n", daemon, fname);
}

static void logging_facility_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "log facility %s\n", yang_dnode_get_string(dnode, NULL));
}

static void logging_record_priority_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (enable)
		vty_out(vty, "log record-priority\n");
	else if (show_defaults)
		vty_out(vty, "no log record-priority\n");
}
static void logging_timestamp_precision_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	const char *prec = yang_dnode_get_string(dnode, NULL);

	if (strcmp(prec, "0") || show_defaults)
		vty_out(vty, "log timestamp precision %s\n", prec);
}
static void logging_error_category_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (!enable)
		vty_out(vty, "no log error-category\n");
	else if (show_defaults)
		vty_out(vty, "log record-category\n");
}
static void logging_unique_id_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (!enable)
		vty_out(vty, "no log unique-id\n");
	else if (show_defaults)
		vty_out(vty, "log unique-id\n");
}
static void logging_immediate_mode_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	bool enable = yang_dnode_get_bool(dnode, NULL);

	if (enable)
		vty_out(vty, "log immediate-mode\n");
	else if (show_defaults)
		vty_out(vty, "no log immediate-mode\n");
}

static void logging_uid_backtrace_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	vty_out(vty, "debug unique-id %s backtrace\n", yang_dnode_get_string(dnode, "uid"));
}

const struct frr_yang_module_info frr_logging_cli_info = {
	.name = "frr-logging",
	.ignore_cfg_cbs = true,
	.nodes = {
		{ .xpath = "/frr-logging:logging/stdout", .cbs.cli_show = logging_stdout_cli_write },
		{ .xpath = "/frr-logging:logging/syslog", .cbs.cli_show = logging_syslog_cli_write },
		{ .xpath = "/frr-logging:logging/file/filename", .cbs.cli_show = logging_file_filename_cli_write },
		{ .xpath = "/frr-logging:logging/filtered-file/filename", .cbs.cli_show = logging_filtered_file_filename_cli_write },
		/* This is not saved, but may be the future. */
		/* { .xpath = "/frr-logging:logging/filter-text", .cbs.cli_show = logging_filter_text_cli_write }, */
		{ .xpath = "/frr-logging:logging/daemon-file/filename", .cbs.cli_show = logging_daemon_file_filename_cli_write },
		{ .xpath = "/frr-logging:logging/facility", .cbs.cli_show = logging_facility_cli_write },
		{ .xpath = "/frr-logging:logging/record-priority", .cbs.cli_show = logging_record_priority_cli_write },
		{ .xpath = "/frr-logging:logging/timestamp-precision", .cbs.cli_show = logging_timestamp_precision_cli_write },
		{ .xpath = "/frr-logging:logging/error-category", .cbs.cli_show = logging_error_category_cli_write },
		{ .xpath = "/frr-logging:logging/unique-id", .cbs.cli_show = logging_unique_id_cli_write },
		{ .xpath = "/frr-logging:logging/immediate-mode", .cbs.cli_show = logging_immediate_mode_cli_write },
		{ .xpath = "/frr-logging:logging/uid-backtrace", .cbs.cli_show = logging_uid_backtrace_cli_write },
		{ .xpath = NULL },
	}
};
