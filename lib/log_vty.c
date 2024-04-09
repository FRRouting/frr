// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Logging - VTY code
 * Copyright (C) 2019 Cumulus Networks, Inc.
 *                    Stephen Worley
 */

#include <zebra.h>

#include "lib/log_vty.h"
#include "command.h"
#include "lib/log.h"
#include "lib/zlog_targets.h"
#include "lib/zlog_5424.h"
#include "lib/lib_errors.h"
#include "lib/printfrr.h"
#include "lib/systemd.h"
#include "lib/vtysh_daemons.h"

#include "lib/log_vty_clippy.c"

#define ZLOG_MAXLVL(a, b) MAX(a, b)

DEFINE_HOOK(zlog_rotate, (), ());
DEFINE_HOOK(zlog_cli_show, (struct vty * vty), (vty));

static unsigned logmsgs_with_persist_bt;

static const int log_default_lvl = LOG_DEBUG;

static int log_config_stdout_lvl = ZLOG_DISABLED;
static int log_config_syslog_lvl = ZLOG_DISABLED;
static int log_cmdline_stdout_lvl = ZLOG_DISABLED;
static int log_cmdline_syslog_lvl = ZLOG_DISABLED;

static struct zlog_cfg_file zt_file_cmdline = {
	.prio_min = ZLOG_DISABLED,
	.ts_subsec = LOG_TIMESTAMP_PRECISION,
};
static struct zlog_cfg_file zt_file = {
	.prio_min = ZLOG_DISABLED,
	.ts_subsec = LOG_TIMESTAMP_PRECISION,
};
static struct zlog_cfg_filterfile zt_filterfile = {
	.parent =
		{
			.prio_min = ZLOG_DISABLED,
			.ts_subsec = LOG_TIMESTAMP_PRECISION,
		},
};

static struct zlog_cfg_file zt_stdout_file = {
	.prio_min = ZLOG_DISABLED,
	.ts_subsec = LOG_TIMESTAMP_PRECISION,
};
static struct zlog_cfg_5424 zt_stdout_journald = {
	.prio_min = ZLOG_DISABLED,

	.fmt = ZLOG_FMT_JOURNALD,
	.dst = ZLOG_5424_DST_UNIX,
	.filename = "/run/systemd/journal/socket",

	/* this can't be changed through config since this target substitutes
	 * in for the "plain" stdout target
	 */
	.facility = LOG_DAEMON,
	.kw_version = false,
	.kw_location = true,
	.kw_uid = true,
	.kw_ec = true,
	.kw_args = true,
};
static bool stdout_journald_in_use;

const char *zlog_progname;
static const char *zlog_protoname;

static const struct facility_map {
	int facility;
	const char *name;
	size_t match;
} syslog_facilities[] = {
	{LOG_KERN, "kern", 1},
	{LOG_USER, "user", 2},
	{LOG_MAIL, "mail", 1},
	{LOG_DAEMON, "daemon", 1},
	{LOG_AUTH, "auth", 1},
	{LOG_SYSLOG, "syslog", 1},
	{LOG_LPR, "lpr", 2},
	{LOG_NEWS, "news", 1},
	{LOG_UUCP, "uucp", 2},
	{LOG_CRON, "cron", 1},
#ifdef LOG_FTP
	{LOG_FTP, "ftp", 1},
#endif
	{LOG_LOCAL0, "local0", 6},
	{LOG_LOCAL1, "local1", 6},
	{LOG_LOCAL2, "local2", 6},
	{LOG_LOCAL3, "local3", 6},
	{LOG_LOCAL4, "local4", 6},
	{LOG_LOCAL5, "local5", 6},
	{LOG_LOCAL6, "local6", 6},
	{LOG_LOCAL7, "local7", 6},
	{0, NULL, 0},
};

static const char * const zlog_priority[] = {
	"emergencies",   "alerts",	"critical",  "errors", "warnings",
	"notifications", "informational", "debugging", NULL,
};

const char *zlog_priority_str(int priority)
{
	if (priority > LOG_DEBUG)
		return "???";
	return zlog_priority[priority];
}

const char *facility_name(int facility)
{
	const struct facility_map *fm;

	for (fm = syslog_facilities; fm->name; fm++)
		if (fm->facility == facility)
			return fm->name;
	return "";
}

int facility_match(const char *str)
{
	const struct facility_map *fm;

	for (fm = syslog_facilities; fm->name; fm++)
		if (!strncmp(str, fm->name, fm->match))
			return fm->facility;
	return -1;
}

int log_level_match(const char *s)
{
	int level;

	for (level = 0; zlog_priority[level] != NULL; level++)
		if (!strncmp(s, zlog_priority[level], 2))
			return level;
	return ZLOG_DISABLED;
}

void zlog_rotate(void)
{
	zlog_file_rotate(&zt_file);
	zlog_file_rotate(&zt_filterfile.parent);
	zlog_file_rotate(&zt_file_cmdline);
	hook_call(zlog_rotate);
}


void log_show_syslog(struct vty *vty)
{
	int level = zlog_syslog_get_prio_min();

	vty_out(vty, "Syslog logging: ");
	if (level == ZLOG_DISABLED)
		vty_out(vty, "disabled\n");
	else
		vty_out(vty, "level %s, facility %s, ident %s\n",
			zlog_priority[level],
			facility_name(zlog_syslog_get_facility()),
			zlog_progname);
}

DEFUN_NOSH (show_logging,
	    show_logging_cmd,
	    "show logging",
	    SHOW_STR
	    "Show current logging configuration\n")
{
	int stdout_prio;

	log_show_syslog(vty);

	stdout_prio = stdout_journald_in_use ? zt_stdout_journald.prio_min
					     : zt_stdout_file.prio_min;

	vty_out(vty, "Stdout logging: ");
	if (stdout_prio == ZLOG_DISABLED)
		vty_out(vty, "disabled");
	else
		vty_out(vty, "level %s", zlog_priority[stdout_prio]);
	vty_out(vty, "\n");

	vty_out(vty, "File logging: ");
	if (zt_file.prio_min == ZLOG_DISABLED || !zt_file.filename)
		vty_out(vty, "disabled");
	else
		vty_out(vty, "level %s, filename %s",
			zlog_priority[zt_file.prio_min], zt_file.filename);
	vty_out(vty, "\n");

	if (zt_filterfile.parent.prio_min != ZLOG_DISABLED
	    && zt_filterfile.parent.filename)
		vty_out(vty, "Filtered-file logging: level %s, filename %s\n",
			zlog_priority[zt_filterfile.parent.prio_min],
			zt_filterfile.parent.filename);

	if (log_cmdline_syslog_lvl != ZLOG_DISABLED)
		vty_out(vty,
			"From command line: \"--log syslog --log-level %s\"\n",
			zlog_priority[log_cmdline_syslog_lvl]);
	if (log_cmdline_stdout_lvl != ZLOG_DISABLED)
		vty_out(vty,
			"From command line: \"--log stdout --log-level %s\"\n",
			zlog_priority[log_cmdline_stdout_lvl]);
	if (zt_file_cmdline.prio_min != ZLOG_DISABLED)
		vty_out(vty,
			"From command line: \"--log file:%s --log-level %s\"\n",
			zt_file_cmdline.filename,
			zlog_priority[zt_file_cmdline.prio_min]);

	vty_out(vty, "Protocol name: %s\n", zlog_protoname);
	vty_out(vty, "Record priority: %s\n",
		(zt_file.record_priority ? "enabled" : "disabled"));
	vty_out(vty, "Timestamp precision: %d\n", zt_file.ts_subsec);

	hook_call(zlog_cli_show, vty);
	return CMD_SUCCESS;
}

static void log_stdout_apply_level(void)
{
	int maxlvl;

	maxlvl = ZLOG_MAXLVL(log_config_stdout_lvl, log_cmdline_stdout_lvl);

	if (stdout_journald_in_use) {
		zt_stdout_journald.prio_min = maxlvl;
		zlog_5424_apply_meta(&zt_stdout_journald);
	} else {
		zt_stdout_file.prio_min = maxlvl;
		zlog_file_set_other(&zt_stdout_file);
	}
}

DEFPY (config_log_stdout,
       config_log_stdout_cmd,
       "log stdout [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Set stdout logging level\n"
       LOG_LEVEL_DESC)
{
	int level;

	if (levelarg) {
		level = log_level_match(levelarg);
		if (level == ZLOG_DISABLED)
			return CMD_ERR_NO_MATCH;
	} else
		level = log_default_lvl;

	log_config_stdout_lvl = level;
	log_stdout_apply_level();
	return CMD_SUCCESS;
}

DEFUN (no_config_log_stdout,
       no_config_log_stdout_cmd,
       "no log stdout [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Cancel logging to stdout\n"
       LOG_LEVEL_DESC)
{
	log_config_stdout_lvl = ZLOG_DISABLED;
	log_stdout_apply_level();
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (config_log_monitor,
       config_log_monitor_cmd,
       "log monitor [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       "Logging control\n"
       "Set terminal line (monitor) logging level\n"
       LOG_LEVEL_DESC)
{
	vty_out(vty, "%% \"log monitor\" is deprecated and does nothing.\n");
	return CMD_SUCCESS;
}

DEFUN_HIDDEN (no_config_log_monitor,
       no_config_log_monitor_cmd,
       "no log monitor [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Disable terminal line (monitor) logging\n"
       LOG_LEVEL_DESC)
{
	return CMD_SUCCESS;
}

DEFPY_NOSH (debug_uid_backtrace,
	    debug_uid_backtrace_cmd,
	    "[no] debug unique-id UID backtrace",
	    NO_STR
	    DEBUG_STR
	    "Options per individual log message, by unique ID\n"
	    "Log message unique ID (XXXXX-XXXXX)\n"
	    "Add backtrace to log when message is printed\n")
{
	struct xrefdata search, *xrd;
	struct xrefdata_logmsg *xrdl;
	uint8_t flag;

	strlcpy(search.uid, uid, sizeof(search.uid));
	xrd = xrefdata_uid_find(&xrefdata_uid, &search);

	if (!xrd)
		return CMD_ERR_NOTHING_TODO;

	if (xrd->xref->type != XREFT_LOGMSG) {
		vty_out(vty, "%% ID \"%s\" is not a log message\n", uid);
		return CMD_WARNING;
	}
	xrdl = container_of(xrd, struct xrefdata_logmsg, xrefdata);

	flag = (vty->node == CONFIG_NODE) ? LOGMSG_FLAG_PERSISTENT
					  : LOGMSG_FLAG_EPHEMERAL;

	if ((xrdl->fl_print_bt & flag) == (no ? 0 : flag))
		return CMD_SUCCESS;
	if (flag == LOGMSG_FLAG_PERSISTENT)
		logmsgs_with_persist_bt += no ? -1 : 1;

	xrdl->fl_print_bt ^= flag;
	return CMD_SUCCESS;
}

static int set_log_file(struct zlog_cfg_file *target, struct vty *vty,
			const char *fname, int loglevel)
{
	char path[MAXPATHLEN + 1];
	const char *fullpath;
	bool ok;


	/* Path detection. */
	if (!IS_DIRECTORY_SEP(*fname)) {
		char cwd[MAXPATHLEN + 1];

		cwd[MAXPATHLEN] = '\0';

		if (getcwd(cwd, MAXPATHLEN) == NULL) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "config_log_file: Unable to alloc mem!");
			return CMD_WARNING_CONFIG_FAILED;
		}

		int pr = snprintf(path, sizeof(path), "%s/%s", cwd, fname);
		if (pr < 0 || (unsigned int)pr >= sizeof(path)) {
			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"%s: Path too long ('%s/%s'); system maximum is %u",
				__func__, cwd, fname, MAXPATHLEN);
			return CMD_WARNING_CONFIG_FAILED;
		}

		fullpath = path;
	} else
		fullpath = fname;

	target->prio_min = loglevel;
	ok = zlog_file_set_filename(target, fullpath);

	if (!ok) {
		if (vty)
			vty_out(vty, "can't open logfile %s\n", fname);
		return CMD_WARNING_CONFIG_FAILED;
	}
	return CMD_SUCCESS;
}

void command_setup_early_logging(const char *dest, const char *level)
{
	int nlevel;
	char *sep;
	int len;
	char type[8];

	if (level) {
		nlevel = log_level_match(level);

		if (nlevel == ZLOG_DISABLED) {
			fprintf(stderr, "invalid log level \"%s\"\n", level);
			exit(1);
		}
	} else
		nlevel = log_default_lvl;

	if (!dest)
		return;

	sep = strchr(dest, ':');
	len = sep ? (int)(sep - dest) : (int)strlen(dest);

	snprintfrr(type, sizeof(type), "%.*s", len, dest);

	if (strcmp(type, "stdout") == 0) {
		log_cmdline_stdout_lvl = nlevel;
		log_stdout_apply_level();
		return;
	}
	if (strcmp(type, "syslog") == 0) {
		log_cmdline_syslog_lvl = nlevel;
		zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl,
						     log_cmdline_syslog_lvl));
		return;
	}
	if (strcmp(type, "file") == 0 && sep) {
		sep++;
		set_log_file(&zt_file_cmdline, NULL, sep, nlevel);
		return;
	}
	if (strcmp(type, "monitor") == 0 && sep) {
		struct zlog_live_cfg cfg = {};
		unsigned long fd;
		char *endp;

		sep++;
		fd = strtoul(sep, &endp, 10);
		if (!*sep || *endp) {
			fprintf(stderr, "invalid monitor fd \"%s\"\n", sep);
			exit(1);
		}

		zlog_live_open_fd(&cfg, nlevel, fd);
		zlog_live_disown(&cfg);
		return;
	}

	fprintf(stderr, "invalid log target \"%s\" (\"%s\")\n", type, dest);
	exit(1);
}

DEFUN (clear_log_cmdline,
       clear_log_cmdline_cmd,
       "clear log cmdline-targets",
       CLEAR_STR
       "Logging control\n"
       "Disable log targets specified at startup by --log option\n")
{
	zt_file_cmdline.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_file_cmdline);

	log_cmdline_syslog_lvl = ZLOG_DISABLED;
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl,
					     log_cmdline_syslog_lvl));

	log_cmdline_stdout_lvl = ZLOG_DISABLED;
	log_stdout_apply_level();

	return CMD_SUCCESS;
}

/* Per-daemon log file config */
DEFUN (config_log_dmn_file,
       config_log_dmn_file_cmd,
       "log daemon " DAEMONS_LIST " file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Specific daemon\n"
       DAEMONS_STR
       "Logging to file\n"
       "Logging filename\n"
       LOG_LEVEL_DESC)
{
	int level = log_default_lvl;
	int idx = 0;
	const char *d_str;
	const char *filename;
	const char *levelarg = NULL;

	d_str = argv[2]->text;

	/* Ignore if not for this daemon */
	if (!strmatch(d_str, frr_get_progname()))
		return CMD_SUCCESS;

	if (argv_find(argv, argc, "file", &idx))
		filename = argv[idx + 1]->arg;
	else
		return CMD_SUCCESS;

	if (argc > 5)
		levelarg = argv[5]->text;

	if (levelarg) {
		level = log_level_match(levelarg);
		if (level == ZLOG_DISABLED)
			return CMD_ERR_NO_MATCH;
	}
	return set_log_file(&zt_file, vty, filename, level);
}

/* Per-daemon no log file */
DEFUN (no_config_log_dmn_file,
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
	const char *d_str;

	d_str = argv[3]->text;

	/* Ignore if not for this daemon */
	if (!strmatch(d_str, frr_get_progname()))
		return CMD_SUCCESS;

	zt_file.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_file);
	return CMD_SUCCESS;
}

DEFPY (config_log_file,
       config_log_file_cmd,
       "log file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Logging to file\n"
       "Logging filename\n"
       LOG_LEVEL_DESC)
{
	int level = log_default_lvl;

	if (levelarg) {
		level = log_level_match(levelarg);
		if (level == ZLOG_DISABLED)
			return CMD_ERR_NO_MATCH;
	}
	return set_log_file(&zt_file, vty, filename, level);
}

DEFUN (no_config_log_file,
       no_config_log_file_cmd,
       "no log file [FILENAME [LEVEL]]",
       NO_STR
       "Logging control\n"
       "Cancel logging to file\n"
       "Logging file name\n"
       "Logging level\n")
{
	zt_file.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_file);
	return CMD_SUCCESS;
}

DEFPY (config_log_syslog,
       config_log_syslog_cmd,
       "log syslog [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Set syslog logging level\n"
       LOG_LEVEL_DESC)
{
	int level;

	if (levelarg) {
		level = log_level_match(levelarg);

		if (level == ZLOG_DISABLED)
			return CMD_ERR_NO_MATCH;
	} else
		level = log_default_lvl;

	log_config_syslog_lvl = level;
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl,
					     log_cmdline_syslog_lvl));
	return CMD_SUCCESS;
}

DEFUN (no_config_log_syslog,
       no_config_log_syslog_cmd,
       "no log syslog [<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>] [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>]",
       NO_STR
       "Logging control\n"
       "Cancel logging to syslog\n"
       LOG_FACILITY_DESC
       LOG_LEVEL_DESC)
{
	log_config_syslog_lvl = ZLOG_DISABLED;
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl,
					     log_cmdline_syslog_lvl));
	return CMD_SUCCESS;
}

DEFPY (config_log_facility,
       config_log_facility_cmd,
       "log facility <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>$facilityarg",
       "Logging control\n"
       "Facility parameter for syslog messages\n"
       LOG_FACILITY_DESC)
{
	int facility = facility_match(facilityarg);

	zlog_syslog_set_facility(facility);
	return CMD_SUCCESS;
}

DEFUN (no_config_log_facility,
       no_config_log_facility_cmd,
       "no log facility [<kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>]",
       NO_STR
       "Logging control\n"
       "Reset syslog facility to default (daemon)\n"
       LOG_FACILITY_DESC)
{
	zlog_syslog_set_facility(LOG_DAEMON);
	return CMD_SUCCESS;
}

DEFUN (config_log_record_priority,
       config_log_record_priority_cmd,
       "log record-priority",
       "Logging control\n"
       "Log the priority of the message within the message\n")
{
	zt_file.record_priority = true;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.record_priority = true;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.record_priority = true;
	zlog_file_set_other(&zt_filterfile.parent);
	return CMD_SUCCESS;
}

DEFUN (no_config_log_record_priority,
       no_config_log_record_priority_cmd,
       "no log record-priority",
       NO_STR
       "Logging control\n"
       "Do not log the priority of the message within the message\n")
{
	zt_file.record_priority = false;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.record_priority = false;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.record_priority = false;
	zlog_file_set_other(&zt_filterfile.parent);
	return CMD_SUCCESS;
}

DEFPY (config_log_timestamp_precision,
       config_log_timestamp_precision_cmd,
       "log timestamp precision (0-6)",
       "Logging control\n"
       "Timestamp configuration\n"
       "Set the timestamp precision\n"
       "Number of subsecond digits\n")
{
	zt_file.ts_subsec = precision;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.ts_subsec = precision;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.ts_subsec = precision;
	zlog_file_set_other(&zt_filterfile.parent);
	return CMD_SUCCESS;
}

DEFUN (no_config_log_timestamp_precision,
       no_config_log_timestamp_precision_cmd,
       "no log timestamp precision [(0-6)]",
       NO_STR
       "Logging control\n"
       "Timestamp configuration\n"
       "Reset the timestamp precision to the default value of 0\n"
       "Number of subsecond digits\n")
{
	zt_file.ts_subsec = 0;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.ts_subsec = 0;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.ts_subsec = 0;
	zlog_file_set_other(&zt_filterfile.parent);
	return CMD_SUCCESS;
}

DEFPY (config_log_ec,
       config_log_ec_cmd,
       "[no] log error-category",
       NO_STR
       "Logging control\n"
       "Prefix log message text with [EC 9999] code\n")
{
	zlog_set_prefix_ec(!no);
	return CMD_SUCCESS;
}

DEFPY (config_log_xid,
       config_log_xid_cmd,
       "[no] log unique-id",
       NO_STR
       "Logging control\n"
       "Prefix log message text with [XXXXX-XXXXX] identifier\n")
{
	zlog_set_prefix_xid(!no);
	return CMD_SUCCESS;
}

DEFPY (config_log_filterfile,
       config_log_filterfile_cmd,
       "log filtered-file FILENAME [<emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg]",
       "Logging control\n"
       "Logging to file with string filter\n"
       "Logging filename\n"
       LOG_LEVEL_DESC)
{
	int level = log_default_lvl;

	if (levelarg) {
		level = log_level_match(levelarg);
		if (level == ZLOG_DISABLED)
			return CMD_ERR_NO_MATCH;
	}
	return set_log_file(&zt_filterfile.parent, vty, filename, level);
}

DEFUN (no_config_log_filterfile,
       no_config_log_filterfile_cmd,
       "no log filtered-file [FILENAME [LEVEL]]",
       NO_STR
       "Logging control\n"
       "Cancel logging to file with string filter\n"
       "Logging file name\n"
       "Logging level\n")
{
	zt_filterfile.parent.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_filterfile.parent);
	return CMD_SUCCESS;
}

DEFPY (log_filter,
       log_filter_cmd,
       "[no] log filter-text WORD$filter",
       NO_STR
       "Logging control\n"
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
       "clear log filter-text",
       CLEAR_STR
       "Logging control\n"
       FILTER_LOG_STR)
{
	zlog_filter_clear();
	return CMD_SUCCESS;
}

/* Show log filter */
DEFPY (show_log_filter,
       show_log_filter_cmd,
       "show logging filter-text",
       SHOW_STR
       "Show current logging configuration\n"
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

/* Enable/disable 'immediate' mode, with no output buffering */
DEFPY (log_immediate_mode,
       log_immediate_mode_cmd,
       "[no] log immediate-mode",
       NO_STR
       "Logging control\n"
       "Output immediately, without buffering\n")
{
	zlog_set_immediate(!no);
	return CMD_SUCCESS;
}

void log_config_write(struct vty *vty)
{
	bool show_cmdline_hint = false;

	if (zt_file.prio_min != ZLOG_DISABLED && zt_file.filename) {
		vty_out(vty, "log file %s", zt_file.filename);

		if (zt_file.prio_min != log_default_lvl)
			vty_out(vty, " %s", zlog_priority[zt_file.prio_min]);
		vty_out(vty, "\n");
	}

	if (zt_filterfile.parent.prio_min != ZLOG_DISABLED
	    && zt_filterfile.parent.filename) {
		vty_out(vty, "log filtered-file %s",
			zt_filterfile.parent.filename);

		if (zt_filterfile.parent.prio_min != log_default_lvl)
			vty_out(vty, " %s",
				zlog_priority[zt_filterfile.parent.prio_min]);
		vty_out(vty, "\n");
	}

	if (log_config_stdout_lvl != ZLOG_DISABLED) {
		vty_out(vty, "log stdout");

		if (log_config_stdout_lvl != log_default_lvl)
			vty_out(vty, " %s",
				zlog_priority[log_config_stdout_lvl]);
		vty_out(vty, "\n");
	}

	if (log_config_syslog_lvl != ZLOG_DISABLED) {
		vty_out(vty, "log syslog");

		if (log_config_syslog_lvl != log_default_lvl)
			vty_out(vty, " %s",
				zlog_priority[log_config_syslog_lvl]);
		vty_out(vty, "\n");
	}

	if (log_cmdline_syslog_lvl != ZLOG_DISABLED) {
		vty_out(vty,
			"! \"log syslog %s\" enabled by \"--log\" startup option\n",
			zlog_priority[log_cmdline_syslog_lvl]);
		show_cmdline_hint = true;
	}
	if (log_cmdline_stdout_lvl != ZLOG_DISABLED) {
		vty_out(vty,
			"! \"log stdout %s\" enabled by \"--log\" startup option\n",
			zlog_priority[log_cmdline_stdout_lvl]);
		show_cmdline_hint = true;
	}
	if (zt_file_cmdline.prio_min != ZLOG_DISABLED) {
		vty_out(vty,
			"! \"log file %s %s\" enabled by \"--log\" startup option\n",
			zt_file_cmdline.filename,
			zlog_priority[zt_file_cmdline.prio_min]);
		show_cmdline_hint = true;
	}
	if (show_cmdline_hint)
		vty_out(vty,
			"! use \"clear log cmdline-targets\" to remove this target\n");

	if (zlog_syslog_get_facility() != LOG_DAEMON)
		vty_out(vty, "log facility %s\n",
			facility_name(zlog_syslog_get_facility()));

	if (zt_file.record_priority == 1)
		vty_out(vty, "log record-priority\n");

	if (zt_file.ts_subsec > 0)
		vty_out(vty, "log timestamp precision %d\n",
			zt_file.ts_subsec);

	if (!zlog_get_prefix_ec())
		vty_out(vty, "no log error-category\n");
	if (!zlog_get_prefix_xid())
		vty_out(vty, "no log unique-id\n");
	if (zlog_get_immediate_mode())
		vty_out(vty, "log immediate-mode\n");

	if (logmsgs_with_persist_bt) {
		struct xrefdata *xrd;
		struct xrefdata_logmsg *xrdl;

		vty_out(vty, "!\n");

		frr_each (xrefdata_uid, &xrefdata_uid, xrd) {
			if (xrd->xref->type != XREFT_LOGMSG)
				continue;

			xrdl = container_of(xrd, struct xrefdata_logmsg,
					    xrefdata);
			if (xrdl->fl_print_bt & LOGMSG_FLAG_PERSISTENT)
				vty_out(vty, "debug unique-id %s backtrace\n",
					xrd->uid);
		}
	}
}

static int log_vty_fini(void)
{
	if (zt_file_cmdline.filename)
		zlog_file_fini(&zt_file_cmdline);
	if (zt_file.filename)
		zlog_file_fini(&zt_file);
	return 0;
}


static int log_vty_init(const char *progname, const char *protoname,
			 unsigned short instance, uid_t uid, gid_t gid)
{
	zlog_progname = progname;
	zlog_protoname = protoname;

	hook_register(zlog_fini, log_vty_fini);

	zlog_set_prefix_ec(true);
	zlog_set_prefix_xid(true);

	zlog_filterfile_init(&zt_filterfile);

	if (sd_stdout_is_journal) {
		stdout_journald_in_use = true;
		zlog_5424_init(&zt_stdout_journald);
		zlog_5424_apply_dst(&zt_stdout_journald);
	} else
		zlog_file_set_fd(&zt_stdout_file, STDOUT_FILENO);
	return 0;
}

__attribute__((_CONSTRUCTOR(475))) static void log_vty_preinit(void)
{
	hook_register(zlog_init, log_vty_init);
}

void log_cmd_init(void)
{
	install_element(VIEW_NODE, &show_logging_cmd);
	install_element(ENABLE_NODE, &clear_log_cmdline_cmd);

	install_element(CONFIG_NODE, &config_log_stdout_cmd);
	install_element(CONFIG_NODE, &no_config_log_stdout_cmd);
	install_element(CONFIG_NODE, &config_log_monitor_cmd);
	install_element(CONFIG_NODE, &no_config_log_monitor_cmd);
	install_element(CONFIG_NODE, &config_log_file_cmd);
	install_element(CONFIG_NODE, &config_log_dmn_file_cmd);
	install_element(CONFIG_NODE, &no_config_log_dmn_file_cmd);
	install_element(CONFIG_NODE, &no_config_log_file_cmd);
	install_element(CONFIG_NODE, &config_log_syslog_cmd);
	install_element(CONFIG_NODE, &no_config_log_syslog_cmd);
	install_element(CONFIG_NODE, &config_log_facility_cmd);
	install_element(CONFIG_NODE, &no_config_log_facility_cmd);
	install_element(CONFIG_NODE, &config_log_record_priority_cmd);
	install_element(CONFIG_NODE, &no_config_log_record_priority_cmd);
	install_element(CONFIG_NODE, &config_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &no_config_log_timestamp_precision_cmd);
	install_element(CONFIG_NODE, &config_log_ec_cmd);
	install_element(CONFIG_NODE, &config_log_xid_cmd);

	install_element(VIEW_NODE, &show_log_filter_cmd);
	install_element(CONFIG_NODE, &log_filter_cmd);
	install_element(CONFIG_NODE, &log_filter_clear_cmd);
	install_element(CONFIG_NODE, &config_log_filterfile_cmd);
	install_element(CONFIG_NODE, &no_config_log_filterfile_cmd);
	install_element(CONFIG_NODE, &log_immediate_mode_cmd);

	install_element(ENABLE_NODE, &debug_uid_backtrace_cmd);
	install_element(CONFIG_NODE, &debug_uid_backtrace_cmd);

	log_5424_cmd_init();
}
