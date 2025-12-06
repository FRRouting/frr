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
#include "lib/northbound_cli.h"
#include "lib/printfrr.h"
#include "lib/systemd.h"
#include "lib/vtysh_daemons.h"

#include "lib/log_vty_clippy.c"

#define ZLOG_MAXLVL(a, b) MAX(a, b)

DEFINE_HOOK(zlog_rotate, (), ());
DEFINE_HOOK(zlog_cli_show, (struct vty * vty), (vty));

uint logmsgs_with_persist_bt;

int log_config_stdout_lvl = ZLOG_DISABLED;
int log_config_syslog_lvl = ZLOG_DISABLED;
int log_cmdline_stdout_lvl = ZLOG_DISABLED;
int log_cmdline_syslog_lvl = ZLOG_DISABLED;

struct zlog_cfg_file zt_file_cmdline = {
	.prio_min = ZLOG_DISABLED,
	.ts_subsec = LOG_TIMESTAMP_PRECISION,
};
struct zlog_cfg_file zt_file = {
	.prio_min = ZLOG_DISABLED,
	.ts_subsec = LOG_TIMESTAMP_PRECISION,
};
struct zlog_cfg_filterfile zt_filterfile = {
	.parent =
		{
			.prio_min = ZLOG_DISABLED,
			.ts_subsec = LOG_TIMESTAMP_PRECISION,
		},
};

struct zlog_cfg_file zt_stdout_file = {
	.prio_min = ZLOG_DISABLED,
	.ts_subsec = LOG_TIMESTAMP_PRECISION,
};
struct zlog_cfg_5424 zt_stdout_journald = {
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
bool stdout_journald_in_use;

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

const char *const zlog_priority[] = {
	"emergencies",	 "alerts",	  "critical",  "errors", "warnings",
	"notifications", "informational", "debugging", NULL,
};

const char *const syslog_severity[] = {
	"emergency", "alert", "critical", "error", "warning", "notice", "info", "debug", NULL,
};

const char *zlog_priority_str(int priority)
{
	if (priority > LOG_DEBUG)
		return "invalid";
	else if (priority < 0)
		return "disabled";
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

const char *log_lev2sev(const char *level_name)
{
	int level = log_level_match(level_name);

	if (level == ZLOG_DISABLED)
		return "emergency";

	return syslog_severity[level];
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

void clear_cmdline_targets(void)
{
	zt_file_cmdline.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_file_cmdline);

	log_cmdline_syslog_lvl = ZLOG_DISABLED;
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl, log_cmdline_syslog_lvl));

	log_cmdline_stdout_lvl = ZLOG_DISABLED;
	log_stdout_apply_level();
}

DEFPY(send_log,
      send_log_cmd,
      "send log [level <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg] LINE...",
      "Send message\n"
      "Send log message\n"
      "Level of log message\n"
      LOG_LEVEL_DESC
      "Log message to send\n")
{
	const char *buf = vty->buf;
	int level = log_default_lvl;

	if (levelarg) {
		/* this checks using first 2 chars so works for both priority and severity */
		level = log_level_match(levelarg);
		assert(level != ZLOG_DISABLED);
	}

	/* find start of LINE in `buf` */
	while (*buf && isspace(*buf))
		buf++;
	for (; *buf && (*argv)->type != VARIABLE_TKN; argv++) {
		while (*buf && !isspace(*buf))
			buf++;
		while (*buf && isspace(*buf))
			buf++;
	}

	zlog(level, "%s", buf);
	return CMD_SUCCESS;
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
	vty_out(vty, "Record severity: %s\n", (zt_file.record_severity ? "enabled" : "disabled"));
	vty_out(vty, "Timestamp precision: %d\n", zt_file.ts_subsec);

	hook_call(zlog_cli_show, vty);
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
	install_element(VIEW_NODE, &send_log_cmd);
	install_element(VIEW_NODE, &show_logging_cmd);
	install_element(VIEW_NODE, &show_log_filter_cmd);
	install_element(ENABLE_NODE, &debug_uid_backtrace_cmd);

	log_5424_cmd_init();
}
