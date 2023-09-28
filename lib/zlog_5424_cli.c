// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
 */

#include "zebra.h"
#include "zlog_5424.h"

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#include "lib/command.h"
#include "lib/libfrr.h"
#include "lib/log_vty.h"

DEFINE_MTYPE_STATIC(LOG, LOG_5424_CONFIG, "extended syslog config");
DEFINE_MTYPE_STATIC(LOG, LOG_5424_DATA, "extended syslog config items");

static int target_cmp(const struct zlog_cfg_5424_user *a,
		      const struct zlog_cfg_5424_user *b)
{
	return strcmp(a->name, b->name);
}

DECLARE_RBTREE_UNIQ(targets, struct zlog_cfg_5424_user, targets_item,
		    target_cmp);
DEFINE_QOBJ_TYPE(zlog_cfg_5424_user);

static struct targets_head targets = INIT_RBTREE_UNIQ(targets);
static struct event_loop *log_5424_master;

static void clear_dst(struct zlog_cfg_5424_user *cfg);

struct log_option {
	const char *name;
	ptrdiff_t offs;
	bool dflt;
};

/* clang-format off */
static struct log_option log_opts[] = {
	{ "code-location",	offsetof(struct zlog_cfg_5424, kw_location) },
	{ "version",		offsetof(struct zlog_cfg_5424, kw_version) },
	{ "unique-id",		offsetof(struct zlog_cfg_5424, kw_uid), true },
	{ "error-category",	offsetof(struct zlog_cfg_5424, kw_ec), true },
	{ "format-args",	offsetof(struct zlog_cfg_5424, kw_args) },
	{},
};

#define DFLT_TS_FLAGS		(6 | ZLOG_TS_UTC)
#define DFLT_FACILITY		LOG_DAEMON
#define DFLT_PRIO_MIN		LOG_DEBUG
/* clang-format on */

enum unix_special {
	SPECIAL_NONE = 0,
	SPECIAL_SYSLOG,
	SPECIAL_JOURNALD,
};

static struct zlog_cfg_5424_user *log_5424_alloc(const char *name)
{
	struct zlog_cfg_5424_user *cfg;

	cfg = XCALLOC(MTYPE_LOG_5424_CONFIG, sizeof(*cfg));
	cfg->name = XSTRDUP(MTYPE_LOG_5424_DATA, name);

	cfg->cfg.master = log_5424_master;
	cfg->cfg.kw_location = true;
	cfg->cfg.kw_version = false;
	cfg->cfg.facility = DFLT_FACILITY;
	cfg->cfg.prio_min = DFLT_PRIO_MIN;
	cfg->cfg.ts_flags = DFLT_TS_FLAGS;
	clear_dst(cfg);

	for (struct log_option *opt = log_opts; opt->name; opt++) {
		bool *ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);
		*ptr = opt->dflt;
	}

	zlog_5424_init(&cfg->cfg);

	QOBJ_REG(cfg, zlog_cfg_5424_user);
	targets_add(&targets, cfg);
	return cfg;
}

static void log_5424_free(struct zlog_cfg_5424_user *cfg, bool keepopen)
{
	targets_del(&targets, cfg);
	QOBJ_UNREG(cfg);

	zlog_5424_fini(&cfg->cfg, keepopen);
	clear_dst(cfg);

	XFREE(MTYPE_LOG_5424_DATA, cfg->filename);
	XFREE(MTYPE_LOG_5424_DATA, cfg->name);
	XFREE(MTYPE_LOG_5424_CONFIG, cfg);
}

static void clear_dst(struct zlog_cfg_5424_user *cfg)
{
	XFREE(MTYPE_LOG_5424_DATA, cfg->filename);
	cfg->cfg.filename = cfg->filename;

	XFREE(MTYPE_LOG_5424_DATA, cfg->file_user);
	XFREE(MTYPE_LOG_5424_DATA, cfg->file_group);
	XFREE(MTYPE_LOG_5424_DATA, cfg->envvar);

	cfg->cfg.fd = -1;
	cfg->cfg.file_uid = -1;
	cfg->cfg.file_gid = -1;
	cfg->cfg.file_mode = LOGFILE_MASK & 0666;
	cfg->cfg.file_nocreate = false;
	cfg->cfg.dst = ZLOG_5424_DST_NONE;
}

static int reconf_dst(struct zlog_cfg_5424_user *cfg, struct vty *vty)
{
	if (!cfg->reconf_dst && !cfg->reconf_meta && vty->type != VTY_FILE)
		vty_out(vty,
			"%% Changes will be applied when exiting this config block\n");

	cfg->reconf_dst = true;
	return CMD_SUCCESS;
}

static int reconf_meta(struct zlog_cfg_5424_user *cfg, struct vty *vty)
{
	if (!cfg->reconf_dst && !cfg->reconf_meta && vty->type != VTY_FILE)
		vty_out(vty,
			"%% Changes will be applied when exiting this config block\n");

	cfg->reconf_meta = true;
	return CMD_SUCCESS;
}

static int reconf_clear_dst(struct zlog_cfg_5424_user *cfg, struct vty *vty)
{
	if (cfg->cfg.dst == ZLOG_5424_DST_NONE)
		return CMD_SUCCESS;

	clear_dst(cfg);
	return reconf_dst(cfg, vty);
}

#include "lib/zlog_5424_cli_clippy.c"

DEFPY_NOSH(log_5424_target,
	   log_5424_target_cmd,
	   "log extended-syslog EXTLOGNAME",
	   "Logging control\n"
	   "Extended RFC5424 syslog (including file targets)\n"
	   "Name identifying this syslog target\n")
{
	struct zlog_cfg_5424_user *cfg, ref;

	ref.name = (char *)extlogname;
	cfg = targets_find(&targets, &ref);

	if (!cfg)
		cfg = log_5424_alloc(extlogname);

	VTY_PUSH_CONTEXT(EXTLOG_NODE, cfg);
	return CMD_SUCCESS;
}

DEFPY(no_log_5424_target,
      no_log_5424_target_cmd,
      "no log extended-syslog EXTLOGNAME",
      NO_STR
      "Logging control\n"
      "Extended RFC5424 syslog (including file targets)\n"
      "Name identifying this syslog target\n")
{
	struct zlog_cfg_5424_user *cfg, ref;

	ref.name = (char *)extlogname;
	cfg = targets_find(&targets, &ref);

	if (!cfg) {
		vty_out(vty, "%% No extended syslog target named \"%s\"\n",
			extlogname);
		return CMD_WARNING;
	}

	log_5424_free(cfg, false);
	return CMD_SUCCESS;
}

/*    "format <rfc3164|rfc5424|local-syslogd|journald>$fmt" */
#define FORMAT_HELP                                                            \
	"Select log message formatting\n"                                      \
	"RFC3164 (legacy) syslog\n"                                            \
	"RFC5424 (modern) syslog, supports structured data (default)\n"        \
	"modified RFC3164 without hostname for local syslogd (/dev/log)\n"     \
	"journald (systemd log) native format\n"                               \
	/* end */

static enum zlog_5424_format log_5424_fmt(const char *fmt,
					  enum zlog_5424_format dflt)
{
	if (!fmt)
		return dflt;
	else if (!strcmp(fmt, "rfc5424"))
		return ZLOG_FMT_5424;
	else if (!strcmp(fmt, "rfc3164"))
		return ZLOG_FMT_3164;
	else if (!strcmp(fmt, "local-syslogd"))
		return ZLOG_FMT_LOCAL;
	else if (!strcmp(fmt, "journald"))
		return ZLOG_FMT_JOURNALD;

	return dflt;
}

DEFPY(log_5424_destination_file,
      log_5424_destination_file_cmd,
      "[no] destination file$type PATH "
		"[create$create [{user WORD|group WORD|mode PERMS}]"
		"|no-create$nocreate] "
		"[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to file\n"
      "Path to destination\n"
      "Create file if it does not exist\n"
      "Set file owner\n"
      "User name\n"
      "Set file group\n"
      "Group name\n"
      "Set permissions\n"
      "File permissions (octal)\n"
      "Do not create file if it does not exist\n"
      FORMAT_HELP)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	enum zlog_5424_dst dst;
	bool reconf = true, warn_perm = false;
	char *prev_user, *prev_group;
	mode_t perm_val = LOGFILE_MASK & 0666;
	enum zlog_5424_format fmtv;

	if (no)
		return reconf_clear_dst(cfg, vty);

	fmtv = log_5424_fmt(fmt, ZLOG_FMT_5424);

	if (perms) {
		char *errp = (char *)perms;

		perm_val = strtoul(perms, &errp, 8);
		if (*errp || errp == perms || perm_val == 0 ||
		    (perm_val & ~0666)) {
			vty_out(vty, "%% Invalid permissions value \"%s\"\n",
				perms);
			return CMD_WARNING;
		}
	}

	dst = (strcmp(type, "fifo") == 0) ? ZLOG_5424_DST_FIFO
					  : ZLOG_5424_DST_FILE;

	if (cfg->filename && !strcmp(path, cfg->filename) &&
	    dst == cfg->cfg.dst && cfg->cfg.active && cfg->cfg.fmt == fmtv)
		reconf = false;

	/* keep for compare below */
	prev_user = cfg->file_user;
	prev_group = cfg->file_group;
	cfg->file_user = NULL;
	cfg->file_group = NULL;

	clear_dst(cfg);

	cfg->filename = XSTRDUP(MTYPE_LOG_5424_DATA, path);
	cfg->cfg.dst = dst;
	cfg->cfg.filename = cfg->filename;
	cfg->cfg.fmt = fmtv;

	if (nocreate)
		cfg->cfg.file_nocreate = true;
	else {
		if (user) {
			struct passwd *pwent;

			warn_perm |= (prev_user && strcmp(user, prev_user));
			cfg->file_user = XSTRDUP(MTYPE_LOG_5424_DATA, user);

			errno = 0;
			pwent = getpwnam(user);
			if (!pwent)
				vty_out(vty,
					"%% Could not look up user \"%s\" (%s), file owner will be left untouched!\n",
					user,
					errno ? safe_strerror(errno)
					      : "No entry by this user name");
			else
				cfg->cfg.file_uid = pwent->pw_uid;
		}
		if (group) {
			struct group *grent;

			warn_perm |= (prev_group && strcmp(group, prev_group));
			cfg->file_group = XSTRDUP(MTYPE_LOG_5424_DATA, group);

			errno = 0;
			grent = getgrnam(group);
			if (!grent)
				vty_out(vty,
					"%% Could not look up group \"%s\" (%s), file group will be left untouched!\n",
					group,
					errno ? safe_strerror(errno)
					      : "No entry by this group name");
			else
				cfg->cfg.file_gid = grent->gr_gid;
		}
	}
	XFREE(MTYPE_LOG_5424_DATA, prev_user);
	XFREE(MTYPE_LOG_5424_DATA, prev_group);

	if (cfg->cfg.file_uid != (uid_t)-1 || cfg->cfg.file_gid != (gid_t)-1) {
		struct stat st;

		if (stat(cfg->filename, &st) == 0) {
			warn_perm |= (st.st_uid != cfg->cfg.file_uid);
			warn_perm |= (st.st_gid != cfg->cfg.file_gid);
		}
	}
	if (warn_perm)
		vty_out(vty,
			"%% Warning: ownership and permission bits are only applied when creating\n"
			"%%          log files.  Use system tools to change existing files.\n"
			"%%          FRR may also be missing necessary privileges to set these.\n");

	if (reconf)
		return reconf_dst(cfg, vty);

	return CMD_SUCCESS;
}

/* FIFOs are for legacy /dev/log implementations;  using this is very much not
 * recommended since it can unexpectedly block in logging calls.  Also the fd
 * would need to be reopened when the process at the other end restarts.  None
 * of this is handled - use at your own caution.  It's _HIDDEN for a purpose.
 */
ALIAS_HIDDEN(log_5424_destination_file,
	     log_5424_destination_fifo_cmd,
      "[no] destination fifo$type PATH "
		"[create$create [{owner WORD|group WORD|permissions PERMS}]"
		"|no-create$nocreate] "
		"[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to filesystem FIFO\n"
      "Path to destination\n"
      "Create file if it does not exist\n"
      "Set file owner\n"
      "User name\n"
      "Set file group\n"
      "Group name\n"
      "Set permissions\n"
      "File permissions (octal)\n"
      "Do not create file if it does not exist\n"
      FORMAT_HELP)

static int dst_unix(struct vty *vty, const char *no, const char *path,
		    enum zlog_5424_format fmt, enum unix_special special)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);

	if (no)
		return reconf_clear_dst(cfg, vty);

	cfg->unix_special = special;

	if (cfg->cfg.dst == ZLOG_5424_DST_UNIX && cfg->filename &&
	    !strcmp(path, cfg->filename) && cfg->cfg.active &&
	    cfg->cfg.fmt == fmt)
		return CMD_SUCCESS;

	clear_dst(cfg);

	cfg->filename = XSTRDUP(MTYPE_LOG_5424_DATA, path);
	cfg->cfg.dst = ZLOG_5424_DST_UNIX;
	cfg->cfg.filename = cfg->filename;
	cfg->cfg.fmt = fmt;

	cfg->cfg.reconn_backoff = 25;
	cfg->cfg.reconn_backoff_cur = 25;
	cfg->cfg.reconn_backoff_max = 10000;
	return reconf_dst(cfg, vty);
}

DEFPY(log_5424_destination_unix,
      log_5424_destination_unix_cmd,
      "[no] destination unix PATH "
		 "[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to unix socket\n"
      "Unix socket path\n"
      FORMAT_HELP)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	enum zlog_5424_format fmtv = log_5424_fmt(fmt, ZLOG_FMT_5424);

	return dst_unix(vty, no, path, fmtv, SPECIAL_NONE);
}

DEFPY(log_5424_destination_journald,
      log_5424_destination_journald_cmd,
      "[no] destination journald",
      NO_STR
      "Log destination setup\n"
      "Log directly to systemd's journald\n")
{
	return dst_unix(vty, no, "/run/systemd/journal/socket",
			ZLOG_FMT_JOURNALD, SPECIAL_JOURNALD);
}

#if defined(__FreeBSD_version) && (__FreeBSD_version >= 1200061)
#define ZLOG_FMT_DEV_LOG	ZLOG_FMT_5424
#elif defined(__NetBSD_Version__) && (__NetBSD_Version__ >= 500000000)
#define ZLOG_FMT_DEV_LOG	ZLOG_FMT_5424
#else
#define ZLOG_FMT_DEV_LOG	ZLOG_FMT_LOCAL
#endif

DEFPY(log_5424_destination_syslog,
      log_5424_destination_syslog_cmd,
      "[no] destination syslog [supports-rfc5424]$supp5424",
      NO_STR
      "Log destination setup\n"
      "Log directly to syslog\n"
      "Use RFC5424 format (please refer to documentation)\n")
{
	int format = supp5424 ? ZLOG_FMT_5424 : ZLOG_FMT_DEV_LOG;

	/* unfortunately, there is no way to detect 5424 support */
	return dst_unix(vty, no, "/dev/log", format, SPECIAL_SYSLOG);
}

/* could add something like
 *   "destination <udp|tcp>$proto <A.B.C.D|X:X::X:X> (1-65535)$port"
 * here, but there are 2 reasons not to do that:
 *
 *  - each FRR daemon would open its own connection, there's no system level
 *    aggregation.  That's the system's syslogd's job.  It likely also
 *    supports directing & filtering log messages with configurable rules.
 *  - we're likely not going to support DTLS or TLS for more secure logging;
 *    adding this would require a considerable amount of additional config
 *    and an entire TLS library to begin with.  A proper syslogd implements
 *    all of this, why reinvent the wheel?
 */

DEFPY(log_5424_destination_fd,
      log_5424_destination_fd_cmd,
      "[no] destination <fd <(0-63)$fd|envvar WORD>|stdout$fd1|stderr$fd2>"
		 "[format <rfc3164|rfc5424|local-syslogd|journald>$fmt]",
      NO_STR
      "Log destination setup\n"
      "Log to pre-opened file descriptor\n"
      "File descriptor number (must be open at startup)\n"
      "Read file descriptor number from environment variable\n"
      "Environment variable name\n"
      "Log to standard output\n"
      "Log to standard error output\n"
      FORMAT_HELP)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	bool envvar_problem = false;
	enum zlog_5424_format fmtv;

	if (no)
		return reconf_clear_dst(cfg, vty);

	fmtv = log_5424_fmt(fmt, ZLOG_FMT_5424);

	if (envvar) {
		char *envval;

		envval = getenv(envvar);
		if (!envval)
			envvar_problem = true;
		else {
			char *errp = envval;

			fd = strtoul(envval, &errp, 0);
			if (errp == envval || *errp)
				envvar_problem = true;
		}

		if (envvar_problem)
			fd = -1;
	} else if (fd1)
		fd = 1;
	else if (fd2)
		fd = 2;

	if (cfg->cfg.dst == ZLOG_5424_DST_FD && cfg->cfg.fd == fd &&
	    cfg->cfg.active && cfg->cfg.fmt == fmtv)
		return CMD_SUCCESS;

	clear_dst(cfg);

	cfg->cfg.dst = ZLOG_5424_DST_FD;
	cfg->cfg.fd = fd;
	cfg->cfg.fmt = fmtv;
	if (envvar)
		cfg->envvar = XSTRDUP(MTYPE_LOG_5424_DATA, envvar);

	if (envvar_problem)
		vty_out(vty,
			"%% environment variable \"%s\" not present or invalid.\n",
			envvar);
	if (!frr_is_startup_fd(fd))
		vty_out(vty,
			"%% file descriptor %d was not open when this process was started\n",
			(int)fd);
	if (envvar_problem || !frr_is_startup_fd(fd))
		vty_out(vty,
			"%% configuration will be saved but has no effect currently\n");

	return reconf_dst(cfg, vty);
}

DEFPY(log_5424_destination_none,
      log_5424_destination_none_cmd,
      "[no] destination [none]",
      NO_STR
      "Log destination setup\n"
      "Deconfigure destination\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);

	return reconf_clear_dst(cfg, vty);
}

/* end of destinations */

DEFPY(log_5424_prio,
      log_5424_prio_cmd,
      "[no] priority <emergencies|alerts|critical|errors|warnings|notifications|informational|debugging>$levelarg",
      NO_STR
      "Set minimum message priority to include for this target\n"
      LOG_LEVEL_DESC)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	int prio_min = log_level_match(levelarg);

	if (prio_min == cfg->cfg.prio_min)
		return CMD_SUCCESS;

	cfg->cfg.prio_min = prio_min;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_facility,
      log_5424_facility_cmd,
      "[no] facility <kern|user|mail|daemon|auth|syslog|lpr|news|uucp|cron|local0|local1|local2|local3|local4|local5|local6|local7>$facilityarg",
      NO_STR
      "Set syslog facility to use\n"
      LOG_FACILITY_DESC)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	int facility = facility_match(facilityarg);

	if (cfg->cfg.facility == facility)
		return CMD_SUCCESS;

	cfg->cfg.facility = facility;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_meta,
      log_5424_meta_cmd,
      "[no] structured-data <code-location|version|unique-id|error-category|format-args>$option",
      NO_STR
      "Select structured data (key/value pairs) to include in each message\n"
      "FRR source code location\n"
      "FRR version\n"
      "Unique message identifier (XXXXX-XXXXX)\n"
      "Error category (EC numeric)\n"
      "Individual formatted log message arguments\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	bool val = !no, *ptr;
	struct log_option *opt = log_opts;

	while (opt->name && strcmp(opt->name, option))
		opt++;
	if (!opt->name)
		return CMD_WARNING;

	ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);
	if (*ptr == val)
		return CMD_SUCCESS;

	*ptr = val;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_ts_prec,
      log_5424_ts_prec_cmd,
      "[no] timestamp precision (0-9)",
      NO_STR
      "Timestamp options\n"
      "Number of sub-second digits to include\n"
      "Number of sub-second digits to include\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	uint32_t ts_flags = cfg->cfg.ts_flags;

	ts_flags &= ~ZLOG_TS_PREC;
	if (no)
		ts_flags |= DFLT_TS_FLAGS & ZLOG_TS_PREC;
	else
		ts_flags |= precision;

	if (ts_flags == cfg->cfg.ts_flags)
		return CMD_SUCCESS;

	cfg->cfg.ts_flags = ts_flags;
	return reconf_meta(cfg, vty);
}

DEFPY(log_5424_ts_local,
      log_5424_ts_local_cmd,
      "[no] timestamp local-time",
      NO_STR
      "Timestamp options\n"
      "Use local system time zone rather than UTC\n")
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);
	uint32_t ts_flags = cfg->cfg.ts_flags;

	ts_flags &= ~ZLOG_TS_UTC;
	if (no)
		ts_flags |= DFLT_TS_FLAGS & ZLOG_TS_UTC;
	else
		ts_flags |= (~DFLT_TS_FLAGS) & ZLOG_TS_UTC;

	if (ts_flags == cfg->cfg.ts_flags)
		return CMD_SUCCESS;

	cfg->cfg.ts_flags = ts_flags;
	return reconf_meta(cfg, vty);
}

static int log_5424_node_exit(struct vty *vty)
{
	VTY_DECLVAR_CONTEXT(zlog_cfg_5424_user, cfg);

	if ((cfg->reconf_dst || cfg->reconf_meta) && vty->type != VTY_FILE)
		vty_out(vty, "%% applying changes.\n");

	if (cfg->reconf_dst)
		zlog_5424_apply_dst(&cfg->cfg);
	else if (cfg->reconf_meta)
		zlog_5424_apply_meta(&cfg->cfg);

	cfg->reconf_dst = cfg->reconf_meta = false;
	return 1;
}

static int log_5424_config_write(struct vty *vty)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg) {
		const char *fmt_str = "";

		vty_out(vty, "log extended %s\n", cfg->name);

		switch (cfg->cfg.fmt) {
		case ZLOG_FMT_5424:
			fmt_str = " format rfc5424";
			break;
		case ZLOG_FMT_3164:
			fmt_str = " format rfc3164";
			break;
		case ZLOG_FMT_LOCAL:
			fmt_str = " format local-syslogd";
			break;
		case ZLOG_FMT_JOURNALD:
			fmt_str = " format journald";
			break;
		}

		switch (cfg->cfg.dst) {
		case ZLOG_5424_DST_NONE:
			vty_out(vty, " ! no destination configured\n");
			break;

		case ZLOG_5424_DST_FD:
			if (cfg->cfg.fmt == ZLOG_FMT_5424)
				fmt_str = "";

			if (cfg->envvar)
				vty_out(vty, " destination fd envvar %s%s\n",
					cfg->envvar, fmt_str);
			else if (cfg->cfg.fd == 1)
				vty_out(vty, " destination stdout%s\n",
					fmt_str);
			else if (cfg->cfg.fd == 2)
				vty_out(vty, " destination stderr%s\n",
					fmt_str);
			else
				vty_out(vty, " destination fd %d%s\n",
					cfg->cfg.fd, fmt_str);
			break;

		case ZLOG_5424_DST_FILE:
		case ZLOG_5424_DST_FIFO:
			if (cfg->cfg.fmt == ZLOG_FMT_5424)
				fmt_str = "";

			vty_out(vty, " destination %s %s",
				(cfg->cfg.dst == ZLOG_5424_DST_FIFO) ? "fifo"
								     : "file",
				cfg->filename);

			if (cfg->cfg.file_nocreate)
				vty_out(vty, " no-create");
			else if (cfg->file_user || cfg->file_group ||
				 cfg->cfg.file_mode != (LOGFILE_MASK & 0666)) {
				vty_out(vty, " create");

				if (cfg->file_user)
					vty_out(vty, " user %s",
						cfg->file_user);
				if (cfg->file_group)
					vty_out(vty, " group %s",
						cfg->file_group);
				if (cfg->cfg.file_mode != (LOGFILE_MASK & 0666))
					vty_out(vty, " mode %04o",
						cfg->cfg.file_mode);
			}
			vty_out(vty, "%s\n", fmt_str);
			break;

		case ZLOG_5424_DST_UNIX:
			switch (cfg->unix_special) {
			case SPECIAL_NONE:
				vty_out(vty, " destination unix %s%s\n",
					cfg->filename, fmt_str);
				break;
			case SPECIAL_SYSLOG:
				if (cfg->cfg.fmt == ZLOG_FMT_DEV_LOG)
					vty_out(vty, " destination syslog\n");
				else
					vty_out(vty,
						" destination syslog supports-rfc5424\n");
				break;
			case SPECIAL_JOURNALD:
				vty_out(vty, " destination journald\n");
				break;
			}
			break;
		}

		if (cfg->cfg.prio_min != LOG_DEBUG)
			vty_out(vty, " priority %s\n",
				zlog_priority_str(cfg->cfg.prio_min));
		if (cfg->cfg.facility != DFLT_FACILITY)
			vty_out(vty, " facility %s\n",
				facility_name(cfg->cfg.facility));

		for (struct log_option *opt = log_opts; opt->name; opt++) {
			bool *ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);

			if (*ptr != opt->dflt)
				vty_out(vty, " %sstructured-data %s\n",
					*ptr ? "" : "no ", opt->name);
		}

		if ((cfg->cfg.ts_flags ^ DFLT_TS_FLAGS) & ZLOG_TS_PREC)
			vty_out(vty, " timestamp precision %u\n",
				cfg->cfg.ts_flags & ZLOG_TS_PREC);

		if ((cfg->cfg.ts_flags ^ DFLT_TS_FLAGS) & ZLOG_TS_UTC) {
			if (cfg->cfg.ts_flags & ZLOG_TS_UTC)
				vty_out(vty, " no timestamp local-time\n");
			else
				vty_out(vty, " timestamp local-time\n");
		}

		vty_out(vty, "!\n");
	}
	return 0;
}

static int log_5424_show(struct vty *vty)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg) {
		vty_out(vty, "\nExtended log target %pSQq\n", cfg->name);

		switch (cfg->cfg.dst) {
		case ZLOG_5424_DST_NONE:
			vty_out(vty,
				"  Inactive (no destination configured)\n");
			break;

		case ZLOG_5424_DST_FD:
			if (cfg->envvar)
				vty_out(vty,
					"  logging to fd %d from environment variable %pSE\n",
					cfg->cfg.fd, cfg->envvar);
			else if (cfg->cfg.fd == 1)
				vty_out(vty, "  logging to stdout\n");
			else if (cfg->cfg.fd == 2)
				vty_out(vty, "  logging to stderr\n");
			else
				vty_out(vty, "  logging to fd %d\n",
					cfg->cfg.fd);
			break;

		case ZLOG_5424_DST_FILE:
		case ZLOG_5424_DST_FIFO:
		case ZLOG_5424_DST_UNIX:
			vty_out(vty, "  logging to %s: %pSE\n",
				(cfg->cfg.dst == ZLOG_5424_DST_FIFO) ? "fifo"
				: (cfg->cfg.dst == ZLOG_5424_DST_UNIX)
					? "unix socket"
					: "file",
				cfg->filename);
			break;
		}

		vty_out(vty, "  log level: %s, facility: %s\n",
			zlog_priority_str(cfg->cfg.prio_min),
			facility_name(cfg->cfg.facility));

		bool any_meta = false, first = true;

		for (struct log_option *opt = log_opts; opt->name; opt++) {
			bool *ptr = (bool *)(((char *)&cfg->cfg) + opt->offs);

			any_meta |= *ptr;
		}

		if (!any_meta)
			continue;

		switch (cfg->cfg.fmt) {
		case ZLOG_FMT_5424:
		case ZLOG_FMT_JOURNALD:
			vty_out(vty, "  structured data: ");

			for (struct log_option *opt = log_opts; opt->name;
			     opt++) {
				bool *ptr = (bool *)(((char *)&cfg->cfg) +
						     opt->offs);

				if (*ptr) {
					vty_out(vty, "%s%s", first ? "" : ", ",
						opt->name);
					first = false;
				}
			}
			break;

		case ZLOG_FMT_3164:
		case ZLOG_FMT_LOCAL:
			vty_out(vty,
				"  structured data is not supported by the selected format\n");
			break;
		}

		vty_out(vty, "\n");

		size_t lost_msgs;
		int last_errno;
		bool stale_errno;
		struct timeval err_ts;
		int64_t since;

		zlog_5424_state(&cfg->cfg, &lost_msgs, &last_errno,
				&stale_errno, &err_ts);
		vty_out(vty, "  number of lost messages: %zu\n", lost_msgs);

		if (last_errno == 0)
			since = 0;
		else
			since = monotime_since(&err_ts, NULL);
		vty_out(vty,
			"  last error: %s (%lld.%06llds ago, currently %s)\n",
			last_errno ? safe_strerror(last_errno) : "none",
			since / 1000000LL, since % 1000000LL,
			stale_errno ? "OK" : "erroring");
	}
	return 0;
}

static struct cmd_node extlog_node = {
	.name = "extended",
	.node = EXTLOG_NODE,
	.parent_node = CONFIG_NODE,
	.prompt = "%s(config-ext-log)# ",

	.config_write = log_5424_config_write,
	.node_exit = log_5424_node_exit,
};

static void log_5424_autocomplete(vector comps, struct cmd_token *token)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, cfg->name));
}

static const struct cmd_variable_handler log_5424_var_handlers[] = {
	{.tokenname = "EXTLOGNAME", .completions = log_5424_autocomplete},
	{.completions = NULL},
};

void log_5424_cmd_init(void)
{
	hook_register(zlog_cli_show, log_5424_show);

	cmd_variable_handler_register(log_5424_var_handlers);

	/* CLI commands. */
	install_node(&extlog_node);
	install_default(EXTLOG_NODE);

	install_element(CONFIG_NODE, &log_5424_target_cmd);
	install_element(CONFIG_NODE, &no_log_5424_target_cmd);

	install_element(EXTLOG_NODE, &log_5424_destination_file_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_fifo_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_unix_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_journald_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_syslog_cmd);
	install_element(EXTLOG_NODE, &log_5424_destination_fd_cmd);

	install_element(EXTLOG_NODE, &log_5424_meta_cmd);
	install_element(EXTLOG_NODE, &log_5424_prio_cmd);
	install_element(EXTLOG_NODE, &log_5424_facility_cmd);
	install_element(EXTLOG_NODE, &log_5424_ts_prec_cmd);
	install_element(EXTLOG_NODE, &log_5424_ts_local_cmd);
}

/* hooks */

static int log_5424_early_init(struct event_loop *master);
static int log_5424_rotate(void);
static int log_5424_fini(void);

__attribute__((_CONSTRUCTOR(475))) static void zlog_5424_startup_init(void)
{
	hook_register(frr_early_init, log_5424_early_init);
	hook_register(zlog_rotate, log_5424_rotate);
	hook_register(frr_fini, log_5424_fini);
}

static int log_5424_early_init(struct event_loop *master)
{
	log_5424_master = master;

	return 0;
}

static int log_5424_rotate(void)
{
	struct zlog_cfg_5424_user *cfg;

	frr_each (targets, &targets, cfg)
		if (!zlog_5424_rotate(&cfg->cfg))
			zlog_err(
				"log rotation on extended log target %s failed",
				cfg->name);

	return 0;
}

static int log_5424_fini(void)
{
	struct zlog_cfg_5424_user *cfg;

	while ((cfg = targets_pop(&targets)))
		log_5424_free(cfg, true);

	log_5424_master = NULL;

	return 0;
}
