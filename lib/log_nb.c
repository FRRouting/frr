// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * June 8 2025, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2025, LabN Consulting, L.L.C.
 *
 */
#include <zebra.h>
#include "lib/command.h"
#include "lib/northbound.h"
#include "lib/lib_errors.h"
#include "lib/log.h"
#include "lib/log_vty.h"
#include "lib/vty.h"
// #include "lib/zlog_targets.h"
#include "lib/zlog_5424.h"

#define ZLOG_MAXLVL(a, b) MAX(a, b)

/* Default logging level in the YANG model */
const int log_default_lvl = LOG_DEBUG;

void log_stdout_apply_level(void)
{
	int maxlvl;

	maxlvl = ZLOG_MAXLVL(log_config_stdout_lvl, log_cmdline_stdout_lvl);

	if (stdout_journald_in_use) {
		if (zt_stdout_journald.prio_min == maxlvl)
			return;
		zt_stdout_journald.prio_min = maxlvl;
		zlog_5424_apply_meta(&zt_stdout_journald);
	} else {
		if (zt_stdout_file.prio_min == maxlvl)
			return;
		zt_stdout_file.prio_min = maxlvl;
		zlog_file_set_other(&zt_stdout_file);
	}
}

static int set_log_file(struct zlog_cfg_file *target, struct vty *vty, const char *fname,
			int loglevel)
{
	char path[MAXPATHLEN + 1];
	const char *fullpath;
	bool ok;

	/* Path detection. */
	if (!IS_DIRECTORY_SEP(*fname)) {
		char cwd[MAXPATHLEN + 1];
		int pr;

		cwd[MAXPATHLEN] = '\0';

		if (getcwd(cwd, MAXPATHLEN) == NULL) {
			flog_err_sys(EC_LIB_SYSTEM_CALL, "config_log_file: Unable to alloc mem!");
			return CMD_WARNING_CONFIG_FAILED;
		}

		pr = snprintf(path, sizeof(path), "%s/%s", cwd, fname);
		if (pr < 0 || (unsigned int)pr >= sizeof(path)) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "%s: Path too long ('%s/%s'); system maximum is %u", __func__,
				     cwd, fname, MAXPATHLEN);
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
		zlog_syslog_set_prio_min(
			ZLOG_MAXLVL(log_config_syslog_lvl, log_cmdline_syslog_lvl));
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

static int _get_level_value(const struct lyd_node *dnode, const char *xpath)
{
	const struct lyd_node *level_node;
	const char *level_str;

	assert(dnode);

	if (!xpath)
		level_node = dnode;
	else if (yang_dnode_exists(dnode, xpath))
		level_node = yang_dnode_get(dnode, xpath);
	else
		/* If we change the YANG level defaults this needs to look those up */
		return log_default_lvl;
	assert(level_node);

	level_str = lyd_get_value(level_node);
	assert(level_str);

	return log_level_match(level_str);
}

/*
 * XPath: /frr-logging:logging/stdout
 */
static int logging_stdout_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	log_config_stdout_lvl = _get_level_value(args->dnode, "level");
	log_stdout_apply_level();
	return NB_OK;
}


static int logging_stdout_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	log_config_stdout_lvl = ZLOG_DISABLED;
	log_stdout_apply_level();
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/stdout/level
 */
static int logging_stdout_level_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	log_config_stdout_lvl = _get_level_value(args->dnode, NULL);
	log_stdout_apply_level();
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/syslog
 */
static int logging_syslog_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	log_config_syslog_lvl = _get_level_value(args->dnode, "level");
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl, log_cmdline_syslog_lvl));
	return NB_OK;
}


static int logging_syslog_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	log_config_syslog_lvl = ZLOG_DISABLED;
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl, log_cmdline_syslog_lvl));
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/syslog/level
 */
static int logging_syslog_level_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	log_config_syslog_lvl = _get_level_value(args->dnode, NULL);
	zlog_syslog_set_prio_min(ZLOG_MAXLVL(log_config_syslog_lvl, log_cmdline_syslog_lvl));
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/file/filename
 */
static int logging_file_filename_modify(struct nb_cb_modify_args *args)
{
	const char *fname;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* XXX Need to check to see if daemon specific if set and ignore if so */

	fname = yang_dnode_get_string(args->dnode, NULL);
	level = _get_level_value(args->dnode, "../level");
	if (set_log_file(&zt_file, NULL, fname, level) != CMD_SUCCESS) {
		snprintf(args->errmsg, args->errmsg_len, "%% Can't open log file %s", fname);
		return NB_ERR_INCONSISTENCY;
	}
	return NB_OK;
}

static int logging_file_filename_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* XXX Need to check to see if daemon specific if set and ignore if so */

	zt_file.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_file);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/file/level
 */
static int logging_file_level_modify(struct nb_cb_modify_args *args)
{
	const char *fname = NULL;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* XXX Need to check to see if daemon specific if set and ignore if so */

	if (yang_dnode_exists(args->dnode, "../filename"))
		fname = yang_dnode_get_string(args->dnode, "../filename");
	if (!fname)
		fname = zt_file.filename;
	level = _get_level_value(args->dnode, NULL);
	if (set_log_file(&zt_file, NULL, fname, level) != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/filtered-file/filename
 */
static int logging_filtered_file_filename_modify(struct nb_cb_modify_args *args)
{
	const char *fname;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	fname = yang_dnode_get_string(args->dnode, NULL);
	level = _get_level_value(args->dnode, "../level");
	if (set_log_file(&zt_filterfile.parent, NULL, fname, level) != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;
	return NB_OK;
}

static int logging_filtered_file_filename_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zt_filterfile.parent.prio_min = ZLOG_DISABLED;
	zlog_file_set_other(&zt_filterfile.parent);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/filtered-file/level
 */
static int logging_filtered_file_level_modify(struct nb_cb_modify_args *args)
{
	const char *fname = NULL;
	int level;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (yang_dnode_exists(args->dnode, "../filename"))
		fname = yang_dnode_get_string(args->dnode, "../filename");
	if (!fname)
		fname = zt_file.filename;
	level = _get_level_value(args->dnode, NULL);
	if (set_log_file(&zt_filterfile.parent, NULL, fname, level) != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/filter-text
 */
static int logging_filter_text_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zlog_filter_add(yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}


static int logging_filter_text_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zlog_filter_del(yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/daemon-file
 */
static int logging_daemon_file_create(struct nb_cb_create_args *args)
{
	const char *daemon, *fname;
	int level;

	/* XXX Revist this and how it interacts with log file */

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	daemon = yang_dnode_get_string(args->dnode, "daemon");
	if (!strmatch(daemon, frr_get_progname()))
		return NB_OK;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	fname = yang_dnode_get_string(args->dnode, "filename");
	level = _get_level_value(args->dnode, "level");
	if (set_log_file(&zt_file, NULL, fname, level) != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;
	return NB_OK;
}


static int logging_daemon_file_destroy(struct nb_cb_destroy_args *args)
{
	const char *daemon;

	/* XXX Revist this and how it interacts with log file */
	/* Probably need to restore the /frr-logging:logging/file config */

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	daemon = yang_dnode_get_string(args->dnode, "daemon");
	if (!strmatch(daemon, frr_get_progname()))
		return NB_OK;


	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/daemon-file/filename
 */
static int logging_daemon_file_filename_modify(struct nb_cb_modify_args *args)
{
	const char *daemon;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* XXX Revist this and how it interacts with log file */

	daemon = yang_dnode_get_string(args->dnode, "../daemon");
	if (!strmatch(daemon, frr_get_progname()))
		return NB_OK;

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/daemon-file/level
 */
static int logging_daemon_file_level_modify(struct nb_cb_modify_args *args)
{
	const char *daemon, *fname;
	int level;

	/* XXX Revist this and how it interacts with log file */

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	daemon = yang_dnode_get_string(args->dnode, "../daemon");
	if (!strmatch(daemon, frr_get_progname()))
		return NB_OK;

	fname = yang_dnode_get_string(args->dnode, "../filename");
	level = _get_level_value(args->dnode, NULL);
	if (set_log_file(&zt_file, NULL, fname, level) != CMD_SUCCESS)
		return NB_ERR_INCONSISTENCY;
	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/facility
 */
static int logging_facility_modify(struct nb_cb_modify_args *args)
{
	const char *fs, *s;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	s = yang_dnode_get_string(args->dnode, NULL);
	fs = strchr(s, ':');
	if (fs)
		s = fs + 1;

	zlog_syslog_set_facility(facility_match(s));

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/record-priority
 */
static int logging_record_priority_modify(struct nb_cb_modify_args *args)
{
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	zt_file.record_priority = val;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.record_priority = val;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.record_priority = val;
	zlog_file_set_other(&zt_filterfile.parent);

	return NB_OK;
}

/*
 * XPath: /frr-logging:logging/record-severity
 */
static int logging_record_severity_modify(struct nb_cb_modify_args *args)
{
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	zt_file.record_severity = val;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.record_severity = val;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.record_severity = val;
	zlog_file_set_other(&zt_filterfile.parent);

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/timestamp-precision
 */
static int logging_timestamp_precision_modify(struct nb_cb_modify_args *args)
{
	uint8_t val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	val = yang_dnode_get_uint8(args->dnode, NULL);
	zt_file.ts_subsec = val;
	zlog_file_set_other(&zt_file);
	if (!stdout_journald_in_use) {
		zt_stdout_file.ts_subsec = val;
		zlog_file_set_other(&zt_stdout_file);
	}
	zt_filterfile.parent.ts_subsec = val;
	zlog_file_set_other(&zt_filterfile.parent);
	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/error-category
 */
static int logging_error_category_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zlog_set_prefix_ec(yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/unique-id
 */
static int logging_unique_id_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zlog_set_prefix_xid(yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/immediate-mode
 */
static int logging_immediate_mode_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	zlog_set_immediate(yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/uid-backtrace
 */
static int logging_uid_backtrace_create(struct nb_cb_create_args *args)
{
	struct xrefdata search, *xrd;
	struct xrefdata_logmsg *xrdl;
	const char *uid;

	if (args->event != NB_EV_APPLY && args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* XXX need to put some limits on the value in the YANG model */
	uid = yang_dnode_get_string(args->dnode, "uid");
	strlcpy(search.uid, uid, sizeof(search.uid));
	xrd = xrefdata_uid_find(&xrefdata_uid, &search);

	if (args->event == NB_EV_VALIDATE) {
		if (!xrd || xrd->xref->type != XREFT_LOGMSG) {
			if (args->errmsg && args->errmsg_len)
				snprintfrr(args->errmsg, args->errmsg_len,
					   "UID '%s' does not identify a log messages", uid);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	}

	/* This was done in the validation step */
	assert(xrd && xrd->xref->type == XREFT_LOGMSG);
	xrdl = container_of(xrd, struct xrefdata_logmsg, xrefdata);
	if (!(xrdl->fl_print_bt & LOGMSG_FLAG_PERSISTENT)) {
		xrdl->fl_print_bt |= LOGMSG_FLAG_PERSISTENT;
		logmsgs_with_persist_bt++;
	}

	return NB_OK;
}


static int logging_uid_backtrace_destroy(struct nb_cb_destroy_args *args)
{
	struct xrefdata search, *xrd;
	struct xrefdata_logmsg *xrdl;
	const char *uid;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	uid = yang_dnode_get_string(args->dnode, "uid");
	strlcpy(search.uid, uid, sizeof(search.uid));
	xrd = xrefdata_uid_find(&xrefdata_uid, &search);
	if (!xrd || xrd->xref->type != XREFT_LOGMSG)
		return NB_OK;

	xrdl = container_of(xrd, struct xrefdata_logmsg, xrefdata);
	if (xrdl->fl_print_bt & LOGMSG_FLAG_PERSISTENT) {
		xrdl->fl_print_bt &= ~LOGMSG_FLAG_PERSISTENT;
		logmsgs_with_persist_bt--;
	}

	return NB_OK;
}


/*
 * XPath: /frr-logging:logging/clear-cmdline-targets
 */
static int clear_cmdline_targets_rpc(struct nb_cb_rpc_args *args)
{
	clear_cmdline_targets();
	return NB_OK;
}


/* clang-format off */
struct frr_yang_module_info frr_logging_nb_info = {
	.name = "frr-logging",
	.nodes = {
		{
			.xpath = "/frr-logging:clear-cmdline-targets",
			.cbs = {
				.rpc = clear_cmdline_targets_rpc,
			}
		},
		{
			.xpath = "/frr-logging:logging/stdout",
			.cbs = {
				.create = logging_stdout_create,
				.destroy = logging_stdout_destroy,
			}
		},
		{
			.xpath = "/frr-logging:logging/stdout/level",
			.cbs = {
				.modify = logging_stdout_level_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/syslog",
			.cbs = {
				.create = logging_syslog_create,
				.destroy = logging_syslog_destroy,
			}
		},
		{
			.xpath = "/frr-logging:logging/syslog/level",
			.cbs = {
				.modify = logging_syslog_level_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/file/filename",
			.cbs = {
				.modify = logging_file_filename_modify,
				.destroy = logging_file_filename_destroy,
			}
		},
		{
			.xpath = "/frr-logging:logging/file/level",
			.cbs = {
				.modify = logging_file_level_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/filtered-file/filename",
			.cbs = {
				.modify = logging_filtered_file_filename_modify,
				.destroy = logging_filtered_file_filename_destroy,
			}
		},
		{
			.xpath = "/frr-logging:logging/filtered-file/level",
			.cbs = {
				.modify = logging_filtered_file_level_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/filter-text",
			.cbs = {
				.create = logging_filter_text_create,
				.destroy = logging_filter_text_destroy,
			}
		},
		{
			.xpath = "/frr-logging:logging/daemon-file",
			.cbs = {
				.create = logging_daemon_file_create,
				.destroy = logging_daemon_file_destroy,
			}
		},
		{
			.xpath = "/frr-logging:logging/daemon-file/filename",
			.cbs = {
				.modify = logging_daemon_file_filename_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/daemon-file/level",
			.cbs = {
				.modify = logging_daemon_file_level_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/facility",
			.cbs = {
				.modify = logging_facility_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/record-priority",
			.cbs = {
				.modify = logging_record_priority_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/record-severity",
			.cbs = {
				.modify = logging_record_severity_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/timestamp-precision",
			.cbs = {
				.modify = logging_timestamp_precision_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/error-category",
			.cbs = {
				.modify = logging_error_category_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/unique-id",
			.cbs = {
				.modify = logging_unique_id_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/immediate-mode",
			.cbs = {
				.modify = logging_immediate_mode_modify,
			}
		},
		{
			.xpath = "/frr-logging:logging/uid-backtrace",
			.cbs = {
				.create = logging_uid_backtrace_create,
				.destroy = logging_uid_backtrace_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
