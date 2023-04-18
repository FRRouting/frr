// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2021  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_ZLOG_5424_H
#define _FRR_ZLOG_5424_H

#include <sys/stat.h>

#include "typerb.h"
#include "zlog.h"
#include "zlog_targets.h"
#include "qobj.h"

struct event;
struct event_loop;

enum zlog_5424_dst {
	/* can be used to disable a target temporarily */
	ZLOG_5424_DST_NONE = 0,

	ZLOG_5424_DST_FD,
	ZLOG_5424_DST_FILE,
	ZLOG_5424_DST_FIFO,
	ZLOG_5424_DST_UNIX,

#define ZLOG_5424_DST_LAST ZLOG_5424_DST_UNIX
};

enum zlog_5424_format {
	ZLOG_FMT_5424 = 0,
	ZLOG_FMT_3164,
	ZLOG_FMT_LOCAL,
	ZLOG_FMT_JOURNALD,

#define ZLOG_FMT_LAST ZLOG_FMT_JOURNALD
};

/* actual RCU'd logging backend */
struct zlt_5424;

struct zlog_cfg_5424 {
	struct zlt_5424 *active;

	pthread_mutex_t cfg_mtx;

	/* general settings for all dsts */
	int facility;
	int prio_min;
	bool kw_version;
	bool kw_location;
	bool kw_uid;
	bool kw_ec;
	bool kw_args;

	uint32_t ts_flags;

	enum zlog_5424_format fmt;

	/* destination specifics */
	enum zlog_5424_dst dst;

	/* pre-opened FD.  not the actual fd we log to */
	int fd;

	/* file, fifo, unix */
	bool file_nocreate;

	const char *filename;
	mode_t file_mode;
	/* -1 = no change */
	uid_t file_uid;
	gid_t file_gid;

	/* remaining fields are internally used & updated by the 5424
	 * code - *not* config.  don't set these.
	 */

	/* sockets only - read handler to reconnect on errors */
	struct event_loop *master;
	struct event *t_reconnect;
	unsigned int reconn_backoff, reconn_backoff_cur, reconn_backoff_max;
	int sock_type;
	struct sockaddr_storage sa;
	socklen_t sa_len;
};

/* these don't do malloc/free to allow using a static global */
extern void zlog_5424_init(struct zlog_cfg_5424 *zcf);

/* keepopen = true => for shutdown, just zap the config, keep logging */
extern void zlog_5424_fini(struct zlog_cfg_5424 *zcf, bool keepopen);

/* apply metadata/config changes */
extern bool zlog_5424_apply_meta(struct zlog_cfg_5424 *zcf);

/* apply changes requiring (re-)opening the destination
 *
 * also does log cycling/rotate & applies _meta at the same time
 */
extern bool zlog_5424_apply_dst(struct zlog_cfg_5424 *zcf);

/* SIGHUP log rotation */
extern bool zlog_5424_rotate(struct zlog_cfg_5424 *zcf);

extern void zlog_5424_state(struct zlog_cfg_5424 *zcf, size_t *lost_msgs,
			    int *last_errno, bool *stale_errno,
			    struct timeval *err_ts);

/* this is the dynamically allocated "variant" */
PREDECL_RBTREE_UNIQ(targets);

struct zlog_cfg_5424_user {
	struct targets_item targets_item;
	char *name;

	struct zlog_cfg_5424 cfg;

	char *envvar;

	/* non-const, always same as cfg.filename */
	char *filename;

	/* uid/gid strings to write back out in show config */
	char *file_user;
	char *file_group;

	bool reconf_dst;
	bool reconf_meta;

	int unix_special;

	QOBJ_FIELDS;
};

DECLARE_QOBJ_TYPE(zlog_cfg_5424_user);

extern void log_5424_cmd_init(void);

#endif /* _FRR_ZLOG_5424_H */
