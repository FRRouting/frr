// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_ZLOG_TARGETS_H
#define _FRR_ZLOG_TARGETS_H

#include <pthread.h>

#include "zlog.h"

#ifdef __cplusplus
extern "C" {
#endif

/* multiple file log targets can be active */

struct zlt_fd;

struct zlog_cfg_file {
	struct zlt_fd *active;

	pthread_mutex_t cfg_mtx;

	/* call zlog_file_set_other() to apply these */
	int prio_min;
	char ts_subsec;
	bool record_priority;

	/* call zlog_file_set_filename/fd() to change this */
	char *filename;
	int fd;

	void (*zlog_wrap)(struct zlog_target *zt, struct zlog_msg *msgs[],
			  size_t nmsgs);
};

extern void zlog_file_init(struct zlog_cfg_file *zcf);
extern void zlog_file_fini(struct zlog_cfg_file *zcf);

extern void zlog_file_set_other(struct zlog_cfg_file *zcf);
extern bool zlog_file_set_filename(struct zlog_cfg_file *zcf, const char *name);
extern bool zlog_file_set_fd(struct zlog_cfg_file *zcf, int fd);
extern bool zlog_file_rotate(struct zlog_cfg_file *zcf);

extern void zlog_fd(struct zlog_target *zt, struct zlog_msg *msgs[],
		    size_t nmsgs);

/* syslog is always limited to one target */

extern void zlog_syslog_set_facility(int facility);
extern int zlog_syslog_get_facility(void);

/* use ZLOG_DISABLED to disable */
extern void zlog_syslog_set_prio_min(int prio_min);
extern int zlog_syslog_get_prio_min(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ZLOG_TARGETS_H */
