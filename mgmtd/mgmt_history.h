// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 * Copyright (c) 2023, LabN Consulting, L.L.C.
 *
 */
#ifndef _FRR_MGMTD_HISTORY_H_
#define _FRR_MGMTD_HISTORY_H_

#include "vrf.h"

PREDECL_DLIST(mgmt_cmt_infos);

struct mgmt_ds_ctx;

/*
 * Rollback specific commit from commit history.
 *
 * vty
 *    VTY context.
 *
 * cmtid_str
 *    Specific commit id from commit history.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_history_rollback_by_id(struct vty *vty, const char *cmtid_str);

/*
 * Rollback n commits from commit history.
 *
 * vty
 *    VTY context.
 *
 * num_cmts
 *    Number of commits to be rolled back.
 *
 * Returns:
 *    0 on success, -1 on failure.
 */
extern int mgmt_history_rollback_n(struct vty *vty, int num_cmts);

extern void mgmt_history_rollback_complete(bool success);

/*
 * Show mgmt commit history.
 */
extern void show_mgmt_cmt_history(struct vty *vty);

extern void mgmt_history_new_record(struct mgmt_ds_ctx *ds_ctx);

extern void mgmt_history_destroy(void);
extern void mgmt_history_init(void);

/*
 * 012345678901234567890123456789
 * 2023-12-31T12:12:12,012345678
 * 20231231121212012345678
 */
#define MGMT_LONG_TIME_FMT "%Y-%m-%dT%H:%M:%S"
#define MGMT_LONG_TIME_MAX_LEN 30
#define MGMT_SHORT_TIME_FMT "%Y%m%d%H%M%S"
#define MGMT_SHORT_TIME_MAX_LEN 24

static inline const char *
mgmt_time_to_string(struct timespec *tv, bool long_fmt, char *buffer, size_t sz)
{
	struct tm tm;
	size_t n;

	localtime_r(&tv->tv_sec, &tm);

	if (long_fmt) {
		n = strftime(buffer, sz, MGMT_LONG_TIME_FMT, &tm);
		assert(n < sz);
		snprintf(&buffer[n], sz - n, ",%09lu", tv->tv_nsec);
	} else {
		n = strftime(buffer, sz, MGMT_SHORT_TIME_FMT, &tm);
		assert(n < sz);
		snprintf(&buffer[n], sz - n, "%09lu", tv->tv_nsec);
	}

	return buffer;
}

static inline const char *mgmt_realtime_to_string(struct timeval *tv, char *buf,
						  size_t sz)
{
	struct timespec ts = {.tv_sec = tv->tv_sec,
			      .tv_nsec = tv->tv_usec * 1000};

	return mgmt_time_to_string(&ts, true, buf, sz);
}

#endif /* _FRR_MGMTD_HISTORY_H_ */
