// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include <string.h>
#include <sys/time.h>
#include <time.h>

#include "log.h"
#include "frrevent.h"
#include "lib_errors.h"

#include "pim_time.h"

static int gettime_monotonic(struct timeval *tv)
{
	int result;

	result = gettimeofday(tv, 0);
	if (result) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s: gettimeofday() failure: errno=%d: %s",
			     __func__, errno, safe_strerror(errno));
	}

	return result;
}

/*
  pim_time_monotonic_sec():
  number of seconds since some unspecified starting point
*/
int64_t pim_time_monotonic_sec(void)
{
	struct timeval now_tv;

	if (gettime_monotonic(&now_tv)) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s: gettime_monotonic() failure: errno=%d: %s",
			     __func__, errno, safe_strerror(errno));
		return -1;
	}

	return now_tv.tv_sec;
}

/*
  pim_time_monotonic_dsec():
  number of deciseconds since some unspecified starting point
*/
int64_t pim_time_monotonic_dsec(void)
{
	struct timeval now_tv;
	int64_t now_dsec;

	if (gettime_monotonic(&now_tv)) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s: gettime_monotonic() failure: errno=%d: %s",
			     __func__, errno, safe_strerror(errno));
		return -1;
	}

	now_dsec = ((int64_t)now_tv.tv_sec) * 10
		   + ((int64_t)now_tv.tv_usec) / 100000;

	return now_dsec;
}

int64_t pim_time_monotonic_usec(void)
{
	struct timeval now_tv;
	int64_t now_dsec;

	if (gettime_monotonic(&now_tv)) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "%s: gettime_monotonic() failure: errno=%d: %s",
			     __func__, errno, safe_strerror(errno));
		return -1;
	}

	now_dsec =
		((int64_t)now_tv.tv_sec) * 1000000 + ((int64_t)now_tv.tv_usec);

	return now_dsec;
}

int pim_time_mmss(char *buf, int buf_size, long sec)
{
	long mm;
	int wr;

	assert(buf_size >= 5);

	mm = sec / 60;
	sec %= 60;

	wr = snprintf(buf, buf_size, "%02ld:%02ld", mm, sec);

	return wr != 8;
}

static int pim_time_hhmmss(char *buf, int buf_size, long sec)
{
	long hh;
	long mm;
	int wr;

	assert(buf_size >= 8);

	hh = sec / 3600;
	sec %= 3600;
	mm = sec / 60;
	sec %= 60;

	wr = snprintf(buf, buf_size, "%02ld:%02ld:%02ld", hh, mm, sec);

	return wr != 8;
}

void pim_time_timer_to_mmss(char *buf, int buf_size, struct event *t_timer)
{
	if (t_timer) {
		pim_time_mmss(buf, buf_size,
			      event_timer_remain_second(t_timer));
	} else {
		snprintf(buf, buf_size, "--:--");
	}
}

void pim_time_timer_to_hhmmss(char *buf, int buf_size, struct event *t_timer)
{
	if (t_timer) {
		pim_time_hhmmss(buf, buf_size,
				event_timer_remain_second(t_timer));
	} else {
		snprintf(buf, buf_size, "--:--:--");
	}
}

void pim_time_uptime(char *buf, int buf_size, int64_t uptime_sec)
{
	assert(buf_size >= 8);

	pim_time_hhmmss(buf, buf_size, uptime_sec);
}

void pim_time_uptime_begin(char *buf, int buf_size, int64_t now, int64_t begin)
{
	if (begin > 0)
		pim_time_uptime(buf, buf_size, now - begin);
	else
		snprintf(buf, buf_size, "--:--:--");
}

long pim_time_timer_remain_msec(struct event *t_timer)
{
	/* no timer thread running means timer has expired: return 0 */

	return t_timer ? event_timer_remain_msec(t_timer) : 0;
}
