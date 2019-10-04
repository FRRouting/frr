/*
 * Copyright (c) 2017  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_MONOTIME_H
#define _FRR_MONOTIME_H

#include <stdint.h>
#include <time.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TIMESPEC_TO_TIMEVAL
/* should be in sys/time.h on BSD & Linux libcs */
#define TIMESPEC_TO_TIMEVAL(tv, ts)                                            \
	do {                                                                   \
		(tv)->tv_sec = (ts)->tv_sec;                                   \
		(tv)->tv_usec = (ts)->tv_nsec / 1000;                          \
	} while (0)
#endif
#ifndef TIMEVAL_TO_TIMESPEC
/* should be in sys/time.h on BSD & Linux libcs */
#define TIMEVAL_TO_TIMESPEC(tv, ts)                                            \
	do {                                                                   \
		(ts)->tv_sec = (tv)->tv_sec;                                   \
		(ts)->tv_nsec = (tv)->tv_usec * 1000;                          \
	} while (0)
#endif

static inline time_t monotime(struct timeval *tvo)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	if (tvo) {
		TIMESPEC_TO_TIMEVAL(tvo, &ts);
	}
	return ts.tv_sec;
}

#define ONE_DAY_SECOND 60*60*24
#define ONE_WEEK_SECOND ONE_DAY_SECOND*7
#define ONE_YEAR_SECOND ONE_DAY_SECOND*365

/* the following two return microseconds, not time_t!
 *
 * also, they're negative forms of each other, but having both makes the
 * code more readable
 */
static inline int64_t monotime_since(const struct timeval *ref,
				     struct timeval *out)
{
	struct timeval tv;
	monotime(&tv);
	timersub(&tv, ref, &tv);
	if (out)
		*out = tv;
	return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}

static inline int64_t monotime_until(const struct timeval *ref,
				     struct timeval *out)
{
	struct timeval tv;
	monotime(&tv);
	timersub(ref, &tv, &tv);
	if (out)
		*out = tv;
	return (int64_t)tv.tv_sec * 1000000LL + tv.tv_usec;
}

static inline time_t monotime_to_realtime(const struct timeval *mono,
					  struct timeval *realout)
{
	struct timeval delta, real;

	monotime_since(mono, &delta);
	gettimeofday(&real, NULL);

	timersub(&real, &delta, &real);
	if (realout)
		*realout = real;
	return real.tv_sec;
}

/* Char buffer size for time-to-string api */
#define MONOTIME_STRLEN 32

static inline char *time_to_string(time_t ts, char *buf)
{
	struct timeval tv;
	time_t tbuf;

	monotime(&tv);
	tbuf = time(NULL) - (tv.tv_sec - ts);

	return ctime_r(&tbuf, buf);
}

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MONOTIME_H */
