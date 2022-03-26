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

struct fbuf;
struct printfrr_eargs;

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

/* Linux/glibc is sadly missing these timespec helpers */
#ifndef timespecadd
#define timespecadd(tsp, usp, vsp)                                             \
	do {                                                                   \
		(vsp)->tv_sec = (tsp)->tv_sec + (usp)->tv_sec;                 \
		(vsp)->tv_nsec = (tsp)->tv_nsec + (usp)->tv_nsec;              \
		if ((vsp)->tv_nsec >= 1000000000L) {                           \
			(vsp)->tv_sec++;                                       \
			(vsp)->tv_nsec -= 1000000000L;                         \
		}                                                              \
	} while (0)
#endif

#ifndef timespecsub
#define timespecsub(tsp, usp, vsp)                                             \
	do {                                                                   \
		(vsp)->tv_sec = (tsp)->tv_sec - (usp)->tv_sec;                 \
		(vsp)->tv_nsec = (tsp)->tv_nsec - (usp)->tv_nsec;              \
		if ((vsp)->tv_nsec < 0) {                                      \
			(vsp)->tv_sec--;                                       \
			(vsp)->tv_nsec += 1000000000L;                         \
		}                                                              \
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

#define ONE_DAY_SECOND (60 * 60 * 24)
#define ONE_WEEK_SECOND (ONE_DAY_SECOND * 7)
#define ONE_YEAR_SECOND (ONE_DAY_SECOND * 365)

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

/* Convert interval to human-friendly string, used in cli output e.g. */
static inline const char *frrtime_to_interval(time_t t, char *buf,
					      size_t buflen)
{
	struct tm tm;

	gmtime_r(&t, &tm);

	if (t < ONE_DAY_SECOND)
		snprintf(buf, buflen, "%02d:%02d:%02d", tm.tm_hour, tm.tm_min,
			 tm.tm_sec);
	else if (t < ONE_WEEK_SECOND)
		snprintf(buf, buflen, "%dd%02dh%02dm", tm.tm_yday, tm.tm_hour,
			 tm.tm_min);
	else
		snprintf(buf, buflen, "%02dw%dd%02dh", tm.tm_yday / 7,
			 tm.tm_yday - ((tm.tm_yday / 7) * 7), tm.tm_hour);
	return buf;
}

enum {
	/* n/a - input was seconds precision, don't print any fractional */
	TIMEFMT_SECONDS = (1 << 0),
	/* caller is directly invoking printfrr_time and has pre-specified
	 * I/Iu/Is/M/Mu/Ms/R/Ru/Rs (for printing timers)
	 */
	TIMEFMT_PRESELECT = (1 << 1),
	/* don't print any output - this is needed for invoking printfrr_time
	 * from another printfrr extensions to skip over flag characters
	 */
	TIMEFMT_SKIP = (1 << 2),
	/* use spaces in appropriate places */
	TIMEFMT_SPACE = (1 << 3),

	/* input interpretations: */
	TIMEFMT_REALTIME = (1 << 8),
	TIMEFMT_MONOTONIC = (1 << 9),
	TIMEFMT_SINCE = (1 << 10),
	TIMEFMT_UNTIL = (1 << 11),

	TIMEFMT_ABSOLUTE = TIMEFMT_REALTIME | TIMEFMT_MONOTONIC,
	TIMEFMT_ANCHORS = TIMEFMT_SINCE | TIMEFMT_UNTIL,

	/* calendaric formats: */
	TIMEFMT_ISO8601 = (1 << 16),

	/* interval formats: */
	/* 't' - use [t]raditional 3-block format */
	TIMEFMT_BASIC = (1 << 24),
	/* 'm' - select mm:ss */
	TIMEFMT_MMSS = (1 << 25),
	/* 'h' - select hh:mm:ss */
	TIMEFMT_HHMMSS = (1 << 26),
	/* 'd' - print as decimal number of seconds */
	TIMEFMT_DECIMAL = (1 << 27),
	/* 'mx'/'hx' - replace zero value with "--:--" or "--:--:--" */
	TIMEFMT_DASHES = (1 << 31),

	/* helpers for reference */
	TIMEFMT_TIMER_DEADLINE =
		TIMEFMT_PRESELECT | TIMEFMT_MONOTONIC | TIMEFMT_UNTIL,
	TIMEFMT_TIMER_INTERVAL = TIMEFMT_PRESELECT,
};

extern ssize_t printfrr_time(struct fbuf *buf, struct printfrr_eargs *ea,
			     const struct timespec *ts, unsigned int flags);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_MONOTIME_H */
