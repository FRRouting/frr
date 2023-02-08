// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2019  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "compiler.h"

#include <string.h>
#include <ctype.h>
#include <time.h>

#include "printfrr.h"
#include "monotime.h"

printfrr_ext_autoreg_p("HX", printfrr_hexdump);
static ssize_t printfrr_hexdump(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	ssize_t ret = 0;
	ssize_t input_len = printfrr_ext_len(ea);
	char sep = ' ';
	const uint8_t *pos, *end;

	if (ea->fmt[0] == 'c') {
		ea->fmt++;
		sep = ':';
	} else if (ea->fmt[0] == 'n') {
		ea->fmt++;
		sep = '\0';
	}

	if (input_len < 0)
		return 0;

	for (pos = ptr, end = pos + input_len; pos < end; pos++) {
		if (sep && pos != ptr)
			ret += bputch(buf, sep);
		ret += bputhex(buf, *pos);
	}

	return ret;
}

/* string analog for hexdumps / the "this." in ("74 68 69 73 0a  |this.|") */

printfrr_ext_autoreg_p("HS", printfrr_hexdstr);
static ssize_t printfrr_hexdstr(struct fbuf *buf, struct printfrr_eargs *ea,
				const void *ptr)
{
	ssize_t ret = 0;
	ssize_t input_len = printfrr_ext_len(ea);
	const uint8_t *pos, *end;

	if (input_len < 0)
		return 0;

	for (pos = ptr, end = pos + input_len; pos < end; pos++) {
		if (*pos >= 0x20 && *pos < 0x7f)
			ret += bputch(buf, *pos);
		else
			ret += bputch(buf, '.');
	}

	return ret;
}

enum escape_flags {
	ESC_N_R_T	= (1 << 0),	/* use \n \r \t instead of \x0a ...*/
	ESC_SPACE	= (1 << 1),	/* \  */
	ESC_BACKSLASH	= (1 << 2),	/* \\ */
	ESC_DBLQUOTE	= (1 << 3),	/* \" */
	ESC_SGLQUOTE	= (1 << 4),	/* \' */
	ESC_BACKTICK	= (1 << 5),	/* \` */
	ESC_DOLLAR	= (1 << 6),	/* \$ */
	ESC_CLBRACKET	= (1 << 7),	/* \] for RFC5424 syslog */
	ESC_OTHER	= (1 << 8),	/* remaining non-alpha */

	ESC_ALL = ESC_N_R_T | ESC_SPACE | ESC_BACKSLASH | ESC_DBLQUOTE
		| ESC_SGLQUOTE | ESC_DOLLAR | ESC_OTHER,
	ESC_QUOTSTRING = ESC_N_R_T | ESC_BACKSLASH | ESC_DBLQUOTE,
	/* if needed: ESC_SHELL = ... */
};

static ssize_t bquote(struct fbuf *buf, const uint8_t *pos, size_t len,
		      unsigned int flags)
{
	ssize_t ret = 0;
	const uint8_t *end = pos + len;

	for (; pos < end; pos++) {
		/* here's to hoping this might be a bit faster... */
		if (__builtin_expect(!!isalnum(*pos), 1)) {
			ret += bputch(buf, *pos);
			continue;
		}

		switch (*pos) {
		case '%':
		case '+':
		case ',':
		case '-':
		case '.':
		case '/':
		case ':':
		case '@':
		case '_':
			ret += bputch(buf, *pos);
			continue;

		case '\r':
			if (!(flags & ESC_N_R_T))
				break;
			ret += bputch(buf, '\\');
			ret += bputch(buf, 'r');
			continue;
		case '\n':
			if (!(flags & ESC_N_R_T))
				break;
			ret += bputch(buf, '\\');
			ret += bputch(buf, 'n');
			continue;
		case '\t':
			if (!(flags & ESC_N_R_T))
				break;
			ret += bputch(buf, '\\');
			ret += bputch(buf, 't');
			continue;

		case ' ':
			if (flags & ESC_SPACE)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '\\':
			if (flags & ESC_BACKSLASH)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '"':
			if (flags & ESC_DBLQUOTE)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '\'':
			if (flags & ESC_SGLQUOTE)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '`':
			if (flags & ESC_BACKTICK)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case '$':
			if (flags & ESC_DOLLAR)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		case ']':
			if (flags & ESC_CLBRACKET)
				ret += bputch(buf, '\\');
			ret += bputch(buf, *pos);
			continue;

		/* remaining: !#&'()*;<=>?[^{|}~ */

		default:
			if (*pos >= 0x20 && *pos < 0x7f) {
				if (flags & ESC_OTHER)
					ret += bputch(buf, '\\');
				ret += bputch(buf, *pos);
				continue;
			}
		}
		ret += bputch(buf, '\\');
		ret += bputch(buf, 'x');
		ret += bputhex(buf, *pos);
	}

	return ret;
}

printfrr_ext_autoreg_p("SE", printfrr_escape);
static ssize_t printfrr_escape(struct fbuf *buf, struct printfrr_eargs *ea,
			       const void *vptr)
{
	ssize_t len = printfrr_ext_len(ea);
	const uint8_t *ptr = vptr;
	bool null_is_empty = false;

	if (ea->fmt[0] == 'n') {
		null_is_empty = true;
		ea->fmt++;
	}

	if (!ptr) {
		if (null_is_empty)
			return 0;
		return bputs(buf, "(null)");
	}

	if (len < 0)
		len = strlen((const char *)ptr);

	return bquote(buf, ptr, len, ESC_ALL);
}

printfrr_ext_autoreg_p("SQ", printfrr_quote);
static ssize_t printfrr_quote(struct fbuf *buf, struct printfrr_eargs *ea,
			      const void *vptr)
{
	ssize_t len = printfrr_ext_len(ea);
	const uint8_t *ptr = vptr;
	ssize_t ret = 0;
	bool null_is_empty = false;
	bool do_quotes = false;
	unsigned int flags = ESC_QUOTSTRING;

	while (ea->fmt[0]) {
		switch (ea->fmt[0]) {
		case 'n':
			null_is_empty = true;
			ea->fmt++;
			continue;
		case 'q':
			do_quotes = true;
			ea->fmt++;
			continue;
		case 's':
			flags |= ESC_CLBRACKET;
			flags &= ~ESC_N_R_T;
			ea->fmt++;
			continue;
		}
		break;
	}

	if (!ptr) {
		if (null_is_empty)
			return bputs(buf, do_quotes ? "\"\"" : "");
		return bputs(buf, "(null)");
	}

	if (len < 0)
		len = strlen((const char *)ptr);

	if (do_quotes)
		ret += bputch(buf, '"');
	ret += bquote(buf, ptr, len, flags);
	if (do_quotes)
		ret += bputch(buf, '"');
	return ret;
}

static ssize_t printfrr_abstime(struct fbuf *buf, struct printfrr_eargs *ea,
				const struct timespec *ts, unsigned int flags);
static ssize_t printfrr_reltime(struct fbuf *buf, struct printfrr_eargs *ea,
				const struct timespec *ts, unsigned int flags);

ssize_t printfrr_time(struct fbuf *buf, struct printfrr_eargs *ea,
		      const struct timespec *ts, unsigned int flags)
{
	bool have_abs, have_anchor;

	if (!(flags & TIMEFMT_PRESELECT)) {
		switch (ea->fmt[0]) {
		case 'I':
			/* no bit set */
			break;
		case 'M':
			flags |= TIMEFMT_MONOTONIC;
			break;
		case 'R':
			flags |= TIMEFMT_REALTIME;
			break;
		default:
			return bputs(buf,
				     "{invalid time format input specifier}");
		}
		ea->fmt++;

		if (ea->fmt[0] == 's') {
			flags |= TIMEFMT_SINCE;
			ea->fmt++;
		} else if (ea->fmt[0] == 'u') {
			flags |= TIMEFMT_UNTIL;
			ea->fmt++;
		}
	}

	have_abs = !!(flags & TIMEFMT_ABSOLUTE);
	have_anchor = !!(flags & TIMEFMT_ANCHORS);

	if (have_abs ^ have_anchor)
		return printfrr_abstime(buf, ea, ts, flags);
	else
		return printfrr_reltime(buf, ea, ts, flags);
}

static ssize_t do_subsec(struct fbuf *buf, const struct timespec *ts,
			 int precision, unsigned int flags)
{
	unsigned long long frac;

	if (precision <= 0 || (flags & TIMEFMT_SECONDS))
		return 0;

	frac = ts->tv_nsec;
	if (precision > 9)
		precision = 9;
	for (int i = precision; i < 9; i++)
		frac /= 10;
	return bprintfrr(buf, ".%0*llu", precision, frac);
}

static ssize_t printfrr_abstime(struct fbuf *buf, struct printfrr_eargs *ea,
				const struct timespec *ts, unsigned int flags)
{
	struct timespec real_ts[1];
	struct tm tm;
	char cbuf[32] = ""; /* manpage says 26 for ctime_r */
	ssize_t ret = 0;
	int precision = ea->precision;

	while (ea->fmt[0]) {
		char ch = *ea->fmt++;

		switch (ch) {
		case 'p':
			flags |= TIMEFMT_SPACE;
			continue;
		case 'i':
			flags |= TIMEFMT_ISO8601;
			continue;
		}

		ea->fmt--;
		break;
	}

	if (flags & TIMEFMT_SKIP)
		return 0;
	if (!ts)
		return bputch(buf, '-');

	if (flags & TIMEFMT_REALTIME)
		*real_ts = *ts;
	else if (flags & TIMEFMT_MONOTONIC) {
		struct timespec mono_now[1];

		clock_gettime(CLOCK_REALTIME, real_ts);
		clock_gettime(CLOCK_MONOTONIC, mono_now);

		timespecsub(real_ts, mono_now, real_ts);
		timespecadd(real_ts, ts, real_ts);
	} else {
		clock_gettime(CLOCK_REALTIME, real_ts);

		if (flags & TIMEFMT_SINCE)
			timespecsub(real_ts, ts, real_ts);
		else /* flags & TIMEFMT_UNTIL */
			timespecadd(real_ts, ts, real_ts);
	}

	localtime_r(&real_ts->tv_sec, &tm);

	if (flags & TIMEFMT_ISO8601) {
		if (flags & TIMEFMT_SPACE)
			strftime(cbuf, sizeof(cbuf), "%Y-%m-%d %H:%M:%S", &tm);
		else
			strftime(cbuf, sizeof(cbuf), "%Y-%m-%dT%H:%M:%S", &tm);
		ret += bputs(buf, cbuf);

		if (precision == -1)
			precision = 3;
		ret += do_subsec(buf, real_ts, precision, flags);
	} else {
		size_t len;

		asctime_r(&tm, cbuf);

		len = strlen(cbuf);
		if (!len)
			/* WTF. */
			return 0;
		if (cbuf[len - 1] == '\n')
			cbuf[len - 1] = '\0';

		ret += bputs(buf, cbuf);
	}
	return ret;
}

static ssize_t printfrr_reltime(struct fbuf *buf, struct printfrr_eargs *ea,
				const struct timespec *ts, unsigned int flags)
{
	struct timespec real_ts[1];
	ssize_t ret = 0;
	const char *space = "";
	const char *dashes = "-";
	int precision = ea->precision;

	while (ea->fmt[0]) {
		char ch = *ea->fmt++;

		switch (ch) {
		case 'p':
			flags |= TIMEFMT_SPACE;
			space = " ";
			continue;
		case 't':
			flags |= TIMEFMT_BASIC;
			continue;
		case 'd':
			flags |= TIMEFMT_DECIMAL;
			continue;
		case 'm':
			flags |= TIMEFMT_MMSS;
			dashes = "--:--";
			continue;
		case 'h':
			flags |= TIMEFMT_HHMMSS;
			dashes = "--:--:--";
			continue;
		case 'x':
			flags |= TIMEFMT_DASHES;
			continue;
		}

		ea->fmt--;
		break;
	}

	if (flags & TIMEFMT_SKIP)
		return 0;
	if (!ts)
		return bputch(buf, '-');

	if (flags & TIMEFMT_ABSOLUTE) {
		struct timespec anchor[1];

		if (flags & TIMEFMT_REALTIME)
			clock_gettime(CLOCK_REALTIME, anchor);
		else
			clock_gettime(CLOCK_MONOTONIC, anchor);
		if (flags & TIMEFMT_UNTIL)
			timespecsub(ts, anchor, real_ts);
		else /* flags & TIMEFMT_SINCE */
			timespecsub(anchor, ts, real_ts);
	} else
		*real_ts = *ts;

	if (real_ts->tv_sec == 0 && real_ts->tv_nsec == 0 &&
	    (flags & TIMEFMT_DASHES))
		return bputs(buf, dashes);

	if (real_ts->tv_sec < 0) {
		if (flags & TIMEFMT_DASHES)
			return bputs(buf, dashes);

		/* -0.3s is { -1s + 700ms } */
		real_ts->tv_sec = -real_ts->tv_sec - 1;
		real_ts->tv_nsec = 1000000000L - real_ts->tv_nsec;
		if (real_ts->tv_nsec >= 1000000000L) {
			real_ts->tv_sec++;
			real_ts->tv_nsec -= 1000000000L;
		}

		/* all formats have a - make sense in front */
		ret += bputch(buf, '-');
	}

	if (flags & TIMEFMT_DECIMAL) {
		ret += bprintfrr(buf, "%lld", (long long)real_ts->tv_sec);
		if (precision == -1)
			precision = 3;
		ret += do_subsec(buf, real_ts, precision, flags);
		return ret;
	}

	/* these divisions may be slow on embedded boxes, hence only do the
	 * ones we need, plus the ?: zero check to hopefully skip zeros fast
	 */
	lldiv_t min_sec = lldiv(real_ts->tv_sec, 60);

	if (flags & TIMEFMT_MMSS) {
		ret += bprintfrr(buf, "%02lld:%02lld", min_sec.quot,
				 min_sec.rem);
		ret += do_subsec(buf, real_ts, precision, flags);
		return ret;
	}

	lldiv_t hour_min = min_sec.quot ? lldiv(min_sec.quot, 60) : (lldiv_t){};

	if (flags & TIMEFMT_HHMMSS) {
		ret += bprintfrr(buf, "%02lld:%02lld:%02lld", hour_min.quot,
				 hour_min.rem, min_sec.rem);
		ret += do_subsec(buf, real_ts, precision, flags);
		return ret;
	}

	lldiv_t day_hour =
		hour_min.quot ? lldiv(hour_min.quot, 24) : (lldiv_t){};
	lldiv_t week_day =
		day_hour.quot ? lldiv(day_hour.quot, 7) : (lldiv_t){};

	/* if sub-second precision is not supported, return */
	if (flags & TIMEFMT_BASIC) {
		/* match frrtime_to_interval (without space flag) */
		if (week_day.quot)
			ret += bprintfrr(buf, "%lldw%s%lldd%s%02lldh",
					 week_day.quot, space, week_day.rem,
					 space, day_hour.rem);
		else if (day_hour.quot)
			ret += bprintfrr(buf, "%lldd%s%02lldh%s%02lldm",
					 day_hour.quot, space, day_hour.rem,
					 space, hour_min.rem);
		else
			ret += bprintfrr(buf, "%02lld:%02lld:%02lld",
					 hour_min.quot, hour_min.rem,
					 min_sec.rem);
		/* no sub-seconds here */
		return ret;
	}

	/* default format */
	if (week_day.quot)
		ret += bprintfrr(buf, "%lldw%s", week_day.quot, space);
	if (week_day.rem || week_day.quot)
		ret += bprintfrr(buf, "%lldd%s", week_day.rem, space);

	ret += bprintfrr(buf, "%02lld:%02lld:%02lld", day_hour.rem,
			 hour_min.rem, min_sec.rem);

	if (precision == -1)
		precision = 3;
	ret += do_subsec(buf, real_ts, precision, flags);
	return ret;
}

printfrr_ext_autoreg_p("TS", printfrr_ts);
static ssize_t printfrr_ts(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *vptr)
{
	const struct timespec *ts = vptr;

	return printfrr_time(buf, ea, ts, 0);
}

printfrr_ext_autoreg_p("TV", printfrr_tv);
static ssize_t printfrr_tv(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *vptr)
{
	const struct timeval *tv = vptr;
	struct timespec ts;

	if (!tv)
		return printfrr_time(buf, ea, NULL, 0);

	ts.tv_sec = tv->tv_sec;
	ts.tv_nsec = tv->tv_usec * 1000;
	return printfrr_time(buf, ea, &ts, 0);
}

printfrr_ext_autoreg_p("TT", printfrr_tt);
static ssize_t printfrr_tt(struct fbuf *buf, struct printfrr_eargs *ea,
			   const void *vptr)
{
	const time_t *tt = vptr;
	struct timespec ts;

	if (!tt)
		return printfrr_time(buf, ea, NULL, TIMEFMT_SECONDS);

	ts.tv_sec = *tt;
	ts.tv_nsec = 0;
	return printfrr_time(buf, ea, &ts, TIMEFMT_SECONDS);
}
