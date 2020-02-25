/*
 * Logging of zebra
 * Copyright (C) 1997, 1998, 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#define FRR_DEFINE_DESC_TABLE

#include <zebra.h>

#include "zclient.h"
#include "log.h"
#include "log_int.h"
#include "memory.h"
#include "command.h"
#include "lib_errors.h"
#include "lib/hook.h"
#include "printfrr.h"
#include "frr_pthread.h"

#ifndef SUNOS_5
#include <sys/un.h>
#endif
/* for printstack on solaris */
#ifdef HAVE_UCONTEXT_H
#include <ucontext.h>
#endif

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>
#endif

DEFINE_MTYPE_STATIC(LIB, ZLOG, "Logging")

/* hook for external logging */
DEFINE_HOOK(zebra_ext_log, (int priority, const char *format, va_list args),
	    (priority, format, args));

static int logfile_fd = -1; /* Used in signal handler. */

struct zlog *zlog_default = NULL;
bool zlog_startup_stderr = true;

/* lock protecting zlog_default for mt-safe zlog */
static pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;

const char *zlog_priority[] = {
	"emergencies",   "alerts",	"critical",  "errors", "warnings",
	"notifications", "informational", "debugging", NULL,
};

static char zlog_filters[ZLOG_FILTERS_MAX][ZLOG_FILTER_LENGTH_MAX + 1];
static uint8_t zlog_filter_count;

/*
 * look for a match on the filter in the current filters, loglock must be held
 */
static int zlog_filter_lookup(const char *lookup)
{
	for (int i = 0; i < zlog_filter_count; i++) {
		if (strncmp(lookup, zlog_filters[i], sizeof(zlog_filters[0]))
		    == 0)
			return i;
	}
	return -1;
}

void zlog_filter_clear(void)
{
	frr_with_mutex(&loglock) {
		zlog_filter_count = 0;
	}
}

int zlog_filter_add(const char *filter)
{
	frr_with_mutex(&loglock) {
		if (zlog_filter_count >= ZLOG_FILTERS_MAX)
			return 1;

		if (zlog_filter_lookup(filter) != -1)
			/* Filter already present */
			return -1;

		strlcpy(zlog_filters[zlog_filter_count], filter,
			sizeof(zlog_filters[0]));

		if (zlog_filters[zlog_filter_count][0] == '\0')
			/* Filter was either empty or didn't get copied
			 * correctly
			 */
			return -1;

		zlog_filter_count++;
	}
	return 0;
}

int zlog_filter_del(const char *filter)
{
	frr_with_mutex(&loglock) {
		int found_idx = zlog_filter_lookup(filter);
		int last_idx = zlog_filter_count - 1;

		if (found_idx == -1)
			/* Didn't find the filter to delete */
			return -1;

		/* Adjust the filter array */
		memmove(zlog_filters[found_idx], zlog_filters[found_idx + 1],
			(last_idx - found_idx) * sizeof(zlog_filters[0]));

		zlog_filter_count--;
	}
	return 0;
}

/* Dump all filters to buffer, delimited by new line */
int zlog_filter_dump(char *buf, size_t max_size)
{
	int len = 0;

	frr_with_mutex(&loglock) {
		for (int i = 0; i < zlog_filter_count; i++) {
			int ret;
			ret = snprintf(buf + len, max_size - len, " %s\n",
				       zlog_filters[i]);
			len += ret;
			if ((ret < 0) || ((size_t)len >= max_size))
				return -1;
		}
	}

	return len;
}

/*
 * write_wrapper
 *
 * glibc has declared that the return value from write *must* not be
 * ignored.
 * gcc see's this problem and issues a warning for the line.
 *
 * Why is this a big deal you say?  Because both of them are right
 * and if you have -Werror enabled then all calls to write
 * generate a build error and the build stops.
 *
 * clang has helpfully allowed this construct:
 * (void)write(...)
 * to tell the compiler yeah I know it has a return value
 * I don't care about it at this time.
 * gcc doesn't have this ability.
 *
 * This code was written such that it didn't care about the
 * return value from write.  At this time do I want
 * to go through and fix and test this code for correctness.
 * So just wrapper the bad behavior and move on.
 */
static void write_wrapper(int fd, const void *buf, size_t count)
{
	if (write(fd, buf, count) <= 0)
		return;

	return;
}

/**
 * Looks up a message in a message list by key.
 *
 * If the message is not found, returns the provided error message.
 *
 * Terminates when it hits a struct message that's all zeros.
 *
 * @param mz the message list
 * @param kz the message key
 * @param nf the message to return if not found
 * @return the message
 */
const char *lookup_msg(const struct message *mz, int kz, const char *nf)
{
	static struct message nt = {0};
	const char *rz = nf ? nf : "(no message found)";
	const struct message *pnt;
	for (pnt = mz; memcmp(pnt, &nt, sizeof(struct message)); pnt++)
		if (pnt->key == kz) {
			rz = pnt->str ? pnt->str : rz;
			break;
		}
	return rz;
}

/* For time string format. */
size_t quagga_timestamp(int timestamp_precision, char *buf, size_t buflen)
{
	static struct {
		time_t last;
		size_t len;
		char buf[28];
	} cache;
	struct timeval clock;

	gettimeofday(&clock, NULL);

	/* first, we update the cache if the time has changed */
	if (cache.last != clock.tv_sec) {
		struct tm *tm;
		cache.last = clock.tv_sec;
		tm = localtime(&cache.last);
		cache.len = strftime(cache.buf, sizeof(cache.buf),
				     "%Y/%m/%d %H:%M:%S", tm);
	}
	/* note: it's not worth caching the subsecond part, because
	   chances are that back-to-back calls are not sufficiently close
	   together
	   for the clock not to have ticked forward */

	if (buflen > cache.len) {
		memcpy(buf, cache.buf, cache.len);
		if ((timestamp_precision > 0)
		    && (buflen > cache.len + 1 + timestamp_precision)) {
			/* should we worry about locale issues? */
			static const int divisor[] = {0,   100000, 10000, 1000,
						      100, 10,     1};
			int prec;
			char *p = buf + cache.len + 1
				  + (prec = timestamp_precision);
			*p-- = '\0';
			while (prec > 6)
			/* this is unlikely to happen, but protect anyway */
			{
				*p-- = '0';
				prec--;
			}
			clock.tv_usec /= divisor[prec];
			do {
				*p-- = '0' + (clock.tv_usec % 10);
				clock.tv_usec /= 10;
			} while (--prec > 0);
			*p = '.';
			return cache.len + 1 + timestamp_precision;
		}
		buf[cache.len] = '\0';
		return cache.len;
	}
	if (buflen > 0)
		buf[0] = '\0';
	return 0;
}

static inline void timestamp_control_render(struct timestamp_control *ctl)
{
	if (!ctl->already_rendered) {
		ctl->len = quagga_timestamp(ctl->precision, ctl->buf,
					    sizeof(ctl->buf));
		ctl->already_rendered = 1;
	}
}

/* Utility routine for current time printing. */
static void time_print(FILE *fp, struct timestamp_control *ctl)
{
	timestamp_control_render(ctl);
	fprintf(fp, "%s ", ctl->buf);
}

static int time_print_buf(char *buf, int len, int max_size,
			  struct timestamp_control *ctl)
{
	timestamp_control_render(ctl);

	if (ctl->len + 1 >= (unsigned long)max_size)
		return -1;

	return snprintf(buf + len, max_size - len, "%s ", ctl->buf);
}

static void vzlog_file(struct zlog *zl, struct timestamp_control *tsctl,
		       const char *proto_str, int record_priority, int priority,
		       FILE *fp, const char *msg)
{
	time_print(fp, tsctl);
	if (record_priority)
		fprintf(fp, "%s: ", zlog_priority[priority]);

	fprintf(fp, "%s%s\n", proto_str, msg);
	fflush(fp);
}

/* Search a buf for the filter strings, loglock must be held */
static int search_buf(const char *buf)
{
	char *found = NULL;

	for (int i = 0; i < zlog_filter_count; i++) {
		found = strstr(buf, zlog_filters[i]);
		if (found != NULL)
			return 0;
	}

	return -1;
}

/* Filter out a log */
static int vzlog_filter(struct zlog *zl, struct timestamp_control *tsctl,
			const char *proto_str, int priority, const char *msg)
{
	int len = 0;
	int ret = 0;
	char buf[1024] = "";

	ret = time_print_buf(buf, len, sizeof(buf), tsctl);

	len += ret;
	if ((ret < 0) || ((size_t)len >= sizeof(buf)))
		goto search;

	if (zl && zl->record_priority)
		snprintf(buf + len, sizeof(buf) - len, "%s: %s: %s",
			 zlog_priority[priority], proto_str, msg);
	else
		snprintf(buf + len, sizeof(buf) - len, "%s: %s", proto_str,
			 msg);

search:
	return search_buf(buf);
}

/* va_list version of zlog. */
void vzlog(int priority, const char *format, va_list args)
{
	frr_mutex_lock_autounlock(&loglock);

	char proto_str[32] = "";
	int original_errno = errno;
	struct timestamp_control tsctl = {};
	tsctl.already_rendered = 0;
	struct zlog *zl = zlog_default;
	char buf[256], *msg;

	if (zl == NULL) {
		tsctl.precision = 0;
	} else {
		tsctl.precision = zl->timestamp_precision;
		if (zl->instance)
			sprintf(proto_str, "%s[%d]: ", zl->protoname,
				zl->instance);
		else
			sprintf(proto_str, "%s: ", zl->protoname);
	}

	msg = vasnprintfrr(MTYPE_TMP, buf, sizeof(buf), format, args);

	/* If it doesn't match on a filter, do nothing with the debug log */
	if ((priority == LOG_DEBUG) && zlog_filter_count
	    && vzlog_filter(zl, &tsctl, proto_str, priority, msg))
		goto out;

	/* call external hook */
	hook_call(zebra_ext_log, priority, format, args);

	/* When zlog_default is also NULL, use stderr for logging. */
	if (zl == NULL) {
		time_print(stderr, &tsctl);
		fprintf(stderr, "%s: %s\n", "unknown", msg);
		fflush(stderr);
		goto out;
	}

	/* Syslog output */
	if (priority <= zl->maxlvl[ZLOG_DEST_SYSLOG])
		syslog(priority | zlog_default->facility, "%s", msg);

	/* File output. */
	if ((priority <= zl->maxlvl[ZLOG_DEST_FILE]) && zl->fp)
		vzlog_file(zl, &tsctl, proto_str, zl->record_priority, priority,
			   zl->fp, msg);

	/* fixed-config logging to stderr while we're stating up & haven't
	 * daemonized / reached mainloop yet
	 *
	 * note the "else" on stdout output -- we don't want to print the same
	 * message to both stderr and stdout. */
	if (zlog_startup_stderr && priority <= LOG_WARNING)
		vzlog_file(zl, &tsctl, proto_str, 1, priority, stderr, msg);
	else if (priority <= zl->maxlvl[ZLOG_DEST_STDOUT])
		vzlog_file(zl, &tsctl, proto_str, zl->record_priority, priority,
			   stdout, msg);

	/* Terminal monitor. */
	if (priority <= zl->maxlvl[ZLOG_DEST_MONITOR])
		vty_log((zl->record_priority ? zlog_priority[priority] : NULL),
			proto_str, msg, &tsctl);

out:
	if (msg != buf)
		XFREE(MTYPE_TMP, msg);
	errno = original_errno;
}

int vzlog_test(int priority)
{
	frr_mutex_lock_autounlock(&loglock);

	struct zlog *zl = zlog_default;

	/* When zlog_default is also NULL, use stderr for logging. */
	if (zl == NULL)
		return 1;
	/* Syslog output */
	else if (priority <= zl->maxlvl[ZLOG_DEST_SYSLOG])
		return 1;
	/* File output. */
	else if ((priority <= zl->maxlvl[ZLOG_DEST_FILE]) && zl->fp)
		return 1;
	/* stdout output. */
	else if (priority <= zl->maxlvl[ZLOG_DEST_STDOUT])
		return 1;
	/* Terminal monitor. */
	else if (priority <= zl->maxlvl[ZLOG_DEST_MONITOR])
		return 1;

	return 0;
}

/*
 * crash handling
 *
 * NB: only AS-Safe (async-signal) functions can be used here!
 */

/* Needs to be enhanced to support Solaris. */
static int syslog_connect(void)
{
#ifdef SUNOS_5
	return -1;
#else
	int fd;
	struct sockaddr_un addr;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		return -1;
	addr.sun_family = AF_UNIX;
#ifdef _PATH_LOG
#define SYSLOG_SOCKET_PATH _PATH_LOG
#else
#define SYSLOG_SOCKET_PATH "/dev/log"
#endif
	strlcpy(addr.sun_path, SYSLOG_SOCKET_PATH, sizeof(addr.sun_path));
#undef SYSLOG_SOCKET_PATH
	if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
		close(fd);
		return -1;
	}
	return fd;
#endif
}

static void syslog_sigsafe(int priority, const char *msg, size_t msglen)
{
	static int syslog_fd = -1;
	char buf[sizeof("<1234567890>ripngd[1234567890]: ") + msglen + 50];
	struct fbuf fb = { .buf = buf, .pos = buf, .len = sizeof(buf) };

	if ((syslog_fd < 0) && ((syslog_fd = syslog_connect()) < 0))
		return;

	/* forget about the timestamp, too difficult in a signal handler */
	bprintfrr(&fb, "<%d>%s", priority, zlog_default->ident);
	if (zlog_default->syslog_options & LOG_PID)
		bprintfrr(&fb, "[%ld]", (long)getpid());
	bprintfrr(&fb, ": %s", msg);
	write_wrapper(syslog_fd, fb.buf, fb.pos - fb.buf);
}

static int open_crashlog(void)
{
	char crashlog_buf[PATH_MAX];
	const char *crashlog_default = "/var/tmp/frr.crashlog", *crashlog;

	if (!zlog_default || !zlog_default->ident)
		crashlog = crashlog_default;
	else {
		snprintfrr(crashlog_buf, sizeof(crashlog_buf),
			   "/var/tmp/frr.%s.crashlog", zlog_default->ident);
		crashlog = crashlog_buf;
	}
	return open(crashlog, O_WRONLY | O_CREAT | O_EXCL, LOGFILE_MASK);
}

/* N.B. implicit priority is most severe */
#define PRI LOG_CRIT

static void crash_write(struct fbuf *fb, char *msgstart)
{
	if (fb->pos == fb->buf)
		return;
	if (!msgstart)
		msgstart = fb->buf;

	/* If no file logging configured, try to write to fallback log file. */
	if ((logfile_fd >= 0) || ((logfile_fd = open_crashlog()) >= 0))
		write(logfile_fd, fb->buf, fb->pos - fb->buf);
	if (!zlog_default)
		write(STDERR_FILENO, fb->buf, fb->pos - fb->buf);
	else {
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
			write(STDOUT_FILENO, fb->buf, fb->pos - fb->buf);
		/* Remove trailing '\n' for monitor and syslog */
		fb->pos--;
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
			vty_log_fixed(fb->buf, fb->pos - fb->buf);
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
			syslog_sigsafe(PRI | zlog_default->facility, msgstart,
				       fb->pos - msgstart);
	}
}

/* Note: the goal here is to use only async-signal-safe functions. */
void zlog_signal(int signo, const char *action, void *siginfo_v,
		 void *program_counter)
{
	siginfo_t *siginfo = siginfo_v;
	time_t now;
	char buf[sizeof("DEFAULT: Received signal S at T (si_addr 0xP, PC 0xP); aborting...")
		 + 100];
	char *msgstart;
	struct fbuf fb = { .buf = buf, .pos = buf, .len = sizeof(buf) };

	time(&now);
	if (zlog_default)
		bprintfrr(&fb, "%s: ", zlog_default->protoname);

	msgstart = fb.pos;

	bprintfrr(&fb, "Received signal %d at %lld", signo, (long long)now);
	if (program_counter)
		bprintfrr(&fb, " (si_addr 0x%tx, PC 0x%tx)",
			  (ptrdiff_t)siginfo->si_addr,
			  (ptrdiff_t)program_counter);
	else
		bprintfrr(&fb, " (si_addr 0x%tx)",
			  (ptrdiff_t)siginfo->si_addr);
	bprintfrr(&fb, "; %s\n", action);

	crash_write(&fb, msgstart);

	zlog_backtrace_sigsafe(PRI, program_counter);

	fb.pos = buf;

	struct thread *tc;
	tc = pthread_getspecific(thread_current);

	if (!tc)
		bprintfrr(&fb, "no thread information available\n");
	else
		bprintfrr(&fb, "in thread %s scheduled from %s:%d\n",
			  tc->funcname, tc->schedfrom, tc->schedfrom_line);

	crash_write(&fb, NULL);
}

/* Log a backtrace using only async-signal-safe functions.
   Needs to be enhanced to support syslog logging. */
void zlog_backtrace_sigsafe(int priority, void *program_counter)
{
#ifdef HAVE_LIBUNWIND
	char buf[256];
	struct fbuf fb = { .buf = buf, .len = sizeof(buf) };
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip, off, sp;
	Dl_info dlinfo;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	while (unw_step(&cursor) > 0) {
		char name[128] = "?";

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (!unw_get_proc_name(&cursor, buf, sizeof(buf), &off))
			snprintfrr(name, sizeof(name), "%s+%#lx",
				   buf, (long)off);

		fb.pos = buf;
		if (unw_is_signal_frame(&cursor))
			bprintfrr(&fb, "    ---- signal ----\n");
		bprintfrr(&fb, "%-30s %16lx %16lx", name, (long)ip, (long)sp);
		if (dladdr((void *)ip, &dlinfo))
			bprintfrr(&fb, " %s (mapped at %p)",
				  dlinfo.dli_fname, dlinfo.dli_fbase);
		bprintfrr(&fb, "\n");
		crash_write(&fb, NULL);
	}
#elif defined(HAVE_GLIBC_BACKTRACE) || defined(HAVE_PRINTSTACK)
	static const char pclabel[] = "Program counter: ";
	void *array[64];
	int size;
	char buf[128];
	struct fbuf fb = { .buf = buf, .pos = buf, .len = sizeof(buf) };
	char **bt = NULL;

#ifdef HAVE_GLIBC_BACKTRACE
	size = backtrace(array, array_size(array));
	if (size <= 0 || (size_t)size > array_size(array))
		return;

#define DUMP(FD)                                                               \
	{                                                                      \
		if (program_counter) {                                         \
			write_wrapper(FD, pclabel, sizeof(pclabel) - 1);       \
			backtrace_symbols_fd(&program_counter, 1, FD);         \
		}                                                              \
		write_wrapper(FD, fb.buf, fb.pos - fb.buf);                    \
		backtrace_symbols_fd(array, size, FD);                         \
	}
#elif defined(HAVE_PRINTSTACK)
	size = 0;

#define DUMP(FD)                                                               \
	{                                                                      \
		if (program_counter)                                           \
			write_wrapper((FD), pclabel, sizeof(pclabel) - 1);     \
		write_wrapper((FD), fb.buf, fb.pos - fb.buf);                  \
		printstack((FD));                                              \
	}
#endif /* HAVE_GLIBC_BACKTRACE, HAVE_PRINTSTACK */

	bprintfrr(&fb, "Backtrace for %d stack frames:\n", size);

	if ((logfile_fd >= 0) || ((logfile_fd = open_crashlog()) >= 0))
		DUMP(logfile_fd)
	if (!zlog_default)
		DUMP(STDERR_FILENO)
	else {
		if (priority <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
			DUMP(STDOUT_FILENO)
		/* Remove trailing '\n' for monitor and syslog */
		fb.pos--;
		if (priority <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
			vty_log_fixed(fb.buf, fb.pos - fb.buf);
		if (priority <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
			syslog_sigsafe(priority | zlog_default->facility,
				       fb.buf, fb.pos - fb.buf);
		{
			int i;
#ifdef HAVE_GLIBC_BACKTRACE
			bt = backtrace_symbols(array, size);
#endif
			/* Just print the function addresses. */
			for (i = 0; i < size; i++) {
				fb.pos = buf;
				if (bt)
					bprintfrr(&fb, "%s", bt[i]);
				else
					bprintfrr(&fb, "[bt %d] 0x%tx", i,
						  (ptrdiff_t)(array[i]));
				if (priority
				    <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
					vty_log_fixed(fb.buf, fb.pos - fb.buf);
				if (priority
				    <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
					syslog_sigsafe(priority
						| zlog_default->facility,
						fb.buf, fb.pos - fb.buf);
			}
			if (bt)
				free(bt);
		}
	}
#undef DUMP
#endif /* HAVE_STRACK_TRACE */
}

void zlog_backtrace(int priority)
{
#ifdef HAVE_LIBUNWIND
	char buf[100];
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip, off, sp;
	Dl_info dlinfo;

	unw_getcontext(&uc);
	unw_init_local(&cursor, &uc);
	zlog(priority, "Backtrace:");
	while (unw_step(&cursor) > 0) {
		char name[128] = "?";

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (unw_is_signal_frame(&cursor))
			zlog(priority, "    ---- signal ----");

		if (!unw_get_proc_name(&cursor, buf, sizeof(buf), &off))
			snprintf(name, sizeof(name), "%s+%#lx",
				buf, (long)off);

		if (dladdr((void *)ip, &dlinfo))
			zlog(priority, "%-30s %16lx %16lx %s (mapped at %p)",
				name, (long)ip, (long)sp,
				dlinfo.dli_fname, dlinfo.dli_fbase);
		else
			zlog(priority, "%-30s %16lx %16lx",
				name, (long)ip, (long)sp);
	}
#elif defined(HAVE_GLIBC_BACKTRACE)
	void *array[20];
	int size, i;
	char **strings;

	size = backtrace(array, array_size(array));
	if (size <= 0 || (size_t)size > array_size(array)) {
		flog_err_sys(
			EC_LIB_SYSTEM_CALL,
			"Cannot get backtrace, returned invalid # of frames %d "
			"(valid range is between 1 and %lu)",
			size, (unsigned long)(array_size(array)));
		return;
	}
	zlog(priority, "Backtrace for %d stack frames:", size);
	if (!(strings = backtrace_symbols(array, size))) {
		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "Cannot get backtrace symbols (out of memory?)");
		for (i = 0; i < size; i++)
			zlog(priority, "[bt %d] %p", i, array[i]);
	} else {
		for (i = 0; i < size; i++)
			zlog(priority, "[bt %d] %s", i, strings[i]);
		free(strings);
	}
#else /* !HAVE_GLIBC_BACKTRACE && !HAVE_LIBUNWIND */
	zlog(priority, "No backtrace available on this platform.");
#endif
}

void zlog(int priority, const char *format, ...)
{
	va_list args;

	va_start(args, format);
	vzlog(priority, format, args);
	va_end(args);
}

#define ZLOG_FUNC(FUNCNAME, PRIORITY)                                          \
	void FUNCNAME(const char *format, ...)                                 \
	{                                                                      \
		va_list args;                                                  \
		va_start(args, format);                                        \
		vzlog(PRIORITY, format, args);                                 \
		va_end(args);                                                  \
	}

ZLOG_FUNC(zlog_err, LOG_ERR)

ZLOG_FUNC(zlog_warn, LOG_WARNING)

ZLOG_FUNC(zlog_info, LOG_INFO)

ZLOG_FUNC(zlog_notice, LOG_NOTICE)

ZLOG_FUNC(zlog_debug, LOG_DEBUG)

#undef ZLOG_FUNC

void zlog_thread_info(int log_level)
{
	struct thread *tc;
	tc = pthread_getspecific(thread_current);

	if (tc)
		zlog(log_level,
		     "Current thread function %s, scheduled from "
		     "file %s, line %u",
		     tc->funcname, tc->schedfrom, tc->schedfrom_line);
	else
		zlog(log_level, "Current thread not known/applicable");
}

void _zlog_assert_failed(const char *assertion, const char *file,
			 unsigned int line, const char *function)
{
	/* Force fallback file logging? */
	if (zlog_default && !zlog_default->fp
	    && ((logfile_fd = open_crashlog()) >= 0)
	    && ((zlog_default->fp = fdopen(logfile_fd, "w")) != NULL))
		zlog_default->maxlvl[ZLOG_DEST_FILE] = LOG_ERR;
	zlog(LOG_CRIT, "Assertion `%s' failed in file %s, line %u, function %s",
	     assertion, file, line, (function ? function : "?"));
	zlog_backtrace(LOG_CRIT);
	zlog_thread_info(LOG_CRIT);
	log_memstats(stderr, "log");
	abort();
}

void memory_oom(size_t size, const char *name)
{
	flog_err_sys(EC_LIB_SYSTEM_CALL,
		     "out of memory: failed to allocate %zu bytes for %s"
		     "object",
		     size, name);
	zlog_backtrace(LOG_ERR);
	abort();
}

/* Open log stream */
void openzlog(const char *progname, const char *protoname,
	      unsigned short instance, int syslog_flags, int syslog_facility)
{
	struct zlog *zl;
	unsigned int i;

	zl = XCALLOC(MTYPE_ZLOG, sizeof(struct zlog));

	zl->ident = progname;
	zl->protoname = protoname;
	zl->instance = instance;
	zl->facility = syslog_facility;
	zl->syslog_options = syslog_flags;

	/* Set default logging levels. */
	for (i = 0; i < array_size(zl->maxlvl); i++)
		zl->maxlvl[i] = ZLOG_DISABLED;
	zl->maxlvl[ZLOG_DEST_MONITOR] = LOG_DEBUG;
	zl->default_lvl = LOG_DEBUG;

	openlog(progname, syslog_flags, zl->facility);

	frr_with_mutex(&loglock) {
		zlog_default = zl;
	}

#ifdef HAVE_GLIBC_BACKTRACE
	/* work around backtrace() using lazily resolved dynamically linked
	 * symbols, which will otherwise cause funny breakage in the SEGV
	 * handler.
	 * (particularly, the dynamic linker can call malloc(), which uses locks
	 * in programs linked with -pthread, thus can deadlock.) */
	void *bt[4];
	backtrace(bt, array_size(bt));
	free(backtrace_symbols(bt, 0));
	backtrace_symbols_fd(bt, 0, 0);
#endif
}

void closezlog(void)
{
	frr_mutex_lock_autounlock(&loglock);

	struct zlog *zl = zlog_default;

	closelog();

	if (zl->fp != NULL)
		fclose(zl->fp);

	XFREE(MTYPE_ZLOG, zl->filename);

	XFREE(MTYPE_ZLOG, zl);
	zlog_default = NULL;
}

/* Called from command.c. */
void zlog_set_level(zlog_dest_t dest, int log_level)
{
	frr_with_mutex(&loglock) {
		zlog_default->maxlvl[dest] = log_level;
	}
}

int zlog_set_file(const char *filename, int log_level)
{
	struct zlog *zl;
	FILE *fp;
	mode_t oldumask;
	int ret = 1;

	/* There is opend file.  */
	zlog_reset_file();

	/* Open file. */
	oldumask = umask(0777 & ~LOGFILE_MASK);
	fp = fopen(filename, "a");
	umask(oldumask);
	if (fp == NULL) {
		ret = 0;
	} else {
		frr_with_mutex(&loglock) {
			zl = zlog_default;

			/* Set flags. */
			zl->filename = XSTRDUP(MTYPE_ZLOG, filename);
			zl->maxlvl[ZLOG_DEST_FILE] = log_level;
			zl->fp = fp;
			logfile_fd = fileno(fp);
		}
	}

	return ret;
}

/* Reset opend file. */
int zlog_reset_file(void)
{
	frr_mutex_lock_autounlock(&loglock);

	struct zlog *zl = zlog_default;

	if (zl->fp)
		fclose(zl->fp);
	zl->fp = NULL;
	logfile_fd = -1;
	zl->maxlvl[ZLOG_DEST_FILE] = ZLOG_DISABLED;

	XFREE(MTYPE_ZLOG, zl->filename);
	zl->filename = NULL;

	return 1;
}

/* Reopen log file. */
int zlog_rotate(void)
{
	pthread_mutex_lock(&loglock);

	struct zlog *zl = zlog_default;
	int level;
	int ret = 1;

	if (zl->fp)
		fclose(zl->fp);
	zl->fp = NULL;
	logfile_fd = -1;
	level = zl->maxlvl[ZLOG_DEST_FILE];
	zl->maxlvl[ZLOG_DEST_FILE] = ZLOG_DISABLED;

	if (zl->filename) {
		mode_t oldumask;
		int save_errno;

		oldumask = umask(0777 & ~LOGFILE_MASK);
		zl->fp = fopen(zl->filename, "a");
		save_errno = errno;
		umask(oldumask);
		if (zl->fp == NULL) {

			pthread_mutex_unlock(&loglock);

			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"Log rotate failed: cannot open file %s for append: %s",
				zl->filename, safe_strerror(save_errno));
			ret = -1;

			pthread_mutex_lock(&loglock);
		} else {
			logfile_fd = fileno(zl->fp);
			zl->maxlvl[ZLOG_DEST_FILE] = level;
		}
	}

	pthread_mutex_unlock(&loglock);

	return ret;
}

/* Wrapper around strerror to handle case where it returns NULL. */
const char *safe_strerror(int errnum)
{
	const char *s = strerror(errnum);
	return (s != NULL) ? s : "Unknown error";
}

#define DESC_ENTRY(T) [(T)] = { (T), (#T), '\0' }
static const struct zebra_desc_table command_types[] = {
	DESC_ENTRY(ZEBRA_INTERFACE_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_ADDRESS_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_ADDRESS_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_UP),
	DESC_ENTRY(ZEBRA_INTERFACE_DOWN),
	DESC_ENTRY(ZEBRA_INTERFACE_SET_MASTER),
	DESC_ENTRY(ZEBRA_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_ROUTE_DELETE),
	DESC_ENTRY(ZEBRA_ROUTE_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DELETE),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DEFAULT_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE),
	DESC_ENTRY(ZEBRA_ROUTER_ID_ADD),
	DESC_ENTRY(ZEBRA_ROUTER_ID_DELETE),
	DESC_ENTRY(ZEBRA_ROUTER_ID_UPDATE),
	DESC_ENTRY(ZEBRA_HELLO),
	DESC_ENTRY(ZEBRA_CAPABILITIES),
	DESC_ENTRY(ZEBRA_NEXTHOP_REGISTER),
	DESC_ENTRY(ZEBRA_NEXTHOP_UNREGISTER),
	DESC_ENTRY(ZEBRA_NEXTHOP_UPDATE),
	DESC_ENTRY(ZEBRA_INTERFACE_NBR_ADDRESS_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_NBR_ADDRESS_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_BFD_DEST_UPDATE),
	DESC_ENTRY(ZEBRA_IMPORT_ROUTE_REGISTER),
	DESC_ENTRY(ZEBRA_IMPORT_ROUTE_UNREGISTER),
	DESC_ENTRY(ZEBRA_IMPORT_CHECK_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_DEST_REGISTER),
	DESC_ENTRY(ZEBRA_BFD_DEST_DEREGISTER),
	DESC_ENTRY(ZEBRA_BFD_DEST_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_DEST_REPLAY),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ROUTE_DEL),
	DESC_ENTRY(ZEBRA_VRF_UNREGISTER),
	DESC_ENTRY(ZEBRA_VRF_ADD),
	DESC_ENTRY(ZEBRA_VRF_DELETE),
	DESC_ENTRY(ZEBRA_VRF_LABEL),
	DESC_ENTRY(ZEBRA_INTERFACE_VRF_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_CLIENT_REGISTER),
	DESC_ENTRY(ZEBRA_BFD_CLIENT_DEREGISTER),
	DESC_ENTRY(ZEBRA_INTERFACE_ENABLE_RADV),
	DESC_ENTRY(ZEBRA_INTERFACE_DISABLE_RADV),
	DESC_ENTRY(ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB),
	DESC_ENTRY(ZEBRA_INTERFACE_LINK_PARAMS),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_ADD),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_DELETE),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_REPLACE),
	DESC_ENTRY(ZEBRA_IPMR_ROUTE_STATS),
	DESC_ENTRY(ZEBRA_LABEL_MANAGER_CONNECT),
	DESC_ENTRY(ZEBRA_LABEL_MANAGER_CONNECT_ASYNC),
	DESC_ENTRY(ZEBRA_GET_LABEL_CHUNK),
	DESC_ENTRY(ZEBRA_RELEASE_LABEL_CHUNK),
	DESC_ENTRY(ZEBRA_FEC_REGISTER),
	DESC_ENTRY(ZEBRA_FEC_UNREGISTER),
	DESC_ENTRY(ZEBRA_FEC_UPDATE),
	DESC_ENTRY(ZEBRA_ADVERTISE_ALL_VNI),
	DESC_ENTRY(ZEBRA_ADVERTISE_DEFAULT_GW),
	DESC_ENTRY(ZEBRA_ADVERTISE_SVI_MACIP),
	DESC_ENTRY(ZEBRA_ADVERTISE_SUBNET),
	DESC_ENTRY(ZEBRA_LOCAL_ES_ADD),
	DESC_ENTRY(ZEBRA_LOCAL_ES_DEL),
	DESC_ENTRY(ZEBRA_VNI_ADD),
	DESC_ENTRY(ZEBRA_VNI_DEL),
	DESC_ENTRY(ZEBRA_L3VNI_ADD),
	DESC_ENTRY(ZEBRA_L3VNI_DEL),
	DESC_ENTRY(ZEBRA_REMOTE_VTEP_ADD),
	DESC_ENTRY(ZEBRA_REMOTE_VTEP_DEL),
	DESC_ENTRY(ZEBRA_MACIP_ADD),
	DESC_ENTRY(ZEBRA_MACIP_DEL),
	DESC_ENTRY(ZEBRA_IP_PREFIX_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_IP_PREFIX_ROUTE_DEL),
	DESC_ENTRY(ZEBRA_REMOTE_MACIP_ADD),
	DESC_ENTRY(ZEBRA_REMOTE_MACIP_DEL),
	DESC_ENTRY(ZEBRA_DUPLICATE_ADDR_DETECTION),
	DESC_ENTRY(ZEBRA_PW_ADD),
	DESC_ENTRY(ZEBRA_PW_DELETE),
	DESC_ENTRY(ZEBRA_PW_SET),
	DESC_ENTRY(ZEBRA_PW_UNSET),
	DESC_ENTRY(ZEBRA_PW_STATUS_UPDATE),
	DESC_ENTRY(ZEBRA_RULE_ADD),
	DESC_ENTRY(ZEBRA_RULE_DELETE),
	DESC_ENTRY(ZEBRA_RULE_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_TABLE_MANAGER_CONNECT),
	DESC_ENTRY(ZEBRA_GET_TABLE_CHUNK),
	DESC_ENTRY(ZEBRA_RELEASE_TABLE_CHUNK),
	DESC_ENTRY(ZEBRA_IPSET_CREATE),
	DESC_ENTRY(ZEBRA_IPSET_DESTROY),
	DESC_ENTRY(ZEBRA_IPSET_ENTRY_ADD),
	DESC_ENTRY(ZEBRA_IPSET_ENTRY_DELETE),
	DESC_ENTRY(ZEBRA_IPSET_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_IPSET_ENTRY_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_IPTABLE_ADD),
	DESC_ENTRY(ZEBRA_IPTABLE_DELETE),
	DESC_ENTRY(ZEBRA_IPTABLE_NOTIFY_OWNER),
	DESC_ENTRY(ZEBRA_VXLAN_FLOOD_CONTROL),
	DESC_ENTRY(ZEBRA_VXLAN_SG_ADD),
	DESC_ENTRY(ZEBRA_VXLAN_SG_DEL),
	DESC_ENTRY(ZEBRA_VXLAN_SG_REPLAY),
	DESC_ENTRY(ZEBRA_ERROR),
};
#undef DESC_ENTRY

static const struct zebra_desc_table unknown = {0, "unknown", '?'};

static const struct zebra_desc_table *zroute_lookup(unsigned int zroute)
{
	unsigned int i;

	if (zroute >= array_size(route_types)) {
		flog_err(EC_LIB_DEVELOPMENT, "unknown zebra route type: %u",
			 zroute);
		return &unknown;
	}
	if (zroute == route_types[zroute].type)
		return &route_types[zroute];
	for (i = 0; i < array_size(route_types); i++) {
		if (zroute == route_types[i].type) {
			zlog_warn(
				"internal error: route type table out of order "
				"while searching for %u, please notify developers",
				zroute);
			return &route_types[i];
		}
	}
	flog_err(EC_LIB_DEVELOPMENT,
		 "internal error: cannot find route type %u in table!", zroute);
	return &unknown;
}

const char *zebra_route_string(unsigned int zroute)
{
	return zroute_lookup(zroute)->string;
}

char zebra_route_char(unsigned int zroute)
{
	return zroute_lookup(zroute)->chr;
}

const char *zserv_command_string(unsigned int command)
{
	if (command >= array_size(command_types)) {
		flog_err(EC_LIB_DEVELOPMENT, "unknown zserv command type: %u",
			 command);
		return unknown.string;
	}
	return command_types[command].string;
}

int proto_name2num(const char *s)
{
	unsigned i;

	for (i = 0; i < array_size(route_types); ++i)
		if (strcasecmp(s, route_types[i].string) == 0)
			return route_types[i].type;
	return -1;
}

int proto_redistnum(int afi, const char *s)
{
	if (!s)
		return -1;

	if (afi == AFI_IP) {
		if (strmatch(s, "kernel"))
			return ZEBRA_ROUTE_KERNEL;
		else if (strmatch(s, "connected"))
			return ZEBRA_ROUTE_CONNECT;
		else if (strmatch(s, "static"))
			return ZEBRA_ROUTE_STATIC;
		else if (strmatch(s, "rip"))
			return ZEBRA_ROUTE_RIP;
		else if (strmatch(s, "eigrp"))
			return ZEBRA_ROUTE_EIGRP;
		else if (strmatch(s, "ospf"))
			return ZEBRA_ROUTE_OSPF;
		else if (strmatch(s, "isis"))
			return ZEBRA_ROUTE_ISIS;
		else if (strmatch(s, "bgp"))
			return ZEBRA_ROUTE_BGP;
		else if (strmatch(s, "table"))
			return ZEBRA_ROUTE_TABLE;
		else if (strmatch(s, "vnc"))
			return ZEBRA_ROUTE_VNC;
		else if (strmatch(s, "vnc-direct"))
			return ZEBRA_ROUTE_VNC_DIRECT;
		else if (strmatch(s, "nhrp"))
			return ZEBRA_ROUTE_NHRP;
		else if (strmatch(s, "babel"))
			return ZEBRA_ROUTE_BABEL;
		else if (strmatch(s, "sharp"))
			return ZEBRA_ROUTE_SHARP;
		else if (strmatch(s, "openfabric"))
			return ZEBRA_ROUTE_OPENFABRIC;
	}
	if (afi == AFI_IP6) {
		if (strmatch(s, "kernel"))
			return ZEBRA_ROUTE_KERNEL;
		else if (strmatch(s, "connected"))
			return ZEBRA_ROUTE_CONNECT;
		else if (strmatch(s, "static"))
			return ZEBRA_ROUTE_STATIC;
		else if (strmatch(s, "ripng"))
			return ZEBRA_ROUTE_RIPNG;
		else if (strmatch(s, "ospf6"))
			return ZEBRA_ROUTE_OSPF6;
		else if (strmatch(s, "isis"))
			return ZEBRA_ROUTE_ISIS;
		else if (strmatch(s, "bgp"))
			return ZEBRA_ROUTE_BGP;
		else if (strmatch(s, "table"))
			return ZEBRA_ROUTE_TABLE;
		else if (strmatch(s, "vnc"))
			return ZEBRA_ROUTE_VNC;
		else if (strmatch(s, "vnc-direct"))
			return ZEBRA_ROUTE_VNC_DIRECT;
		else if (strmatch(s, "nhrp"))
			return ZEBRA_ROUTE_NHRP;
		else if (strmatch(s, "babel"))
			return ZEBRA_ROUTE_BABEL;
		else if (strmatch(s, "sharp"))
			return ZEBRA_ROUTE_SHARP;
		else if (strmatch(s, "openfabric"))
			return ZEBRA_ROUTE_OPENFABRIC;
	}
	return -1;
}

void zlog_hexdump(const void *mem, unsigned int len)
{
	unsigned long i = 0;
	unsigned int j = 0;
	unsigned int columns = 8;
	/*
	 * 19 bytes for 0xADDRESS:
	 * 24 bytes for data; 2 chars plus a space per data byte
	 *  1 byte for space
	 *  8 bytes for ASCII representation
	 *  1 byte for a newline
	 * =====================
	 * 53 bytes per 8 bytes of data
	 *  1 byte for null term
	 */
	size_t bs = ((len / 8) + 1) * 53 + 1;
	char buf[bs];
	char *s = buf;
	const unsigned char *memch = mem;

	memset(buf, 0, sizeof(buf));

	for (i = 0; i < len + ((len % columns) ? (columns - len % columns) : 0);
	     i++) {
		/* print offset */
		if (i % columns == 0)
			s += snprintf(s, bs - (s - buf),
				      "0x%016lx: ", (unsigned long)memch + i);

		/* print hex data */
		if (i < len)
			s += snprintf(s, bs - (s - buf), "%02x ", memch[i]);

		/* end of block, just aligning for ASCII dump */
		else
			s += snprintf(s, bs - (s - buf), "   ");

		/* print ASCII dump */
		if (i % columns == (columns - 1)) {
			for (j = i - (columns - 1); j <= i; j++) {
				/* end of block not really printing */
				if (j >= len)
					s += snprintf(s, bs - (s - buf), " ");
				else if (isprint(memch[j]))
					s += snprintf(s, bs - (s - buf), "%c",
						      memch[j]);
				else /* other char */
					s += snprintf(s, bs - (s - buf), ".");
			}
			s += snprintf(s, bs - (s - buf), "\n");
		}
	}
	zlog_debug("\n%s", buf);
}

const char *zlog_sanitize(char *buf, size_t bufsz, const void *in, size_t inlen)
{
	const char *inbuf = in;
	char *pos = buf, *end = buf + bufsz;
	const char *iend = inbuf + inlen;

	memset(buf, 0, bufsz);
	for (; inbuf < iend; inbuf++) {
		/* don't write partial escape sequence */
		if (end - pos < 5)
			break;

		if (*inbuf == '\n')
			snprintf(pos, end - pos, "\\n");
		else if (*inbuf == '\r')
			snprintf(pos, end - pos, "\\r");
		else if (*inbuf == '\t')
			snprintf(pos, end - pos, "\\t");
		else if (*inbuf < ' ' || *inbuf == '"' || *inbuf >= 127)
			snprintf(pos, end - pos, "\\x%02hhx", *inbuf);
		else
			*pos = *inbuf;

		pos += strlen(pos);
	}
	return buf;
}
