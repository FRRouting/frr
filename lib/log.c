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
#ifndef SUNOS_5
#include <sys/un.h>
#endif
/* for printstack on solaris */
#ifdef HAVE_UCONTEXT_H
#include <ucontext.h>
#endif

DEFINE_MTYPE_STATIC(LIB, ZLOG, "Logging")

static int logfile_fd = -1; /* Used in signal handler. */

struct zlog *zlog_default = NULL;
bool zlog_startup_stderr = true;

/* lock protecting zlog_default for mt-safe zlog */
pthread_mutex_t loglock = PTHREAD_MUTEX_INITIALIZER;

const char *zlog_priority[] = {
	"emergencies",   "alerts",	"critical",  "errors", "warnings",
	"notifications", "informational", "debugging", NULL,
};

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

/* Utility routine for current time printing. */
static void time_print(FILE *fp, struct timestamp_control *ctl)
{
	if (!ctl->already_rendered) {
		ctl->len = quagga_timestamp(ctl->precision, ctl->buf,
					    sizeof(ctl->buf));
		ctl->already_rendered = 1;
	}
	fprintf(fp, "%s ", ctl->buf);
}


static void vzlog_file(struct zlog *zl, struct timestamp_control *tsctl,
		       const char *proto_str, int record_priority,
		       int priority, FILE *fp, const char *format,
		       va_list args)
{
	va_list ac;

	time_print(fp, tsctl);
	if (record_priority)
		fprintf(fp, "%s: ", zlog_priority[priority]);

	fprintf(fp, "%s", proto_str);
	va_copy(ac, args);
	vfprintf(fp, format, ac);
	va_end(ac);
	fprintf(fp, "\n");
	fflush(fp);
}

/* va_list version of zlog. */
void vzlog(int priority, const char *format, va_list args)
{
	pthread_mutex_lock(&loglock);

	char proto_str[32];
	int original_errno = errno;
	struct timestamp_control tsctl;
	tsctl.already_rendered = 0;
	struct zlog *zl = zlog_default;

	/* When zlog_default is also NULL, use stderr for logging. */
	if (zl == NULL) {
		tsctl.precision = 0;
		time_print(stderr, &tsctl);
		fprintf(stderr, "%s: ", "unknown");
		vfprintf(stderr, format, args);
		fprintf(stderr, "\n");
		fflush(stderr);

		/* In this case we return at here. */
		errno = original_errno;
		pthread_mutex_unlock(&loglock);
		return;
	}
	tsctl.precision = zl->timestamp_precision;

	/* Syslog output */
	if (priority <= zl->maxlvl[ZLOG_DEST_SYSLOG]) {
		va_list ac;
		va_copy(ac, args);
		vsyslog(priority | zlog_default->facility, format, ac);
		va_end(ac);
	}

	if (zl->instance)
		sprintf(proto_str, "%s[%d]: ", zl->protoname, zl->instance);
	else
		sprintf(proto_str, "%s: ", zl->protoname);

	/* File output. */
	if ((priority <= zl->maxlvl[ZLOG_DEST_FILE]) && zl->fp)
		vzlog_file(zl, &tsctl, proto_str, zl->record_priority,
				priority, zl->fp, format, args);

	/* fixed-config logging to stderr while we're stating up & haven't
	 * daemonized / reached mainloop yet
	 *
	 * note the "else" on stdout output -- we don't want to print the same
	 * message to both stderr and stdout. */
	if (zlog_startup_stderr && priority <= LOG_WARNING)
		vzlog_file(zl, &tsctl, proto_str, 1,
				priority, stderr, format, args);
	else if (priority <= zl->maxlvl[ZLOG_DEST_STDOUT])
		vzlog_file(zl, &tsctl, proto_str, zl->record_priority,
				priority, stdout, format, args);

	/* Terminal monitor. */
	if (priority <= zl->maxlvl[ZLOG_DEST_MONITOR])
		vty_log((zl->record_priority ? zlog_priority[priority] : NULL),
			proto_str, format, &tsctl, args);

	errno = original_errno;
	pthread_mutex_unlock(&loglock);
}

int vzlog_test(int priority)
{
	pthread_mutex_lock(&loglock);

	int ret = 0;

	struct zlog *zl = zlog_default;

	/* When zlog_default is also NULL, use stderr for logging. */
	if (zl == NULL)
		ret = 1;
	/* Syslog output */
	else if (priority <= zl->maxlvl[ZLOG_DEST_SYSLOG])
		ret = 1;
	/* File output. */
	else if ((priority <= zl->maxlvl[ZLOG_DEST_FILE]) && zl->fp)
		ret = 1;
	/* stdout output. */
	else if (priority <= zl->maxlvl[ZLOG_DEST_STDOUT])
		ret = 1;
	/* Terminal monitor. */
	else if (priority <= zl->maxlvl[ZLOG_DEST_MONITOR])
		ret = 1;

	pthread_mutex_unlock(&loglock);

	return ret;
}

static char *str_append(char *dst, int len, const char *src)
{
	while ((len-- > 0) && *src)
		*dst++ = *src++;
	return dst;
}

static char *num_append(char *s, int len, u_long x)
{
	char buf[30];
	char *t;

	if (!x)
		return str_append(s, len, "0");
	*(t = &buf[sizeof(buf) - 1]) = '\0';
	while (x && (t > buf)) {
		*--t = '0' + (x % 10);
		x /= 10;
	}
	return str_append(s, len, t);
}

#if defined(SA_SIGINFO) || defined(HAVE_STACK_TRACE)
static char *hex_append(char *s, int len, u_long x)
{
	char buf[30];
	char *t;

	if (!x)
		return str_append(s, len, "0");
	*(t = &buf[sizeof(buf) - 1]) = '\0';
	while (x && (t > buf)) {
		u_int cc = (x % 16);
		*--t = ((cc < 10) ? ('0' + cc) : ('a' + cc - 10));
		x /= 16;
	}
	return str_append(s, len, t);
}
#endif

/* Needs to be enhanced to support Solaris. */
static int syslog_connect(void)
{
#ifdef SUNOS_5
	return -1;
#else
	int fd;
	char *s;
	struct sockaddr_un addr;

	if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0)
		return -1;
	addr.sun_family = AF_UNIX;
#ifdef _PATH_LOG
#define SYSLOG_SOCKET_PATH _PATH_LOG
#else
#define SYSLOG_SOCKET_PATH "/dev/log"
#endif
	s = str_append(addr.sun_path, sizeof(addr.sun_path),
		       SYSLOG_SOCKET_PATH);
#undef SYSLOG_SOCKET_PATH
	*s = '\0';
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
	char *s;

	if ((syslog_fd < 0) && ((syslog_fd = syslog_connect()) < 0))
		return;

#define LOC s,buf+sizeof(buf)-s
	s = buf;
	s = str_append(LOC, "<");
	s = num_append(LOC, priority);
	s = str_append(LOC, ">");
	/* forget about the timestamp, too difficult in a signal handler */
	s = str_append(LOC, zlog_default->ident);
	if (zlog_default->syslog_options & LOG_PID) {
		s = str_append(LOC, "[");
		s = num_append(LOC, getpid());
		s = str_append(LOC, "]");
	}
	s = str_append(LOC, ": ");
	s = str_append(LOC, msg);
	write_wrapper(syslog_fd, buf, s - buf);
#undef LOC
}

static int open_crashlog(void)
{
#define CRASHLOG_PREFIX "/var/tmp/quagga."
#define CRASHLOG_SUFFIX "crashlog"
	if (zlog_default && zlog_default->ident) {
		/* Avoid strlen since it is not async-signal-safe. */
		const char *p;
		size_t ilen;

		for (p = zlog_default->ident, ilen = 0; *p; p++)
			ilen++;
		{
			char buf[sizeof(CRASHLOG_PREFIX) + ilen
				 + sizeof(CRASHLOG_SUFFIX) + 3];
			char *s = buf;
#define LOC s,buf+sizeof(buf)-s
			s = str_append(LOC, CRASHLOG_PREFIX);
			s = str_append(LOC, zlog_default->ident);
			s = str_append(LOC, ".");
			s = str_append(LOC, CRASHLOG_SUFFIX);
#undef LOC
			*s = '\0';
			return open(buf, O_WRONLY | O_CREAT | O_EXCL,
				    LOGFILE_MASK);
		}
	}
	return open(CRASHLOG_PREFIX CRASHLOG_SUFFIX,
		    O_WRONLY | O_CREAT | O_EXCL, LOGFILE_MASK);
#undef CRASHLOG_SUFFIX
#undef CRASHLOG_PREFIX
}

/* Note: the goal here is to use only async-signal-safe functions. */
void zlog_signal(int signo, const char *action
#ifdef SA_SIGINFO
		 ,
		 siginfo_t *siginfo, void *program_counter
#endif
		 )
{
	time_t now;
	char buf[sizeof("DEFAULT: Received signal S at T (si_addr 0xP, PC 0xP); aborting...")
		 + 100];
	char *s = buf;
	char *msgstart = buf;
#define LOC s,buf+sizeof(buf)-s

	time(&now);
	if (zlog_default) {
		s = str_append(LOC, zlog_default->protoname);
		*s++ = ':';
		*s++ = ' ';
		msgstart = s;
	}
	s = str_append(LOC, "Received signal ");
	s = num_append(LOC, signo);
	s = str_append(LOC, " at ");
	s = num_append(LOC, now);
#ifdef SA_SIGINFO
	s = str_append(LOC, " (si_addr 0x");
	s = hex_append(LOC, (u_long)(siginfo->si_addr));
	if (program_counter) {
		s = str_append(LOC, ", PC 0x");
		s = hex_append(LOC, (u_long)program_counter);
	}
	s = str_append(LOC, "); ");
#else  /* SA_SIGINFO */
	s = str_append(LOC, "; ");
#endif /* SA_SIGINFO */
	s = str_append(LOC, action);
	if (s < buf + sizeof(buf))
		*s++ = '\n';

/* N.B. implicit priority is most severe */
#define PRI LOG_CRIT

#define DUMP(FD) write_wrapper(FD, buf, s-buf);
	/* If no file logging configured, try to write to fallback log file. */
	if ((logfile_fd >= 0) || ((logfile_fd = open_crashlog()) >= 0))
		DUMP(logfile_fd)
	if (!zlog_default)
		DUMP(STDERR_FILENO)
	else {
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
			DUMP(STDOUT_FILENO)
		/* Remove trailing '\n' for monitor and syslog */
		*--s = '\0';
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
			vty_log_fixed(buf, s - buf);
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
			syslog_sigsafe(PRI | zlog_default->facility, msgstart,
				       s - msgstart);
	}
#undef DUMP

	zlog_backtrace_sigsafe(PRI,
#ifdef SA_SIGINFO
			       program_counter
#else
			       NULL
#endif
			       );

	s = buf;
	struct thread *tc;
	tc = pthread_getspecific(thread_current);
	if (!tc)
		s = str_append(LOC, "no thread information available\n");
	else {
		s = str_append(LOC, "in thread ");
		s = str_append(LOC, tc->funcname);
		s = str_append(LOC, " scheduled from ");
		s = str_append(LOC, tc->schedfrom);
		s = str_append(LOC, ":");
		s = num_append(LOC, tc->schedfrom_line);
		s = str_append(LOC, "\n");
	}

#define DUMP(FD) write_wrapper(FD, buf, s-buf);
	/* If no file logging configured, try to write to fallback log file. */
	if (logfile_fd >= 0)
		DUMP(logfile_fd)
	if (!zlog_default)
		DUMP(STDERR_FILENO)
	else {
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
			DUMP(STDOUT_FILENO)
		/* Remove trailing '\n' for monitor and syslog */
		*--s = '\0';
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
			vty_log_fixed(buf, s - buf);
		if (PRI <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
			syslog_sigsafe(PRI | zlog_default->facility, msgstart,
				       s - msgstart);
	}
#undef DUMP

#undef PRI
#undef LOC
}

/* Log a backtrace using only async-signal-safe functions.
   Needs to be enhanced to support syslog logging. */
void zlog_backtrace_sigsafe(int priority, void *program_counter)
{
#ifdef HAVE_STACK_TRACE
	static const char pclabel[] = "Program counter: ";
	void *array[64];
	int size;
	char buf[100];
	char *s, **bt = NULL;
#define LOC s,buf+sizeof(buf)-s

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
		write_wrapper(FD, buf, s - buf);                               \
		backtrace_symbols_fd(array, size, FD);                         \
	}
#elif defined(HAVE_PRINTSTACK)
#define DUMP(FD)                                                               \
	{                                                                      \
		if (program_counter)                                           \
			write_wrapper((FD), pclabel, sizeof(pclabel) - 1);     \
		write_wrapper((FD), buf, s - buf);                             \
		printstack((FD));                                              \
	}
#endif /* HAVE_GLIBC_BACKTRACE, HAVE_PRINTSTACK */

	s = buf;
	s = str_append(LOC, "Backtrace for ");
	s = num_append(LOC, size);
	s = str_append(LOC, " stack frames:\n");

	if ((logfile_fd >= 0) || ((logfile_fd = open_crashlog()) >= 0))
		DUMP(logfile_fd)
	if (!zlog_default)
		DUMP(STDERR_FILENO)
	else {
		if (priority <= zlog_default->maxlvl[ZLOG_DEST_STDOUT])
			DUMP(STDOUT_FILENO)
		/* Remove trailing '\n' for monitor and syslog */
		*--s = '\0';
		if (priority <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
			vty_log_fixed(buf, s - buf);
		if (priority <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
			syslog_sigsafe(priority | zlog_default->facility, buf,
				       s - buf);
		{
			int i;
#ifdef HAVE_GLIBC_BACKTRACE
			bt = backtrace_symbols(array, size);
#endif
			/* Just print the function addresses. */
			for (i = 0; i < size; i++) {
				s = buf;
				if (bt)
					s = str_append(LOC, bt[i]);
				else {
					s = str_append(LOC, "[bt ");
					s = num_append(LOC, i);
					s = str_append(LOC, "] 0x");
					s = hex_append(LOC, (u_long)(array[i]));
				}
				*s = '\0';
				if (priority
				    <= zlog_default->maxlvl[ZLOG_DEST_MONITOR])
					vty_log_fixed(buf, s - buf);
				if (priority
				    <= zlog_default->maxlvl[ZLOG_DEST_SYSLOG])
					syslog_sigsafe(
						priority
							| zlog_default
								  ->facility,
						buf, s - buf);
			}
			if (bt)
				free(bt);
		}
	}
#undef DUMP
#undef LOC
#endif /* HAVE_STRACK_TRACE */
}

void zlog_backtrace(int priority)
{
#ifndef HAVE_GLIBC_BACKTRACE
	zlog(priority, "No backtrace available on this platform.");
#else
	void *array[20];
	int size, i;
	char **strings;

	size = backtrace(array, array_size(array));
	if (size <= 0 || (size_t)size > array_size(array)) {
		zlog_err(
			"Cannot get backtrace, returned invalid # of frames %d "
			"(valid range is between 1 and %lu)",
			size, (unsigned long)(array_size(array)));
		return;
	}
	zlog(priority, "Backtrace for %d stack frames:", size);
	if (!(strings = backtrace_symbols(array, size))) {
		zlog_err("Cannot get backtrace symbols (out of memory?)");
		for (i = 0; i < size; i++)
			zlog(priority, "[bt %d] %p", i, array[i]);
	} else {
		for (i = 0; i < size; i++)
			zlog(priority, "[bt %d] %s", i, strings[i]);
		free(strings);
	}
#endif /* HAVE_GLIBC_BACKTRACE */
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
	zlog_err(
		"out of memory: failed to allocate %zu bytes for %s"
		"object",
		size, name);
	zlog_backtrace(LOG_ERR);
	abort();
}

/* Open log stream */
void openzlog(const char *progname, const char *protoname, u_short instance,
	      int syslog_flags, int syslog_facility)
{
	struct zlog *zl;
	u_int i;

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

	pthread_mutex_lock(&loglock);
	zlog_default = zl;
	pthread_mutex_unlock(&loglock);

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
	pthread_mutex_lock(&loglock);
	struct zlog *zl = zlog_default;

	closelog();

	if (zl->fp != NULL)
		fclose(zl->fp);

	if (zl->filename != NULL)
		XFREE(MTYPE_ZLOG, zl->filename);

	XFREE(MTYPE_ZLOG, zl);
	zlog_default = NULL;
	pthread_mutex_unlock(&loglock);
}

/* Called from command.c. */
void zlog_set_level(zlog_dest_t dest, int log_level)
{
	pthread_mutex_lock(&loglock);
	zlog_default->maxlvl[dest] = log_level;
	pthread_mutex_unlock(&loglock);
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
		pthread_mutex_lock(&loglock);
		zl = zlog_default;

		/* Set flags. */
		zl->filename = XSTRDUP(MTYPE_ZLOG, filename);
		zl->maxlvl[ZLOG_DEST_FILE] = log_level;
		zl->fp = fp;
		logfile_fd = fileno(fp);
		pthread_mutex_unlock(&loglock);
	}

	return ret;
}

/* Reset opend file. */
int zlog_reset_file(void)
{
	pthread_mutex_lock(&loglock);

	struct zlog *zl = zlog_default;

	if (zl->fp)
		fclose(zl->fp);
	zl->fp = NULL;
	logfile_fd = -1;
	zl->maxlvl[ZLOG_DEST_FILE] = ZLOG_DISABLED;

	if (zl->filename)
		XFREE(MTYPE_ZLOG, zl->filename);
	zl->filename = NULL;

	pthread_mutex_unlock(&loglock);

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
			zlog_err(
				"Log rotate failed: cannot open file %s for append: %s",
				zl->filename, safe_strerror(save_errno));
			ret = -1;
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
	DESC_ENTRY(ZEBRA_IPV4_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_IPV4_ROUTE_DELETE),
	DESC_ENTRY(ZEBRA_IPV6_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_IPV6_ROUTE_DELETE),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DELETE),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DEFAULT_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_DEFAULT_DELETE),
	DESC_ENTRY(ZEBRA_ROUTER_ID_ADD),
	DESC_ENTRY(ZEBRA_ROUTER_ID_DELETE),
	DESC_ENTRY(ZEBRA_ROUTER_ID_UPDATE),
	DESC_ENTRY(ZEBRA_HELLO),
	DESC_ENTRY(ZEBRA_NEXTHOP_REGISTER),
	DESC_ENTRY(ZEBRA_NEXTHOP_UNREGISTER),
	DESC_ENTRY(ZEBRA_NEXTHOP_UPDATE),
	DESC_ENTRY(ZEBRA_INTERFACE_NBR_ADDRESS_ADD),
	DESC_ENTRY(ZEBRA_INTERFACE_NBR_ADDRESS_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_BFD_DEST_UPDATE),
	DESC_ENTRY(ZEBRA_IMPORT_ROUTE_REGISTER),
	DESC_ENTRY(ZEBRA_IMPORT_ROUTE_UNREGISTER),
	DESC_ENTRY(ZEBRA_IMPORT_CHECK_UPDATE),
	DESC_ENTRY(ZEBRA_IPV4_ROUTE_IPV6_NEXTHOP_ADD),
	DESC_ENTRY(ZEBRA_BFD_DEST_REGISTER),
	DESC_ENTRY(ZEBRA_BFD_DEST_DEREGISTER),
	DESC_ENTRY(ZEBRA_BFD_DEST_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_DEST_REPLAY),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ROUTE_ADD),
	DESC_ENTRY(ZEBRA_REDISTRIBUTE_ROUTE_DEL),
	DESC_ENTRY(ZEBRA_VRF_UNREGISTER),
	DESC_ENTRY(ZEBRA_VRF_ADD),
	DESC_ENTRY(ZEBRA_VRF_DELETE),
	DESC_ENTRY(ZEBRA_INTERFACE_VRF_UPDATE),
	DESC_ENTRY(ZEBRA_BFD_CLIENT_REGISTER),
	DESC_ENTRY(ZEBRA_INTERFACE_ENABLE_RADV),
	DESC_ENTRY(ZEBRA_INTERFACE_DISABLE_RADV),
	DESC_ENTRY(ZEBRA_IPV4_NEXTHOP_LOOKUP_MRIB),
	DESC_ENTRY(ZEBRA_INTERFACE_LINK_PARAMS),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_ADD),
	DESC_ENTRY(ZEBRA_MPLS_LABELS_DELETE),
	DESC_ENTRY(ZEBRA_IPMR_ROUTE_STATS),
	DESC_ENTRY(ZEBRA_LABEL_MANAGER_CONNECT),
	DESC_ENTRY(ZEBRA_GET_LABEL_CHUNK),
	DESC_ENTRY(ZEBRA_RELEASE_LABEL_CHUNK),
	DESC_ENTRY(ZEBRA_ADVERTISE_ALL_VNI),
	DESC_ENTRY(ZEBRA_ADVERTISE_DEFAULT_GW),
	DESC_ENTRY(ZEBRA_ADVERTISE_SUBNET),
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
	DESC_ENTRY(ZEBRA_PW_ADD),
	DESC_ENTRY(ZEBRA_PW_DELETE),
	DESC_ENTRY(ZEBRA_PW_SET),
	DESC_ENTRY(ZEBRA_PW_UNSET),
	DESC_ENTRY(ZEBRA_PW_STATUS_UPDATE),
};
#undef DESC_ENTRY

static const struct zebra_desc_table unknown = {0, "unknown", '?'};

static const struct zebra_desc_table *zroute_lookup(u_int zroute)
{
	u_int i;

	if (zroute >= array_size(route_types)) {
		zlog_err("unknown zebra route type: %u", zroute);
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
	zlog_err("internal error: cannot find route type %u in table!", zroute);
	return &unknown;
}

const char *zebra_route_string(u_int zroute)
{
	return zroute_lookup(zroute)->string;
}

char zebra_route_char(u_int zroute)
{
	return zroute_lookup(zroute)->chr;
}

const char *zserv_command_string(unsigned int command)
{
	if (command >= array_size(command_types)) {
		zlog_err("unknown zserv command type: %u", command);
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
	}
	return -1;
}

void zlog_hexdump(const void *mem, unsigned int len)
{
	unsigned long i = 0;
	unsigned int j = 0;
	unsigned int columns = 8;
	char buf[(len * 4) + ((len / 4) * 20) + 30];
	char *s = buf;

	for (i = 0; i < len + ((len % columns) ? (columns - len % columns) : 0);
	     i++) {
		/* print offset */
		if (i % columns == 0)
			s += sprintf(s, "0x%016lx: ", (unsigned long)mem + i);

		/* print hex data */
		if (i < len)
			s += sprintf(s, "%02x ", 0xFF & ((const char *)mem)[i]);

		/* end of block, just aligning for ASCII dump */
		else
			s += sprintf(s, "   ");

		/* print ASCII dump */
		if (i % columns == (columns - 1)) {
			for (j = i - (columns - 1); j <= i; j++) {
				if (j >= len) /* end of block, not really
						 printing */
					s += sprintf(s, " ");

				else if (
					isprint((int)((const char *)mem)
							[j])) /* printable char
								 */
					s += sprintf(
						s, "%c",
						0xFF & ((const char *)mem)[j]);

				else /* other char */
					s += sprintf(s, ".");
			}
			s += sprintf(s, "\n");
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
