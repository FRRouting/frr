/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
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

#include "zebra.h"

#include <unistd.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <time.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <pthread.h>

/* gettid() & co. */
#ifdef HAVE_PTHREAD_NP_H
#include <pthread_np.h>
#endif
#ifdef linux
#include <sys/syscall.h>
#endif
#ifdef __FreeBSD__
#include <sys/thr.h>
#endif
#ifdef __NetBSD__
#include <lwp.h>
#endif
#ifdef __DragonFly__
#include <sys/lwp.h>
#endif
#ifdef __APPLE__
#include <mach/mach_traps.h>
#endif

#include "memory.h"
#include "atomlist.h"
#include "printfrr.h"
#include "frrcu.h"
#include "zlog.h"
#include "trace.h"

DEFINE_MTYPE_STATIC(LIB, LOG_MESSAGE,  "log message")
DEFINE_MTYPE_STATIC(LIB, LOG_TLSBUF,   "log thread-local buffer")

DEFINE_HOOK(zlog_init, (const char *progname, const char *protoname,
			unsigned short instance, uid_t uid, gid_t gid),
		       (progname, protoname, instance, uid, gid))
DEFINE_KOOH(zlog_fini, (), ())
DEFINE_HOOK(zlog_aux_init, (const char *prefix, int prio_min),
			   (prefix, prio_min))

char zlog_prefix[128];
size_t zlog_prefixsz;
int zlog_tmpdirfd = -1;

/* these are kept around because logging is initialized (and directories
 * & files created) before zprivs code switches to the FRR user;  therefore
 * we need to chown() things so we don't get permission errors later when
 * trying to delete things on shutdown
 */
static uid_t zlog_uid = -1;
static gid_t zlog_gid = -1;

DECLARE_ATOMLIST(zlog_targets, struct zlog_target, head);
static struct zlog_targets_head zlog_targets;

/* cf. zlog.h for additional comments on this struct.
 *
 * Note: you MUST NOT pass the format string + va_list to non-FRR format
 * string functions (e.g. vsyslog, sd_journal_printv, ...) since FRR uses an
 * extended prinf() with additional formats (%pI4 and the like).
 *
 * Also remember to use va_copy() on args.
 */

struct zlog_msg {
	struct timespec ts;
	int prio;

	const char *fmt;
	va_list args;

	char *stackbuf;
	size_t stackbufsz;
	char *text;
	size_t textlen;

	/* This is always ISO8601 with sub-second precision 9 here, it's
	 * converted for callers as needed.  ts_dot points to the "."
	 * separating sub-seconds.  ts_zonetail is "Z" or "+00:00" for the
	 * local time offset.
	 *
	 * Valid if ZLOG_TS_ISO8601 is set.
	 * (0 if timestamp has not been formatted yet)
	 */
	uint32_t ts_flags;
	char ts_str[32], *ts_dot, ts_zonetail[8];
};

/* thread-local log message buffering
 *
 * This is strictly optional and set up by calling zlog_tls_buffer_init()
 * on a particular thread.
 *
 * If in use, this will create a temporary file in /var/tmp which is used as
 * memory-mapped MAP_SHARED log message buffer.  The idea there is that buffer
 * access doesn't require any syscalls, but in case of a crash the kernel
 * knows to sync the memory back to disk.  This way the user can still get the
 * last log messages if there were any left unwritten in the buffer.
 *
 * Sizing this dynamically isn't particularly useful, so here's an 8k buffer
 * with a message limit of 64 messages.  Message metadata (e.g. priority,
 * timestamp) aren't in the mmap region, so they're lost on crash, but we can
 * live with that.
 */

#if defined(HAVE_OPENAT) && defined(HAVE_UNLINKAT)
#define CAN_DO_TLS 1
#endif

#define TLS_LOG_BUF_SIZE	8192
#define TLS_LOG_MAXMSG		64

struct zlog_tls {
	char *mmbuf;
	size_t bufpos;

	size_t nmsgs;
	struct zlog_msg msgs[TLS_LOG_MAXMSG];
	struct zlog_msg *msgp[TLS_LOG_MAXMSG];
};

static inline void zlog_tls_free(void *arg);

/* proper ELF TLS is a bit faster than pthread_[gs]etspecific, so if it's
 * available we'll use it here
 */

#ifdef __OpenBSD__
static pthread_key_t zlog_tls_key;

static void zlog_tls_key_init(void) __attribute__((_CONSTRUCTOR(500)));
static void zlog_tls_key_init(void)
{
	pthread_key_create(&zlog_tls_key, zlog_tls_free);
}

static void zlog_tls_key_fini(void) __attribute__((_DESTRUCTOR(500)));
static void zlog_tls_key_fini(void)
{
	pthread_key_delete(zlog_tls_key);
}

static inline struct zlog_tls *zlog_tls_get(void)
{
	return pthread_getspecific(zlog_tls_key);
}

static inline void zlog_tls_set(struct zlog_tls *val)
{
	pthread_setspecific(zlog_tls_key, val);
}
#else
# ifndef thread_local
#  define thread_local __thread
# endif

static thread_local struct zlog_tls *zlog_tls_var
	__attribute__((tls_model("initial-exec")));

static inline struct zlog_tls *zlog_tls_get(void)
{
	return zlog_tls_var;
}

static inline void zlog_tls_set(struct zlog_tls *val)
{
	zlog_tls_var = val;
}
#endif

#ifdef CAN_DO_TLS
static long zlog_gettid(void)
{
	long rv = -1;
#ifdef HAVE_PTHREAD_GETTHREADID_NP
	rv = pthread_getthreadid_np();
#elif defined(linux)
	rv = syscall(__NR_gettid);
#elif defined(__NetBSD__)
	rv = _lwp_self();
#elif defined(__FreeBSD__)
	thr_self(&rv);
#elif defined(__DragonFly__)
	rv = lwp_gettid();
#elif defined(__OpenBSD__)
	rv = getthrid();
#elif defined(__sun)
	rv = pthread_self();
#elif defined(__APPLE__)
	rv = mach_thread_self();
	mach_port_deallocate(mach_task_self(), rv);
#endif
	return rv;
}

void zlog_tls_buffer_init(void)
{
	struct zlog_tls *zlog_tls;
	char mmpath[MAXPATHLEN];
	int mmfd;
	size_t i;

	zlog_tls = zlog_tls_get();

	if (zlog_tls || zlog_tmpdirfd < 0)
		return;

	zlog_tls = XCALLOC(MTYPE_LOG_TLSBUF, sizeof(*zlog_tls));
	for (i = 0; i < array_size(zlog_tls->msgp); i++)
		zlog_tls->msgp[i] = &zlog_tls->msgs[i];

	snprintfrr(mmpath, sizeof(mmpath), "logbuf.%ld", zlog_gettid());

	mmfd = openat(zlog_tmpdirfd, mmpath,
		      O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
	if (mmfd < 0) {
		zlog_err("failed to open thread log buffer \"%s\": %s",
			 mmpath, strerror(errno));
		goto out_anon;
	}
	fchown(mmfd, zlog_uid, zlog_gid);

#ifdef HAVE_POSIX_FALLOCATE
	if (posix_fallocate(mmfd, 0, TLS_LOG_BUF_SIZE) != 0)
	/* note next statement is under above if() */
#endif
	if (ftruncate(mmfd, TLS_LOG_BUF_SIZE) < 0) {
		zlog_err("failed to allocate thread log buffer \"%s\": %s",
			 mmpath, strerror(errno));
		goto out_anon_unlink;
	}

	zlog_tls->mmbuf = mmap(NULL, TLS_LOG_BUF_SIZE, PROT_READ | PROT_WRITE,
			      MAP_SHARED, mmfd, 0);
	if (zlog_tls->mmbuf == MAP_FAILED) {
		zlog_err("failed to mmap thread log buffer \"%s\": %s",
			 mmpath, strerror(errno));
		goto out_anon_unlink;
	}

	close(mmfd);
	zlog_tls_set(zlog_tls);
	return;

out_anon_unlink:
	unlink(mmpath);
	close(mmfd);
out_anon:

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
	zlog_tls->mmbuf = mmap(NULL, TLS_LOG_BUF_SIZE, PROT_READ | PROT_WRITE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);

	if (!zlog_tls->mmbuf) {
		zlog_err("failed to anonymous-mmap thread log buffer: %s",
			 strerror(errno));
		XFREE(MTYPE_LOG_TLSBUF, zlog_tls);
		zlog_tls_set(NULL);
		return;
	}

	zlog_tls_set(zlog_tls);
}

void zlog_tls_buffer_fini(void)
{
	char mmpath[MAXPATHLEN];

	zlog_tls_buffer_flush();

	zlog_tls_free(zlog_tls_get());
	zlog_tls_set(NULL);

	snprintfrr(mmpath, sizeof(mmpath), "logbuf.%ld", zlog_gettid());
	if (unlinkat(zlog_tmpdirfd, mmpath, 0))
		zlog_err("unlink logbuf: %s (%d)", strerror(errno), errno);
}

#else /* !CAN_DO_TLS */
void zlog_tls_buffer_init(void)
{
}

void zlog_tls_buffer_fini(void)
{
}
#endif

static inline void zlog_tls_free(void *arg)
{
	struct zlog_tls *zlog_tls = arg;

	if (!zlog_tls)
		return;

	munmap(zlog_tls->mmbuf, TLS_LOG_BUF_SIZE);
	XFREE(MTYPE_LOG_TLSBUF, zlog_tls);
}

void zlog_tls_buffer_flush(void)
{
	struct zlog_target *zt;
	struct zlog_tls *zlog_tls = zlog_tls_get();

	if (!zlog_tls)
		return;
	if (!zlog_tls->nmsgs)
		return;

	rcu_read_lock();
	frr_each (zlog_targets, &zlog_targets, zt) {
		if (!zt->logfn)
			continue;

		zt->logfn(zt, zlog_tls->msgp, zlog_tls->nmsgs);
	}
	rcu_read_unlock();

	zlog_tls->bufpos = 0;
	zlog_tls->nmsgs = 0;
}


static void vzlog_notls(int prio, const char *fmt, va_list ap)
{
	struct zlog_target *zt;
	struct zlog_msg stackmsg = {
		.prio = prio & LOG_PRIMASK,
		.fmt = fmt,
	}, *msg = &stackmsg;
	char stackbuf[512];

	clock_gettime(CLOCK_REALTIME, &msg->ts);
	va_copy(msg->args, ap);
	msg->stackbuf = stackbuf;
	msg->stackbufsz = sizeof(stackbuf);

	rcu_read_lock();
	frr_each (zlog_targets, &zlog_targets, zt) {
		if (prio > zt->prio_min)
			continue;
		if (!zt->logfn)
			continue;

		zt->logfn(zt, &msg, 1);
	}
	rcu_read_unlock();

	va_end(msg->args);
	if (msg->text && msg->text != stackbuf)
		XFREE(MTYPE_LOG_MESSAGE, msg->text);
}

static void vzlog_tls(struct zlog_tls *zlog_tls, int prio,
		      const char *fmt, va_list ap)
{
	struct zlog_target *zt;
	struct zlog_msg *msg;
	char *buf;
	bool ignoremsg = true;
	bool immediate = false;

	/* avoid further processing cost if no target wants this message */
	rcu_read_lock();
	frr_each (zlog_targets, &zlog_targets, zt) {
		if (prio > zt->prio_min)
			continue;
		ignoremsg = false;
		break;
	}
	rcu_read_unlock();

	if (ignoremsg)
		return;

	msg = &zlog_tls->msgs[zlog_tls->nmsgs];
	zlog_tls->nmsgs++;
	if (zlog_tls->nmsgs == array_size(zlog_tls->msgs))
		immediate = true;

	memset(msg, 0, sizeof(*msg));
	clock_gettime(CLOCK_REALTIME, &msg->ts);
	va_copy(msg->args, ap);
	msg->stackbuf = buf = zlog_tls->mmbuf + zlog_tls->bufpos;
	msg->stackbufsz = TLS_LOG_BUF_SIZE - zlog_tls->bufpos - 1;
	msg->fmt = fmt;
	msg->prio = prio & LOG_PRIMASK;
	if (msg->prio < LOG_INFO)
		immediate = true;

	if (!immediate) {
		/* messages written later need to take the formatting cost
		 * immediately since we can't hold a reference on varargs
		 */
		zlog_msg_text(msg, NULL);

		if (msg->text != buf)
			/* zlog_msg_text called malloc() on us :( */
			immediate = true;
		else {
			zlog_tls->bufpos += msg->textlen + 1;
			/* write a second \0 to mark current end position
			 * (in case of crash this signals end of unwritten log
			 * messages in mmap'd logbuf file)
			 */
			zlog_tls->mmbuf[zlog_tls->bufpos] = '\0';

			/* avoid malloc() for next message */
			if (TLS_LOG_BUF_SIZE - zlog_tls->bufpos < 256)
				immediate = true;
		}
	}

	if (immediate)
		zlog_tls_buffer_flush();

	va_end(msg->args);
	if (msg->text && msg->text != buf)
		XFREE(MTYPE_LOG_MESSAGE, msg->text);
}

void vzlog(int prio, const char *fmt, va_list ap)
{
	struct zlog_tls *zlog_tls = zlog_tls_get();

#ifdef HAVE_LTTNG
	va_list copy;
	va_copy(copy, ap);
	char *msg = vasprintfrr(MTYPE_LOG_MESSAGE, fmt, copy);

	switch (prio) {
	case LOG_ERR:
		tracelog(TRACE_ERR, msg);
		break;
	case LOG_WARNING:
		tracelog(TRACE_WARNING, msg);
		break;
	case LOG_DEBUG:
		tracelog(TRACE_DEBUG, msg);
		break;
	case LOG_NOTICE:
		tracelog(TRACE_DEBUG, msg);
		break;
	case LOG_INFO:
	default:
		tracelog(TRACE_INFO, msg);
		break;
	}

	va_end(copy);
	XFREE(MTYPE_LOG_MESSAGE, msg);
#endif

	if (zlog_tls)
		vzlog_tls(zlog_tls, prio, fmt, ap);
	else
		vzlog_notls(prio, fmt, ap);
}

void zlog_sigsafe(const char *text, size_t len)
{
	struct zlog_target *zt;
	const char *end = text + len, *nlpos;

	while (text < end) {
		nlpos = memchr(text, '\n', end - text);
		if (!nlpos)
			nlpos = end;

		frr_each (zlog_targets, &zlog_targets, zt) {
			if (LOG_CRIT > zt->prio_min)
				continue;
			if (!zt->logfn_sigsafe)
				continue;

			zt->logfn_sigsafe(zt, text, nlpos - text);
		}

		if (nlpos == end)
			break;
		text = nlpos + 1;
	}
}


int zlog_msg_prio(struct zlog_msg *msg)
{
	return msg->prio;
}

const char *zlog_msg_text(struct zlog_msg *msg, size_t *textlen)
{
	if (!msg->text) {
		va_list args;

		va_copy(args, msg->args);
		msg->text = vasnprintfrr(MTYPE_LOG_MESSAGE, msg->stackbuf,
					 msg->stackbufsz, msg->fmt, args);
		msg->textlen = strlen(msg->text);
		va_end(args);
	}
	if (textlen)
		*textlen = msg->textlen;
	return msg->text;
}

#define ZLOG_TS_FORMAT		(ZLOG_TS_ISO8601 | ZLOG_TS_LEGACY)
#define ZLOG_TS_FLAGS		~ZLOG_TS_PREC

size_t zlog_msg_ts(struct zlog_msg *msg, char *out, size_t outsz,
		   uint32_t flags)
{
	size_t len1;

	if (!(flags & ZLOG_TS_FORMAT))
		return 0;

	if (!(msg->ts_flags & ZLOG_TS_FORMAT) ||
	    ((msg->ts_flags ^ flags) & ZLOG_TS_UTC)) {
		struct tm tm;

		if (flags & ZLOG_TS_UTC)
			gmtime_r(&msg->ts.tv_sec, &tm);
		else
			localtime_r(&msg->ts.tv_sec, &tm);

		strftime(msg->ts_str, sizeof(msg->ts_str),
			 "%Y-%m-%dT%H:%M:%S", &tm);

		if (flags & ZLOG_TS_UTC) {
			msg->ts_zonetail[0] = 'Z';
			msg->ts_zonetail[1] = '\0';
		} else
			snprintfrr(msg->ts_zonetail, sizeof(msg->ts_zonetail),
				   "%+03d:%02d",
				   (int)(tm.tm_gmtoff / 3600),
				   (int)(labs(tm.tm_gmtoff) / 60) % 60);

		msg->ts_dot = msg->ts_str + strlen(msg->ts_str);
		snprintfrr(msg->ts_dot,
			   msg->ts_str + sizeof(msg->ts_str) - msg->ts_dot,
			   ".%09lu", (unsigned long)msg->ts.tv_nsec);

		msg->ts_flags = ZLOG_TS_ISO8601 | (flags & ZLOG_TS_UTC);
	}

	len1 = flags & ZLOG_TS_PREC;
	len1 = (msg->ts_dot - msg->ts_str) + (len1 ? len1 + 1 : 0);

	if (len1 > strlen(msg->ts_str))
		len1 = strlen(msg->ts_str);

	if (flags & ZLOG_TS_LEGACY) {
		if (len1 + 1 > outsz)
			return 0;

		/* just swap out the formatting, faster than redoing it */
		for (char *p = msg->ts_str; p < msg->ts_str + len1; p++) {
			switch (*p) {
			case '-':
				*out++ = '/';
				break;
			case 'T':
				*out++ = ' ';
				break;
			default:
				*out++ = *p;
			}
		}
		*out = '\0';
		return len1;
	} else {
		size_t len2 = strlen(msg->ts_zonetail);

		if (len1 + len2 + 1 > outsz)
			return 0;
		memcpy(out, msg->ts_str, len1);
		memcpy(out + len1, msg->ts_zonetail, len2);
		out[len1 + len2] = '\0';
		return len1 + len2;
	}
}

/* setup functions */

struct zlog_target *zlog_target_clone(struct memtype *mt,
				      struct zlog_target *oldzt, size_t size)
{
	struct zlog_target *newzt;

	newzt = XCALLOC(mt, size);
	if (oldzt) {
		newzt->prio_min = oldzt->prio_min;
		newzt->logfn = oldzt->logfn;
		newzt->logfn_sigsafe = oldzt->logfn_sigsafe;
	}

	return newzt;
}

struct zlog_target *zlog_target_replace(struct zlog_target *oldzt,
					struct zlog_target *newzt)
{
	if (newzt)
		zlog_targets_add_tail(&zlog_targets, newzt);
	if (oldzt)
		zlog_targets_del(&zlog_targets, oldzt);
	return oldzt;
}


/* common init */

#define TMPBASEDIR "/var/tmp/frr"

static char zlog_tmpdir[MAXPATHLEN];

void zlog_aux_init(const char *prefix, int prio_min)
{
	if (prefix)
		strlcpy(zlog_prefix, prefix, sizeof(zlog_prefix));

	hook_call(zlog_aux_init, prefix, prio_min);
}

void zlog_init(const char *progname, const char *protoname,
	       unsigned short instance, uid_t uid, gid_t gid)
{
	zlog_uid = uid;
	zlog_gid = gid;

	if (instance) {
		snprintfrr(zlog_tmpdir, sizeof(zlog_tmpdir),
			   "/var/tmp/frr/%s-%d.%ld",
			   progname, instance, (long)getpid());

		zlog_prefixsz = snprintfrr(zlog_prefix, sizeof(zlog_prefix),
					   "%s[%d]: ", protoname, instance);
	} else {
		snprintfrr(zlog_tmpdir, sizeof(zlog_tmpdir),
			   "/var/tmp/frr/%s.%ld",
			   progname, (long)getpid());

		zlog_prefixsz = snprintfrr(zlog_prefix, sizeof(zlog_prefix),
					   "%s: ", protoname);
	}

	if (mkdir(TMPBASEDIR, 0700) != 0) {
		if (errno != EEXIST) {
			zlog_err("failed to mkdir \"%s\": %s",
				 TMPBASEDIR, strerror(errno));
			goto out_warn;
		}
	}
	chown(TMPBASEDIR, zlog_uid, zlog_gid);

	if (mkdir(zlog_tmpdir, 0700) != 0) {
		zlog_err("failed to mkdir \"%s\": %s",
			 zlog_tmpdir, strerror(errno));
		goto out_warn;
	}

#ifdef O_PATH
	zlog_tmpdirfd = open(zlog_tmpdir,
			     O_PATH | O_RDONLY | O_CLOEXEC);
#else
	zlog_tmpdirfd = open(zlog_tmpdir,
			     O_DIRECTORY | O_RDONLY | O_CLOEXEC);
#endif
	if (zlog_tmpdirfd < 0) {
		zlog_err("failed to open \"%s\": %s",
			 zlog_tmpdir, strerror(errno));
		goto out_warn;
	}

#ifdef AT_EMPTY_PATH
	fchownat(zlog_tmpdirfd, "", zlog_uid, zlog_gid, AT_EMPTY_PATH);
#else
	chown(zlog_tmpdir, zlog_uid, zlog_gid);
#endif

	hook_call(zlog_init, progname, protoname, instance, uid, gid);
	return;

out_warn:
	zlog_err("crashlog and per-thread log buffering unavailable!");
	hook_call(zlog_init, progname, protoname, instance, uid, gid);
}

void zlog_fini(void)
{
	hook_call(zlog_fini);

	if (zlog_tmpdirfd >= 0) {
		close(zlog_tmpdirfd);
		zlog_tmpdirfd = -1;

		if (rmdir(zlog_tmpdir))
			zlog_err("failed to rmdir \"%s\": %s",
				 zlog_tmpdir, strerror(errno));
	}
}
