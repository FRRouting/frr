// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
 */

#include "zebra.h"
#include <sys/stat.h>
#include <fcntl.h>

#ifdef HAVE_GLIBC_BACKTRACE
#include <execinfo.h>
#endif /* HAVE_GLIBC_BACKTRACE */

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

#ifdef HAVE_LIBUNWIND
#define UNW_LOCAL_ONLY
#include <libunwind.h>
#include <dlfcn.h>
#endif

#include "memory.h"
#include "atomlist.h"
#include "printfrr.h"
#include "frrcu.h"
#include "zlog.h"
#include "zlog_live.h"
#include "libfrr_trace.h"
#include "frrevent.h"

DEFINE_MTYPE_STATIC(LIB, LOG_MESSAGE,  "log message");
DEFINE_MTYPE_STATIC(LIB, LOG_TLSBUF,   "log thread-local buffer");

DEFINE_HOOK(zlog_init, (const char *progname, const char *protoname,
			unsigned short instance, uid_t uid, gid_t gid),
		       (progname, protoname, instance, uid, gid));
DEFINE_KOOH(zlog_fini, (), ());
DEFINE_HOOK(zlog_aux_init, (const char *prefix, int prio_min),
			   (prefix, prio_min));

char zlog_prefix[128];
size_t zlog_prefixsz;
int zlog_tmpdirfd = -1;
int zlog_instance = -1;

static atomic_bool zlog_ec = true, zlog_xid = true;

/* these are kept around because logging is initialized (and directories
 * & files created) before zprivs code switches to the FRR user;  therefore
 * we need to chown() things so we don't get permission errors later when
 * trying to delete things on shutdown
 */
static uid_t zlog_uid = -1;
static gid_t zlog_gid = -1;

DECLARE_ATOMLIST(zlog_targets, struct zlog_target, head);
static struct zlog_targets_head zlog_targets;

/* Global setting for buffered vs immediate output. The default is
 * per-pthread buffering.
 */
static bool zlog_default_immediate;

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
	const struct xref_logmsg *xref;

	char *stackbuf;
	size_t stackbufsz;
	char *text;
	size_t textlen;
	size_t hdrlen;

	/* for relayed log messages ONLY (cf. zlog_recirculate_live_msg) */
	intmax_t pid, tid;

	/* This is always ISO8601 with sub-second precision 9 here, it's
	 * converted for callers as needed.  ts_dot points to the "."
	 * separating sub-seconds.  ts_zonetail is "Z" or "+00:00" for the
	 * local time offset.
	 *
	 * Valid if ZLOG_TS_ISO8601 is set.
	 * (0 if timestamp has not been formatted yet)
	 */
	char ts_str[32], *ts_dot, ts_zonetail[8];
	uint32_t ts_flags;

	/* "mmm dd hh:mm:ss" for 3164 legacy syslog - too dissimilar from
	 * the above, so just kept separately here.
	 */
	uint32_t ts_3164_flags;
	char ts_3164_str[16];

	/* at the time of writing, 16 args was the actual maximum of arguments
	 * to a single zlog call.  Particularly printing flag bitmasks seems
	 * to drive this.  That said, the overhead of dynamically sizing this
	 * probably outweighs the value.  If anything, a printfrr extension
	 * for printing flag bitmasks might be a good idea.
	 */
	struct fmt_outpos argpos[24];
	size_t n_argpos;
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
	bool do_unlink;

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
static intmax_t zlog_gettid(void)
{
#ifndef __OpenBSD__
	/* accessing a TLS variable is much faster than a syscall */
	static thread_local intmax_t cached_tid = -1;
	if (cached_tid != -1)
		return cached_tid;
#endif

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

#ifndef __OpenBSD__
	cached_tid = rv;
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

	snprintfrr(mmpath, sizeof(mmpath), "logbuf.%jd", zlog_gettid());

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
	zlog_tls->do_unlink = true;

	close(mmfd);
	zlog_tls_set(zlog_tls);
	return;

out_anon_unlink:
	unlinkat(zlog_tmpdirfd, mmpath, 0);
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
	struct zlog_tls *zlog_tls = zlog_tls_get();
	bool do_unlink = zlog_tls ? zlog_tls->do_unlink : false;

	zlog_tls_buffer_flush();

	zlog_tls_free(zlog_tls);
	zlog_tls_set(NULL);

	snprintfrr(mmpath, sizeof(mmpath), "logbuf.%jd", zlog_gettid());
	if (do_unlink && unlinkat(zlog_tmpdirfd, mmpath, 0))
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

void zlog_msg_pid(struct zlog_msg *msg, intmax_t *pid, intmax_t *tid)
{
#ifndef __OpenBSD__
	static thread_local intmax_t cached_pid = -1;
#endif

	/* recirculated messages */
	if (msg->pid) {
		*pid = msg->pid;
		*tid = msg->tid;
		return;
	}

#ifndef __OpenBSD__
	if (cached_pid != -1)
		*pid = cached_pid;
	else
		cached_pid = *pid = (intmax_t)getpid();
#else
	*pid = (intmax_t)getpid();
#endif
#ifdef CAN_DO_TLS
	*tid = zlog_gettid();
#else
	*tid = *pid;
#endif
}

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
	frr_each_safe (zlog_targets, &zlog_targets, zt) {
		if (!zt->logfn)
			continue;

		zt->logfn(zt, zlog_tls->msgp, zlog_tls->nmsgs);
	}
	rcu_read_unlock();

	zlog_tls->bufpos = 0;
	zlog_tls->nmsgs = 0;
}


static void vzlog_notls(const struct xref_logmsg *xref, int prio,
			const char *fmt, va_list ap)
{
	struct zlog_target *zt;
	struct zlog_msg stackmsg = {
		.prio = prio & LOG_PRIMASK,
		.fmt = fmt,
		.xref = xref,
	}, *msg = &stackmsg;
	char stackbuf[512];

	clock_gettime(CLOCK_REALTIME, &msg->ts);
	va_copy(msg->args, ap);
	msg->stackbuf = stackbuf;
	msg->stackbufsz = sizeof(stackbuf);

	rcu_read_lock();
	frr_each_safe (zlog_targets, &zlog_targets, zt) {
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

static void vzlog_tls(struct zlog_tls *zlog_tls, const struct xref_logmsg *xref,
		      int prio, const char *fmt, va_list ap)
{
	struct zlog_target *zt;
	struct zlog_msg *msg;
	char *buf;
	bool ignoremsg = true;
	bool immediate = zlog_default_immediate;

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
	msg->xref = xref;
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

/* reinject log message received by zlog_recirculate_recv().  As of writing,
 * only used in the ldpd parent process to proxy messages from lde/ldpe
 * subprocesses.
 */
void zlog_recirculate_live_msg(uint8_t *data, size_t len)
{
	struct zlog_target *zt;
	struct zlog_msg stackmsg = {}, *msg = &stackmsg;
	struct zlog_live_hdr *hdr;
	struct xrefdata *xrefdata, ref = {};

	if (len < sizeof(*hdr))
		return;

	hdr = (struct zlog_live_hdr *)data;
	if (hdr->hdrlen < sizeof(*hdr))
		return;
	data += hdr->hdrlen;
	len -= sizeof(*hdr);

	msg->ts.tv_sec = hdr->ts_sec;
	msg->ts.tv_nsec = hdr->ts_nsec;
	msg->pid = hdr->pid;
	msg->tid = hdr->tid;
	msg->prio = hdr->prio;

	if (hdr->textlen > len)
		return;
	msg->textlen = hdr->textlen;
	msg->hdrlen = hdr->texthdrlen;
	msg->text = (char *)data;

	/* caller needs to make sure we have a trailing \n\0, it's not
	 * transmitted on zlog_live
	 */
	if (msg->text[msg->textlen] != '\n' ||
	    msg->text[msg->textlen + 1] != '\0')
		return;

	static_assert(sizeof(msg->argpos[0]) == sizeof(hdr->argpos[0]),
		      "in-memory struct doesn't match on-wire variant");
	msg->n_argpos = MIN(hdr->n_argpos, array_size(msg->argpos));
	memcpy(msg->argpos, hdr->argpos, msg->n_argpos * sizeof(msg->argpos[0]));

	/* This will only work if we're in the same daemon: we received a log
	 * message uid and are now doing a lookup in *our* known uids to find
	 * it.  This works for ldpd because it's the same binary containing the
	 * same log messages, and ldpd is the only use case right now.
	 *
	 * When the uid is not found, the log message uid is lost but the
	 * message itself is still processed correctly.  If this is needed,
	 * this can be made to work in two ways:
	 * (a) synthesize a temporary xref_logmsg from the received data.
	 *     This is a bit annoying due to lifetimes with per-thread buffers.
	 * (b) extract and aggregate all log messages.  This already happens
	 *     with frr.xref but that would need to be fed back in.
	 */
	strlcpy(ref.uid, hdr->uid, sizeof(ref.uid));
	xrefdata = xrefdata_uid_find(&xrefdata_uid, &ref);

	if (xrefdata && xrefdata->xref->type == XREFT_LOGMSG) {
		struct xref_logmsg *xref_logmsg;

		xref_logmsg = (struct xref_logmsg *)xrefdata->xref;
		msg->xref = xref_logmsg;
		msg->fmt = xref_logmsg->fmtstring;
	} else {
		/* fake out format string... */
		msg->fmt = msg->text + hdr->texthdrlen;
	}

	rcu_read_lock();
	frr_each_safe (zlog_targets, &zlog_targets, zt) {
		if (msg->prio > zt->prio_min)
			continue;
		if (!zt->logfn)
			continue;

		zt->logfn(zt, &msg, 1);
	}
	rcu_read_unlock();
}

static void zlog_backtrace_msg(const struct xref_logmsg *xref, int prio)
{
	struct event *tc = pthread_getspecific(thread_current);
	const char *uid = xref->xref.xrefdata->uid;
	bool found_thread = false;

	zlog(prio, "| (%s) message in thread %jd, at %s(), %s:%d", uid,
	     zlog_gettid(), xref->xref.func, xref->xref.file, xref->xref.line);

#ifdef HAVE_LIBUNWIND
	const char *threadfunc = tc ? tc->xref->funcname : NULL;
	bool found_caller = false;
	unw_cursor_t cursor;
	unw_context_t uc;
	unw_word_t ip, off, sp;
	Dl_info dlinfo;

	unw_getcontext(&uc);

	unw_init_local(&cursor, &uc);
	while (unw_step(&cursor) > 0) {
		char buf[96], name[128] = "?";
		bool is_thread = false;

		unw_get_reg(&cursor, UNW_REG_IP, &ip);
		unw_get_reg(&cursor, UNW_REG_SP, &sp);

		if (unw_is_signal_frame(&cursor))
			zlog(prio, "| (%s)    ---- signal ----", uid);

		if (!unw_get_proc_name(&cursor, buf, sizeof(buf), &off)) {
			if (!strcmp(buf, xref->xref.func))
				found_caller = true;
			if (threadfunc && !strcmp(buf, threadfunc))
				found_thread = is_thread = true;

			snprintf(name, sizeof(name), "%s+%#lx", buf, (long)off);
		}

		if (!found_caller)
			continue;

		if (dladdr((void *)ip, &dlinfo))
			zlog(prio, "| (%s) %-36s %16lx+%08lx %16lx %s", uid,
			     name, (long)dlinfo.dli_fbase,
			     (long)ip - (long)dlinfo.dli_fbase, (long)sp,
			     dlinfo.dli_fname);
		else
			zlog(prio, "| (%s) %-36s %16lx %16lx", uid, name,
			     (long)ip, (long)sp);

		if (is_thread)
			zlog(prio, "| (%s) ^- scheduled from %s(), %s:%u", uid,
			     tc->xref->xref.func, tc->xref->xref.file,
			     tc->xref->xref.line);
	}
#elif defined(HAVE_GLIBC_BACKTRACE)
	void *frames[64];
	char **names = NULL;
	int n_frames, i;

	n_frames = backtrace(frames, array_size(frames));
	if (n_frames < 0)
		n_frames = 0;
	if (n_frames)
		names = backtrace_symbols(frames, n_frames);

	for (i = 0; i < n_frames; i++) {
		void *retaddr = frames[i];
		char *loc = names[i];

		zlog(prio, "| (%s) %16lx %-36s", uid, (long)retaddr, loc);
	}
	free(names);
#endif
	if (!found_thread && tc)
		zlog(prio, "| (%s) scheduled from %s(), %s:%u", uid,
		     tc->xref->xref.func, tc->xref->xref.file,
		     tc->xref->xref.line);
}

void vzlogx(const struct xref_logmsg *xref, int prio,
	    const char *fmt, va_list ap)
{
	struct zlog_tls *zlog_tls = zlog_tls_get();

#ifdef HAVE_LTTNG
	va_list copy;
	va_copy(copy, ap);
	char *msg = vasprintfrr(MTYPE_LOG_MESSAGE, fmt, copy);

	switch (prio) {
	case LOG_ERR:
		frrtracelog(TRACE_ERR, msg);
		break;
	case LOG_WARNING:
		frrtracelog(TRACE_WARNING, msg);
		break;
	case LOG_DEBUG:
		frrtracelog(TRACE_DEBUG, msg);
		break;
	case LOG_NOTICE:
		frrtracelog(TRACE_DEBUG, msg);
		break;
	case LOG_INFO:
	default:
		frrtracelog(TRACE_INFO, msg);
		break;
	}

	va_end(copy);
	XFREE(MTYPE_LOG_MESSAGE, msg);
#endif

	if (zlog_tls)
		vzlog_tls(zlog_tls, xref, prio, fmt, ap);
	else
		vzlog_notls(xref, prio, fmt, ap);

	if (xref) {
		struct xrefdata_logmsg *xrdl;

		xrdl = container_of(xref->xref.xrefdata, struct xrefdata_logmsg,
				    xrefdata);
		if (xrdl->fl_print_bt)
			zlog_backtrace_msg(xref, prio);
	}
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

void _zlog_assert_failed(const struct xref_assert *xref, const char *extra, ...)
{
	va_list ap;
	static bool assert_in_assert; /* "global-ish" variable, init to 0 */

	if (assert_in_assert)
		abort();
	assert_in_assert = true;

	if (extra) {
		struct va_format vaf;

		va_start(ap, extra);
		vaf.fmt = extra;
		vaf.va = &ap;

		zlog(LOG_CRIT,
		     "%s:%d: %s(): assertion (%s) failed, extra info: %pVA",
		     xref->xref.file, xref->xref.line, xref->xref.func,
		     xref->expr, &vaf);

		va_end(ap);
	} else
		zlog(LOG_CRIT, "%s:%d: %s(): assertion (%s) failed",
		     xref->xref.file, xref->xref.line, xref->xref.func,
		     xref->expr);

	/* abort() prints backtrace & memstats in SIGABRT handler */
	abort();
}

int zlog_msg_prio(struct zlog_msg *msg)
{
	return msg->prio;
}

const struct xref_logmsg *zlog_msg_xref(struct zlog_msg *msg)
{
	return msg->xref;
}

const char *zlog_msg_text(struct zlog_msg *msg, size_t *textlen)
{
	if (!msg->text) {
		va_list args;
		bool do_xid, do_ec;
		size_t need = 0, hdrlen;
		struct fbuf fb = {
			.buf = msg->stackbuf,
			.pos = msg->stackbuf,
			.len = msg->stackbufsz,
		};

		do_ec = atomic_load_explicit(&zlog_ec, memory_order_relaxed);
		do_xid = atomic_load_explicit(&zlog_xid, memory_order_relaxed);

		if (msg->xref && do_xid && msg->xref->xref.xrefdata->uid[0]) {
			need += bputch(&fb, '[');
			need += bputs(&fb, msg->xref->xref.xrefdata->uid);
			need += bputch(&fb, ']');
		}
		if (msg->xref && do_ec && msg->xref->ec)
			need += bprintfrr(&fb, "[EC %u]", msg->xref->ec);
		if (need)
			need += bputch(&fb, ' ');

		msg->hdrlen = hdrlen = need;
		assert(hdrlen < msg->stackbufsz);

		fb.outpos = msg->argpos;
		fb.outpos_n = array_size(msg->argpos);
		fb.outpos_i = 0;

		va_copy(args, msg->args);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		/* format-string checking is done further up the chain */
		need += vbprintfrr(&fb, msg->fmt, args);
#pragma GCC diagnostic pop
		va_end(args);

		msg->textlen = need;
		need += bputch(&fb, '\n');

		if (need <= msg->stackbufsz)
			msg->text = msg->stackbuf;
		else {
			msg->text = XMALLOC(MTYPE_LOG_MESSAGE, need);

			memcpy(msg->text, msg->stackbuf, hdrlen);

			fb.buf = msg->text;
			fb.len = need;
			fb.pos = msg->text + hdrlen;
			fb.outpos_i = 0;

			va_copy(args, msg->args);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
			/* same as above */
			vbprintfrr(&fb, msg->fmt, args);
#pragma GCC diagnostic pop
			va_end(args);

			bputch(&fb, '\n');
		}

		msg->n_argpos = fb.outpos_i;
	}
	if (textlen)
		*textlen = msg->textlen;
	return msg->text;
}

void zlog_msg_args(struct zlog_msg *msg, size_t *hdrlen, size_t *n_argpos,
		   const struct fmt_outpos **argpos)
{
	if (!msg->text)
		zlog_msg_text(msg, NULL);

	if (hdrlen)
		*hdrlen = msg->hdrlen;
	if (n_argpos)
		*n_argpos = msg->n_argpos;
	if (argpos)
		*argpos = msg->argpos;
}

#define ZLOG_TS_FORMAT		(ZLOG_TS_ISO8601 | ZLOG_TS_LEGACY)
#define ZLOG_TS_FLAGS		~ZLOG_TS_PREC

size_t zlog_msg_ts(struct zlog_msg *msg, struct fbuf *out, uint32_t flags)
{
	size_t outsz = out ? (out->buf + out->len - out->pos) : 0;
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
		if (!out)
			return len1;

		if (len1 > outsz) {
			memset(out->pos, 0, outsz);
			out->pos += outsz;
			return len1;
		}

		/* just swap out the formatting, faster than redoing it */
		for (char *p = msg->ts_str; p < msg->ts_str + len1; p++) {
			switch (*p) {
			case '-':
				*out->pos++ = '/';
				break;
			case 'T':
				*out->pos++ = ' ';
				break;
			default:
				*out->pos++ = *p;
			}
		}
		return len1;
	} else {
		size_t len2 = strlen(msg->ts_zonetail);

		if (!out)
			return len1 + len2;

		if (len1 + len2 > outsz) {
			memset(out->pos, 0, outsz);
			out->pos += outsz;
			return len1 + len2;
		}

		memcpy(out->pos, msg->ts_str, len1);
		out->pos += len1;
		memcpy(out->pos, msg->ts_zonetail, len2);
		out->pos += len2;
		return len1 + len2;
	}
}

size_t zlog_msg_ts_3164(struct zlog_msg *msg, struct fbuf *out, uint32_t flags)
{
	flags &= ZLOG_TS_UTC;

	if (!msg->ts_3164_str[0] || flags != msg->ts_3164_flags) {
		/* these are "hardcoded" in RFC3164, so they're here too... */
		static const char *const months[12] = {
			"Jan", "Feb", "Mar", "Apr", "May", "Jun",
			"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
		};
		struct tm tm;

		/* RFC3164 explicitly asks for local time, but common usage
		 * also includes UTC.
		 */
		if (flags & ZLOG_TS_UTC)
			gmtime_r(&msg->ts.tv_sec, &tm);
		else
			localtime_r(&msg->ts.tv_sec, &tm);

		snprintfrr(msg->ts_3164_str, sizeof(msg->ts_3164_str),
			   "%3s %2d %02d:%02d:%02d", months[tm.tm_mon],
			   tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);

		msg->ts_3164_flags = flags;
	}
	return bputs(out, msg->ts_3164_str);
}

void zlog_msg_tsraw(struct zlog_msg *msg, struct timespec *ts)
{
	memcpy(ts, &msg->ts, sizeof(*ts));
}

void zlog_set_prefix_ec(bool enable)
{
	atomic_store_explicit(&zlog_ec, enable, memory_order_relaxed);
}

bool zlog_get_prefix_ec(void)
{
	return atomic_load_explicit(&zlog_ec, memory_order_relaxed);
}

void zlog_set_prefix_xid(bool enable)
{
	atomic_store_explicit(&zlog_xid, enable, memory_order_relaxed);
}

bool zlog_get_prefix_xid(void)
{
	return atomic_load_explicit(&zlog_xid, memory_order_relaxed);
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

/*
 * Enable or disable 'immediate' output - default is to buffer
 * each pthread's messages.
 */
void zlog_set_immediate(bool set_p)
{
	zlog_default_immediate = set_p;
}

bool zlog_get_immediate_mode(void)
{
	return zlog_default_immediate;
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
	zlog_instance = instance;

	if (instance) {
		snprintfrr(zlog_tmpdir, sizeof(zlog_tmpdir), "%s/%s-%d.%ld",
			   TMPBASEDIR, progname, instance, (long)getpid());

		zlog_prefixsz = snprintfrr(zlog_prefix, sizeof(zlog_prefix),
					   "%s[%d]: ", protoname, instance);
	} else {
		snprintfrr(zlog_tmpdir, sizeof(zlog_tmpdir), "%s/%s.%ld",
			   TMPBASEDIR, progname, (long)getpid());

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
