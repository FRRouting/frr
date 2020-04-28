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

#ifndef _FRR_ZLOG_H
#define _FRR_ZLOG_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/uio.h>

#include "atomlist.h"
#include "frrcu.h"
#include "memory.h"
#include "hook.h"

#ifdef __cplusplus
extern "C" {
#endif

extern char zlog_prefix[];
extern size_t zlog_prefixsz;
extern int zlog_tmpdirfd;

struct xref_logmsg {
	struct xref xref;

	const char *fmtstring;
	uint32_t priority;
	uint32_t ec;
};

struct xrefdata_logmsg {
	struct xrefdata xrefdata;

	/* nothing more here right now */
};

/* These functions are set up to write to stdout/stderr without explicit
 * initialization and/or before config load.  There is no need to call e.g.
 * fprintf(stderr, ...) just because it's "too early" at startup.  Depending
 * on context, it may still be the right thing to use fprintf though -- try to
 * determine wether something is a log message or something else.
 */

extern void vzlogx(const struct xref_logmsg *xref, int prio, const char *fmt, va_list ap);
#define vzlog(prio, ...) vzlogx(NULL, prio, __VA_ARGS__)

PRINTFRR(2, 3)
static inline void zlog(int prio, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vzlog(prio, fmt, ap);
	va_end(ap);
}

PRINTFRR(2, 3)
static inline void zlog_ref(const struct xref_logmsg *xref, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vzlogx(xref, xref->priority, fmt, ap);
	va_end(ap);
}

#define _zlog_ref(prio, msg, ...) do {                                         \
		static struct xrefdata xrefdata = {                            \
			.hashstr = (msg),                                      \
			.hashu32 = { (prio), 0 },                              \
		};                                                             \
		DEFINE_XREF(xref, logmsg, &xrefdata,                           \
			.fmtstring = (msg),                                    \
			.priority = (prio),                                    \
		);                                                             \
		zlog_ref(&xref, (msg), ## __VA_ARGS__);                        \
	} while (0)

#define zlog_err(...)    _zlog_ref(LOG_ERR, __VA_ARGS__)
#define zlog_warn(...)   _zlog_ref(LOG_WARNING, __VA_ARGS__)
#define zlog_info(...)   _zlog_ref(LOG_INFO, __VA_ARGS__)
#define zlog_notice(...) _zlog_ref(LOG_NOTICE, __VA_ARGS__)
#define zlog_debug(...)  _zlog_ref(LOG_DEBUG, __VA_ARGS__)

#define _zlog_ecref(ec_, prio, msg, ...) do {                                  \
		static struct xrefdata xrefdata = {                            \
			.hashstr = (msg),                                      \
			.hashu32 = { (prio), (ec_) },                          \
		};                                                             \
		DEFINE_XREF(xref, logmsg, &xrefdata,                           \
			.fmtstring = (msg),                                    \
			.priority = (prio),                                    \
			.ec = (ec_),                                           \
		);                                                             \
		zlog_ref(&xref, "[EC %u] " msg, ec_, ## __VA_ARGS__);          \
	} while (0)

#define flog_err(ferr_id, format, ...)                                         \
	_zlog_ecref(ferr_id, LOG_ERR, format, ## __VA_ARGS__)
#define flog_warn(ferr_id, format, ...)                                        \
	_zlog_ecref(ferr_id, LOG_WARNING, format, ## __VA_ARGS__)

#define flog_err_sys(ferr_id, format, ...)                                     \
	flog_err(ferr_id, format, ##__VA_ARGS__)
#define flog(priority, ferr_id, format, ...)                                   \
	zlog(priority, "[EC %" PRIu32 "] " format, ferr_id, ##__VA_ARGS__)

extern void zlog_sigsafe(const char *text, size_t len);

/* extra priority value to disable a target without deleting it */
#define ZLOG_DISABLED	(LOG_EMERG-1)

/* zlog_msg encapsulates a particular logging call from somewhere in the code.
 * The same struct is passed around to all zlog_targets.
 *
 * This is used to defer formatting the log message until it is actually
 * requested by one of the targets.  If none of the targets needs the message
 * formatted, the formatting call is avoided entirely.
 *
 * This struct is opaque / private to the core zlog code.  Logging targets
 * should use zlog_msg_* functions to get text / timestamps / ... for a
 * message.
 */

struct zlog_msg;

extern int zlog_msg_prio(struct zlog_msg *msg);
extern const struct xref_logmsg *zlog_msg_xref(struct zlog_msg *msg);

/* pass NULL as textlen if you don't need it. */
extern const char *zlog_msg_text(struct zlog_msg *msg, size_t *textlen);

/* timestamp formatting control flags */

/* sub-second digit count */
#define ZLOG_TS_PREC		0xfU

/* 8601:   0000-00-00T00:00:00Z      (if used with ZLOG_TS_UTC)
 *         0000-00-00T00:00:00+00:00 (otherwise)
 * Legacy: 0000/00/00 00:00:00       (no TZ indicated!)
 */
#define ZLOG_TS_ISO8601		(1 << 8)
#define ZLOG_TS_LEGACY		(1 << 9)

/* default is local time zone */
#define ZLOG_TS_UTC		(1 << 10)

extern size_t zlog_msg_ts(struct zlog_msg *msg, char *out, size_t outsz,
			  uint32_t flags);

/* This list & struct implements the actual logging targets.  It is accessed
 * lock-free from all threads, and thus MUST only be changed atomically, i.e.
 * RCU.
 *
 * Since there's no atomic replace, the replacement action is an add followed
 * by a delete.  This means that during logging config changes, log messages
 * may be duplicated in the log target that is being changed.  The old entry
 * being changed MUST also at the very least not crash or do other stupid
 * things.
 *
 * This list and struct are NOT related to config.  Logging config is kept
 * separately, and results in creating appropriate zlog_target(s) to realize
 * the config.  Log targets may also be created from varying sources, e.g.
 * command line options, or VTY commands ("log monitor").
 *
 * struct zlog_target is intended to be embedded into a larger structure that
 * contains additional field for the specific logging target, e.g. an fd or
 * additional options.  It MUST be the first field in that larger struct.
 */

PREDECL_ATOMLIST(zlog_targets)
struct zlog_target {
	struct zlog_targets_item head;

	int prio_min;

	void (*logfn)(struct zlog_target *zt, struct zlog_msg *msg[],
		      size_t nmsgs);

	/* for crash handlers, set to NULL if log target can't write crash logs
	 * without possibly deadlocking (AS-Safe)
	 *
	 * text is not \0 terminated & split up into lines (e.g. no \n)
	 */
	void (*logfn_sigsafe)(struct zlog_target *zt, const char *text,
			      size_t len);

	struct rcu_head rcu_head;
};

/* make a copy for RCUpdating.  oldzt may be NULL to allocate a fresh one. */
extern struct zlog_target *zlog_target_clone(struct memtype *mt,
					     struct zlog_target *oldzt,
					     size_t size);

/* update the zlog_targets list;  both oldzt and newzt may be NULL.  You
 * still need to zlog_target_free() the old target afterwards if it wasn't
 * NULL.
 *
 * Returns oldzt so you can zlog_target_free(zlog_target_replace(old, new));
 * (Some log targets may need extra cleanup inbetween, but remember the old
 * target MUST remain functional until the end of the current RCU cycle.)
 */
extern struct zlog_target *zlog_target_replace(struct zlog_target *oldzt,
					       struct zlog_target *newzt);

/* Mostly for symmetry for zlog_target_clone(), just rcu_free() internally. */
#define zlog_target_free(mt, zt) \
	rcu_free(mt, zt, rcu_head)

extern void zlog_init(const char *progname, const char *protoname,
		      unsigned short instance, uid_t uid, gid_t gid);
DECLARE_HOOK(zlog_init, (const char *progname, const char *protoname,
			 unsigned short instance, uid_t uid, gid_t gid),
			(progname, protoname, instance, uid, gid))

extern void zlog_fini(void);
DECLARE_KOOH(zlog_fini, (), ())

/* for tools & test programs, i.e. anything not a daemon.
 * (no cleanup needed at exit)
 */
extern void zlog_aux_init(const char *prefix, int prio_min);
DECLARE_HOOK(zlog_aux_init, (const char *prefix, int prio_min),
			    (prefix, prio_min))

extern void zlog_startup_end(void);

extern void zlog_tls_buffer_init(void);
extern void zlog_tls_buffer_flush(void);
extern void zlog_tls_buffer_fini(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ZLOG_H */
