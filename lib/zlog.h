// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
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

#include <assert.h>

#include "atomlist.h"
#include "frrcu.h"
#include "memory.h"
#include "hook.h"
#include "printfrr.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MGROUP(LOG);

extern char zlog_prefix[];
extern size_t zlog_prefixsz;
extern int zlog_tmpdirfd;
extern int zlog_instance;
extern const char *zlog_progname;

struct xref_logmsg {
	struct xref xref;

	const char *fmtstring;
	uint32_t priority;
	uint32_t ec;
	const char *args;
};

/* whether flag was added in config mode or enable mode */
#define LOGMSG_FLAG_EPHEMERAL	(1 << 0)
#define LOGMSG_FLAG_PERSISTENT	(1 << 1)

struct xrefdata_logmsg {
	struct xrefdata xrefdata;

	uint8_t fl_print_bt;
};

/* These functions are set up to write to stdout/stderr without explicit
 * initialization and/or before config load.  There is no need to call e.g.
 * fprintf(stderr, ...) just because it's "too early" at startup.  Depending
 * on context, it may still be the right thing to use fprintf though -- try to
 * determine whether something is a log message or something else.
 */

extern void vzlogx(const struct xref_logmsg *xref, int prio, const char *fmt,
		   va_list ap) PRINTFRR(3, 0);
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
static inline void zlog_ref(const struct xref_logmsg *xref,
			    const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vzlogx(xref, xref->priority, fmt, ap);
	va_end(ap);
}

#define _zlog_ecref(ec_, prio, msg, ...)                                       \
	do {                                                                   \
		static struct xrefdata_logmsg _xrefdata = {                    \
			.xrefdata =                                            \
				{                                              \
					.xref = NULL,                          \
					.uid = {},                             \
					.hashstr = (msg),                      \
					.hashu32 = {(prio), (ec_)},            \
				},                                             \
		};                                                             \
		static const struct xref_logmsg _xref __attribute__(           \
			(used)) = {                                            \
			.xref = XREF_INIT(XREFT_LOGMSG, &_xrefdata.xrefdata,   \
					  __func__),                           \
			.fmtstring = (msg),                                    \
			.priority = (prio),                                    \
			.ec = (ec_),                                           \
			.args = (#__VA_ARGS__),                                \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		zlog_ref(&_xref, (msg), ##__VA_ARGS__);                        \
	} while (0)

#define zlog_err(...)    _zlog_ecref(0, LOG_ERR, __VA_ARGS__)
#define zlog_warn(...)   _zlog_ecref(0, LOG_WARNING, __VA_ARGS__)
#define zlog_info(...)   _zlog_ecref(0, LOG_INFO, __VA_ARGS__)
#define zlog_notice(...) _zlog_ecref(0, LOG_NOTICE, __VA_ARGS__)
#define zlog_debug(...)  _zlog_ecref(0, LOG_DEBUG, __VA_ARGS__)

#define flog_err(ferr_id, format, ...)                                         \
	_zlog_ecref(ferr_id, LOG_ERR, format, ## __VA_ARGS__)
#define flog_warn(ferr_id, format, ...)                                        \
	_zlog_ecref(ferr_id, LOG_WARNING, format, ## __VA_ARGS__)

#define flog_err_sys(ferr_id, format, ...)                                     \
	_zlog_ecref(ferr_id, LOG_ERR, format, ## __VA_ARGS__)

extern void zlog_sigsafe(const char *text, size_t len);

/* recirculate a log message from zlog_live */
extern void zlog_recirculate_live_msg(uint8_t *data, size_t len);

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

/* text is NOT \0 terminated; instead there is a \n after textlen since the
 * logging targets would jump extra hoops otherwise for a single byte.  (the
 * \n is not included in textlen)
 *
 * calling this with NULL textlen is likely wrong.
 * use  "%.*s", (int)textlen, text  when passing to printf-like functions
 */
extern const char *zlog_msg_text(struct zlog_msg *msg, size_t *textlen);

extern void zlog_msg_args(struct zlog_msg *msg, size_t *hdrlen,
			  size_t *n_argpos, const struct fmt_outpos **argpos);

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

struct timespec;

extern size_t zlog_msg_ts(struct zlog_msg *msg, struct fbuf *out,
			  uint32_t flags);
extern void zlog_msg_tsraw(struct zlog_msg *msg, struct timespec *ts);

/* "mmm dd hh:mm:ss" for RFC3164 syslog.  Only ZLOG_TS_UTC for flags. */
extern size_t zlog_msg_ts_3164(struct zlog_msg *msg, struct fbuf *out,
			       uint32_t flags);

/* currently just returns the current PID/TID since we never write another
 * thread's messages
 */
extern void zlog_msg_pid(struct zlog_msg *msg, intmax_t *pid, intmax_t *tid);

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

PREDECL_ATOMLIST(zlog_targets);
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
			(progname, protoname, instance, uid, gid));

extern void zlog_fini(void);
DECLARE_KOOH(zlog_fini, (), ());

extern void zlog_set_prefix_ec(bool enable);
extern bool zlog_get_prefix_ec(void);
extern void zlog_set_prefix_xid(bool enable);
extern bool zlog_get_prefix_xid(void);

/* for tools & test programs, i.e. anything not a daemon.
 * (no cleanup needed at exit)
 */
extern void zlog_aux_init(const char *prefix, int prio_min);
DECLARE_HOOK(zlog_aux_init, (const char *prefix, int prio_min),
			    (prefix, prio_min));

extern void zlog_startup_end(void);

extern void zlog_tls_buffer_init(void);
extern void zlog_tls_buffer_flush(void);
extern void zlog_tls_buffer_fini(void);

/* Enable or disable 'immediate' output - default is to buffer messages. */
extern void zlog_set_immediate(bool set_p);
bool zlog_get_immediate_mode(void);

extern const char *zlog_priority_str(int priority);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ZLOG_H */
