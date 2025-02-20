// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-19  David Lamparter, for NetDEF, Inc.
 */

#include "zebra.h"

#include <fcntl.h>
#include <sys/un.h>
#include <syslog.h>

#include "memory.h"
#include "frrcu.h"
#include "frr_pthread.h"
#include "printfrr.h"
#include "zlog.h"
#include "zlog_targets.h"

/* these allocations are intentionally left active even when doing full exit
 * cleanup, in order to keep the logging subsystem fully functional until the
 * absolute end.
 */

DEFINE_MGROUP_ACTIVEATEXIT(LOG, "logging subsystem");

DEFINE_MTYPE_STATIC(LOG, LOG_FD,        "log file target");
DEFINE_MTYPE_STATIC(LOG, LOG_FD_NAME,   "log file name");
DEFINE_MTYPE_STATIC(LOG, LOG_FD_ROTATE, "log file rotate helper");
DEFINE_MTYPE_STATIC(LOG, LOG_SYSL,      "syslog target");

struct zlt_fd {
	struct zlog_target zt;

	atomic_uint_fast32_t fd;

	char ts_subsec;
	bool record_priority;

	struct rcu_head_close head_close;
};

static const char * const prionames[] = {
	[LOG_EMERG] =	"emergencies: ",
	[LOG_ALERT] =	"alerts: ",
	[LOG_CRIT] =	"critical: ",
	[LOG_ERR] =	"errors: ",
	[LOG_WARNING] =	"warnings: ",
	[LOG_NOTICE] =	"notifications: ",
	[LOG_INFO] =	"informational: ",
	[LOG_DEBUG] =	"debugging: ",
};

void zlog_fd(struct zlog_target *zt, struct zlog_msg *msgs[], size_t nmsgs)
{
	struct zlt_fd *zte = container_of(zt, struct zlt_fd, zt);
	int fd;
	size_t i, textlen, iovpos = 0;
	size_t niov = MIN(4 * nmsgs + 1, IOV_MAX);
	struct iovec iov[niov];
	/* "\nYYYY-MM-DD HH:MM:SS.NNNNNNNNN+ZZ:ZZ " = 37 chars */
#define TS_LEN 40
	char ts_buf[TS_LEN * nmsgs], *ts_pos = ts_buf;

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);

	for (i = 0; i < nmsgs; i++) {
		struct zlog_msg *msg = msgs[i];
		int prio = zlog_msg_prio(msg);

		if (prio <= zt->prio_min) {
			struct fbuf fbuf = {
				.buf = ts_buf,
				.pos = ts_pos,
				.len = sizeof(ts_buf),
			};

			iov[iovpos].iov_base = ts_pos;
			zlog_msg_ts(msg, &fbuf,
				    ZLOG_TS_LEGACY | zte->ts_subsec);
			ts_pos = fbuf.pos;

			*ts_pos++ = ' ';
			iov[iovpos].iov_len =
				ts_pos - (char *)iov[iovpos].iov_base;

			iovpos++;

			if (zte->record_priority) {
				iov[iovpos].iov_base = (char *)prionames[prio];
				iov[iovpos].iov_len =
					strlen(iov[iovpos].iov_base);

				iovpos++;
			}

			iov[iovpos].iov_base = zlog_prefix;
			iov[iovpos].iov_len = zlog_prefixsz;

			iovpos++;

			iov[iovpos].iov_base =
				(char *)zlog_msg_text(msg, &textlen);
			iov[iovpos].iov_len = textlen + 1;

			iovpos++;
		}

		/* conditions that trigger writing:
		 *  - out of space for more timestamps/headers
		 *  - this being the last message in the batch
		 *  - not enough remaining iov entries
		 */
		if (iovpos > 0 && (ts_buf + sizeof(ts_buf) - ts_pos < TS_LEN
				   || i + 1 == nmsgs
				   || array_size(iov) - iovpos < 5)) {
			writev(fd, iov, iovpos);

			iovpos = 0;
			ts_pos = ts_buf;
		}
	}

	assert(iovpos == 0);
}

static void zlog_fd_sigsafe(struct zlog_target *zt, const char *text,
			    size_t len)
{
	struct zlt_fd *zte = container_of(zt, struct zlt_fd, zt);
	struct iovec iov[4];
	int fd;

	iov[0].iov_base = (char *)prionames[LOG_CRIT];
	iov[0].iov_len = zte->record_priority ? strlen(iov[0].iov_base) : 0;

	iov[1].iov_base = zlog_prefix;
	iov[1].iov_len = zlog_prefixsz;

	iov[2].iov_base = (char *)text;
	iov[2].iov_len = len;

	iov[3].iov_base = (char *)"\n";
	iov[3].iov_len = 1;

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);

	writev(fd, iov, array_size(iov));
}

/*
 * (re-)configuration
 */

void zlog_file_init(struct zlog_cfg_file *zcf)
{
	memset(zcf, 0, sizeof(*zcf));
	zcf->prio_min = ZLOG_DISABLED;
	zcf->fd = -1;
	pthread_mutex_init(&zcf->cfg_mtx, NULL);
}

static void zlog_file_target_free(struct zlt_fd *zlt)
{
	if (!zlt)
		return;

	rcu_close(&zlt->head_close, zlt->fd);
	rcu_free(MTYPE_LOG_FD, zlt, zt.rcu_head);
}

void zlog_file_fini(struct zlog_cfg_file *zcf)
{
	if (zcf->active) {
		struct zlt_fd *ztf;
		struct zlog_target *zt;

		zt = zlog_target_replace(&zcf->active->zt, NULL);
		ztf = container_of(zt, struct zlt_fd, zt);
		zlog_file_target_free(ztf);
	}
	XFREE(MTYPE_LOG_FD_NAME, zcf->filename);
	pthread_mutex_destroy(&zcf->cfg_mtx);
}

static bool zlog_file_cycle(struct zlog_cfg_file *zcf)
{
	struct zlog_target *zt, *old;
	struct zlt_fd *zlt = NULL;
	int fd;
	bool rv = true;

	do {
		if (zcf->prio_min == ZLOG_DISABLED)
			break;

		if (zcf->fd != -1)
			fd = dup(zcf->fd);
		else if (zcf->filename)
			fd = open(zcf->filename,
				  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC
					| O_NOCTTY,
				  LOGFILE_MASK);
		else
			fd = -1;

		if (fd < 0) {
			rv = false;
			break;
		}

		zt = zlog_target_clone(MTYPE_LOG_FD, &zcf->active->zt,
				       sizeof(*zlt));
		zlt = container_of(zt, struct zlt_fd, zt);

		zlt->fd = fd;
		zlt->record_priority = zcf->record_priority;
		zlt->ts_subsec = zcf->ts_subsec;

		zlt->zt.prio_min = zcf->prio_min;
		zlt->zt.logfn = zcf->zlog_wrap ? zcf->zlog_wrap : zlog_fd;
		zlt->zt.logfn_sigsafe = zlog_fd_sigsafe;
	} while (0);

	old = zlog_target_replace(zcf->active ? &zcf->active->zt : NULL,
				  zlt ? &zlt->zt : NULL);
	zcf->active = zlt;

	zlog_file_target_free(container_of_null(old, struct zlt_fd, zt));

	return rv;
}

void zlog_file_set_other(struct zlog_cfg_file *zcf)
{
	frr_with_mutex (&zcf->cfg_mtx) {
		zlog_file_cycle(zcf);
	}
}

bool zlog_file_set_filename(struct zlog_cfg_file *zcf, const char *filename)
{
	frr_with_mutex (&zcf->cfg_mtx) {
		XFREE(MTYPE_LOG_FD_NAME, zcf->filename);
		zcf->filename = XSTRDUP(MTYPE_LOG_FD_NAME, filename);
		zcf->fd = -1;

		return zlog_file_cycle(zcf);
	}
	assert(0);
	return false;
}

bool zlog_file_set_fd(struct zlog_cfg_file *zcf, int fd)
{
	frr_with_mutex (&zcf->cfg_mtx) {
		if (zcf->fd == fd)
			return true;

		XFREE(MTYPE_LOG_FD_NAME, zcf->filename);
		zcf->fd = fd;

		return zlog_file_cycle(zcf);
	}
	assert(0);
	return false;
}

struct rcu_close_rotate {
	struct rcu_head_close head_close;
	struct rcu_head head_self;
};

bool zlog_file_rotate(struct zlog_cfg_file *zcf)
{
	struct rcu_close_rotate *rcr;
	int fd;

	frr_with_mutex (&zcf->cfg_mtx) {
		if (!zcf->active || !zcf->filename)
			return true;

		fd = open(zcf->filename,
			  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOCTTY,
			  LOGFILE_MASK);
		if (fd < 0)
			return false;

		fd = atomic_exchange_explicit(&zcf->active->fd,
					      (uint_fast32_t)fd,
					      memory_order_relaxed);
	}

	rcr = XCALLOC(MTYPE_LOG_FD_ROTATE, sizeof(*rcr));
	rcu_close(&rcr->head_close, fd);
	rcu_free(MTYPE_LOG_FD_ROTATE, rcr, head_self);

	return true;
}

/* fixed crash logging */

static struct zlt_fd zlog_crashlog;

static void zlog_crashlog_sigsafe(struct zlog_target *zt, const char *text,
				  size_t len)
{
	static int crashlog_fd = -1;

	if (crashlog_fd == -1) {
#ifdef HAVE_OPENAT
		crashlog_fd = openat(zlog_tmpdirfd, "crashlog",
				     O_WRONLY | O_APPEND | O_CREAT,
				     LOGFILE_MASK);
#endif
		if (crashlog_fd < 0)
			crashlog_fd = -2;
	}

	if (crashlog_fd == -2)
		return;

	zlog_crashlog.fd = crashlog_fd;
	zlog_fd_sigsafe(&zlog_crashlog.zt, text, len);
}

/* this is used for assert failures (they don't need AS-Safe logging) */
static void zlog_crashlog_plain(struct zlog_target *zt, struct zlog_msg *msgs[],
				size_t nmsgs)
{
	size_t i, len;
	const char *text;

	for (i = 0; i < nmsgs; i++) {
		if (zlog_msg_prio(msgs[i]) > zt->prio_min)
			continue;

		text = zlog_msg_text(msgs[i], &len);
		zlog_crashlog_sigsafe(zt, text, len);
	}
}

static void zlog_crashlog_init(void)
{
	zlog_crashlog.zt.prio_min = LOG_CRIT;
	zlog_crashlog.zt.logfn = zlog_crashlog_plain;
	zlog_crashlog.zt.logfn_sigsafe = zlog_crashlog_sigsafe;
	zlog_crashlog.fd = -1;

	zlog_target_replace(NULL, &zlog_crashlog.zt);
}

/* fixed logging for test/auxiliary programs */

static struct zlt_fd zlog_aux_stdout;
static bool zlog_is_aux;

static int zlt_aux_init(const char *prefix, int prio_min)
{
	zlog_is_aux = true;

	zlog_aux_stdout.zt.prio_min = prio_min;
	zlog_aux_stdout.zt.logfn = zlog_fd;
	zlog_aux_stdout.zt.logfn_sigsafe = zlog_fd_sigsafe;
	zlog_aux_stdout.fd = STDOUT_FILENO;

	zlog_target_replace(NULL, &zlog_aux_stdout.zt);
	zlog_startup_end();
	return 0;
}

static int zlt_init(const char *progname, const char *protoname,
		     unsigned short instance, uid_t uid, gid_t gid)
{
	openlog(progname, LOG_CONS | LOG_NDELAY | LOG_PID, LOG_DAEMON);
	return 0;
}

static int zlt_fini(void)
{
	closelog();
	return 0;
}

/* fixed startup logging to stderr */

static struct zlt_fd zlog_startup_stderr;

__attribute__((_CONSTRUCTOR(450))) static void zlog_startup_init(void)
{
	zlog_startup_stderr.zt.prio_min = LOG_WARNING;
	zlog_startup_stderr.zt.logfn = zlog_fd;
	zlog_startup_stderr.zt.logfn_sigsafe = zlog_fd_sigsafe;
	zlog_startup_stderr.fd = STDERR_FILENO;

	zlog_target_replace(NULL, &zlog_startup_stderr.zt);

	hook_register(zlog_aux_init, zlt_aux_init);
	hook_register(zlog_init, zlt_init);
	hook_register(zlog_fini, zlt_fini);
}

void zlog_startup_end(void)
{
	static bool startup_ended = false;

	if (startup_ended)
		return;
	startup_ended = true;

	zlog_target_replace(&zlog_startup_stderr.zt, NULL);

	if (zlog_is_aux)
		return;

	/* until here, crashlogs go to stderr */
	zlog_crashlog_init();
}

/* syslog */

struct zlt_syslog {
	struct zlog_target zt;

	int syslog_facility;
};

static void zlog_syslog(struct zlog_target *zt, struct zlog_msg *msgs[],
			size_t nmsgs)
{
	size_t i;
	struct zlt_syslog *zte = container_of(zt, struct zlt_syslog, zt);
	const char *text;
	size_t text_len;

	for (i = 0; i < nmsgs; i++) {
		if (zlog_msg_prio(msgs[i]) > zt->prio_min)
			continue;

		text = zlog_msg_text(msgs[i], &text_len);
		syslog(zlog_msg_prio(msgs[i]) | zte->syslog_facility, "%.*s",
		       (int)text_len, text);
	}
}

#ifndef _PATH_LOG
#define _PATH_LOG "/dev/log"
#endif

static void zlog_syslog_sigsafe(struct zlog_target *zt, const char *text,
				size_t len)
{
	static int syslog_fd = -1;

	char hdr[192];
	size_t hdrlen;
	struct iovec iov[2];

	if (syslog_fd == -1) {
		syslog_fd = socket(AF_UNIX, SOCK_DGRAM, 0);
		if (syslog_fd >= 0) {
			struct sockaddr_un sa;
			socklen_t salen = sizeof(sa);

			sa.sun_family = AF_UNIX;
			strlcpy(sa.sun_path, _PATH_LOG, sizeof(sa.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
			salen = sa.sun_len = SUN_LEN(&sa);
#endif
			if (connect(syslog_fd, (struct sockaddr *)&sa, salen)) {
				close(syslog_fd);
				syslog_fd = -1;
			}
		}

		/* /dev/log could be a fifo instead of a socket */
		if (syslog_fd == -1) {
			syslog_fd = open(_PATH_LOG, O_WRONLY | O_NOCTTY);
			if (syslog_fd < 0)
				/* give up ... */
				syslog_fd = -2;
		}
	}

	if (syslog_fd == -2)
		return;

	/* note zlog_prefix includes trailing ": ", need to cut off 2 chars */
	hdrlen = snprintfrr(hdr, sizeof(hdr), "<%d>%.*s[%ld]: ", LOG_CRIT,
			    zlog_prefixsz > 2 ? (int)(zlog_prefixsz - 2) : 0,
			    zlog_prefix, (long)getpid());

	iov[0].iov_base = hdr;
	iov[0].iov_len = hdrlen;

	iov[1].iov_base = (char *)text;
	iov[1].iov_len = len;

	writev(syslog_fd, iov, array_size(iov));
}


static pthread_mutex_t syslog_cfg_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct zlt_syslog *zlt_syslog;
static int syslog_facility = LOG_DAEMON;
static int syslog_prio_min = ZLOG_DISABLED;

void zlog_syslog_set_facility(int facility)
{
	struct zlog_target *newztc;
	struct zlt_syslog *newzt;

	frr_with_mutex (&syslog_cfg_mutex) {
		if (facility == syslog_facility)
			return;
		syslog_facility = facility;

		if (syslog_prio_min == ZLOG_DISABLED)
			return;

		newztc = zlog_target_clone(MTYPE_LOG_SYSL, &zlt_syslog->zt,
					   sizeof(*newzt));
		newzt = container_of(newztc, struct zlt_syslog, zt);
		newzt->syslog_facility = syslog_facility;

		zlog_target_free(MTYPE_LOG_SYSL,
				 zlog_target_replace(&zlt_syslog->zt,
						     &newzt->zt));

		zlt_syslog = newzt;
	}
}

int zlog_syslog_get_facility(void)
{
	frr_with_mutex (&syslog_cfg_mutex) {
		return syslog_facility;
	}
	assert(0);
	return 0;
}

void zlog_syslog_set_prio_min(int prio_min)
{
	struct zlog_target *newztc;
	struct zlt_syslog *newzt = NULL;

	frr_with_mutex (&syslog_cfg_mutex) {
		if (prio_min == syslog_prio_min)
			return;
		syslog_prio_min = prio_min;

		if (syslog_prio_min != ZLOG_DISABLED) {
			newztc = zlog_target_clone(MTYPE_LOG_SYSL,
						   &zlt_syslog->zt,
						   sizeof(*newzt));
			newzt = container_of(newztc, struct zlt_syslog, zt);
			newzt->zt.prio_min = prio_min;
			newzt->zt.logfn = zlog_syslog;
			newzt->zt.logfn_sigsafe = zlog_syslog_sigsafe;
			newzt->syslog_facility = syslog_facility;
		}

		zlog_target_free(MTYPE_LOG_SYSL,
				 zlog_target_replace(&zlt_syslog->zt,
						     &newzt->zt));

		zlt_syslog = newzt;
	}
}

int zlog_syslog_get_prio_min(void)
{
	frr_with_mutex (&syslog_cfg_mutex) {
		return syslog_prio_min;
	}
	assert(0);
	return 0;
}
