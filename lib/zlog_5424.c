// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-21  David Lamparter, for NetDEF, Inc.
 */

/* when you work on this code, please install a fuzzer (e.g. AFL) and run
 * tests/lib/fuzz_zlog.c
 *
 * The most likely type of bug in this code is an off-by-one error in the
 * buffer management pieces, and this isn't easily covered by an unit test
 * or topotests.  Fuzzing is the best tool here, but the CI can't do that
 * since it's quite resource intensive.
 */

#include "zebra.h"

#include "zlog_5424.h"

#include <sys/un.h>
#include <syslog.h>

#include "memory.h"
#include "frrcu.h"
#include "printfrr.h"
#include "typerb.h"
#include "frr_pthread.h"
#include "command.h"
#include "monotime.h"
#include "frrevent.h"

#include "lib/version.h"
#include "lib/lib_errors.h"

DEFINE_MTYPE_STATIC(LOG, LOG_5424, "extended log target");
DEFINE_MTYPE_STATIC(LOG, LOG_5424_ROTATE, "extended log rotate helper");

/* the actual log target data structure
 *
 * remember this is RCU'd by the core zlog functions.  Changing anything
 * works by allocating a new struct, filling it, adding it, and removing the
 * old one.
 */
struct zlt_5424 {
	struct zlog_target zt;

	atomic_uint_fast32_t fd;

	enum zlog_5424_format fmt;
	uint32_t ts_flags;
	int facility;

	/* the various extra pieces to add... */
	bool kw_version : 1;
	bool kw_location : 1;
	bool kw_uid : 1;
	bool kw_ec : 1;
	bool kw_args : 1;

	/* some formats may or may not include the trailing \n */
	bool use_nl : 1;

	/* for DGRAM & SEQPACKET sockets, send 1 log message per packet, since
	 * the socket preserves packet boundaries.  On Linux, this uses
	 * sendmmsg() for efficiency, on other systems we need a syscall each.
	 */
	bool packets : 1;

	/* for DGRAM, in order to not have to reconnect, we need to use
	 * sendto()/sendmsg() with the destination given; otherwise we'll get
	 * ENOTCONN.  (We do a connect(), which serves to verify the type of
	 * socket, but if the receiver goes away, the kernel disconnects the
	 * socket so writev() no longer works since the destination is now
	 * unspecified.)
	 */
	struct sockaddr_storage sa;
	socklen_t sa_len;

	/* these are both getting set, but current_err is cleared on success,
	 * so we know whether the error is current or past.
	 */
	int last_err, current_err;
	atomic_size_t lost_msgs;
	struct timeval last_err_ts;

	struct rcu_head_close head_close;
};

static int zlog_5424_open(struct zlog_cfg_5424 *zcf, int sock_type);

/* rough header length estimate
 * ============================
 *
 *   ^ = might grow
 *
 *  49^ longest filename (pceplib/test/pcep_utils_double_linked_list_test.h)
 *   5^ highest line number (48530, bgpd/bgp_nb_config.c)
 *  65^ longest function name
 *      (lib_prefix_list_entry_ipv6_prefix_length_greater_or_equal_destroy)
 *  11  unique id ("XXXXX-XXXXX")
 *  10  EC ("4294967295" or "0xffffffff")
 *  35  ISO8601 TS at full length ("YYYY-MM-DD HH:MM:SS.NNNNNNNNN+ZZ:ZZ")
 * ---
 * 175
 *
 * rarely used (hopefully...):
 *  26^ FRR_VERSION ("10.10.10-dev-gffffffffffff")
 * ---
 * 201
 *
 * x16  highest number of format parameters currently
 *  40  estimate for hostname + 2*daemon + pid
 *
 * specific format overhead:
 *
 * RFC3164 - shorter than the others
 * RFC5424 - 175 + "<999>1 "=7 + 52 (location@50145) + 40 (host/...)
 *	rarely: + 65 + 26 (for [origin])
 *	args:  16 * (8 + per-arg (20?)) = ~448
 *
 * so without "args@", origin or (future) keywords, around 256 seems OK
 * with args@ and/or origin and/or keywords, 512 seems more reasonable
 *
 * but - note the code allocates this amount multiplied by the number of
 * messages in the incoming batch (minimum 3), this means short messages and
 * long messages smooth each other out.
 *
 * Since the code handles space-exceeded by grabbing a bunch of stack memory,
 * a reasonable middle ground estimate is desirable here, so ...
 * *drumroll*
 * let's go with 128 + args?128.  (remember the minimum 3 multiplier)
 *
 * low_space is the point where we don't try to fit another message in & just
 * submit what we have to the kernel.
 *
 * The zlog code only buffers debug & informational messages, so in production
 * usage most of the calls will be writing out only 1 message.  This makes
 * the min *3 multiplier quite useful.
 */

static inline size_t zlog_5424_bufsz(struct zlt_5424 *zte, size_t nmsgs,
				     size_t *low_space)
{
	size_t ret = 128;

	if (zte->kw_args)
		ret += 128;
	*low_space = ret;
	return ret * MAX(nmsgs, 3);
}

struct state {
	struct fbuf *fbuf;
	struct iovec *iov;
};

/* stack-based keyword support is likely to bump this to 3 or 4 */
#define IOV_PER_MSG 2
_Static_assert(IOV_MAX >= IOV_PER_MSG,
	       "this code won't work with IOV_MAX < IOV_PER_MSG");

/* the following functions are quite similar, but trying to merge them just
 * makes a big mess.  check the others when touching one.
 *
 *		timestamp	keywords	hostname
 * RFC5424	ISO8601		yes		yes
 * RFC3164	RFC3164		no		yes
 * local	RFC3164		no		no
 * journald	ISO8601(unused)	yes		(unused)
 */

static size_t zlog_5424_one(struct zlt_5424 *zte, struct zlog_msg *msg,
			    struct state *state)
{
	size_t textlen;
	struct fbuf *fbuf = state->fbuf;
	char *orig_pos = fbuf->pos;
	size_t need = 0;
	int prio = zlog_msg_prio(msg);
	intmax_t pid, tid;

	zlog_msg_pid(msg, &pid, &tid);

	need += bprintfrr(fbuf, "<%d>1 ", prio | zte->facility);
	need += zlog_msg_ts(msg, fbuf, zte->ts_flags);
	need += bprintfrr(fbuf, " %s %s %jd %.*s ", cmd_hostname_get() ?: "-",
			  zlog_progname, pid, (int)(zlog_prefixsz - 2),
			  zlog_prefix);

	if (zte->kw_version)
		need += bprintfrr(
			fbuf,
			"[origin enterpriseId=\"50145\" software=\"FRRouting\" swVersion=\"%s\"]",
			FRR_VERSION);

	const struct xref_logmsg *xref;
	struct xrefdata *xrefdata;

	need += bprintfrr(fbuf, "[location@50145 tid=\"%jd\"", tid);
	if (zlog_instance > 0)
		need += bprintfrr(fbuf, " instance=\"%d\"", zlog_instance);

	xref = zlog_msg_xref(msg);
	xrefdata = xref ? xref->xref.xrefdata : NULL;
	if (xrefdata) {
		if (zte->kw_uid)
			need += bprintfrr(fbuf, " id=\"%s\"", xrefdata->uid);
		if (zte->kw_ec && prio <= LOG_WARNING)
			need += bprintfrr(fbuf, " ec=\"%u\"", xref->ec);
		if (zte->kw_location)
			need += bprintfrr(
				fbuf, " file=\"%s\" line=\"%d\" func=\"%s\"",
				xref->xref.file, xref->xref.line,
				xref->xref.func);
	}
	need += bputch(fbuf, ']');

	size_t hdrlen, n_argpos;
	const struct fmt_outpos *argpos;
	const char *text;

	text = zlog_msg_text(msg, &textlen);
	zlog_msg_args(msg, &hdrlen, &n_argpos, &argpos);

	if (zte->kw_args && n_argpos) {
		need += bputs(fbuf, "[args@50145");

		for (size_t i = 0; i < n_argpos; i++) {
			int len = argpos[i].off_end - argpos[i].off_start;

			need += bprintfrr(fbuf, " arg%zu=%*pSQsq", i + 1, len,
					  text + argpos[i].off_start);
		}

		need += bputch(fbuf, ']');
	}

	need += bputch(fbuf, ' ');

	if (orig_pos + need > fbuf->buf + fbuf->len) {
		/* not enough space in the buffer for headers.  the loop in
		 * zlog_5424() will flush other messages that are already in
		 * the buffer, grab a bigger buffer if needed, and try again.
		 */
		fbuf->pos = orig_pos;
		return need;
	}

	/* NB: zlog_5424 below assumes we use max. IOV_PER_MSG iovs here */
	state->iov->iov_base = orig_pos;
	state->iov->iov_len = fbuf->pos - orig_pos;
	state->iov++;

	state->iov->iov_base = (char *)text + hdrlen;
	state->iov->iov_len = textlen - hdrlen + zte->use_nl;
	state->iov++;
	return 0;
}

static size_t zlog_3164_one(struct zlt_5424 *zte, struct zlog_msg *msg,
			    struct state *state)
{
	size_t textlen;
	struct fbuf *fbuf = state->fbuf;
	char *orig_pos = fbuf->pos;
	size_t need = 0;
	int prio = zlog_msg_prio(msg);
	intmax_t pid, tid;

	zlog_msg_pid(msg, &pid, &tid);

	need += bprintfrr(fbuf, "<%d>", prio | zte->facility);
	need += zlog_msg_ts_3164(msg, fbuf, zte->ts_flags);
	if (zte->fmt != ZLOG_FMT_LOCAL) {
		need += bputch(fbuf, ' ');
		need += bputs(fbuf, cmd_hostname_get() ?: "-");
	}
	need += bprintfrr(fbuf, " %s[%jd]: ", zlog_progname, pid);

	if (orig_pos + need > fbuf->buf + fbuf->len) {
		/* not enough space in the buffer for headers.  loop in
		 * zlog_5424() will flush other messages that are already in
		 * the buffer, grab a bigger buffer if needed, and try again.
		 */
		fbuf->pos = orig_pos;
		return need;
	}

	/* NB: zlog_5424 below assumes we use max. IOV_PER_MSG iovs here */
	state->iov->iov_base = orig_pos;
	state->iov->iov_len = fbuf->pos - orig_pos;
	state->iov++;

	state->iov->iov_base = (char *)zlog_msg_text(msg, &textlen);
	state->iov->iov_len = textlen + zte->use_nl;
	state->iov++;
	return 0;
}

static size_t zlog_journald_one(struct zlt_5424 *zte, struct zlog_msg *msg,
				struct state *state)
{
	size_t textlen;
	struct fbuf *fbuf = state->fbuf;
	char *orig_pos = fbuf->pos;
	size_t need = 0;
	int prio = zlog_msg_prio(msg);
	intmax_t pid, tid;

	zlog_msg_pid(msg, &pid, &tid);

	need += bprintfrr(fbuf,
			  "PRIORITY=%d\n"
			  "SYSLOG_FACILITY=%d\n"
			  "TID=%jd\n"
			  "FRR_DAEMON=%s\n"
			  "SYSLOG_TIMESTAMP=",
			  prio, zte->facility, tid, zlog_progname);
	need += zlog_msg_ts(msg, fbuf, zte->ts_flags);
	need += bputch(fbuf, '\n');
	if (zlog_instance > 0)
		need += bprintfrr(fbuf, "FRR_INSTANCE=%d\n", zlog_instance);

	const struct xref_logmsg *xref;
	struct xrefdata *xrefdata;

	xref = zlog_msg_xref(msg);
	xrefdata = xref ? xref->xref.xrefdata : NULL;
	if (xrefdata) {
		if (zte->kw_uid && xrefdata->uid[0])
			need += bprintfrr(fbuf, "FRR_ID=%s\n", xrefdata->uid);
		if (zte->kw_ec && prio <= LOG_WARNING)
			need += bprintfrr(fbuf, "FRR_EC=%d\n", xref->ec);
		if (zte->kw_location)
			need += bprintfrr(fbuf,
					  "CODE_FILE=%s\n"
					  "CODE_LINE=%d\n"
					  "CODE_FUNC=%s\n",
					  xref->xref.file, xref->xref.line,
					  xref->xref.func);
	}

	size_t hdrlen, n_argpos;
	const struct fmt_outpos *argpos;
	const char *text;

	text = zlog_msg_text(msg, &textlen);
	zlog_msg_args(msg, &hdrlen, &n_argpos, &argpos);

	if (zte->kw_args && n_argpos) {
		for (size_t i = 0; i < n_argpos; i++) {
			int len = argpos[i].off_end - argpos[i].off_start;

			/* rather than escape the value, we could use
			 * journald's binary encoding, but that seems a bit
			 * excessive/unnecessary.  99% of things we print here
			 * will just output 1:1 with %pSE.
			 */
			need += bprintfrr(fbuf, "FRR_ARG%zu=%*pSE\n", i + 1,
					  len, text + argpos[i].off_start);
		}
	}

	need += bputs(fbuf, "MESSAGE=");

	if (orig_pos + need > fbuf->buf + fbuf->len) {
		/* not enough space in the buffer for headers.  loop in
		 * zlog_5424() will flush other messages that are already in
		 * the buffer, grab a bigger buffer if needed, and try again.
		 */
		fbuf->pos = orig_pos;
		return need;
	}

	/* NB: zlog_5424 below assumes we use max. IOV_PER_MSG iovs here */
	state->iov->iov_base = orig_pos;
	state->iov->iov_len = fbuf->pos - orig_pos;
	state->iov++;

	state->iov->iov_base = (char *)text + hdrlen;
	state->iov->iov_len = textlen - hdrlen + 1;
	state->iov++;
	return 0;
}

static size_t zlog_one(struct zlt_5424 *zte, struct zlog_msg *msg,
		       struct state *state)
{
	switch (zte->fmt) {
	case ZLOG_FMT_5424:
		return zlog_5424_one(zte, msg, state);
	case ZLOG_FMT_3164:
	case ZLOG_FMT_LOCAL:
		return zlog_3164_one(zte, msg, state);
	case ZLOG_FMT_JOURNALD:
		return zlog_journald_one(zte, msg, state);
	}
	return 0;
}

static void zlog_5424_err(struct zlt_5424 *zte, size_t count)
{
	if (!count) {
		zte->current_err = 0;
		return;
	}

	/* only the counter is atomic because otherwise it'd be meaningless */
	atomic_fetch_add_explicit(&zte->lost_msgs, count, memory_order_relaxed);

	/* these are non-atomic and can provide wrong results when read, but
	 * since they're only for debugging / display, that's OK.
	 */
	zte->current_err = zte->last_err = errno;
	monotime(&zte->last_err_ts);
}

static void zlog_5424(struct zlog_target *zt, struct zlog_msg *msgs[],
		      size_t nmsgs)
{
	size_t i;
	struct zlt_5424 *zte = container_of(zt, struct zlt_5424, zt);
	int fd, ret;
	size_t niov = MIN(IOV_PER_MSG * nmsgs, IOV_MAX);
	struct iovec iov[niov], *iov_last = iov + niov;
	struct mmsghdr mmsg[zte->packets ? nmsgs : 1], *mpos = mmsg;
	size_t count = 0;

	/* refer to size estimate at top of file */
	size_t low_space;
	char hdr_buf[zlog_5424_bufsz(zte, nmsgs, &low_space)];
	struct fbuf hdr_pos = {
		.buf = hdr_buf,
		.pos = hdr_buf,
		.len = sizeof(hdr_buf),
	};
	struct state state = {
		.fbuf = &hdr_pos,
		.iov = iov,
	};

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);

	memset(mmsg, 0, sizeof(mmsg));
	if (zte->sa_len) {
		for (i = 0; i < array_size(mmsg); i++) {
			mmsg[i].msg_hdr.msg_name = (struct sockaddr *)&zte->sa;
			mmsg[i].msg_hdr.msg_namelen = zte->sa_len;
		}
	}
	mmsg[0].msg_hdr.msg_iov = iov;

	for (i = 0; i < nmsgs; i++) {
		int prio = zlog_msg_prio(msgs[i]);
		size_t need = 0;

		if (prio <= zte->zt.prio_min) {
			if (zte->packets)
				mpos->msg_hdr.msg_iov = state.iov;

			need = zlog_one(zte, msgs[i], &state);

			if (zte->packets) {
				mpos->msg_hdr.msg_iovlen =
					state.iov - mpos->msg_hdr.msg_iov;
				mpos++;
			}
			count++;
		}

		/* clang-format off */
		if ((need
		     || (size_t)(hdr_pos.buf + hdr_pos.len - hdr_pos.pos)
				< low_space
		     || i + 1 == nmsgs
		     || state.iov + IOV_PER_MSG > iov_last)
		    && state.iov > iov) {
			/* clang-format on */

			if (zte->packets) {
				struct mmsghdr *sendpos;

				for (sendpos = mmsg; sendpos < mpos;) {
					ret = sendmmsg(fd, sendpos,
						       mpos - sendpos, 0);
					if (ret <= 0)
						break;
					sendpos += ret;
				}
				zlog_5424_err(zte, mpos - sendpos);
				mpos = mmsg;
			} else {
				if (!zte->sa_len)
					ret = writev(fd, iov, state.iov - iov);
				else {
					mpos->msg_hdr.msg_iovlen =
						state.iov - iov;
					ret = sendmsg(fd, &mpos->msg_hdr, 0);
				}

				if (ret < 0)
					zlog_5424_err(zte, count);
				else
					zlog_5424_err(zte, 0);
			}

			count = 0;
			hdr_pos.pos = hdr_buf;
			state.iov = iov;
		}

		/* if need == 0, we just put a message (or nothing) in the
		 * buffer and are continuing for more to batch in a single
		 * writev()
		 */
		if (need == 0)
			continue;

		if (need && need <= sizeof(hdr_buf)) {
			/* don't need to allocate, just try this msg
			 * again without other msgs already using up
			 * buffer space
			 */
			i--;
			continue;
		}

		/* need > sizeof(hdr_buf), need to grab some memory.  Taking
		 * it off the stack is fine here.
		 */
		char buf2[need];
		struct fbuf fbuf2 = {
			.buf = buf2,
			.pos = buf2,
			.len = sizeof(buf2),
		};

		state.fbuf = &fbuf2;
		need = zlog_one(zte, msgs[i], &state);
		assert(need == 0);

		if (!zte->sa_len)
			ret = writev(fd, iov, state.iov - iov);
		else {
			mpos->msg_hdr.msg_iovlen = state.iov - iov;
			ret = sendmsg(fd, &mpos->msg_hdr, 0);
		}

		if (ret < 0)
			zlog_5424_err(zte, 1);
		else
			zlog_5424_err(zte, 0);

		count = 0;
		state.fbuf = &hdr_pos;
		state.iov = iov;
		mpos = mmsg;
	}

	assert(state.iov == iov);
}

/* strftime(), gmtime_r() and localtime_r() aren't AS-Safe (they access locale
 * data), but we need an AS-Safe timestamp below :(
 */
static void gmtime_assafe(time_t ts, struct tm *res)
{
	res->tm_sec = ts % 60;
	ts /= 60;
	res->tm_min = ts % 60;
	ts /= 60;
	res->tm_hour = ts % 24;
	ts /= 24;

	ts -= 11017; /* start on 2020-03-01, 11017 days since 1970-01-01 */

	/* 1461 days = 3 regular years + 1 leap year
	 * this works until 2100, which isn't a leap year
	 *
	 * struct tm.tm_year starts at 1900.
	 */
	res->tm_year = 2000 - 1900 + 4 * (ts / 1461);
	ts = ts % 1461;

	if (ts == 1460) {
		res->tm_year += 4;
		res->tm_mon = 1;
		res->tm_mday = 29;
		return;
	}
	res->tm_year += ts / 365;
	ts %= 365;

	/* note we're starting in march like the romans did... */
	if (ts >= 306) /* Jan 1 of next year */
		res->tm_year++;

	static time_t months[13] = {
		0, 31, 61, 92, 122, 153, 184, 214, 245, 275, 306, 337, 365,
	};
	const size_t month_max = array_size(months) - 1;

	for (size_t i = 0; i < month_max; i++) {
		if (ts < months[i + 1]) {
			res->tm_mon = ((i + 2) % 12);
			res->tm_mday = 1 + ts - months[i];
			break;
		}
	}
}

/* one of the greatest advantages of this logging target:  unlike syslog(),
 * which is not AS-Safe, we can send crashlogs to syslog here.
 */
static void zlog_5424_sigsafe(struct zlog_target *zt, const char *text,
			      size_t len)
{
	static const char *const months_3164[12] = {
		"Jan", "Feb", "Mar", "Apr", "May", "Jun",
		"Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
	};

	struct zlt_5424 *zte = container_of(zt, struct zlt_5424, zt);
	struct iovec iov[3], *iovp = iov;
	char buf[256];
	struct fbuf fbuf = {
		.buf = buf,
		.pos = buf,
		.len = sizeof(buf),
	};
	int fd;
	intmax_t pid = (intmax_t)getpid();
	struct tm tm;

	switch (zte->fmt) {
	case ZLOG_FMT_5424:
		gmtime_assafe(time(NULL), &tm);
		bprintfrr(
			&fbuf,
			"<%d>1 %04u-%02u-%02uT%02u:%02u:%02uZ - %s %jd %.*s  ",
			zte->facility | LOG_CRIT, tm.tm_year + 1900,
			tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min,
			tm.tm_sec, zlog_progname, pid, (int)(zlog_prefixsz - 2),
			zlog_prefix);
		break;

	case ZLOG_FMT_3164:
	case ZLOG_FMT_LOCAL:
		/* this will unfortuantely be wrong by the timezone offset
		 * if the user selected non-UTC.  But not much we can do
		 * about that...
		 */
		gmtime_assafe(time(NULL), &tm);
		bprintfrr(&fbuf, "<%d>%3s %2u %02u:%02u:%02u %s%s[%jd]: ",
			  zte->facility | LOG_CRIT, months_3164[tm.tm_mon],
			  tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
			  (zte->fmt == ZLOG_FMT_LOCAL) ? "" : "- ",
			  zlog_progname, pid);
		break;

	case ZLOG_FMT_JOURNALD:
		bprintfrr(&fbuf,
			  "PRIORITY=%d\n"
			  "SYSLOG_FACILITY=%d\n"
			  "FRR_DAEMON=%s\n"
			  "MESSAGE=",
			  LOG_CRIT, zte->facility, zlog_progname);
		break;
	}

	iovp->iov_base = fbuf.buf;
	iovp->iov_len = fbuf.pos - fbuf.buf;
	iovp++;

	iovp->iov_base = (char *)text;
	iovp->iov_len = len;
	iovp++;

	if (zte->use_nl) {
		iovp->iov_base = (char *)"\n";
		iovp->iov_len = 1;
		iovp++;
	}

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);

	if (!zte->sa_len)
		writev(fd, iov, iovp - iov);
	else {
		struct msghdr mh = {};

		mh.msg_name = (struct sockaddr *)&zte->sa;
		mh.msg_namelen = zte->sa_len;
		mh.msg_iov = iov;
		mh.msg_iovlen = iovp - iov;
		sendmsg(fd, &mh, 0);
	}
}

/* housekeeping & configuration */

void zlog_5424_init(struct zlog_cfg_5424 *zcf)
{
	pthread_mutex_init(&zcf->cfg_mtx, NULL);
}

static void zlog_5424_target_free(struct zlt_5424 *zlt)
{
	if (!zlt)
		return;

	rcu_close(&zlt->head_close, zlt->fd);
	rcu_free(MTYPE_LOG_5424, zlt, zt.rcu_head);
}

void zlog_5424_fini(struct zlog_cfg_5424 *zcf, bool keepopen)
{
	if (keepopen)
		zcf->active = NULL;

	if (zcf->active) {
		struct zlt_5424 *ztf;
		struct zlog_target *zt;

		zt = zlog_target_replace(&zcf->active->zt, NULL);
		ztf = container_of(zt, struct zlt_5424, zt);
		zlog_5424_target_free(ztf);
	}
	pthread_mutex_destroy(&zcf->cfg_mtx);
}

static void zlog_5424_cycle(struct zlog_cfg_5424 *zcf, int fd)
{
	struct zlog_target *old;
	struct zlt_5424 *zlt = NULL, *oldt;

	if (fd >= 0) {
		struct zlog_target *zt;

		/* all of this is swapped in by zlog_target_replace() below,
		 * the old target is RCU-freed afterwards.
		 */
		zt = zlog_target_clone(MTYPE_LOG_5424, &zcf->active->zt,
				       sizeof(*zlt));
		zlt = container_of(zt, struct zlt_5424, zt);

		zlt->fd = fd;
		zlt->kw_version = zcf->kw_version;
		zlt->kw_location = zcf->kw_location;
		zlt->kw_uid = zcf->kw_uid;
		zlt->kw_ec = zcf->kw_ec;
		zlt->kw_args = zcf->kw_args;
		zlt->use_nl = true;
		zlt->facility = zcf->facility;

		/* DGRAM & SEQPACKET = 1 log message per packet */
		zlt->packets = (zcf->sock_type == SOCK_DGRAM) ||
			       (zcf->sock_type == SOCK_SEQPACKET);
		zlt->sa = zcf->sa;
		zlt->sa_len = zcf->sa_len;
		zlt->fmt = zcf->fmt;
		zlt->zt.prio_min = zcf->prio_min;
		zlt->zt.logfn = zlog_5424;
		zlt->zt.logfn_sigsafe = zlog_5424_sigsafe;

		switch (zcf->fmt) {
		case ZLOG_FMT_5424:
		case ZLOG_FMT_JOURNALD:
			zlt->ts_flags = zcf->ts_flags;
			zlt->ts_flags &= ZLOG_TS_PREC | ZLOG_TS_UTC;
			zlt->ts_flags |= ZLOG_TS_ISO8601;
			break;
		case ZLOG_FMT_3164:
		case ZLOG_FMT_LOCAL:
			zlt->ts_flags = zcf->ts_flags & ZLOG_TS_UTC;
			if (zlt->packets)
				zlt->use_nl = false;
			break;
		}
	}

	old = zcf->active ? &zcf->active->zt : NULL;
	old = zlog_target_replace(old, &zlt->zt);
	zcf->active = zlt;

	/* oldt->fd == fd happens for zlog_5424_apply_meta() */
	oldt = container_of(old, struct zlt_5424, zt);
	if (oldt && oldt->fd != (unsigned int)fd)
		rcu_close(&oldt->head_close, oldt->fd);
	rcu_free(MTYPE_LOG_5424, oldt, zt.rcu_head);
}

static void zlog_5424_reconnect(struct event *t)
{
	struct zlog_cfg_5424 *zcf = EVENT_ARG(t);
	int fd = EVENT_FD(t);
	char dummy[256];
	ssize_t ret;

	if (zcf->active) {
		ret = read(fd, dummy, sizeof(dummy));
		if (ret > 0) {
			/* logger is sending us something?!?! */
			event_add_read(t->master, zlog_5424_reconnect, zcf, fd,
				       &zcf->t_reconnect);
			return;
		}

		if (ret == 0)
			zlog_warn("logging socket %pSE closed by peer",
				  zcf->filename);
		else
			zlog_warn("logging socket %pSE error: %m",
				  zcf->filename);
	}

	/* do NOT close() anything here;  other threads may still be writing
	 * and their messages need to be lost rather than end up on a random
	 * other fd that got reassigned the same number, like a BGP session!
	 */
	fd = zlog_5424_open(zcf, -1);

	frr_with_mutex (&zcf->cfg_mtx) {
		zlog_5424_cycle(zcf, fd);
	}
}

static int zlog_5424_unix(struct sockaddr_un *suna, int sock_type)
{
	int fd;
	int size = 1 * 1024 * 1024, prev_size;
	socklen_t opt_size;
	int save_errno;

	fd = socket(AF_UNIX, sock_type, 0);
	if (fd < 0)
		return -1;

	if (connect(fd, (struct sockaddr *)suna, sizeof(*suna))) {
		/* zlog_5424_open() will print the error for connect() */
		save_errno = errno;
		close(fd);
		errno = save_errno;
		return -1;
	}

	opt_size = sizeof(prev_size);
	if (getsockopt(fd, SOL_SOCKET, SO_SNDBUF, &prev_size, &opt_size))
		return fd;

	/* setsockopt_so_sendbuf() logs on error; we don't really care that
	 * much here.  Also, never shrink the buffer below the initial size.
	 */
	while (size > prev_size &&
	       setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == -1)
		size /= 2;

	return fd;
}

static int zlog_5424_open(struct zlog_cfg_5424 *zcf, int sock_type)
{
	int fd = -1;
	int flags = 0;
	int err;
	socklen_t optlen;
	bool do_chown = false;
	bool need_reconnect = false;
	static const int unix_types[] = {
		SOCK_STREAM,
		SOCK_SEQPACKET,
		SOCK_DGRAM,
	};
	struct sockaddr_un sa;

	zcf->sock_type = -1;
	zcf->sa_len = 0;

	switch (zcf->dst) {
	case ZLOG_5424_DST_NONE:
		return -1;

	case ZLOG_5424_DST_FD:
		fd = dup(zcf->fd);
		if (fd < 0) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "failed to dup() log file descriptor: %m (FD limit too low?)");
			return -1;
		}

		optlen = sizeof(sock_type);
		if (!getsockopt(fd, SOL_SOCKET, SO_TYPE, &sock_type, &optlen)) {
			zcf->sock_type = sock_type;
			need_reconnect = (zcf->sock_type != SOCK_DGRAM);
		}
		break;

	case ZLOG_5424_DST_FIFO:
		if (!zcf->filename)
			return -1;

		if (!zcf->file_nocreate) {
			frr_with_privs (lib_privs) {
				mode_t prevmask;

				prevmask = umask(0777 ^ zcf->file_mode);
				err = mkfifo(zcf->filename, 0666);
				umask(prevmask);
			}
			if (err == 0)
				do_chown = true;
			else if (errno != EEXIST)
				return -1;
		}

		flags = O_NONBLOCK;
		/* fallthru */

	case ZLOG_5424_DST_FILE:
		if (!zcf->filename)
			return -1;

		frr_with_privs (lib_privs) {
			fd = open(zcf->filename, flags | O_WRONLY | O_APPEND |
							 O_CLOEXEC | O_NOCTTY);
		}
		if (fd >= 0)
			break;
		if (zcf->file_nocreate || flags) {
			flog_err_sys(EC_LIB_SYSTEM_CALL,
				     "could not open log file %pSE: %m",
				     zcf->filename);
			return -1;
		}

		frr_with_privs (lib_privs) {
			mode_t prevmask;

			prevmask = umask(0777 ^ zcf->file_mode);
			fd = open(zcf->filename,
				  O_WRONLY | O_APPEND | O_CLOEXEC | O_NOCTTY |
					  O_CREAT | O_EXCL,
				  zcf->file_mode);
			umask(prevmask);
		}
		if (fd >= 0) {
			do_chown = true;
			break;
		}

		frr_with_privs (lib_privs) {
			fd = open(zcf->filename,
				  O_WRONLY | O_APPEND | O_CLOEXEC | O_NOCTTY);
		}
		if (fd >= 0)
			break;

		flog_err_sys(EC_LIB_SYSTEM_CALL,
			     "could not open or create log file %pSE: %m",
			     zcf->filename);
		return -1;

	case ZLOG_5424_DST_UNIX:
		if (!zcf->filename)
			return -1;

		memset(&sa, 0, sizeof(sa));
		sa.sun_family = AF_UNIX;
		strlcpy(sa.sun_path, zcf->filename, sizeof(sa.sun_path));

		/* check if ZLOG_5424_DST_FD needs a touch when changing
		 * something here.  the user can pass in a pre-opened unix
		 * socket through a fd at startup.
		 */
		frr_with_privs (lib_privs) {
			if (sock_type != -1)
				fd = zlog_5424_unix(&sa, sock_type);
			else {
				for (size_t i = 0; i < array_size(unix_types);
				     i++) {
					fd = zlog_5424_unix(&sa, unix_types[i]);
					if (fd != -1) {
						zcf->sock_type = unix_types[i];
						break;
					}
				}
			}
		}
		if (fd == -1) {
			zcf->sock_type = -1;

			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"could not connect to log unix path %pSE: %m",
				zcf->filename);
			need_reconnect = true;
			/* no return -1 here, trigger retry code below */
		} else {
			/* datagram sockets are connectionless, restarting
			 * the receiver may lose some packets but will resume
			 * working afterwards without any action from us.
			 */
			need_reconnect = (zcf->sock_type != SOCK_DGRAM);
		}
		break;
	}

	/* viable on both DST_FD and DST_UNIX path */
	if (zcf->sock_type == SOCK_DGRAM) {
		zcf->sa_len = sizeof(zcf->sa);
		if (getpeername(fd, (struct sockaddr *)&zcf->sa,
				&zcf->sa_len)) {
			flog_err_sys(
				EC_LIB_SYSTEM_CALL,
				"could not get remote address for log socket.  logging may break if log receiver restarts.");
			zcf->sa_len = 0;
		}
	}

	if (do_chown) {
		uid_t uid = zcf->file_uid;
		gid_t gid = zcf->file_gid;

		if (uid != (uid_t)-1 || gid != (gid_t)-1) {
			frr_with_privs (lib_privs) {
				err = fchown(fd, uid, gid);
			}
			if (err)
				flog_err_sys(
					EC_LIB_SYSTEM_CALL,
					"failed to chown() log file %pSE: %m",
					zcf->filename);
		}
	}

	if (need_reconnect) {
		assert(zcf->master);

		if (fd != -1) {
			event_add_read(zcf->master, zlog_5424_reconnect, zcf,
				       fd, &zcf->t_reconnect);
			zcf->reconn_backoff_cur = zcf->reconn_backoff;

		} else {
			event_add_timer_msec(zcf->master, zlog_5424_reconnect,
					     zcf, zcf->reconn_backoff_cur,
					     &zcf->t_reconnect);

			zcf->reconn_backoff_cur += zcf->reconn_backoff_cur / 2;
			if (zcf->reconn_backoff_cur > zcf->reconn_backoff_max)
				zcf->reconn_backoff_cur =
					zcf->reconn_backoff_max;
		}
	}

	return fd;
}

bool zlog_5424_apply_dst(struct zlog_cfg_5424 *zcf)
{
	int fd = -1;

	event_cancel(&zcf->t_reconnect);

	if (zcf->prio_min != ZLOG_DISABLED)
		fd = zlog_5424_open(zcf, -1);

	frr_with_mutex (&zcf->cfg_mtx) {
		zlog_5424_cycle(zcf, fd);
	}
	return fd != -1;
}


bool zlog_5424_apply_meta(struct zlog_cfg_5424 *zcf)
{
	frr_with_mutex (&zcf->cfg_mtx) {
		if (zcf->active)
			zlog_5424_cycle(zcf, zcf->active->fd);
	}

	return true;
}

void zlog_5424_state(struct zlog_cfg_5424 *zcf, size_t *lost_msgs,
		     int *last_errno, bool *stale_errno, struct timeval *err_ts)
{
	if (lost_msgs)
		*lost_msgs =
			zcf->active
				? atomic_load_explicit(&zcf->active->lost_msgs,
						       memory_order_relaxed)
				: 0;
	if (last_errno)
		*last_errno = zcf->active ? zcf->active->last_err : 0;
	if (stale_errno)
		*stale_errno = zcf->active ? !zcf->active->current_err : 0;
	if (err_ts && zcf->active)
		*err_ts = zcf->active->last_err_ts;
}

struct rcu_close_rotate {
	struct rcu_head_close head_close;
	struct rcu_head head_self;
};

bool zlog_5424_rotate(struct zlog_cfg_5424 *zcf)
{
	struct rcu_close_rotate *rcr;
	int fd;

	frr_with_mutex (&zcf->cfg_mtx) {
		if (!zcf->active)
			return true;

		event_cancel(&zcf->t_reconnect);

		/* need to retain the socket type because it also influences
		 * other fields (packets) and we can't atomically swap these
		 * out.  But we really want the atomic swap so we neither lose
		 * nor duplicate log messages, particularly for file targets.
		 *
		 * (zlog_5424_apply_dst / zlog_target_replace will cause
		 * duplicate log messages if another thread logs something
		 * while we're right in the middle of swapping out the log
		 * target)
		 */
		fd = zlog_5424_open(zcf, zcf->sock_type);
		if (fd < 0)
			return false;

		fd = atomic_exchange_explicit(&zcf->active->fd,
					      (uint_fast32_t)fd,
					      memory_order_relaxed);
	}

	rcr = XCALLOC(MTYPE_LOG_5424_ROTATE, sizeof(*rcr));
	rcu_close(&rcr->head_close, fd);
	rcu_free(MTYPE_LOG_5424_ROTATE, rcr, head_self);

	return true;
}
