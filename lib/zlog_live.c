/*
 * Copyright (c) 2019-22  David Lamparter, for NetDEF, Inc.
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

#include "zlog_live.h"

#include "memory.h"
#include "frrcu.h"
#include "zlog.h"
#include "printfrr.h"

DEFINE_MTYPE_STATIC(LOG, LOG_LIVE, "log vtysh live target");

enum {
	STATE_NORMAL = 0,
	STATE_FD_DEAD,
	STATE_DISOWNED,
};

struct zlt_live {
	struct zlog_target zt;

	atomic_uint_fast32_t fd;
	struct rcu_head_close head_close;
	struct rcu_head head_self;

	atomic_uint_fast32_t state;
};

static void zlog_live(struct zlog_target *zt, struct zlog_msg *msgs[],
		      size_t nmsgs)
{
	struct zlt_live *zte = container_of(zt, struct zlt_live, zt);
	struct zlog_live_hdr hdrs[nmsgs], *hdr = hdrs;
	struct mmsghdr mmhs[nmsgs], *mmh = mmhs;
	struct iovec iovs[nmsgs * 3], *iov = iovs;
	struct timespec ts;
	size_t i, textlen;
	int fd;
	uint_fast32_t state;

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);

	if (fd < 0)
		return;

	memset(mmhs, 0, sizeof(mmhs));
	memset(hdrs, 0, sizeof(hdrs));

	for (i = 0; i < nmsgs; i++) {
		const struct fmt_outpos *argpos;
		size_t n_argpos, arghdrlen;
		struct zlog_msg *msg = msgs[i];
		int prio = zlog_msg_prio(msg);

		if (prio > zt->prio_min)
			continue;

		zlog_msg_args(msg, &arghdrlen, &n_argpos, &argpos);

		mmh->msg_hdr.msg_iov = iov;

		iov->iov_base = hdr;
		iov->iov_len = sizeof(*hdr);
		iov++;

		if (n_argpos) {
			iov->iov_base = (char *)argpos;
			iov->iov_len = sizeof(*argpos) * n_argpos;
			iov++;
		}

		iov->iov_base = (char *)zlog_msg_text(msg, &textlen);
		iov->iov_len = textlen;
		iov++;

		zlog_msg_tsraw(msg, &ts);

		hdr->ts_sec = ts.tv_sec;
		hdr->ts_nsec = ts.tv_nsec;
		hdr->prio = zlog_msg_prio(msg);
		hdr->flags = 0;
		hdr->textlen = textlen;
		hdr->arghdrlen = arghdrlen;
		hdr->n_argpos = n_argpos;

		mmh->msg_hdr.msg_iovlen = iov - mmh->msg_hdr.msg_iov;
		mmh++;
		hdr++;
	}

	size_t msgtotal = mmh - mmhs;
	ssize_t sent;

	for (size_t msgpos = 0; msgpos < msgtotal; msgpos += sent) {
		sent = sendmmsg(fd, mmhs + msgpos, msgtotal - msgpos, 0);

		if (sent <= 0)
			goto out_err;
	}
	return;

out_err:
	fd = atomic_exchange_explicit(&zte->fd, -1, memory_order_relaxed);
	if (fd < 0)
		return;

	rcu_close(&zte->head_close, fd);
	zlog_target_replace(zt, NULL);

	state = STATE_NORMAL;
	atomic_compare_exchange_strong_explicit(
		&zte->state, &state, STATE_FD_DEAD, memory_order_relaxed,
		memory_order_relaxed);
	if (state == STATE_DISOWNED)
		rcu_free(MTYPE_LOG_LIVE, zte, head_self);
}

static void zlog_live_sigsafe(struct zlog_target *zt, const char *text,
			      size_t len)
{
	struct zlt_live *zte = container_of(zt, struct zlt_live, zt);
	struct zlog_live_hdr hdr[1] = {};
	struct iovec iovs[2], *iov = iovs;
	struct timespec ts;
	int fd;

	fd = atomic_load_explicit(&zte->fd, memory_order_relaxed);
	if (fd < 0)
		return;

	clock_gettime(CLOCK_REALTIME, &ts);

	hdr->ts_sec = ts.tv_sec;
	hdr->ts_nsec = ts.tv_nsec;
	hdr->prio = LOG_CRIT;
	hdr->textlen = len;

	iov->iov_base = (char *)hdr;
	iov->iov_len = sizeof(hdr);
	iov++;

	iov->iov_base = (char *)text;
	iov->iov_len = len;
	iov++;

	writev(fd, iovs, iov - iovs);
}

void zlog_live_open(struct zlog_live_cfg *cfg, int prio_min, int *other_fd)
{
	int sockets[2];
	struct zlt_live *zte;
	struct zlog_target *zt;

	if (cfg->target)
		zlog_live_close(cfg);

	*other_fd = -1;
	if (prio_min == ZLOG_DISABLED)
		return;

	/* the only reason for SEQPACKET here is getting close notifications.
	 * otherwise if you open a bunch of vtysh connections with live logs
	 * and close them all, the fds will stick around until we get an error
	 * when trying to log something to them at some later point -- which
	 * eats up fds and might be *much* later for some daemons.
	 */
	if (socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sockets) < 0) {
		if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sockets) < 0) {
			zlog_warn("%% could not open socket pair: %m");
			return;
		}
	} else
		/* SEQPACKET only: try to zap read direction */
		shutdown(sockets[0], SHUT_RD);

	*other_fd = sockets[1];

	zt = zlog_target_clone(MTYPE_LOG_LIVE, NULL, sizeof(*zte));
	zte = container_of(zt, struct zlt_live, zt);
	cfg->target = zte;

	zte->fd = sockets[0];
	zte->zt.prio_min = prio_min;
	zte->zt.logfn = zlog_live;
	zte->zt.logfn_sigsafe = zlog_live_sigsafe;

	zlog_target_replace(NULL, zt);
}

void zlog_live_close(struct zlog_live_cfg *cfg)
{
	struct zlt_live *zte;
	int fd;

	if (!cfg->target)
		return;

	zte = cfg->target;
	cfg->target = NULL;

	fd = atomic_exchange_explicit(&zte->fd, -1, memory_order_relaxed);

	if (fd >= 0) {
		rcu_close(&zte->head_close, fd);
		zlog_target_replace(&zte->zt, NULL);
	}
	rcu_free(MTYPE_LOG_LIVE, zte, head_self);
}

void zlog_live_disown(struct zlog_live_cfg *cfg)
{
	struct zlt_live *zte;
	uint_fast32_t state;

	if (!cfg->target)
		return;

	zte = cfg->target;
	cfg->target = NULL;

	state = STATE_NORMAL;
	atomic_compare_exchange_strong_explicit(
		&zte->state, &state, STATE_DISOWNED, memory_order_relaxed,
		memory_order_relaxed);
	if (state == STATE_FD_DEAD)
		rcu_free(MTYPE_LOG_LIVE, zte, head_self);
}
