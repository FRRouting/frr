// SPDX-License-Identifier: GPL-2.0-or-later
/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * event.c: implements the BFD loop event handlers.
 *
 * Authors
 * -------
 * Rafael Zalamena <rzalamena@opensourcerouting.org>
 */

#include <zebra.h>

#include "bfd.h"

void tv_normalize(struct timeval *tv);

void tv_normalize(struct timeval *tv)
{
	/* Remove seconds part from microseconds. */
	tv->tv_sec = tv->tv_usec / 1000000;
	tv->tv_usec = tv->tv_usec % 1000000;
}

void bfd_recvtimer_update(struct bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->detect_TO};

	/* Remove previous schedule if any. */
	bfd_recvtimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, bfd_recvtimer_cb, bs, &tv,
			   &bs->recvtimer_ev);
}

void bfd_echo_recvtimer_update(struct bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->echo_detect_TO};

	/* Remove previous schedule if any. */
	bfd_echo_recvtimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, bfd_echo_recvtimer_cb, bs, &tv,
			   &bs->echo_recvtimer_ev);
}

void sbfd_init_recvtimer_update(struct bfd_session *bs)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = bs->detect_TO };

	/* Remove previous schedule if any. */
	sbfd_init_recvtimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) || bs->sock == -1)
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	event_add_timer_tv(master, sbfd_init_recvtimer_cb, bs, &tv, &bs->recvtimer_ev);
}

void sbfd_echo_recvtimer_update(struct bfd_session *bs)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = bs->echo_detect_TO };

	/* Remove previous schedule if any. */
	sbfd_echo_recvtimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) || bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, sbfd_echo_recvtimer_cb, bs, &tv, &bs->echo_recvtimer_ev);
}

void sbfd_init_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = jitter };

	/* Remove previous schedule if any. */
	sbfd_init_xmttimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) || bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, sbfd_init_xmt_cb, bs, &tv, &bs->xmttimer_ev);
	event_set_tardy_threshold(bs->xmttimer_ev, bs->xmt_TO / 2);
}

void sbfd_echo_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = { .tv_sec = 0, .tv_usec = jitter };

	/* Remove previous schedule if any. */
	sbfd_echo_xmttimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) || bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, sbfd_echo_xmt_cb, bs, &tv, &bs->echo_xmttimer_ev);
	event_set_tardy_threshold(bs->echo_xmttimer_ev, bs->echo_xmt_TO / 2);
}

void bfd_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Remove previous schedule if any. */
	bfd_xmttimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, bfd_xmt_cb, bs, &tv, &bs->xmttimer_ev);
	event_set_tardy_threshold(bs->xmttimer_ev, bs->xmt_TO / 2);
}

void bfd_echo_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Remove previous schedule if any. */
	bfd_echo_xmttimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);

	event_add_timer_tv(master, bfd_echo_xmt_cb, bs, &tv,
			   &bs->echo_xmttimer_ev);
	event_set_tardy_threshold(bs->echo_xmttimer_ev, bs->echo_xmt_TO / 2);
}

void bfd_recvtimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->recvtimer_ev);
}

void bfd_echo_recvtimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->echo_recvtimer_ev);
}

void bfd_xmttimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->xmttimer_ev);
}

void bfd_echo_xmttimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->echo_xmttimer_ev);
}

void sbfd_init_recvtimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->recvtimer_ev);
}

void sbfd_echo_recvtimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->echo_recvtimer_ev);
}

void sbfd_init_xmttimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->xmttimer_ev);
}

void sbfd_echo_xmttimer_delete(struct bfd_session *bs)
{
	EVENT_OFF(bs->echo_xmttimer_ev);
}
