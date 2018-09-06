/*********************************************************************
 * Copyright 2017-2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	/* Remove previous schedule if any. */
	if (bs->recvtimer_ev)
		bfd_recvtimer_delete(bs);

	thread_add_timer_tv(master, bfd_recvtimer_cb, bs, &tv,
			    &bs->recvtimer_ev);
}

void bfd_echo_recvtimer_update(struct bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->echo_detect_TO};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	/* Remove previous schedule if any. */
	if (bs->echo_recvtimer_ev)
		bfd_echo_recvtimer_delete(bs);

	thread_add_timer_tv(master, bfd_echo_recvtimer_cb, bs, &tv,
			    &bs->echo_recvtimer_ev);
}

void bfd_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	/* Remove previous schedule if any. */
	if (bs->xmttimer_ev)
		bfd_xmttimer_delete(bs);

	thread_add_timer_tv(master, bfd_xmt_cb, bs, &tv, &bs->xmttimer_ev);
}

void bfd_echo_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN))
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	/* Remove previous schedule if any. */
	if (bs->echo_xmttimer_ev)
		bfd_echo_xmttimer_delete(bs);

	thread_add_timer_tv(master, bfd_echo_xmt_cb, bs, &tv,
			    &bs->echo_xmttimer_ev);
}

void bfd_recvtimer_delete(struct bfd_session *bs)
{
	if (bs->recvtimer_ev == NULL)
		return;

	thread_cancel(bs->recvtimer_ev);
	bs->recvtimer_ev = NULL;
}

void bfd_echo_recvtimer_delete(struct bfd_session *bs)
{
	if (bs->echo_recvtimer_ev == NULL)
		return;

	thread_cancel(bs->echo_recvtimer_ev);
	bs->echo_recvtimer_ev = NULL;
}

void bfd_xmttimer_delete(struct bfd_session *bs)
{
	if (bs->xmttimer_ev == NULL)
		return;

	thread_cancel(bs->xmttimer_ev);
	bs->xmttimer_ev = NULL;
}

void bfd_echo_xmttimer_delete(struct bfd_session *bs)
{
	if (bs->echo_xmttimer_ev == NULL)
		return;

	thread_cancel(bs->echo_xmttimer_ev);
	bs->echo_xmttimer_ev = NULL;
}
