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

	/* Remove previous schedule if any. */
	bfd_recvtimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	thread_add_timer_tv(master, bfd_recvtimer_cb, bs, &tv,
			    &bs->recvtimer_ev);
}

void bfd_echo_recvtimer_update(struct bfd_session *bs)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = bs->echo_detect_TO};

	/* Remove previous schedule if any. */
	bfd_echo_recvtimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	thread_add_timer_tv(master, bfd_echo_recvtimer_cb, bs, &tv,
			    &bs->echo_recvtimer_ev);
}

void bfd_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Remove previous schedule if any. */
	bfd_xmttimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	thread_add_timer_tv(master, bfd_xmt_cb, bs, &tv, &bs->xmttimer_ev);
}

void bfd_echo_xmttimer_update(struct bfd_session *bs, uint64_t jitter)
{
	struct timeval tv = {.tv_sec = 0, .tv_usec = jitter};

	/* Remove previous schedule if any. */
	bfd_echo_xmttimer_delete(bs);

	/* Don't add event if peer is deactivated. */
	if (BFD_CHECK_FLAG(bs->flags, BFD_SESS_FLAG_SHUTDOWN) ||
	    bs->sock == -1)
		return;

	tv_normalize(&tv);
#ifdef BFD_EVENT_DEBUG
	log_debug("%s: sec = %ld, usec = %ld", __func__, tv.tv_sec, tv.tv_usec);
#endif /* BFD_EVENT_DEBUG */

	thread_add_timer_tv(master, bfd_echo_xmt_cb, bs, &tv,
			    &bs->echo_xmttimer_ev);
}

void bfd_recvtimer_delete(struct bfd_session *bs)
{
	THREAD_OFF(bs->recvtimer_ev);
}

void bfd_echo_recvtimer_delete(struct bfd_session *bs)
{
	THREAD_OFF(bs->echo_recvtimer_ev);
}

void bfd_xmttimer_delete(struct bfd_session *bs)
{
	THREAD_OFF(bs->xmttimer_ev);
}

void bfd_echo_xmttimer_delete(struct bfd_session *bs)
{
	THREAD_OFF(bs->echo_xmttimer_ev);
}
