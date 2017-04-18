/*
  BGP I/O.
  Implements a consumer thread to flush packets destined for remote peers.

  Copyright (C) 2017  Cumulus Networks

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING; if not, write to the
  Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
  MA 02110-1301 USA
 */

#include <zebra.h>
#include <sys/time.h>
#include <pthread.h>

#include "thread.h"
#include "hash.h"
#include "stream.h"
#include "memory.h"
#include "log.h"
#include "monotime.h"
#include "network.h"
#include "frr_pthread.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_fsm.h"

static int bgp_write(struct peer *);
static void peer_process_writes(struct hash_backet *, void *);

bool bgp_packet_writes_thread_run = false;

/* Hash table of peers to operate on, associated synchronization primitives and
 * hash table callbacks.
 * ------------------------------------------------------------------------ */
static struct hash *peerhash;
/* Mutex to protect hash table */
static pthread_mutex_t *peerhash_mtx;
/* Condition variable used to notify the write thread that there is work to do
 */
static pthread_cond_t *write_cond;

static unsigned int peer_hash_key_make(void *p)
{
	struct peer *peer = p;
	return sockunion_hash(&peer->su);
}

static int peer_hash_cmp(const void *p1, const void *p2)
{
	const struct peer *peer1 = p1;
	const struct peer *peer2 = p2;
	return (sockunion_same(&peer1->su, &peer2->su)
		&& CHECK_FLAG(peer1->flags, PEER_FLAG_CONFIG_NODE)
			   == CHECK_FLAG(peer2->flags, PEER_FLAG_CONFIG_NODE));
}
/* ------------------------------------------------------------------------ */

void peer_writes_init(void)
{
	peerhash_mtx = XCALLOC(MTYPE_PTHREAD, sizeof(pthread_mutex_t));
	write_cond = XCALLOC(MTYPE_PTHREAD, sizeof(pthread_cond_t));

	// initialize mutex
	pthread_mutex_init(peerhash_mtx, NULL);

	// use monotonic clock with condition variable
	pthread_condattr_t attrs;
	pthread_condattr_init(&attrs);
	pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
	pthread_cond_init(write_cond, &attrs);
	pthread_condattr_destroy(&attrs);

	// initialize peerhash
	peerhash = hash_create_size(2048, peer_hash_key_make, peer_hash_cmp);
}

static void peer_writes_finish(void *arg)
{
	bgp_packet_writes_thread_run = false;

	if (peerhash)
		hash_free(peerhash);

	peerhash = NULL;

	pthread_mutex_unlock(peerhash_mtx);
	pthread_mutex_destroy(peerhash_mtx);
	pthread_cond_destroy(write_cond);

	XFREE(MTYPE_PTHREAD, peerhash_mtx);
	XFREE(MTYPE_PTHREAD, write_cond);
}

void *peer_writes_start(void *arg)
{
	struct timeval currtime = {0, 0};
	struct timeval sleeptime = {0, 500};
	struct timespec next_update = {0, 0};

	pthread_mutex_lock(peerhash_mtx);

	// register cleanup handler
	pthread_cleanup_push(&peer_writes_finish, NULL);

	bgp_packet_writes_thread_run = true;

	while (bgp_packet_writes_thread_run) {
		// wait around until next update time
		if (peerhash->count > 0)
			pthread_cond_timedwait(write_cond, peerhash_mtx,
					       &next_update);
		else // wait around until we have some peers
			while (peerhash->count == 0
			       && bgp_packet_writes_thread_run)
				pthread_cond_wait(write_cond, peerhash_mtx);

		hash_iterate(peerhash, peer_process_writes, NULL);

		monotime(&currtime);
		timeradd(&currtime, &sleeptime, &currtime);
		TIMEVAL_TO_TIMESPEC(&currtime, &next_update);
	}

	// clean up
	pthread_cleanup_pop(1);

	return NULL;
}

int peer_writes_stop(void **result)
{
	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_WRITE);
	bgp_packet_writes_thread_run = false;
	peer_writes_wake();
	pthread_join(fpt->thread, result);
	return 0;
}

void peer_writes_on(struct peer *peer)
{
	if (peer->status == Deleted)
		return;

	pthread_mutex_lock(peerhash_mtx);
	{
		if (!hash_lookup(peerhash, peer)) {
			hash_get(peerhash, peer, hash_alloc_intern);
			peer_lock(peer);
		}

		SET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
	}
	pthread_mutex_unlock(peerhash_mtx);
	peer_writes_wake();
}

void peer_writes_off(struct peer *peer)
{
	pthread_mutex_lock(peerhash_mtx);
	{
		if (hash_release(peerhash, peer)) {
			peer_unlock(peer);
			fprintf(stderr, "Releasing %p\n", peer);
		}

		UNSET_FLAG(peer->thread_flags, PEER_THREAD_WRITES_ON);
	}
	pthread_mutex_unlock(peerhash_mtx);
}

void peer_writes_wake()
{
	pthread_cond_signal(write_cond);
}

/**
 * Callback for hash_iterate. Takes a hash bucket, unwraps it into a peer and
 * synchronously calls bgp_write() on the peer.
 */
static void peer_process_writes(struct hash_backet *hb, void *arg)
{
	static struct peer *peer;
	peer = hb->data;
	pthread_mutex_lock(&peer->obuf_mtx);
	{
		bgp_write(peer);
	}
	pthread_mutex_unlock(&peer->obuf_mtx);

	// dispatch job on main thread
	BGP_TIMER_ON(peer->t_generate_updgrp_packets,
		     bgp_generate_updgrp_packets, 100);
}

/**
 * Flush peer output buffer.
 *
 * This function pops packets off of peer->obuf and writes them to peer->fd.
 * The amount of packets written is equal to the minimum of peer->wpkt_quanta
 * and the number of packets on the output buffer.
 *
 * If write() returns an error, the appropriate FSM event is generated.
 *
 * The return value is equal to the number of packets written
 * (which may be zero).
 */
static int bgp_write(struct peer *peer)
{
	u_char type;
	struct stream *s;
	int num;
	int update_last_write = 0;
	unsigned int count = 0;
	unsigned int oc = 0;

	/* Write packets. The number of packets written is the value of
	 * bgp->wpkt_quanta or the size of the output buffer, whichever is
	 * smaller.*/
	while (count < peer->bgp->wpkt_quanta
	       && (s = stream_fifo_head(peer->obuf))) {
		int writenum;
		do {
			writenum = stream_get_endp(s) - stream_get_getp(s);
			num = write(peer->fd, STREAM_PNT(s), writenum);

			if (num < 0) {
				if (!ERRNO_IO_RETRY(errno))
					BGP_EVENT_ADD(peer, TCP_fatal_error);

				goto done;
			} else if (num != writenum) // incomplete write
				stream_forward_getp(s, num);

		} while (num != writenum);

		/* Retrieve BGP packet type. */
		stream_set_getp(s, BGP_MARKER_SIZE + 2);
		type = stream_getc(s);

		switch (type) {
		case BGP_MSG_OPEN:
			peer->open_out++;
			break;
		case BGP_MSG_UPDATE:
			peer->update_out++;
			break;
		case BGP_MSG_NOTIFY:
			peer->notify_out++;
			/* Double start timer. */
			peer->v_start *= 2;

			/* Overflow check. */
			if (peer->v_start >= (60 * 2))
				peer->v_start = (60 * 2);

			/* Handle Graceful Restart case where the state changes
			   to
			   Connect instead of Idle */
			/* Flush any existing events */
			BGP_EVENT_ADD(peer, BGP_Stop);
			goto done;

		case BGP_MSG_KEEPALIVE:
			peer->keepalive_out++;
			break;
		case BGP_MSG_ROUTE_REFRESH_NEW:
		case BGP_MSG_ROUTE_REFRESH_OLD:
			peer->refresh_out++;
			break;
		case BGP_MSG_CAPABILITY:
			peer->dynamic_cap_out++;
			break;
		}

		count++;
		/* OK we send packet so delete it. */
		stream_free(stream_fifo_pop(peer->obuf));
		update_last_write = 1;
	}

done : {
	/* Update last_update if UPDATEs were written. */
	if (peer->update_out > oc)
		peer->last_update = bgp_clock();

	/* If we TXed any flavor of packet update last_write */
	if (update_last_write)
		peer->last_write = bgp_clock();
}

	return count;
}
