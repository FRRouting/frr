/* BGP Keepalives.
 * Implements a producer thread to generate BGP keepalives for peers.
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Quentin Young
 *
 * This file is part of FRRouting.
 *
 * FRRouting is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2, or (at your option) any later
 * version.
 *
 * FRRouting is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* clang-format off */
#include <zebra.h>
#include <pthread.h>		// for pthread_mutex_lock, pthread_mutex_unlock

#include "frr_pthread.h"        // for frr_pthread
#include "hash.h"		// for hash, hash_clean, hash_create_size...
#include "log.h"		// for zlog_debug
#include "memory.h"		// for MTYPE_TMP, XFREE, XCALLOC, XMALLOC
#include "monotime.h"		// for monotime, monotime_since

#include "bgpd/bgpd.h"          // for peer, PEER_THREAD_KEEPALIVES_ON, peer...
#include "bgpd/bgp_debug.h"	// for bgp_debug_neighbor_events
#include "bgpd/bgp_packet.h"	// for bgp_keepalive_send
#include "bgpd/bgp_keepalives.h"
/* clang-format on */

/*
 * Peer KeepAlive Timer.
 * Associates a peer with the time of its last keepalive.
 */
struct pkat {
	/* the peer to send keepalives to */
	struct peer *peer;
	/* absolute time of last keepalive sent */
	struct timeval last;
};

/* List of peers we are sending keepalives for, and associated mutex. */
static pthread_mutex_t *peerhash_mtx;
static pthread_cond_t *peerhash_cond;
static struct hash *peerhash;

static struct pkat *pkat_new(struct peer *peer)
{
	struct pkat *pkat = XMALLOC(MTYPE_TMP, sizeof(struct pkat));
	pkat->peer = peer;
	monotime(&pkat->last);
	return pkat;
}

static void pkat_del(void *pkat)
{
	XFREE(MTYPE_TMP, pkat);
}


/*
 * Callback for hash_iterate. Determines if a peer needs a keepalive and if so,
 * generates and sends it.
 *
 * For any given peer, if the elapsed time since its last keepalive exceeds its
 * configured keepalive timer, a keepalive is sent to the peer and its
 * last-sent time is reset. Additionally, If the elapsed time does not exceed
 * the configured keepalive timer, but the time until the next keepalive is due
 * is within a hardcoded tolerance, a keepalive is sent as if the configured
 * timer was exceeded. Doing this helps alleviate nanosecond sleeps between
 * ticks by grouping together peers who are due for keepalives at roughly the
 * same time. This tolerance value is arbitrarily chosen to be 100ms.
 *
 * In addition, this function calculates the maximum amount of time that the
 * keepalive thread can sleep before another tick needs to take place. This is
 * equivalent to shortest time until a keepalive is due for any one peer.
 *
 * @return maximum time to wait until next update (0 if infinity)
 */
static void peer_process(struct hash_backet *hb, void *arg)
{
	struct pkat *pkat = hb->data;

	struct timeval *next_update = arg;

	static struct timeval elapsed;  // elapsed time since keepalive
	static struct timeval ka = {0}; // peer->v_keepalive as a timeval
	static struct timeval diff;     // ka - elapsed

	static struct timeval tolerance = {0, 100000};

	/* calculate elapsed time since last keepalive */
	monotime_since(&pkat->last, &elapsed);

	/* calculate difference between elapsed time and configured time */
	ka.tv_sec = pkat->peer->v_keepalive;
	timersub(&ka, &elapsed, &diff);

	int send_keepalive =
		elapsed.tv_sec >= ka.tv_sec || timercmp(&diff, &tolerance, <);

	if (send_keepalive) {
		if (bgp_debug_neighbor_events(pkat->peer))
			zlog_debug("%s [FSM] Timer (keepalive timer expire)",
				   pkat->peer->host);

		bgp_keepalive_send(pkat->peer);
		monotime(&pkat->last);
		memset(&elapsed, 0x00, sizeof(struct timeval));
		diff = ka;
	}

	/* if calculated next update for this peer < current delay, use it */
	if (next_update->tv_sec <= 0 || timercmp(&diff, next_update, <))
		*next_update = diff;
}

static int peer_hash_cmp(const void *f, const void *s)
{
	const struct pkat *p1 = f;
	const struct pkat *p2 = s;
	return p1->peer == p2->peer;
}

static unsigned int peer_hash_key(void *arg)
{
	struct pkat *pkat = arg;
	return (uintptr_t)pkat->peer;
}

/* Cleanup handler / deinitializer. */
static void bgp_keepalives_finish(void *arg)
{
	if (peerhash) {
		hash_clean(peerhash, pkat_del);
		hash_free(peerhash);
	}

	peerhash = NULL;

	pthread_mutex_unlock(peerhash_mtx);
	pthread_mutex_destroy(peerhash_mtx);
	pthread_cond_destroy(peerhash_cond);

	XFREE(MTYPE_TMP, peerhash_mtx);
	XFREE(MTYPE_TMP, peerhash_cond);
}

/*
 * Entry function for peer keepalive generation pthread.
 */
void *bgp_keepalives_start(void *arg)
{
	struct frr_pthread *fpt = arg;
	fpt->master->owner = pthread_self();

	struct timeval currtime = {0, 0};
	struct timeval aftertime = {0, 0};
	struct timeval next_update = {0, 0};
	struct timespec next_update_ts = {0, 0};

	peerhash_mtx = XCALLOC(MTYPE_TMP, sizeof(pthread_mutex_t));
	peerhash_cond = XCALLOC(MTYPE_TMP, sizeof(pthread_cond_t));

	/* initialize mutex */
	pthread_mutex_init(peerhash_mtx, NULL);

	/* use monotonic clock with condition variable */
	pthread_condattr_t attrs;
	pthread_condattr_init(&attrs);
	pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
	pthread_cond_init(peerhash_cond, &attrs);
	pthread_condattr_destroy(&attrs);

	/* initialize peer hashtable */
	peerhash = hash_create_size(2048, peer_hash_key, peer_hash_cmp, NULL);
	pthread_mutex_lock(peerhash_mtx);

	/* register cleanup handler */
	pthread_cleanup_push(&bgp_keepalives_finish, NULL);

	/* notify anybody waiting on us that we are done starting up */
	frr_pthread_notify_running(fpt);

	while (atomic_load_explicit(&fpt->running, memory_order_relaxed)) {
		if (peerhash->count > 0)
			pthread_cond_timedwait(peerhash_cond, peerhash_mtx,
					       &next_update_ts);
		else
			while (peerhash->count == 0
			       && atomic_load_explicit(&fpt->running,
						       memory_order_relaxed))
				pthread_cond_wait(peerhash_cond, peerhash_mtx);

		monotime(&currtime);

		next_update.tv_sec = -1;

		hash_iterate(peerhash, peer_process, &next_update);
		if (next_update.tv_sec == -1)
			memset(&next_update, 0x00, sizeof(next_update));

		monotime_since(&currtime, &aftertime);

		timeradd(&currtime, &next_update, &next_update);
		TIMEVAL_TO_TIMESPEC(&next_update, &next_update_ts);
	}

	/* clean up */
	pthread_cleanup_pop(1);

	return NULL;
}

/* --- thread external functions ------------------------------------------- */

void bgp_keepalives_on(struct peer *peer)
{
	if (CHECK_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON))
		return;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_KEEPALIVES);
	assert(fpt->running);

	/* placeholder bucket data to use for fast key lookups */
	static struct pkat holder = {0};

	if (!peerhash_mtx) {
		zlog_warn("%s: call bgp_keepalives_init() first", __func__);
		return;
	}

	pthread_mutex_lock(peerhash_mtx);
	{
		holder.peer = peer;
		if (!hash_lookup(peerhash, &holder)) {
			struct pkat *pkat = pkat_new(peer);
			hash_get(peerhash, pkat, hash_alloc_intern);
			peer_lock(peer);
		}
		SET_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON);
	}
	pthread_mutex_unlock(peerhash_mtx);
	bgp_keepalives_wake();
}

void bgp_keepalives_off(struct peer *peer)
{
	if (!CHECK_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON))
		return;

	struct frr_pthread *fpt = frr_pthread_get(PTHREAD_KEEPALIVES);
	assert(fpt->running);

	/* placeholder bucket data to use for fast key lookups */
	static struct pkat holder = {0};

	if (!peerhash_mtx) {
		zlog_warn("%s: call bgp_keepalives_init() first", __func__);
		return;
	}

	pthread_mutex_lock(peerhash_mtx);
	{
		holder.peer = peer;
		struct pkat *res = hash_release(peerhash, &holder);
		if (res) {
			pkat_del(res);
			peer_unlock(peer);
		}
		UNSET_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON);
	}
	pthread_mutex_unlock(peerhash_mtx);
}

void bgp_keepalives_wake()
{
	pthread_mutex_lock(peerhash_mtx);
	{
		pthread_cond_signal(peerhash_cond);
	}
	pthread_mutex_unlock(peerhash_mtx);
}

int bgp_keepalives_stop(struct frr_pthread *fpt, void **result)
{
	assert(fpt->running);

	atomic_store_explicit(&fpt->running, false, memory_order_relaxed);
	bgp_keepalives_wake();

	pthread_join(fpt->thread, result);
	return 0;
}
