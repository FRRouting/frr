// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Keepalives.
 * Implements a producer thread to generate BGP keepalives for peers.
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Quentin Young
 */

/* clang-format off */
#include <zebra.h>
#include <pthread.h>		// for pthread_mutex_lock, pthread_mutex_unlock

#include "frr_pthread.h"        // for frr_pthread
#include "hash.h"		// for hash, hash_clean, hash_create_size...
#include "log.h"		// for zlog_debug
#include "memory.h"		// for MTYPE_TMP, XFREE, XCALLOC, XMALLOC
#include "monotime.h"		// for monotime, monotime_since

#include "bgpd/bgpd.h"          // for peer, PEER_EVENT_KEEPALIVES_ON, peer...
#include "bgpd/bgp_debug.h"	// for bgp_debug_neighbor_events
#include "bgpd/bgp_packet.h"	// for bgp_keepalive_send
#include "bgpd/bgp_keepalives.h"
/* clang-format on */

DEFINE_MTYPE_STATIC(BGPD, BGP_PKAT, "Peer KeepAlive Timer");
DEFINE_MTYPE_STATIC(BGPD, BGP_COND, "BGP Peer pthread Conditional");
DEFINE_MTYPE_STATIC(BGPD, BGP_MUTEX, "BGP Peer pthread Mutex");

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
	struct pkat *pkat = XMALLOC(MTYPE_BGP_PKAT, sizeof(struct pkat));
	pkat->peer = peer;
	monotime(&pkat->last);
	return pkat;
}

static void pkat_del(void *pkat)
{
	XFREE(MTYPE_BGP_PKAT, pkat);
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
static void peer_process(struct hash_bucket *hb, void *arg)
{
	struct pkat *pkat = hb->data;

	struct timeval *next_update = arg;

	static struct timeval elapsed;  // elapsed time since keepalive
	static struct timeval ka = {0}; // peer->v_keepalive as a timeval
	static struct timeval diff;     // ka - elapsed

	static const struct timeval tolerance = {0, 100000};

	uint32_t v_ka = atomic_load_explicit(&pkat->peer->v_keepalive,
					     memory_order_relaxed);

	/* 0 keepalive timer means no keepalives */
	if (v_ka == 0)
		return;

	/* calculate elapsed time since last keepalive */
	monotime_since(&pkat->last, &elapsed);

	/* calculate difference between elapsed time and configured time */
	ka.tv_sec = v_ka;
	timersub(&ka, &elapsed, &diff);

	int send_keepalive =
		elapsed.tv_sec >= ka.tv_sec || timercmp(&diff, &tolerance, <);

	if (send_keepalive) {
		if (bgp_debug_keepalive(pkat->peer))
			zlog_debug("%s [FSM] Timer (keepalive timer expire)",
				   pkat->peer->host);

		bgp_keepalive_send(pkat->peer->connection);
		monotime(&pkat->last);
		memset(&elapsed, 0, sizeof(elapsed));
		diff = ka;
	}

	/* if calculated next update for this peer < current delay, use it */
	if (next_update->tv_sec < 0 || timercmp(&diff, next_update, <))
		*next_update = diff;
}

static bool peer_hash_cmp(const void *f, const void *s)
{
	const struct pkat *p1 = f;
	const struct pkat *p2 = s;

	return p1->peer == p2->peer;
}

static unsigned int peer_hash_key(const void *arg)
{
	const struct pkat *pkat = arg;
	return (uintptr_t)pkat->peer;
}

/* Cleanup handler / deinitializer. */
static void bgp_keepalives_finish(void *arg)
{
	hash_clean_and_free(&peerhash, pkat_del);

	pthread_mutex_unlock(peerhash_mtx);
	pthread_mutex_destroy(peerhash_mtx);
	pthread_cond_destroy(peerhash_cond);

	XFREE(MTYPE_BGP_MUTEX, peerhash_mtx);
	XFREE(MTYPE_BGP_COND, peerhash_cond);
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

	/*
	 * The RCU mechanism for each pthread is initialized in a "locked"
	 * state. That's ok for pthreads using the frr_pthread,
	 * event_fetch event loop, because that event loop unlocks regularly.
	 * For foreign pthreads, the lock needs to be unlocked so that the
	 * background rcu pthread can run.
	 */
	rcu_read_unlock();

	peerhash_mtx = XCALLOC(MTYPE_BGP_MUTEX, sizeof(pthread_mutex_t));
	peerhash_cond = XCALLOC(MTYPE_BGP_COND, sizeof(pthread_cond_t));

	/* initialize mutex */
	pthread_mutex_init(peerhash_mtx, NULL);

	/* use monotonic clock with condition variable */
	pthread_condattr_t attrs;
	pthread_condattr_init(&attrs);
	pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
	pthread_cond_init(peerhash_cond, &attrs);
	pthread_condattr_destroy(&attrs);

	/*
	 * We are not using normal FRR pthread mechanics and are
	 * not using fpt_run
	 */
	frr_pthread_set_name(fpt);

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
			memset(&next_update, 0, sizeof(next_update));

		monotime_since(&currtime, &aftertime);

		timeradd(&currtime, &next_update, &next_update);
		TIMEVAL_TO_TIMESPEC(&next_update, &next_update_ts);
	}

	/* clean up */
	pthread_cleanup_pop(1);

	return NULL;
}

/* --- thread external functions ------------------------------------------- */

void bgp_keepalives_on(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (CHECK_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON))
		return;

	struct frr_pthread *fpt = bgp_pth_ka;
	assert(fpt->running);

	/* placeholder bucket data to use for fast key lookups */
	static struct pkat holder = {0};

	/*
	 * We need to ensure that bgp_keepalives_init was called first
	 */
	assert(peerhash_mtx);

	frr_with_mutex (peerhash_mtx) {
		holder.peer = peer;
		if (!hash_lookup(peerhash, &holder)) {
			struct pkat *pkat = pkat_new(peer);
			(void)hash_get(peerhash, pkat, hash_alloc_intern);
			peer_lock(peer);
		}
		SET_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON);
		/* Force the keepalive thread to wake up */
		pthread_cond_signal(peerhash_cond);
	}
}

void bgp_keepalives_off(struct peer_connection *connection)
{
	struct peer *peer = connection->peer;

	if (!CHECK_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON))
		return;

	struct frr_pthread *fpt = bgp_pth_ka;
	assert(fpt->running);

	/* placeholder bucket data to use for fast key lookups */
	static struct pkat holder = {0};

	/*
	 * We need to ensure that bgp_keepalives_init was called first
	 */
	assert(peerhash_mtx);

	frr_with_mutex (peerhash_mtx) {
		holder.peer = peer;
		struct pkat *res = hash_release(peerhash, &holder);
		if (res) {
			pkat_del(res);
			peer_unlock(peer);
		}
		UNSET_FLAG(peer->thread_flags, PEER_THREAD_KEEPALIVES_ON);
	}
}

int bgp_keepalives_stop(struct frr_pthread *fpt, void **result)
{
	assert(fpt->running);

	frr_with_mutex (peerhash_mtx) {
		atomic_store_explicit(&fpt->running, false,
				      memory_order_relaxed);
		pthread_cond_signal(peerhash_cond);
	}

	pthread_join(fpt->thread, result);
	return 0;
}
