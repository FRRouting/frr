/* BGP Keepalives.
 *
 * Implemented server-style in a pthread.
 * --------------------------------------
 * Copyright (C) 2017 Cumulus Networks, Inc.
 *
 * This file is part of Free Range Routing.
 *
 * Free Range Routing is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any later
 * version.
 *
 * Free Range Routing is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GN5U General Public License along
 * with Free Range Routing; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */
#include <zebra.h>
#include <signal.h>
#include <sys/time.h>

#include "thread.h"
#include "log.h"
#include "vty.h"
#include "monotime.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_keepalives.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_packet.h"

/**
 * Peer KeepAlive Timer.
 * Associates a peer with the time of its last keepalive.
 */
struct pkat {
	// the peer to send keepalives to
	struct peer *peer;
	// absolute time of last keepalive sent
	struct timeval last;
};

/* List of peers we are sending keepalives for, and associated mutex. */
static pthread_mutex_t peerlist_mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t peerlist_cond;
static struct list *peerlist;

/* Thread control flag. */
bool bgp_keepalives_thread_run;

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
/**
 * Cleanup thread resources at termination.
 *
 * @param arg not used
 */
static void cleanup_handler(void *arg)
{
	if (peerlist)
		list_delete(peerlist);

	peerlist = NULL;

	pthread_mutex_unlock(&peerlist_mtx);
	pthread_cond_destroy(&peerlist_cond);
	memset(&peerlist_cond, 0, sizeof(peerlist_cond));
}

/*
 * Walks the list of peers, sending keepalives to those that are due for them.
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
static struct timeval update()
{
	struct listnode *ln;
	struct pkat *pkat;

	int update_set = 0;		// whether next_update has been set
	struct timeval next_update;     // max sleep until next tick
	static struct timeval elapsed;  // elapsed time since keepalive
	static struct timeval ka = {0}; // peer->v_keepalive as a timeval
	static struct timeval diff;     // ka - elapsed

	// see function comment
	static struct timeval tolerance = {0, 100000};

	for (ALL_LIST_ELEMENTS_RO(peerlist, ln, pkat)) {
		// calculate elapsed time since last keepalive
		monotime_since(&pkat->last, &elapsed);

		// calculate difference between elapsed time and configured time
		ka.tv_sec = pkat->peer->v_keepalive;
		timersub(&ka, &elapsed, &diff);

		int send_keepalive = elapsed.tv_sec >= ka.tv_sec
				     || timercmp(&diff, &tolerance, <);

		if (send_keepalive) {
			if (bgp_debug_neighbor_events(pkat->peer))
				zlog_debug(
					"%s [FSM] Timer (keepalive timer expire)",
					pkat->peer->host);

			bgp_keepalive_send(pkat->peer);
			monotime(&pkat->last);
			memset(&elapsed, 0x00, sizeof(struct timeval));
			diff = ka; // time until next keepalive == peer
				   // keepalive time
		}

		// if calculated next update for this peer < current delay, use
		// it
		if (!update_set || timercmp(&diff, &next_update, <)) {
			next_update = diff;
			update_set = 1;
		}
	}

	return next_update;
}

void *peer_keepalives_start(void *arg)
{
	struct timeval currtime = {0, 0};
	struct timeval next_update = {0, 0};
	struct timespec next_update_ts = {0, 0};

	// initialize synchronization primitives
	pthread_mutex_lock(&peerlist_mtx);

	// use monotonic clock with condition variable
	pthread_condattr_t attrs;
	pthread_condattr_init(&attrs);
	pthread_condattr_setclock(&attrs, CLOCK_MONOTONIC);
	pthread_cond_init(&peerlist_cond, &attrs);

	// initialize peerlist
	peerlist = list_new();
	peerlist->del = pkat_del;

	// register cleanup handlers
	pthread_cleanup_push(&cleanup_handler, NULL);

	bgp_keepalives_thread_run = true;

	while (bgp_keepalives_thread_run) {
		if (peerlist->count > 0)
			pthread_cond_timedwait(&peerlist_cond, &peerlist_mtx,
					       &next_update_ts);
		else
			while (peerlist->count == 0
			       && bgp_keepalives_thread_run)
				pthread_cond_wait(&peerlist_cond,
						  &peerlist_mtx);

		monotime(&currtime);
		next_update = update();
		timeradd(&currtime, &next_update, &next_update);
		TIMEVAL_TO_TIMESPEC(&next_update, &next_update_ts);
	}

	// clean up
	pthread_cleanup_pop(1);

	return NULL;
}

/* --- thread external functions ------------------------------------------- */

void peer_keepalives_on(struct peer *peer)
{
	pthread_mutex_lock(&peerlist_mtx);
	{
		struct listnode *ln, *nn;
		struct pkat *pkat;

		for (ALL_LIST_ELEMENTS(peerlist, ln, nn, pkat))
			if (pkat->peer == peer) {
				pthread_mutex_unlock(&peerlist_mtx);
				return;
			}

		pkat = pkat_new(peer);
		listnode_add(peerlist, pkat);
		peer_lock(peer);
	}
	pthread_mutex_unlock(&peerlist_mtx);
	peer_keepalives_wake();
}

void peer_keepalives_off(struct peer *peer)
{
	pthread_mutex_lock(&peerlist_mtx);
	{
		struct listnode *ln, *nn;
		struct pkat *pkat;

		for (ALL_LIST_ELEMENTS(peerlist, ln, nn, pkat))
			if (pkat->peer == peer) {
				XFREE(MTYPE_TMP, pkat);
				list_delete_node(peerlist, ln);
				peer_unlock(peer);
			}
	}
	pthread_mutex_unlock(&peerlist_mtx);
}

void peer_keepalives_wake()
{
	pthread_mutex_lock(&peerlist_mtx);
	{
		pthread_cond_signal(&peerlist_cond);
	}
	pthread_mutex_unlock(&peerlist_mtx);
}
