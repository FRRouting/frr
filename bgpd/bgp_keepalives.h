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
#ifndef _BGP_KEEPALIVES_H_
#define _BGP_KEEPALIVES_H_

#include "bgpd.h"

/* Thread control flag.
 *
 * Setting this flag to 'false' while the thread is running will result in
 * thread termination.
 */
extern bool bgp_keepalives_thread_run;

/* Turns on keepalives for a peer.
 *
 * This function adds the peer to an internal list of peers to generate
 * keepalives for.
 *
 * At set intervals, a BGP KEEPALIVE packet is generated and placed on
 * peer->obuf. This operation is thread-safe with respect to peer->obuf.
 *
 * peer->v_keepalive determines the interval. Changing this value before
 * unregistering this peer with peer_keepalives_off() results in undefined
 * behavior.
 *
 * If the peer is already registered for keepalives via this function, nothing
 * happens.
 */
extern void peer_keepalives_on(struct peer *);

/* Turns off keepalives for a peer.
 *
 * Removes the peer from the internal list of peers to generate keepalives for.
 *
 * If the peer is already unregistered for keepalives, nothing happens.
 */
extern void peer_keepalives_off(struct peer *);

/* Pre-run initialization function for keepalives pthread.
 *
 * Initializes synchronization primitives. This should be called before
 * anything else to avoid race conditions.
 */
extern void peer_keepalives_init(void);

/* Entry function for keepalives pthread.
 *
 * This function loops over an internal list of peers, generating keepalives at
 * regular intervals as determined by each peer's keepalive timer.
 *
 * See peer_keepalives_on() for additional details.
 *
 * @param arg pthread arg, not used
 */
extern void *peer_keepalives_start(void *arg);

/* Poking function for keepalives pthread.
 *
 * Under normal circumstances the pthread will automatically wake itself
 * whenever it is necessary to do work. This function may be used to force the
 * thread to wake up and see if there is any work to do, or if it is time to
 * die.
 *
 * It is not necessary to call this after peer_keepalives_on().
 */
extern void peer_keepalives_wake(void);

#endif /* _BGP_KEEPALIVES_H */
