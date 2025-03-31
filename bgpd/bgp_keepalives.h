// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP Keepalives.
 * Implements a producer thread to generate BGP keepalives for peers.
 * Copyright (C) 2017 Cumulus Networks, Inc.
 * Quentin Young
 */

#ifndef _FRR_BGP_KEEPALIVES_H
#define _FRR_BGP_KEEPALIVES_H

#include "frr_pthread.h"
#include "bgpd.h"

/**
 * Turns on keepalives for a peer.
 *
 * This function adds the peer to an internal list of peers to generate
 * keepalives for.
 *
 * At set intervals, a BGP KEEPALIVE packet is generated and placed on
 * peer->obuf. This operation is thread-safe with respect to peer->obuf.
 *
 * peer->v_keepalive determines the interval. Changing this value before
 * unregistering this peer with bgp_keepalives_off() results in undefined
 * behavior.
 *
 * If the peer is already registered for keepalives via this function, nothing
 * happens.
 */
extern void bgp_keepalives_on(struct peer_connection *connection);

/**
 * Turns off keepalives for a peer.
 *
 * Removes the peer from the internal list of peers to generate keepalives for.
 *
 * If the peer is already unregistered for keepalives, nothing happens.
 */
extern void bgp_keepalives_off(struct peer_connection *connection);

/**
 * Pre-run initialization function for keepalives pthread.
 *
 * Initializes synchronization primitives. This should be called before
 * anything else to avoid race conditions.
 */
extern void bgp_keepalives_init(void);

/**
 * Entry function for keepalives pthread.
 *
 * This function loops over an internal list of peers, generating keepalives at
 * regular intervals as determined by each peer's keepalive timer.
 *
 * See bgp_keepalives_on() for additional details.
 *
 * @param arg pthread arg, not used
 */
extern void *bgp_keepalives_start(void *arg);

/**
 * Stops the thread and blocks until it terminates.
 */
int bgp_keepalives_stop(struct frr_pthread *fpt, void **result);

#endif /* _FRR_BGP_KEEPALIVES_H */
