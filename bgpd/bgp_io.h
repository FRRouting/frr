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

#ifndef _FRR_BGP_IO_H
#define _FRR_BGP_IO_H

#include "bgpd/bgpd.h"

/**
 * Control variable for write thread.
 *
 * Setting this variable to false and calling peer_writes_wake() will
 * eventually result in thread termination.
 */
extern bool bgp_packet_writes_thread_run;

/**
 * Initializes data structures and flags for the write thread.
 *
 * This function should be called from the main thread before
 * peer_writes_start() is invoked.
 */
extern void peer_writes_init(void);

/**
 * Start function for write thread.
 *
 * This function should be passed to pthread_create() during BGP startup.
 */
extern void *peer_writes_start(void *arg);

/**
 * Start function for write thread.
 *
 * Uninitializes all resources and stops the thread.
 *
 * @param result -- where to store data result, unused
 */
extern int peer_writes_stop(void **result);

/**
 * Registers a peer with the write thread.
 *
 * This function adds the peer to an internal data structure, which must be
 * locked for write access. This call will block until the structure can be
 * locked.
 *
 * After this function is called, any packets placed on peer->obuf will be
 * written to peer->fd at regular intervals.
 *
 * This function increments the peer reference counter with peer_lock().
 *
 * If the peer is already registered, nothing happens.
 *
 * @param peer - peer to register
 */
extern void peer_writes_on(struct peer *peer);

/**
 * Deregisters a peer with the write thread.
 *
 * This function removes the peer from an internal data structure, which must
 * be locked for write access. This call will block until the structure can be
 * locked.
 *
 * After this function is called, any packets placed on peer->obuf will not be
 * written to peer->fd.
 *
 * This function decrements the peer reference counter with peer_unlock().
 *
 * If the peer is not registered, nothing happens.
 *
 * @param peer - peer to deregister
 */
extern void peer_writes_off(struct peer *peer);

/**
 * Notifies the write thread that there is work to be done.
 *
 * This function has the effect of waking the write thread if it is sleeping.
 * If the thread is not sleeping, this signal will be ignored.
 */
extern void peer_writes_wake(void);

#endif /* _FRR_BGP_IO_H */
