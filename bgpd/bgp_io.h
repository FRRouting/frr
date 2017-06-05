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

#define BGP_WRITE_PACKET_MAX 10U
#define BGP_READ_PACKET_MAX  10U

#include "bgpd/bgpd.h"
#include "frr_pthread.h"

/**
 * Control variable for write thread.
 *
 * Setting this variable to false will eventually result in thread termination.
 */
extern bool bgp_packet_writes_thread_run;

/**
 * Initializes data structures and flags for the write thread.
 *
 * This function should be called from the main thread before
 * bgp_writes_start() is invoked.
 */
extern void bgp_io_init(void);

/**
 * Start function for write thread.
 *
 * @param arg - unused
 */
extern void *bgp_io_start(void *arg);

/**
 * Start function for write thread.
 *
 * Uninitializes all resources and stops the thread.
 *
 * @param result - where to store data result, unused
 */
extern int bgp_io_stop(void **result, struct frr_pthread *fpt);

/**
 * Turns on packet writing for a peer.
 *
 * After this function is called, any packets placed on peer->obuf will be
 * written to peer->fd at regular intervals. Additionally it becomes unsafe to
 * use peer->fd with select() or poll().
 *
 * This function increments the peer reference counter with peer_lock().
 *
 * If the peer is already registered, nothing happens.
 *
 * @param peer - peer to register
 */
extern void bgp_writes_on(struct peer *peer);

/**
 * Turns off packet writing for a peer.
 *
 * After this function is called, any packets placed on peer->obuf will not be
 * written to peer->fd. After this function returns it is safe to use peer->fd
 * with select() or poll().
 *
 * If the flush = true, a last-ditch effort will be made to flush any remaining
 * packets to peer->fd. Upon encountering any error whatsoever, the attempt
 * will abort. If the caller wishes to know whether the flush succeeded they
 * may check peer->obuf->count against zero.
 *
 * If the peer is not registered, nothing happens.
 *
 * @param peer - peer to deregister
 * @param flush - as described
 */
extern void bgp_writes_off(struct peer *peer);

/**
 * Turns on packet reading for a peer.
 *
 * After this function is called, any packets received on peer->fd will be read
 * and copied into the FIFO queue peer->ibuf. Additionally it becomes unsafe to
 * use peer->fd with select() or poll().
 *
 * When a full packet is read, bgp_process_packet() will be scheduled on the
 * main thread.
 *
 * This function increments the peer reference counter with peer_lock().
 *
 * If the peer is already registered, nothing happens.
 *
 * @param peer - peer to register
 */
extern void bgp_reads_on(struct peer *peer);

/**
 * Turns off packet reading for a peer.
 *
 * After this function is called, any packets received on peer->fd will not be
 * read. After this function returns it is safe to use peer->fd with select()
 * or poll().
 *
 * This function decrements the peer reference counter with peer_unlock().
 *
 * If the peer is not registered, nothing happens.
 *
 * @param peer - peer to deregister
 */
extern void bgp_reads_off(struct peer *peer);

#endif /* _FRR_BGP_IO_H */
