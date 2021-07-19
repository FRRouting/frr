/* BGP I/O.
 * Implements packet I/O in a pthread.
 * Copyright (C) 2017  Cumulus Networks
 * Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */

#ifndef _FRR_BGP_IO_H
#define _FRR_BGP_IO_H

#define BGP_WRITE_PACKET_MAX 64U
#define BGP_READ_PACKET_MAX  10U

#include "bgpd/bgpd.h"
#include "frr_pthread.h"

struct peer_connection;

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
 * After this function is called, any packets placed on connection->obuf will be
 * written to connection->fd until no more packets remain.
 *
 * Additionally, it becomes unsafe to perform socket actions on connection->fd.
 *
 * @param peer - peer to register
 */
extern void bgp_writes_on(struct peer_connection *peer);

/**
 * Turns off packet writing for a peer.
 *
 * After this function returns, packets placed on connection->obuf will not be
 * written to connection->fd by the I/O thread.
 *
 * After this function returns it becomes safe to perform socket actions on
 * connection->fd.
 *
 * @param connection - connection to deregister
 * @param flush - as described
 */
extern void bgp_writes_off(struct peer_connection *connection);

/**
 * Turns on packet reading for a peer.
 *
 * After this function is called, any packets received on connection->fd
 * will be read and copied into the FIFO queue connection->ibuf.
 *
 * Additionally, it becomes unsafe to perform socket actions on connection->fd.
 *
 * Whenever one or more packets are placed onto connection->ibuf, a task of type
 * THREAD_EVENT will be placed on the main thread whose handler is
 *
 *   bgp_packet.c:bgp_process_packet()
 *
 * @param connection - The connection to register
 */
extern void bgp_reads_on(struct peer_connection *connection);

/**
 * Turns off packet reading for a peer.
 *
 * After this function is called, any packets received on connection->fd
 * will not be read by the I/O thread.
 *
 * After this function returns it becomes safe to perform socket actions on
 * connection->fd.
 *
 * @param connection - The connection to register for
 */
extern void bgp_reads_off(struct peer_connection *connection);

#endif /* _FRR_BGP_IO_H */
