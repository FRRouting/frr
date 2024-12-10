// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP I/O.
 * Implements packet I/O in a pthread.
 * Copyright (C) 2017  Cumulus Networks
 * Quentin Young
 */

#ifndef _FRR_BGP_IO_H
#define _FRR_BGP_IO_H

#define BGP_WRITE_PACKET_MAX 64U
#define BGP_READ_PACKET_MAX  10U

#include "bgpd/bgpd.h"
#include "frr_pthread.h"

<<<<<<< HEAD
=======
struct peer_connection;

>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
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
<<<<<<< HEAD
 * After this function is called, any packets placed on peer->obuf will be
 * written to peer->fd until no more packets remain.
 *
 * Additionally, it becomes unsafe to perform socket actions on peer->fd.
 *
 * @param peer - peer to register
 */
extern void bgp_writes_on(struct peer *peer);
=======
 * After this function is called, any packets placed on connection->obuf will be
 * written to connection->fd until no more packets remain.
 *
 * Additionally, it becomes unsafe to perform socket actions on connection->fd.
 *
 * @param peer - peer to register
 */
extern void bgp_writes_on(struct peer_connection *peer);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

/**
 * Turns off packet writing for a peer.
 *
<<<<<<< HEAD
 * After this function returns, packets placed on peer->obuf will not be
 * written to peer->fd by the I/O thread.
 *
 * After this function returns it becomes safe to perform socket actions on
 * peer->fd.
 *
 * @param peer - peer to deregister
 * @param flush - as described
 */
extern void bgp_writes_off(struct peer *peer);
=======
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
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

/**
 * Turns on packet reading for a peer.
 *
<<<<<<< HEAD
 * After this function is called, any packets received on peer->fd will be read
 * and copied into the FIFO queue peer->ibuf.
 *
 * Additionally, it becomes unsafe to perform socket actions on peer->fd.
 *
 * Whenever one or more packets are placed onto peer->ibuf, a task of type
=======
 * After this function is called, any packets received on connection->fd
 * will be read and copied into the FIFO queue connection->ibuf.
 *
 * Additionally, it becomes unsafe to perform socket actions on connection->fd.
 *
 * Whenever one or more packets are placed onto connection->ibuf, a task of type
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)
 * THREAD_EVENT will be placed on the main thread whose handler is
 *
 *   bgp_packet.c:bgp_process_packet()
 *
<<<<<<< HEAD
 * @param peer - peer to register
 */
extern void bgp_reads_on(struct peer *peer);
=======
 * @param connection - The connection to register
 */
extern void bgp_reads_on(struct peer_connection *connection);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

/**
 * Turns off packet reading for a peer.
 *
<<<<<<< HEAD
 * After this function is called, any packets received on peer->fd will not be
 * read by the I/O thread.
 *
 * After this function returns it becomes safe to perform socket actions on
 * peer->fd.
 *
 * @param peer - peer to deregister
 */
extern void bgp_reads_off(struct peer *peer);
=======
 * After this function is called, any packets received on connection->fd
 * will not be read by the I/O thread.
 *
 * After this function returns it becomes safe to perform socket actions on
 * connection->fd.
 *
 * @param connection - The connection to register for
 */
extern void bgp_reads_off(struct peer_connection *connection);
>>>>>>> 9b0b9282d (bgpd: Fix bgp core with a possible Intf delete)

#endif /* _FRR_BGP_IO_H */
