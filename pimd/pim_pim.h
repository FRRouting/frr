/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef PIM_PIM_H
#define PIM_PIM_H

#include <zebra.h>

#include "if.h"

#define PIM_PIM_BUFSIZE_READ  (20000)
#define PIM_PIM_BUFSIZE_WRITE (20000)

#define PIM_DEFAULT_HELLO_PERIOD                 (30)   /* seconds, RFC 4601: 4.11 */
#define PIM_DEFAULT_TRIGGERED_HELLO_DELAY        (5)    /* seconds, RFC 4601: 4.11 */
#define PIM_DEFAULT_DR_PRIORITY                  (1)    /* RFC 4601: 4.3.1 */
#define PIM_DEFAULT_PROPAGATION_DELAY_MSEC       (500)  /* RFC 4601: 4.11.  Timer Values */
#define PIM_DEFAULT_OVERRIDE_INTERVAL_MSEC       (2500) /* RFC 4601: 4.11.  Timer Values */
#define PIM_DEFAULT_CAN_DISABLE_JOIN_SUPPRESSION (0)    /* boolean */
#define PIM_DEFAULT_T_PERIODIC                   (60)   /* RFC 4601: 4.11.  Timer Values */

enum pim_msg_type {
	PIM_MSG_TYPE_HELLO = 0,
	PIM_MSG_TYPE_REGISTER,
	PIM_MSG_TYPE_REG_STOP,
	PIM_MSG_TYPE_JOIN_PRUNE,
	PIM_MSG_TYPE_BOOTSTRAP,
	PIM_MSG_TYPE_ASSERT,
	PIM_MSG_TYPE_GRAFT,
	PIM_MSG_TYPE_GRAFT_ACK,
	PIM_MSG_TYPE_CANDIDATE
};

void pim_ifstat_reset(struct interface *ifp);
void pim_sock_reset(struct interface *ifp);
int pim_sock_add(struct interface *ifp);
void pim_sock_delete(struct interface *ifp, const char *delete_message);
void pim_hello_restart_now(struct interface *ifp);
void pim_hello_restart_triggered(struct interface *ifp);

int pim_pim_packet(struct interface *ifp, uint8_t *buf, size_t len);

int pim_msg_send(int fd, struct in_addr src, struct in_addr dst,
		 uint8_t *pim_msg, int pim_msg_size, const char *ifname);

#endif /* PIM_PIM_H */
