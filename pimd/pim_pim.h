// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#ifndef PIM_PIM_H
#define PIM_PIM_H

#include <zebra.h>

#include "if.h"
#include "pim_instance.h"

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

int pim_pim_packet(struct interface *ifp, uint8_t *buf, size_t len,
		   pim_sgaddr sg, bool is_mcast);

int pim_msg_send(int fd, pim_addr src, pim_addr dst, uint8_t *pim_msg,
		 int pim_msg_size, struct interface *ifp);

int pim_hello_send(struct interface *ifp, uint16_t holdtime);

int pim_sock_read_helper(int fd, struct pim_instance *pim, bool is_mcast);
#endif /* PIM_PIM_H */
