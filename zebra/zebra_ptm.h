/*
 * Definitions for prescriptive topology module (PTM).
 * Copyright (C) 1998, 99, 2000 Kunihiro Ishiguro, Toshiaki Takada
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _ZEBRA_PTM_H
#define _ZEBRA_PTM_H

extern const char ZEBRA_PTM_SOCK_NAME[];
#define ZEBRA_PTM_MAX_SOCKBUF 3200 /* 25B *128 ports */
#define ZEBRA_PTM_SEND_MAX_SOCKBUF 512

#define ZEBRA_PTM_BFD_CLIENT_FLAG_REG   (1 << 1) /* client registered with BFD */

#include "zebra/zserv.h"
#include "zebra/interface.h"

/* Zebra ptm context block */
struct zebra_ptm_cb {
	int ptm_sock; /* ptm file descriptor. */

	struct buffer *wb; /* Buffer of data waiting to be written to ptm. */

	struct thread *t_read;  /* Thread for read */
	struct thread *t_write; /* Thread for write */
	struct thread *t_timer; /* Thread for timer */

	char *out_data;
	char *in_data;
	int reconnect_time;

	int ptm_enable;
	int pid;
	uint8_t client_flags[ZEBRA_ROUTE_MAX];
};

#define ZEBRA_PTM_STATUS_DOWN 0
#define ZEBRA_PTM_STATUS_UP 1
#define ZEBRA_PTM_STATUS_UNKNOWN 2

/* For interface ptm-enable configuration. */
#define ZEBRA_IF_PTM_ENABLE_OFF    0
#define ZEBRA_IF_PTM_ENABLE_ON     1
#define ZEBRA_IF_PTM_ENABLE_UNSPEC 2

void zebra_ptm_init(void);
void zebra_ptm_finish(void);
int zebra_ptm_connect(struct thread *t);
void zebra_ptm_write(struct vty *vty);
int zebra_ptm_get_enable_state(void);

/* ZAPI message handlers */
void zebra_ptm_bfd_dst_register(ZAPI_HANDLER_ARGS);
void zebra_ptm_bfd_dst_deregister(ZAPI_HANDLER_ARGS);
void zebra_ptm_bfd_client_register(ZAPI_HANDLER_ARGS);

void zebra_ptm_show_status(struct vty *vty, struct interface *ifp);
void zebra_ptm_if_init(struct zebra_if *zebra_ifp);
void zebra_ptm_if_set_ptm_state(struct interface *ifp,
				struct zebra_if *zebra_ifp);
void zebra_ptm_if_write(struct vty *vty, struct zebra_if *zebra_ifp);
#endif
