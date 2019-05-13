/*
 * header for path monitoring general services
 * Copyright (C) 6WIND 2019
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#ifndef __ZEBRA_PM_H__
#define __ZEBRA_PM_H__

extern const char ZEBRA_PM_SOCK_NAME[];
#define ZEBRA_PM_MAX_SOCKBUF 3200 /* 25B *128 ports */
#define ZEBRA_PM_SEND_MAX_SOCKBUF 512

#define ZEBRA_PM_BFD_CLIENT_FLAG_REG   (1 << 1) /* client registered with BFD */

#include "zebra/zserv.h"
#include "zebra/interface.h"

/* Zebra ptm context block */
struct zebra_pm_cb {
	int pm_sock; /* ptm file descriptor. */

	struct buffer *wb; /* Buffer of data waiting to be written to ptm. */

	struct thread *t_read;  /* Thread for read */
	struct thread *t_write; /* Thread for write */
	struct thread *t_timer; /* Thread for timer */

	char *out_data;
	char *in_data;
	int reconnect_time;

	int pm_enable;
	int pid;
	uint8_t client_flags[ZEBRA_ROUTE_MAX];
};

#define ZEBRA_PM_STATUS_DOWN 0
#define ZEBRA_PM_STATUS_UP 1
#define ZEBRA_PM_STATUS_UNKNOWN 2

/* For interface ptm-enable configuration. */
#define ZEBRA_IF_PM_ENABLE_OFF    0
#define ZEBRA_IF_PM_ENABLE_ON     1
#define ZEBRA_IF_PM_ENABLE_UNSPEC 2

#define IS_PM_ENABLED_PROTOCOL(protocol) ( \
	(protocol) == ZEBRA_ROUTE_STATIC \
)

void zebra_pm_init(void);
void zebra_pm_finish(void);
int zebra_pm_connect(struct thread *t);
void zebra_pm_write(struct vty *vty);
int zebra_pm_get_enable_state(void);

/* ZAPI message handlers */
void zebra_pm_dst_register(struct zserv *client, struct zmsghdr *hdr,
			   struct stream *msg, struct zebra_vrf *zvrf);
void zebra_pm_dst_deregister(struct zserv *client, struct zmsghdr *hdr,
			     struct stream *msg, struct zebra_vrf *zvrf);
void zebra_pm_client_register(struct zserv *client, struct zmsghdr *hdr,
			      struct stream *msg, struct zebra_vrf *zvrf);
void zebra_pm_dst_replay(struct zserv *client, struct zmsghdr *hdr,
			 struct stream *msg, struct zebra_vrf *zvrf);

#endif /* ZEBRA_PM_ */
