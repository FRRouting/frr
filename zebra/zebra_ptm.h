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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#ifndef _ZEBRA_PTM_H
#define _ZEBRA_PTM_H

extern const char ZEBRA_PTM_SOCK_NAME[];
#define ZEBRA_PTM_MAX_SOCKBUF 3200 /* 25B *128 ports */
#define ZEBRA_PTM_SEND_MAX_SOCKBUF 512

/* Zebra ptm context block */
struct zebra_ptm_cb
{
  int ptm_sock; /* ptm file descriptor. */

  struct buffer *wb; /* Buffer of data waiting to be written to ptm. */

  struct thread *t_read; /* Thread for read */
  struct thread *t_write; /* Thread for write */
  struct thread *t_timer; /* Thread for timer */

  char *out_data;
  char *in_data;
  int reconnect_time;

  int ptm_enable;
  int pid;
};

#define ZEBRA_PTM_STATUS_DOWN 0
#define ZEBRA_PTM_STATUS_UP 1
#define ZEBRA_PTM_STATUS_UNKNOWN 2

void zebra_ptm_init (void);
void zebra_ptm_finish(void);
int zebra_ptm_connect (struct thread *t);
void zebra_ptm_write (struct vty *vty);
int zebra_ptm_get_enable_state(void);

int zebra_ptm_bfd_dst_register (struct zserv *client, int sock, u_short length,
                                  int command, vrf_id_t vrf_id);
int zebra_ptm_bfd_dst_deregister (struct zserv *client, int sock,
                                  u_short length, vrf_id_t vrf_id);
void
zebra_ptm_show_status(struct vty *vty, struct interface *ifp);
#endif
