/* BMP support.
 * Copyright (C) 2018 Yasuhiro Ohara
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

#ifndef _BGP_BMP_H_
#define _BGP_BMP_H_

#define BMP_VERSION_3	3

#define BMP_LENGTH_POS  1

/* BMP message types */
#define BMP_TYPE_ROUTE_MONITORING       0
#define BMP_TYPE_STATISTICS_REPORT      1
#define BMP_TYPE_PEER_DOWN_NOTIFICATION 2
#define BMP_TYPE_PEER_UP_NOTIFICATION   3
#define BMP_TYPE_INITIATION             4
#define BMP_TYPE_TERMINATION            5
#define BMP_TYPE_ROUTE_MIRRORING        6

#define BMP_READ_BUFSIZ	1024

/* bmp->state */
#define BMP_None        0
#define BMP_Initiation  1
#define BMP_PeerUp      2
#define BMP_MonitorInit 3
#define BMP_Monitor     4
#define BMP_EndofRIB    5
#define BMP_Mirror      6

struct bmp
{
	int socket;
	char remote[SU_ADDRSTRLEN];
	struct thread *t_read;
	struct thread *t_write;
	struct thread *t_event;

	int state;
	struct stream_fifo *obuf;
};

#define BMP_EVENT_ADD(X)										\
	do {														\
		if ((X)->t_event == NULL)								\
			thread_add_event(bm->master, bmp_event, (X), 0,		\
				&(X)->t_event);									\
	} while (0)

extern void bmp_mirror_packet(struct peer *peer, struct stream *packet);
extern void bmp_serv_sock(const char *hostname, unsigned short port);
extern void bgp_bmp_init(void);

#endif /*_BGP_BMP_H_*/
