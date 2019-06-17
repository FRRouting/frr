/*
 * header for path monitoring echo daemon
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
#ifndef __PM_ECHO_H__
#define __PM_ECHO_H__

#include "zebra.h"

enum pm_echo_alarm {
	PM_ECHO_NONE = 0,
	PM_ECHO_TIMEOUT = 1,
	PM_ECHO_OK = 2,
	PM_ECHO_NHT_UNREACHABLE = 3,
};

struct pm_echo {
	uint32_t discriminator_id;

	int echofd;
	int echofd_rx_ipv6;
	uint8_t *tx_buf;
	uint8_t *rx_buf;
	uint32_t icmp_sequence;

	struct thread *t_echo_tmo;
	struct thread *t_echo_send;
	struct thread *t_echo_receive;
	struct timeval start;
	struct timeval end;
	struct timeval last_rtt;
	enum pm_echo_alarm last_alarm;
	/* to distinguish between network
	 * unreachable and other error
	 */
	int last_errno;

	/* duplicate from config context */
	int timeout;
	int interval;
	int packet_size;

	union sockunion peer;
	union sockunion gw;

	/* operational context */
	bool oper_bind;
	bool oper_connect;
	bool oper_receive;
	bool oper_timeout;
	uint32_t stats_tx;
	uint32_t stats_rx;
	uint32_t stats_rx_timeout;

	struct pm_session *back_ptr;
};

extern int pm_debug_echo;

extern int pm_echo_tmo(struct thread *thread);
extern int pm_echo_send(struct thread *thread);
extern int pm_echo_receive(struct thread *thread);
extern int pm_echo(struct pm_session *pm, char *errormsg,
		   int len_errormsg);
extern void pm_echo_stop(struct pm_session *pm, char *errormsg,
			 int len_errormsg, bool force);
extern void pm_echo_dump(struct vty *vty, struct pm_session *pm);

extern char *pm_echo_get_alarm_str(struct pm_session *pm,
				   char *buf, size_t len);

#endif
