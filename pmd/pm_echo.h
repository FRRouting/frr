/*
 * header for path monitoring echo daemon
 * Copyright 2019 6WIND S.A.
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
#include "pmd/pm_rtt.h"

enum pm_echo_alarm {
	PM_ECHO_NONE = 0,
	PM_ECHO_TIMEOUT = 1,
	PM_ECHO_OK = 2,
	PM_ECHO_NHT_UNREACHABLE = 3,
};

struct pm_echo_retry {
	bool retry_up_in_progress;
	bool retry_down_in_progress;
	bool retry_already_counted;
	int  retry_count;
	int  retry_table_iterator;
	int  retry_table_count_good;
#define PM_ECHO_RETRY_NOK         0
#define PM_ECHO_RETRY_SUCCESSFUL  1
#define PM_ECHO_RETRY_INIT        2
#define PM_ECHO_MAX_RETRY_COUNT   255
	uint8_t retry_table[PM_ECHO_MAX_RETRY_COUNT];
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
	struct pm_rtt_stats *rtt_stats;
	enum pm_echo_alarm last_alarm;
	/* to distinguish between network
	 * unreachable and other error
	 */
	int last_errno;

	/* duplicate from config context */
	int timeout;
	int interval;
	int packet_size;
	uint8_t retries_mode;
	uint8_t retries_consecutive_up;
	uint8_t retries_consecutive_down;
	uint8_t retries_threshold;
	uint8_t retries_total;

	union sockunion peer;
	union sockunion gw;

	/* operational context */
	struct pm_echo_retry retry;

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
extern void pm_echo_trigger_down_event(struct pm_session *pm);

#endif
