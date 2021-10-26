/* MGMTD message definition header.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_MGMTD_H
#define _FRR_MGMTD_H

#include "vrf.h"

#include "defaults.h"
#include "stream.h"

#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_db.h"

#define MGMTD_VTY_PORT 2622
#define MGMTD_SOCKET_BUF_SIZE 65535

extern bool mgmt_debug_be;
extern bool mgmt_debug_fe;
extern bool mgmt_debug_db;
extern bool mgmt_debug_txn;

/*
 * MGMTD master for system wide configurations and variables.
 */
struct mgmt_master {
	struct thread_master *master;

	/* How big should we set the socket buffer size */
	uint32_t socket_buffer;

	/* Databases */
	struct mgmt_db_ctx *running_db;
	struct mgmt_db_ctx *candidate_db;
	struct mgmt_db_ctx *oper_db;

	bool terminating;   /* global flag that sigint terminate seen */
	bool perf_stats_en; /* to enable performance stats measurement */
};

extern struct mgmt_master *mm;

/* Inline functions */
static inline unsigned long timeval_elapsed(struct timeval a, struct timeval b)
{
	return (((a.tv_sec - b.tv_sec) * TIMER_SECOND_MICRO)
		+ (a.tv_usec - b.tv_usec));
}

/*
 * Remove trailing separator from a string.
 *
 * str
 *    A null terminated string.
 *
 * sep
 *    Trailing character that needs to be removed.
 */
static inline void mgmt_remove_trailing_separator(char *str, char sep)
{
	size_t len;

	len = strlen(str);
	if (len && str[len - 1] == sep)
		str[len - 1] = '\0';
}

/* Prototypes. */
extern void mgmt_terminate(void);
extern void mgmt_reset(void);
extern time_t mgmt_clock(void);

extern int mgmt_config_write(struct vty *vty);

extern void mgmt_master_init(struct thread_master *master,
			     const int buffer_size);

extern void mgmt_init(void);

static inline char *mgmt_realtime_to_string(struct timeval *tv, char *buf,
					    size_t sz)
{
	char tmp[50];
	struct tm *lm;

	lm = localtime((const time_t *)&tv->tv_sec);
	if (lm) {
		strftime(tmp, sizeof(tmp), "%Y-%m-%d %H:%M:%S", lm);
		snprintf(buf, sz, "%s.%06lu", tmp,
			 (unsigned long int)tv->tv_usec);
	}

	return buf;
}

#endif /* _FRR_MGMTD_H */
