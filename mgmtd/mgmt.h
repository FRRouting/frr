// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * MGMTD message definition header.
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
 */

#ifndef _FRR_MGMTD_H
#define _FRR_MGMTD_H

#include "vrf.h"

#include "defaults.h"

#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_ds.h"

#define MGMTD_VTY_PORT 2622
#define MGMTD_SOCKET_BUF_SIZE 65535

extern bool mgmt_debug_be;
extern bool mgmt_debug_fe;
extern bool mgmt_debug_ds;
extern bool mgmt_debug_txn;

/*
 * MGMTD master for system wide configurations and variables.
 */
struct mgmt_master {
	struct thread_master *master;

	/* How big should we set the socket buffer size */
	uint32_t socket_buffer;

	/* Datastores */
	struct mgmt_ds_ctx *running_ds;
	struct mgmt_ds_ctx *candidate_ds;
	struct mgmt_ds_ctx *oper_ds;

	bool terminating;   /* global flag that sigint terminate seen */
	bool perf_stats_en; /* to enable performance stats measurement */
};

extern struct mgmt_master *mm;

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
extern void mgmt_vty_init(void);

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
