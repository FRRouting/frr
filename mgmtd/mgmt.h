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
#include "stream.h"

#include "mgmtd/mgmt_memory.h"
#include "mgmtd/mgmt_defines.h"
#include "mgmtd/mgmt_history.h"
#include "mgmtd/mgmt_txn.h"
#include "mgmtd/mgmt_ds.h"

#define MGMTD_VTY_PORT 2622
#define MGMTD_SOCKET_BUF_SIZE 65535
#define MGMTD_MAX_COMMIT_LIST 10

extern bool mgmt_debug_be;
extern bool mgmt_debug_fe;
extern bool mgmt_debug_ds;
extern bool mgmt_debug_txn;

struct mgmt_txn_ctx;

/*
 * MGMTD master for system wide configurations and variables.
 */
struct mgmt_master {
	struct thread_master *master;

	/* How big should we set the socket buffer size */
	uint32_t socket_buffer;

	/* The single instance of config transaction allowed at any time */
	struct mgmt_txns_head txn_list;

	/* Map of Transactions and its ID */
	struct hash *txn_hash;
	uint64_t next_txn_id;

	/* The single instance of config transaction allowed at any time */
	struct mgmt_txn_ctx *cfg_txn;

	/* Datastores */
	struct mgmt_ds_ctx *running_ds;
	struct mgmt_ds_ctx *candidate_ds;
	struct mgmt_ds_ctx *oper_ds;

	bool terminating;   /* global flag that sigint terminate seen */
	bool perf_stats_en; /* to enable performance stats measurement */

	/* List of commit infos */
	struct mgmt_cmt_infos_head cmts; /* List of last 10 commits executed. */
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
extern void mgmt_vty_init(void);

static inline char *mgmt_realtime_to_string(struct timeval *tv, char *buf,
					    size_t sz)
{
	struct tm tm;
	size_t n;

	localtime_r((const time_t *)&tv->tv_sec, &tm);
	n = strftime(buf, sz, "%Y-%m-%dT%H:%M:%S", &tm);
	snprintf(&buf[n], sz - n, ",%06u000", (unsigned int)tv->tv_usec);
	return buf;
}

#endif /* _FRR_MGMTD_H */
