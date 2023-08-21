// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * EIGRP main header.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 */

#ifndef _ZEBRA_EIGRPD_H
#define _ZEBRA_EIGRPD_H

#include <zebra.h>

#include "filter.h"
#include "log.h"
#include "memory.h"

DECLARE_MGROUP(EIGRPD);

/* Set EIGRP version is "classic" - wide metrics comes next */
#define EIGRP_MAJOR_VERSION     1
#define EIGRP_MINOR_VERSION	2

#define EIGRP_TLV_32B_VERSION 1 /* Original 32bit scaled metrics */
#define EIGRP_TLV_64B_VERSION 2 /* Current 64bit 'wide' metrics */
#define EIGRP_TLV_MTR_VERSION 3 /* MTR TLVs with 32bit metric *Not Supported */
#define EIGRP_TLV_SAF_VERSION 4 /* SAF TLVs with 64bit metric *Not Supported */

struct eigrp_master {
	/* EIGRP instance. */
	struct list *eigrp;

	/* EIGRP thread master. */
	struct event_loop *master;

	/* Zebra interface list. */
	struct list *iflist;

	/* EIGRP start time. */
	time_t start_time;

	/* Various EIGRP global configuration. */
	uint8_t options;

#define EIGRP_MASTER_SHUTDOWN (1 << 0) /* deferred-shutdown */
};

/* Extern variables. */
extern struct zclient *zclient;
extern struct event_loop *master;
extern struct eigrp_master *eigrp_om;
extern struct zebra_privs_t eigrpd_privs;

/* Prototypes */
extern void eigrp_master_init(void);
extern void eigrp_terminate(void);
extern void eigrp_finish_final(struct eigrp *eigrp);
extern void eigrp_finish(struct eigrp *eigrp);
extern struct eigrp *eigrp_get(uint16_t as, vrf_id_t vrf_id);
extern struct eigrp *eigrp_lookup(vrf_id_t vrf_id);
extern void eigrp_router_id_update(struct eigrp *eigrp);

#endif /* _ZEBRA_EIGRPD_H */
