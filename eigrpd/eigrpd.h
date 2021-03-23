/*
 * EIGRP main header.
 * Copyright (C) 2013-2014
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
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
	struct thread_master *master;

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
extern struct thread_master *master;
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
