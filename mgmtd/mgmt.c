// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR Management Daemon (MGMTD) program
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 */

#include <zebra.h>
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_memory.h"

bool mgmt_debug_be;
bool mgmt_debug_fe;
bool mgmt_debug_ds;
bool mgmt_debug_txn;

/* MGMTD process wide configuration.  */
static struct mgmt_master mgmt_master;

/* MGMTD process wide configuration pointer to export.  */
struct mgmt_master *mm;

void mgmt_master_init(struct thread_master *master, const int buffer_size)
{
	memset(&mgmt_master, 0, sizeof(struct mgmt_master));

	mm = &mgmt_master;
	mm->master = master;
	mm->terminating = false;
	mm->socket_buffer = buffer_size;
	mm->perf_stats_en = true;
}

void mgmt_init(void)
{

	/* Initialize datastores */
	mgmt_ds_init(mm);

	/* MGMTD VTY commands installation.  */
	mgmt_vty_init();
}

void mgmt_terminate(void)
{
	mgmt_ds_destroy();
}
