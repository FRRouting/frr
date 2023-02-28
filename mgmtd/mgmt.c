// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR Management Daemon (MGMTD) program
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 */

#include <zebra.h>
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_server.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_fe_server.h"
#include "mgmtd/mgmt_fe_adapter.h"
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

	/*
	 * Allocates some vital data structures used by peer commands in
	 * vty_init
	 */
	vty_init_mgmt_fe();

	/* Initialize datastores */
	mgmt_ds_init(mm);

	/* Initialize the MGMTD Backend Adapter Module */
	mgmt_be_adapter_init(mm->master);

	/* Initialize the MGMTD Frontend Adapter Module */
	mgmt_fe_adapter_init(mm->master, mm);

	/* Start the MGMTD Backend Server for clients to connect */
	mgmt_be_server_init(mm->master);

	/* Start the MGMTD Frontend Server for clients to connect */
	mgmt_fe_server_init(mm->master);

	/* MGMTD VTY commands installation.  */
	mgmt_vty_init();
}

void mgmt_terminate(void)
{
	mgmt_fe_server_destroy();
	mgmt_fe_adapter_destroy();
	mgmt_be_server_destroy();
	mgmt_be_adapter_destroy();
	mgmt_ds_destroy();
}
