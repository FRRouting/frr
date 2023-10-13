// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR Management Daemon (MGMTD) program
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 */

#include <zebra.h>
#include "debug.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_adapter.h"
#include "mgmtd/mgmt_ds.h"
#include "mgmtd/mgmt_fe_adapter.h"
#include "mgmtd/mgmt_history.h"
#include "mgmtd/mgmt_memory.h"

struct debug mgmt_debug_be = {.desc = "Management backend adapater"};
struct debug mgmt_debug_ds = {.desc = "Management datastore"};
struct debug mgmt_debug_fe = {.desc = "Management frontend adapater"};
struct debug mgmt_debug_txn = {.desc = "Management transaction"};

/* MGMTD process wide configuration.  */
static struct mgmt_master mgmt_master;

/* MGMTD process wide configuration pointer to export.  */
struct mgmt_master *mm;

void mgmt_master_init(struct event_loop *master, const int buffer_size)
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

	/* Initialize history */
	mgmt_history_init();

	/* Initialize MGMTD Transaction module */
	mgmt_txn_init(mm, mm->master);

	/* Initialize the MGMTD Frontend Adapter Module */
	mgmt_fe_adapter_init(mm->master);

	/*
	 * Initialize the CLI frontend client -- this queues an event for the
	 * client to short-circuit connect to the server (ourselves).
	 */
	vty_init_mgmt_fe();

	/*
	 * MGMTD VTY commands installation -- the frr lib code will queue an
	 * event to read the config files which needs to happen after the
	 * connect from above is made.
	 */
	mgmt_vty_init();

	/*
	 * Initialize the MGMTD Backend Adapter Module
	 *
	 * We do this after the FE stuff so that we have read our config file
	 * prior to any BE connection. Setting up the server will queue a
	 * "socket read" event to accept BE connections. So the code is counting
	 * on the above 2 events to run prior to any `accept` event from here.
	 */
	mgmt_be_adapter_init(mm->master);
}

void mgmt_terminate(void)
{
	mgmt_fe_adapter_destroy();
	mgmt_be_adapter_destroy();
	mgmt_txn_destroy();
	mgmt_history_destroy();
	mgmt_ds_destroy();
}
