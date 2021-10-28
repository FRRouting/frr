/* FRR Management Daemon (MGMTD) program
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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


#include "thread.h"
#include "buffer.h"
#include "stream.h"
#include "ringbuf.h"
#include "command.h"
#include "sockunion.h"
#include "sockopt.h"
#include "network.h"
#include "memory.h"
#include "log.h"
#include "plist.h"
#include "linklist.h"
#include "workqueue.h"
#include "queue.h"
#include "hash.h"
#include "jhash.h"
#include "table.h"
#include "lib/json.h"
#include "frr_pthread.h"
#include "bitfield.h"
#include "lib/md5.h"
#include "lib/typesafe.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_vty.h"
#include "mgmtd/mgmt_bcknd_server.h"
#include "mgmtd/mgmt_bcknd_adapter.h"
#include "mgmtd/mgmt_frntnd_server.h"
#include "mgmtd/mgmt_frntnd_adapter.h"
#include "mgmtd/mgmt_db.h"
#include "mgmtd/mgmt_memory.h"

bool mgmt_debug_bcknd;
bool mgmt_debug_frntnd;
bool mgmt_debug_db;
bool mgmt_debug_trxn;

/* MGMTD process wide configuration.  */
static struct mgmt_master mgmt_master;

/* MGMTD process wide configuration pointer to export.  */
struct mgmt_master *mm;

/* time_t value that is monotonicly increasing
 * and uneffected by adjustments to system clock
 */
time_t mgmt_clock(void)
{
	struct timeval tv;

	monotime(&tv);
	return tv.tv_sec;
}

void mgmt_master_init(struct thread_master *master, const int buffer_size)
{
	memset(&mgmt_master, 0, sizeof(struct mgmt_master));

	mm = &mgmt_master;
	mm->master = master;
	mm->start_time = mgmt_clock();
	mm->terminating = false;
	mm->socket_buffer = buffer_size;
	mm->perf_stats_en = true;
}

static void mgmt_pthreads_init(void)
{
#if 0
	assert(!mgmt__pthd_xyz);

	struct frr_pthread_attr xyz_attr = {
		.start = mgmt_xyz_start,
		.stop = mgmt_xyz_stop,
	};
	mgmt_pthd_xyz = frr_pthread_new(&xyz_attr,
		"MGMTD XYZ thread", "mgmt_xyz");
#endif
}

void mgmt_pthreads_run(void)
{
#if 0
	frr_pthread_run(mgmt_pthd_xyz, NULL);

	/* Wait until threads are ready. */
	frr_pthread_wait_running(mgmt_pthd_xyz);
#endif
}

void mgmt_pthreads_finish(void)
{
	frr_pthread_stop_all();
}

void mgmt_init(void)
{

	/* allocates some vital data structures used by peer commands in
	 * vty_init
	 */
	vty_init_mgmt_frntnd();

	/* pre-init pthreads */
	mgmt_pthreads_init();

	/* Initialize databases */
	mgmt_db_init(mm);

	/* Initialize MGMTD Transaction module */
	mgmt_trxn_init(mm, mm->master);

	/* Initialize the MGMTD Backend Adapter Module */
	mgmt_bcknd_adapter_init(mm->master);

	/* Initialize the MGMTD Frontend Adapter Module */
	mgmt_frntnd_adapter_init(mm->master, mm);

	/* Start the MGMTD Backend Server for clients to connect */
	mgmt_bcknd_server_init(mm->master);

	/* Start the MGMTD Frontend Server for clients to connect */
	mgmt_frntnd_server_init(mm->master);

	/* MGMTD VTY commands installation. */
	mgmt_vty_init();
}

void mgmt_terminate(void)
{
	mgmt_frntnd_server_destroy();
	mgmt_bcknd_server_destroy();
	mgmt_db_destroy();
}
