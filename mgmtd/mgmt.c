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

#include <zebra.h>
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_vty.h"
#include "mgmtd/mgmt_db.h"
#include "mgmtd/mgmt_memory.h"

bool mgmt_debug_be;
bool mgmt_debug_fe;
bool mgmt_debug_db;
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

	/* Initialize databases */
	mgmt_db_init(mm);

	/* MGMTD VTY commands installation.  */
	mgmt_vty_init();
}

void mgmt_terminate(void)
{
	mgmt_db_destroy();
}
