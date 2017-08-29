/*
 * Testing shim and API examples for the new CLI backend.
 *
 * Minimal main() to run grammar_sandbox standalone.
 * [split off grammar_sandbox.c 2017-01-23]
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Copyright (C) 2017 David Lamparter for NetDEF, Inc.
 *
 * This file is part of FreeRangeRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include "command.h"
#include "memory_vty.h"

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");
	if (!isexit)
		exit(0);
}

struct thread_master *master;

int main(int argc, char **argv)
{
	struct thread thread;

	master = thread_master_create(NULL);

	openzlog("grammar_sandbox", "NONE", 0, LOG_CONS | LOG_NDELAY | LOG_PID,
		 LOG_DAEMON);
	zlog_set_level(ZLOG_DEST_SYSLOG, ZLOG_DISABLED);
	zlog_set_level(ZLOG_DEST_STDOUT, LOG_DEBUG);
	zlog_set_level(ZLOG_DEST_MONITOR, ZLOG_DISABLED);

	/* Library inits. */
	cmd_init(1);
	host.name = strdup("test");
	host.domainname = strdup("testdomainname");

	vty_init(master);
	memory_init();

	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* Not reached. */
	exit(0);
}
