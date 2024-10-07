// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Testing shim and API examples for the new CLI backend.
 *
 * Minimal main() to run grammar_sandbox standalone.
 * [split off grammar_sandbox.c 2017-01-23]
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Copyright (C) 2017 David Lamparter for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "command.h"
#include "lib_vty.h"

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");
	if (!isexit)
		exit(0);
}

struct event_loop *master;

int main(int argc, char **argv)
{
	struct event event;

	master = event_master_create(NULL);

	zlog_aux_init("NONE: ", LOG_DEBUG);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	cmd_domainname_set("testdomainname");

	vty_init(master, true);
	lib_cmd_init();
	nb_init(master, NULL, 0, false, false);

	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (event_fetch(master, &event))
		event_call(&event);

	/* Not reached. */
	exit(0);
}
