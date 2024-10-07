// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * generic CLI test helper functions
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 */

#include <zebra.h>
#include <sys/stat.h>

#include "debug.h"
#include "frrevent.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "lib_vty.h"
#include "log.h"

#include "common_cli.h"

struct event_loop *master;

int dump_args(struct vty *vty, const char *descr, int argc,
	      struct cmd_token *argv[])
{
	int i;
	vty_out(vty, "%s with %d args.\n", descr, argc);
	for (i = 0; i < argc; i++) {
		vty_out(vty, "[%02d] %s@%s: %s\n", i, argv[i]->text,
			argv[i]->varname, argv[i]->arg);
	}

	return CMD_SUCCESS;
}

static void vty_do_exit(int isexit)
{
	printf("\nend.\n");
	cmd_terminate();
	vty_terminate();
	nb_terminate();
	yang_terminate();
	event_master_free(master);

	log_memstats(stderr, "testcli");
	if (!isexit)
		exit(0);
}

const struct frr_yang_module_info *const *test_yang_modules = NULL;
int test_log_prio = ZLOG_DISABLED;

/* main routine. */
int main(int argc, char **argv)
{
	struct event thread;
	size_t yangcount;

	/* Set umask before anything for security */
	umask(0027);

	/* master init. */
	master = event_master_create(NULL);

	zlog_aux_init("NONE: ", test_log_prio);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	cmd_domainname_set("test.domain");

	vty_init(master, false);
	lib_cmd_init();
	debug_init();

	for (yangcount = 0; test_yang_modules && test_yang_modules[yangcount];
	     yangcount++)
		;
	nb_init(master, test_yang_modules, yangcount, false, false);

	test_init(argc, argv);

	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (event_fetch(master, &thread))
		event_call(&thread);

	/* Not reached. */
	exit(0);
}
