/*
 * generic CLI test helper functions
 *
 * Copyright (C) 2015 by David Lamparter,
 *                   for Open Source Routing / NetDEF, Inc.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "thread.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "lib_vty.h"
#include "log.h"

#include "common_cli.h"

struct thread_master *master;

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
	thread_master_free(master);

	log_memstats(stderr, "testcli");
	if (!isexit)
		exit(0);
}

const struct frr_yang_module_info *const *test_yang_modules = NULL;
int test_log_prio = ZLOG_DISABLED;

/* main routine. */
int main(int argc, char **argv)
{
	struct thread thread;
	size_t yangcount;

	/* Set umask before anything for security */
	umask(0027);

	/* master init. */
	master = thread_master_create(NULL);

	zlog_aux_init("NONE: ", test_log_prio);

	/* Library inits. */
	cmd_init(1);
	cmd_hostname_set("test");
	cmd_domainname_set("test.domain");

	vty_init(master, false);
	lib_cmd_init();

	for (yangcount = 0; test_yang_modules && test_yang_modules[yangcount];
	     yangcount++)
		;
	nb_init(master, test_yang_modules, yangcount, false);

	test_init(argc, argv);

	vty_stdio(vty_do_exit);

	/* Fetch next active thread. */
	while (thread_fetch(master, &thread))
		thread_call(&thread);

	/* Not reached. */
	exit(0);
}
