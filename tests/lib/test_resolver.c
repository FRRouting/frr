/*
 * FRR c-ares integration test
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
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

/* this test is not run automatically since tests MUST NOT rely on any outside
 * state.  DNS is most definitely "outside state".  A testbed may not have any
 * internet connectivity at all.  It may not have working DNS.  Or worst of
 * all, whatever name we use to test may have a temporary failure entirely
 * beyond our control.
 *
 * The only way this test could be run in a testbed is with an all-local DNS
 * setup, which considering the resolver code is rarely touched is not worth
 * the time at all.  Instead, after touching the resolver code, manually run
 * this test and throw some names at it.
 */

#include <zebra.h>

#include "vty.h"
#include "command.h"
#include "resolver.h"
#include "log.h"
#include "sockunion.h"

#include "tests/lib/cli/common_cli.h"

extern struct thread_master *master;

static void resolver_result(struct resolver_query *resq, const char *errstr,
			    int numaddrs, union sockunion *addr)
{
	int i;

	if (numaddrs <= 0) {
		zlog_warn("hostname resolution failed: %s", errstr);
		return;
	}

	for (i = 0; i < numaddrs; i++)
		zlog_info("resolver result: %pSU", &addr[i]);
}

struct resolver_query query;

DEFUN (test_resolve,
       test_resolve_cmd,
       "resolve WORD",
       "DNS resolver\n"
       "Name to resolve\n")
{
	resolver_resolve(&query, AF_UNSPEC, 0, argv[1]->arg, resolver_result);
	return CMD_SUCCESS;
}

__attribute__((_CONSTRUCTOR(2000)))
static void test_setup(void)
{
	test_log_prio = LOG_DEBUG;
}

void test_init(int argc, char **argv)
{
	resolver_init(master);

	install_element(VIEW_NODE, &test_resolve_cmd);
}
