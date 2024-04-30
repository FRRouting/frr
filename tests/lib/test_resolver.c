// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * FRR c-ares integration test
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
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

extern struct event_loop *master;

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
