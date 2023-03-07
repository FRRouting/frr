// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Quick test for assert()
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* make sure this works with assert.h & nothing else.  also check the include
 * shadowing, we don't want to pick up system assert.h
 */
#include <assert.h>

__attribute__((noinline))
static void func_for_bt(int number)
{
	assert(number > 2);
	assertf(number > 3, "(A) the number was %d", number);
}

#include <zebra.h>
#include "lib/zlog.h"
#include "frrevent.h"
#include "lib/sigevent.h"

int main(int argc, char **argv)
{
	int number = 10;
	struct event_loop *master;

	zlog_aux_init("NONE: ", LOG_DEBUG);

	if (argc > 1)
		number = atoi(argv[1]);

	assert(number > 0);
	assertf(number > 1, "(B) the number was %d", number);

	/* set up SIGABRT handler */
	master = event_master_create("test");
	signal_init(master, 0, NULL);

	func_for_bt(number);
	assert(number > 4);
	assertf(number > 5, "(C) the number was %d", number);

	assertf(number > 10, "(D) the number was %d", number);
	return 0;
}
