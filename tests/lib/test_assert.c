/*
 * Quick test for assert()
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
#include "lib/thread.h"
#include "lib/sigevent.h"

int main(int argc, char **argv)
{
	int number = 10;
	struct thread_master *master;

	zlog_aux_init("NONE: ", LOG_DEBUG);

	if (argc > 1)
		number = atoi(argv[1]);

	assert(number > 0);
	assertf(number > 1, "(B) the number was %d", number);

	/* set up SIGABRT handler */
	master = thread_master_create("test");
	signal_init(master, 0, NULL);

	func_for_bt(number);
	assert(number > 4);
	assertf(number > 5, "(C) the number was %d", number);

	assertf(number > 10, "(D) the number was %d", number);
	return 0;
}
