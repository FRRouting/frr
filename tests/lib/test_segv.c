/*
 * SEGV / backtrace handling test.
 *
 * copied from test-sig.c
 *
 * Copyright (C) 2013 by David Lamparter, Open Source Routing.
 * Copyright (C) 2013 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This file is part of Quagga
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
#include <sigevent.h>
#include "lib/log.h"
#include "lib/memory.h"

struct frr_signal_t sigs[] = {};

struct thread_master *master;

void func1(int *arg);
void func3(void);

void func1(int *arg)
{
	int *null = NULL;
	*null += 1;
	*arg = 1;
}

static void func2(size_t depth, int *arg)
{
	/* variable stack frame size */
	int buf[depth];
	for (size_t i = 0; i < depth; i++)
		buf[i] = arg[i] + 1;
	if (depth > 0)
		func2(depth - 1, buf);
	else
		func1(&buf[0]);
	for (size_t i = 0; i < depth; i++)
		buf[i] = arg[i] + 2;
}

void func3(void)
{
	int buf[6];
	func2(6, buf);
}

static void threadfunc(struct thread *thread)
{
	func3();
}

int main(void)
{
	master = thread_master_create(NULL);
	signal_init(master, array_size(sigs), sigs);

	zlog_aux_init("NONE: ", LOG_DEBUG);

	thread_execute(master, threadfunc, 0, 0);

	exit(0);
}
