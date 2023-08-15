// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * SEGV / backtrace handling test.
 *
 * copied from test-sig.c
 *
 * Copyright (C) 2013 by David Lamparter, Open Source Routing.
 * Copyright (C) 2013 by Internet Systems Consortium, Inc. ("ISC")
 *
 * This file is part of Quagga
 */

#include <zebra.h>
#include <sigevent.h>
#include "lib/log.h"
#include "lib/memory.h"

struct frr_signal_t sigs[] = {};

struct event_loop *master;

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

static void threadfunc(struct event *thread)
{
	func3();
}

int main(void)
{
	master = event_master_create(NULL);
	signal_init(master, array_size(sigs), sigs);

	zlog_aux_init("NONE: ", LOG_DEBUG);

	event_execute(master, threadfunc, 0, 0, NULL);

	exit(0);
}
