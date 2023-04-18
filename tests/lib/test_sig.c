// SPDX-License-Identifier: GPL-2.0-or-later
/*
 */

#include <zebra.h>
#include <sigevent.h>
#include "lib/log.h"
#include "lib/memory.h"

static void sighup(void)
{
	printf("processed hup\n");
}

static void sigusr1(void)
{
	printf("processed usr1\n");
}

static void sigusr2(void)
{
	printf("processed usr2\n");
}

struct frr_signal_t sigs[] = {{
				      .signal = SIGHUP,
				      .handler = &sighup,
			      },
			      {
				      .signal = SIGUSR1,
				      .handler = &sigusr1,
			      },
			      {
				      .signal = SIGUSR2,
				      .handler = &sigusr2,
			      }};

struct event_loop *master;
struct event t;

int main(void)
{
	master = event_master_create(NULL);
	signal_init(master, array_size(sigs), sigs);

	zlog_aux_init("NONE: ", LOG_DEBUG);

	while (event_fetch(master, &t))
		event_call(&t);

	exit(0);
}
