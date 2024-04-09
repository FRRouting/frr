// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 */

#include <zebra.h>

#include <signal.h>

#include "sigevent.h"
#include "memory.h"
#include "log.h"
#include "if.h"

#include "pim_signals.h"
#include "pimd.h"

/*
 * Signal handlers
 */

static void pim_sighup(void)
{
	zlog_info("SIGHUP received, ignoring");
}

static void pim_sigint(void)
{
	zlog_notice("Terminating on signal SIGINT");
	pim_terminate();
	exit(1);
}

static void pim_sigterm(void)
{
	zlog_notice("Terminating on signal SIGTERM");
	pim_terminate();
	exit(1);
}

static void pim_sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t pimd_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &pim_sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &pim_sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &pim_sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &pim_sigterm,
	},
};
