/*
 * PIM for Quagga
 * Copyright (C) 2008  Everton da Silva Marques
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
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

struct quagga_signal_t pimd_signals[] = {
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
