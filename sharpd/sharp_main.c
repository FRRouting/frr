/*
 * SHARP - main code
 * Copyright (C) Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * This file is part of FRR.
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "keychain.h"
#include "distribute.h"
#include "libfrr.h"
#include "routemap.h"

#include "sharp_zebra.h"
#include "sharp_vty.h"

uint32_t total_routes = 0;
uint32_t installed_routes = 0;
uint32_t removed_routes = 0;

zebra_capabilities_t _caps_p[] = {
};

struct zebra_privs_t sharp_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

struct option longopts[] = {{0}};

/* Master of threads. */
struct thread_master *master;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t sharp_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigint,
	},
};

#define SHARP_VTY_PORT 2614

FRR_DAEMON_INFO(sharpd, SHARP, .vty_port = SHARP_VTY_PORT,

		.proghelp = "Implementation of a Sharp of routes daemon.",

		.signals = sharp_signals,
		.n_signals = array_size(sharp_signals),

		.privs = &sharp_privs, )

extern void sharp_vty_init(void);

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&sharpd_di, argc, argv);
	frr_opt_add("", longopts, "");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}

	master = frr_init();

	vrf_init(NULL, NULL, NULL, NULL);

	route_map_init();

	sharp_zebra_init();

	/* Get configuration file. */
	sharp_vty_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
