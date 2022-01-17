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
#include "nexthop_group.h"
#include "link_state.h"

#include "sharp_zebra.h"
#include "sharp_vty.h"
#include "sharp_globals.h"
#include "sharp_nht.h"

DEFINE_MGROUP(SHARPD, "sharpd");

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

	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t sharp_signals[] = {
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

static const struct frr_yang_module_info *const sharpd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
};

FRR_DAEMON_INFO(sharpd, SHARP, .vty_port = SHARP_VTY_PORT,

		.proghelp = "Implementation of a Sharp of routes daemon.",

		.signals = sharp_signals,
		.n_signals = array_size(sharp_signals),

		.privs = &sharp_privs, .yang_modules = sharpd_yang_modules,
		.n_yang_modules = array_size(sharpd_yang_modules),
);

struct sharp_global sg;

static void sharp_global_init(void)
{
	memset(&sg, 0, sizeof(sg));
	sg.nhs = list_new();
	sg.ted = NULL;
	sg.srv6_locators = list_new();
}

static void sharp_start_configuration(void)
{
	zlog_debug("Configuration has started to be read");
}

static void sharp_end_configuration(void)
{
	zlog_debug("Configuration has finished being read");
}

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
		}
	}

	master = frr_init();

	cmd_init_config_callbacks(sharp_start_configuration,
				  sharp_end_configuration);
	sharp_global_init();

	sharp_nhgroup_init();
	vrf_init(NULL, NULL, NULL, NULL);

	sharp_zebra_init();

	/* Get configuration file. */
	sharp_vty_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
