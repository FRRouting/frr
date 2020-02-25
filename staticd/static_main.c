/*
 * STATICd - main code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "thread.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "libfrr.h"
#include "vrf.h"
#include "nexthop.h"
#include "filter.h"

#include "static_vrf.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_zebra.h"

char backup_config_file[256];

bool mpls_enabled;

zebra_capabilities_t _caps_p[] = {
};

struct zebra_privs_t static_privs = {
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

struct option longopts[] = { { 0 } };

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

struct quagga_signal_t static_signals[] = {
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

static const struct frr_yang_module_info *const staticd_yang_modules[] = {
};

#define STATIC_VTY_PORT 2616

FRR_DAEMON_INFO(staticd, STATIC, .vty_port = STATIC_VTY_PORT,

		.proghelp = "Implementation of STATIC.",

		.signals = static_signals,
		.n_signals = array_size(static_signals),

		.privs = &static_privs, .yang_modules = staticd_yang_modules,
		.n_yang_modules = array_size(staticd_yang_modules),
)

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&staticd_di, argc, argv);
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

	access_list_init();
	static_vrf_init();

	static_zebra_init();
	static_vty_init();

	snprintf(backup_config_file, sizeof(backup_config_file),
		 "%s/zebra.conf", frr_sysconfdir);
	staticd_di.backup_config_file = backup_config_file;

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
