// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2020  NetDEF, Inc.
 */
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "frrevent.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "libfrr.h"
#include "vrf.h"
#include "filter.h"

#include "pathd.h"
#include "path_nb.h"
#include "path_zebra.h"
#include "path_errors.h"
#include "path_ted.h"

char backup_config_file[256];

zebra_capabilities_t _caps_p[] = {};

struct zebra_privs_t pathd_privs = {
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
struct event_loop *master;

static struct frr_daemon_info pathd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, pathd_di.config_file, config_default);
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");
	zlog_notice("Unregisterfrom opaque,etc ");
	pathd_shutdown();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t path_signals[] = {
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

static const struct frr_yang_module_info *pathd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_pathd_info,
};

/* clang-format off */
FRR_DAEMON_INFO(pathd, PATH,
	.vty_port = PATH_VTY_PORT,
	.proghelp = "Implementation of PATH.",

	.signals = path_signals,
	.n_signals = array_size(path_signals),

	.privs = &pathd_privs,

	.yang_modules = pathd_yang_modules,
	.n_yang_modules = array_size(pathd_yang_modules),
);
/* clang-format on */

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&pathd_di, argc, argv);
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

	access_list_init();

	path_error_init();
	path_zebra_init(master);
	path_cli_init();
	path_ted_init(master);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
