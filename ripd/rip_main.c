// SPDX-License-Identifier: GPL-2.0-or-later
/* RIPd main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro <kunihiro@zebra.org>
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "frrevent.h"
#include "command.h"
#include "memory.h"
#include "prefix.h"
#include "filter.h"
#include "keychain.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "if_rmap.h"
#include "libfrr.h"
#include "routemap.h"
#include "bfd.h"

#include "ripd/ripd.h"
#include "ripd/rip_bfd.h"
#include "ripd/rip_nb.h"
#include "ripd/rip_errors.h"

/* ripd options. */
static struct option longopts[] = {{0}};

/* ripd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

uint32_t zebra_ecmp_count = MULTIPATH_NUM;

struct zebra_privs_t ripd_privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

/* Master of threads. */
struct event_loop *master;

static struct frr_daemon_info ripd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, ripd_di.config_file, config_default);
}

/* SIGINT handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	bfd_protocol_integration_set_shutdown(true);
	rip_vrf_terminate();
	if_rmap_terminate();
	rip_zclient_stop();
	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

static struct frr_signal_t ripd_signals[] = {
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

static const struct frr_yang_module_info *const ripd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_ripd_info,
	&frr_route_map_info,
	&frr_vrf_info,
};

FRR_DAEMON_INFO(ripd, RIP, .vty_port = RIP_VTY_PORT,

		.proghelp = "Implementation of the RIP routing protocol.",

		.signals = ripd_signals, .n_signals = array_size(ripd_signals),

		.privs = &ripd_privs, .yang_modules = ripd_yang_modules,
		.n_yang_modules = array_size(ripd_yang_modules),
);

#define DEPRECATED_OPTIONS ""

/* Main routine of ripd. */
int main(int argc, char **argv)
{
	frr_preinit(&ripd_di, argc, argv);

	frr_opt_add("" DEPRECATED_OPTIONS, longopts, "");

	/* Command line option parse. */
	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt && opt < 128 && strchr(DEPRECATED_OPTIONS, opt)) {
			fprintf(stderr,
				"The -%c option no longer exists.\nPlease refer to the manual.\n",
				opt);
			continue;
		}

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
		}
	}

	/* Prepare master thread. */
	master = frr_init();

	/* Library initialization. */
	rip_error_init();
	keychain_init();
	rip_vrf_init();

	/* RIP related initialization. */
	rip_init();
	rip_if_init();
	rip_cli_init();
	rip_zclient_init(master);
	rip_bfd_init(master);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
