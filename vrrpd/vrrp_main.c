// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * VRRP entry point.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
 */
#include <zebra.h>

#include <getopt.h>

#include <lib/version.h>

#include "lib/command.h"
#include "lib/filter.h"
#include "lib/if.h"
#include "lib/libfrr.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/nexthop.h"
#include "lib/privs.h"
#include "lib/sigevent.h"
#include "lib/frrevent.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "vrrp.h"
#include "vrrp_debug.h"
#include "vrrp_vty.h"
#include "vrrp_zebra.h"

DEFINE_MGROUP(VRRPD, "vrrpd");

char backup_config_file[256];

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW,
};

struct zebra_privs_t vrrp_privs = {
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

struct option longopts[] = { {0} };

/* Master of threads. */
struct event_loop *master;

static struct frr_daemon_info vrrpd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");

	vty_read_config(NULL, vrrpd_di.config_file, config_default);
}

/* SIGINT / SIGTERM handler. */
static void __attribute__((noreturn)) sigint(void)
{
	zlog_notice("Terminating on signal");

	vrrp_fini();

	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t vrrp_signals[] = {
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

static const struct frr_yang_module_info *const vrrp_yang_modules[] = {
	&frr_filter_info,
	&frr_vrf_info,
	&frr_interface_info,
	&frr_vrrpd_info,
};

/* clang-format off */
FRR_DAEMON_INFO(vrrpd, VRRP,
	.vty_port = VRRP_VTY_PORT,
	.proghelp = "Virtual Router Redundancy Protocol",

	.signals = vrrp_signals,
	.n_signals = array_size(vrrp_signals),

	.privs = &vrrp_privs,

	.yang_modules = vrrp_yang_modules,
	.n_yang_modules = array_size(vrrp_yang_modules),
);
/* clang-format on */

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&vrrpd_di, argc, argv);
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
	vrrp_debug_init();
	vrrp_zebra_init();
	vrrp_vty_init();
	vrrp_init();

	snprintf(backup_config_file, sizeof(backup_config_file),
		 "%s/vrrpd.conf", frr_sysconfdir);
	vrrpd_di.backup_config_file = backup_config_file;

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
