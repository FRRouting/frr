// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - main code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
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
#include "nexthop.h"
#include "filter.h"
#include "routing_nb.h"

#include "static_vrf.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_debug.h"
#include "static_nb.h"

#include "mgmt_be_client.h"

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
struct event_loop *master;

static struct mgmt_be_client *mgmt_be_client;

static struct frr_daemon_info staticd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received and ignored");
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	/* Disable BFD events to avoid wasting processing. */
	bfd_protocol_integration_set_shutdown(true);

	mgmt_be_client_destroy(mgmt_be_client);

	static_vrf_terminate();

	static_zebra_stop();
	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t static_signals[] = {
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
	&frr_interface_info,
	&frr_vrf_info,
	&frr_routing_info,
	&frr_staticd_info,
};

/*
 * NOTE: .flags == FRR_NO_SPLIT_CONFIG to avoid reading split config, mgmtd will
 * do this for us now
 */
/* clang-format off */
FRR_DAEMON_INFO(staticd, STATIC,
	.vty_port = STATIC_VTY_PORT,
	.proghelp = "Implementation of STATIC.",

	.signals = static_signals,
	.n_signals = array_size(static_signals),

	.privs = &static_privs,

	.yang_modules = staticd_yang_modules,
	.n_yang_modules = array_size(staticd_yang_modules),

	.flags = FRR_NO_SPLIT_CONFIG,
);
/* clang-format on */

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
		}
	}

	master = frr_init();

	static_debug_init();
	static_vrf_init();

	static_zebra_init();
	static_vty_init();

	/* Initialize MGMT backend functionalities */
	mgmt_be_client = mgmt_be_client_create("staticd", NULL, 0, master);

	hook_register(routing_conf_event,
		      routing_control_plane_protocols_name_validate);
	hook_register(routing_create,
		      routing_control_plane_protocols_staticd_create);
	hook_register(routing_destroy,
		      routing_control_plane_protocols_staticd_destroy);

	/*
	 * We set FRR_NO_SPLIT_CONFIG flag to avoid reading our config, but we
	 * still need to write one if vtysh tells us to. Setting the host
	 * config filename does this.
	 */
	host_config_set(config_default);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
