// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Dhcpgw - main code
 * Copyright (C) 2025 VyOS Inc.
 * Kyrylo Yatsenko
 */
/*
 * Dhcpgw daemon - static routes via DHCP gateway
 *
 * dhcpgw_routes - tracking routes, adding/removing routes
 * dhcpgw_state - saving/reading state of DHCP gateways - is it up/down, it's
 *                IP address
 * dhcpgw_vty - command line interface
 * sample-*-hook.in - sample hooks for DHCP clients to call update-dhcp-gw
 * update_dhcp_gw - single interface for DHCP clients to save latest DHCP
 *                  gateway state
 */
#include <zebra.h>

#include <lib/version.h>
#include "log.h"

#include "dhcpgw_vty.h"
#include "dhcpgw_debug.h"
#include "dhcpgw_routes.h"

#include "mgmt_be_client.h"

zebra_capabilities_t _caps_p[] = {};

struct zebra_privs_t dhcpgw_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#if defined(VTY_GROUP)
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};

struct option longopts[] = { { 0 } };

/* Master of threads. */
struct event_loop *master;

static struct mgmt_be_client *mgmt_be_client;

static struct frr_daemon_info dhcpgwd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received and ignored");
}

/* SIGINT / SIGTERM handler. */
static FRR_NORETURN void sigint(void)
{
	zlog_notice("Terminating on signal");

	mgmt_be_client_destroy(mgmt_be_client);

	dhcpgw_routes_close();

	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t dhcpgw_signals[] = {
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

/* clang-format off */
static const struct frr_yang_module_info *const dhcpgwd_yang_modules[] = {
	&frr_interface_info,
};
/* clang-format on */

/*
 * NOTE: .flags == FRR_NO_SPLIT_CONFIG to avoid reading split config, mgmtd will
 * do this for us now
 */
/* clang-format off */
FRR_DAEMON_INFO(dhcpgwd, DHCPGW,
	.vty_port = DHCPGW_VTY_PORT,
	.proghelp = "Implementation of DHCPGW.",

	.signals = dhcpgw_signals,
	.n_signals = array_size(dhcpgw_signals),

	.privs = &dhcpgw_privs,

	.yang_modules = dhcpgwd_yang_modules,
	.n_yang_modules = array_size(dhcpgwd_yang_modules),

	.flags = FRR_NO_SPLIT_CONFIG | FRR_MGMTD_BACKEND,
);
/* clang-format on */

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&dhcpgwd_di, argc, argv);
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

	dhcpgw_debug_init();

	dhcpgw_vty_init();

	dhcpgw_routes_init(master);

	/* Initialize MGMT backend functionalities */
	mgmt_be_client = mgmt_be_client_create("dhcpgwd", NULL, 0, master);

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
