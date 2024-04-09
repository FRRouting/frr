// SPDX-License-Identifier: GPL-2.0-or-later
/* NHRP daemon main functions
 * Copyright (c) 2014-2015 Timo Teräs
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <unistd.h>

#include "zebra.h"
#include "privs.h"
#include "getopt.h"
#include "frrevent.h"
#include "sigevent.h"
#include "lib/version.h"
#include "log.h"
#include "memory.h"
#include "command.h"
#include "libfrr.h"
#include "filter.h"

#include "nhrpd.h"
#include "nhrp_errors.h"

DEFINE_MGROUP(NHRPD, "NHRP");

unsigned int debug_flags = 0;

struct event_loop *master;
struct timeval current_time;

/* nhrpd options. */
struct option longopts[] = {{0}};

/* nhrpd privileges */
static zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW, ZCAP_NET_ADMIN,
	ZCAP_DAC_OVERRIDE, /* for now needed to write to
			      /proc/sys/net/ipv4/<if>/send_redirect */
};

struct zebra_privs_t nhrpd_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0
};


static void parse_arguments(int argc, char **argv)
{
	int opt;

	while (1) {
		opt = frr_getopt(argc, argv, 0);
		if (opt < 0)
			break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
		}
	}
}

static void nhrp_sigusr1(void)
{
	zlog_rotate();
}

static void nhrp_request_stop(void)
{
	debugf(NHRP_DEBUG_COMMON, "Exiting...");
	frr_early_fini();

	nhrp_shortcut_terminate();
	nhrp_nhs_terminate();
	nhrp_zebra_terminate();
	vici_terminate();
	evmgr_terminate();
	vrf_terminate();
	nhrp_vc_terminate();

	debugf(NHRP_DEBUG_COMMON, "Done.");

	resolver_terminate();
	frr_fini();

	exit(0);
}

static struct frr_signal_t sighandlers[] = {
	{
		.signal = SIGUSR1,
		.handler = &nhrp_sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &nhrp_request_stop,
	},
	{
		.signal = SIGTERM,
		.handler = &nhrp_request_stop,
	},
};

static const struct frr_yang_module_info *const nhrpd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_vrf_info,
};

/* clang-format off */
FRR_DAEMON_INFO(nhrpd, NHRP,
	.vty_port = NHRP_VTY_PORT,
	.proghelp = "Implementation of the NHRP routing protocol.",

	.signals = sighandlers,
	.n_signals = array_size(sighandlers),

	.privs = &nhrpd_privs,

	.yang_modules = nhrpd_yang_modules,
	.n_yang_modules = array_size(nhrpd_yang_modules),
);
/* clang-format on */

int main(int argc, char **argv)
{
	frr_preinit(&nhrpd_di, argc, argv);
	frr_opt_add("", longopts, "");

	parse_arguments(argc, argv);

	/* Library inits. */
	master = frr_init();
	nhrp_error_init();
	vrf_init(NULL, NULL, NULL, NULL);
	nhrp_interface_init();
	resolver_init(master);

	/*
	 * Run with elevated capabilities, as for all netlink activity
	 * we need privileges anyway.
	 * The assert is for clang SA code where it does
	 * not see the change function being set in lib
	 */
	assert(nhrpd_privs.change);
	nhrpd_privs.change(ZPRIVS_RAISE);

	evmgr_init();
	nhrp_vc_init();
	nhrp_packet_init();
	vici_init();
	hook_register_prio(if_real, 0, nhrp_ifp_create);
	hook_register_prio(if_up, 0, nhrp_ifp_up);
	hook_register_prio(if_down, 0, nhrp_ifp_down);
	hook_register_prio(if_unreal, 0, nhrp_ifp_destroy);
	nhrp_zebra_init();
	nhrp_shortcut_init();

	nhrp_config_init();

	frr_config_fork();
	frr_run(master);
	return 0;
}
