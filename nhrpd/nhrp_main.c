/* NHRP daemon main functions
 * Copyright (c) 2014-2015 Timo Teräs
 *
 * This file is free software: you may copy, redistribute and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 */

#include <unistd.h>

#include "zebra.h"
#include "privs.h"
#include "getopt.h"
#include "thread.h"
#include "sigevent.h"
#include "version.h"
#include "log.h"
#include "memory.h"
#include "memory_vty.h"
#include "command.h"
#include "libfrr.h"

#include "nhrpd.h"
#include "netlink.h"

DEFINE_MGROUP(NHRPD, "NHRP")

unsigned int debug_flags = 0;

struct thread_master *master;
struct timeval current_time;

/* nhrpd options. */
struct option longopts[] = {
	{ 0 }
};

/* nhrpd privileges */
static zebra_capabilities_t _caps_p [] = {
	ZCAP_NET_RAW,
	ZCAP_NET_ADMIN,
	ZCAP_DAC_OVERRIDE,	/* for now needed to write to /proc/sys/net/ipv4/<if>/send_redirect */
};

static struct zebra_privs_t nhrpd_privs = {
#ifdef QUAGGA_USER
	.user = QUAGGA_USER,
#endif
#ifdef QUAGGA_GROUP
	.group = QUAGGA_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = ZEBRA_NUM_OF(_caps_p),
};

static void parse_arguments(int argc, char **argv)
{
	int opt;

	while (1) {
		opt = frr_getopt(argc, argv, 0);
		if(opt < 0) break;

		switch (opt) {
		case 0:
			break;
		default:
			frr_help_exit(1);
			break;
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

	nhrp_shortcut_terminate();
	nhrp_nhs_terminate();
	nhrp_zebra_terminate();
	vici_terminate();
	evmgr_terminate();
	nhrp_vc_terminate();
	vrf_terminate();
	/* memory_terminate(); */
	/* vty_terminate(); */
	cmd_terminate();
	/* signal_terminate(); */
	zprivs_terminate(&nhrpd_privs);

	debugf(NHRP_DEBUG_COMMON, "Done.");

	closezlog();

	exit(0);
}

static struct quagga_signal_t sighandlers[] = {
	{ .signal = SIGUSR1, .handler = &nhrp_sigusr1, },
	{ .signal = SIGINT,  .handler = &nhrp_request_stop, },
	{ .signal = SIGTERM, .handler = &nhrp_request_stop, },
};

FRR_DAEMON_INFO(nhrpd, NHRP,
	.vty_port = NHRP_VTY_PORT,

	.proghelp = "Implementation of the NHRP routing protocol.",

	.signals = sighandlers,
	.n_signals = array_size(sighandlers),

	.privs = &nhrpd_privs,
)

int main(int argc, char **argv)
{
	frr_preinit(&nhrpd_di, argc, argv);
	frr_opt_add("", longopts, "");

	parse_arguments(argc, argv);

	/* Library inits. */
	master = frr_init();
	nhrp_interface_init();
	vrf_init();
	resolver_init();

	/* Run with elevated capabilities, as for all netlink activity
	 * we need privileges anyway. */
	nhrpd_privs.change(ZPRIVS_RAISE);

	netlink_init();
	evmgr_init();
	nhrp_vc_init();
	nhrp_packet_init();
	vici_init();
	nhrp_zebra_init();
	nhrp_shortcut_init();

	nhrp_config_init();

	frr_config_fork();
	frr_run(master);
	return 0;
}
