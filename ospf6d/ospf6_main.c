// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 1999 Yasuhiro Ohara
 */

#include <zebra.h>
#include <lib/version.h>
#include <lib/keychain.h>
#include <stdlib.h>

#include "getopt.h"
#include "frrevent.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "if.h"
#include "filter.h"
#include "prefix.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "bfd.h"
#include "libfrr.h"

#include "ospf6d.h"
#include "ospf6_top.h"
#include "ospf6_message.h"
#include "ospf6_network.h"
#include "ospf6_asbr.h"
#include "ospf6_lsa.h"
#include "ospf6_interface.h"
#include "ospf6_zebra.h"
#include "ospf6_routemap_nb.h"

/* Default configuration file name for ospf6d. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606

/* ospf6d privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

struct zebra_privs_t ospf6d_privs = {
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

/* ospf6d options, we use GNU getopt library. */
struct option longopts[] = {{0}};

/* Master of threads. */
struct event_loop *master;

static void __attribute__((noreturn)) ospf6_exit(int status)
{
	struct vrf *vrf;
	struct interface *ifp;
	struct ospf6 *ospf6;
	struct listnode *node, *nnode;

	frr_early_fini();

	bfd_protocol_integration_set_shutdown(true);

	for (ALL_LIST_ELEMENTS(om6->ospf6, node, nnode, ospf6)) {
		vrf = vrf_lookup_by_id(ospf6->vrf_id);
		ospf6_delete(ospf6);
		ospf6 = NULL;
		FOR_ALL_INTERFACES (vrf, ifp)
			if (ifp->info != NULL)
				ospf6_interface_delete(ifp->info);
	}

	ospf6_message_terminate();
	ospf6_asbr_terminate();
	ospf6_lsa_terminate();

	/* reverse access_list_init */
	access_list_reset();

	/* reverse prefix_list_init */
	prefix_list_add_hook(NULL);
	prefix_list_delete_hook(NULL);
	prefix_list_reset();

	vrf_terminate();

	if (zclient) {
		zclient_stop(zclient);
		zclient_free(zclient);
	}

	frr_fini();
	exit(status);
}

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}

/* SIGINT handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal SIGINT");
	ospf6_exit(0);
}

/* SIGTERM handler. */
static void sigterm(void)
{
	zlog_notice("Terminating on signal SIGTERM");
	ospf6_exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_info("SIGUSR1 received");
	zlog_rotate();
}

struct frr_signal_t ospf6_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &sighup,
	},
	{
		.signal = SIGINT,
		.handler = &sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &sigterm,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1,
	},
};

static const struct frr_yang_module_info *const ospf6d_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
	&frr_ospf_route_map_info,
	&frr_ospf6_route_map_info,
};

FRR_DAEMON_INFO(ospf6d, OSPF6, .vty_port = OSPF6_VTY_PORT,

		.proghelp = "Implementation of the OSPFv3 routing protocol.",

		.signals = ospf6_signals,
		.n_signals = array_size(ospf6_signals),

		.privs = &ospf6d_privs, .yang_modules = ospf6d_yang_modules,
		.n_yang_modules = array_size(ospf6d_yang_modules),
);

/* Main routine of ospf6d. Treatment of argument and starting ospf finite
   state machine is handled here. */
int main(int argc, char *argv[], char *envp[])
{
	int opt;

	frr_preinit(&ospf6d_di, argc, argv);
	frr_opt_add("", longopts, "");

	/* Command line argument treatment. */
	while (1) {
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

	if (geteuid() != 0) {
		errno = EPERM;
		perror(ospf6d_di.progname);
		exit(1);
	}

	/* OSPF6 master init. */
	ospf6_master_init(frr_init());

	/* thread master */
	master = om6->master;

	keychain_init();
	ospf6_vrf_init();
	access_list_init();
	prefix_list_init();

	/* initialize ospf6 */
	ospf6_init(master);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	ospf6_exit(0);
}
