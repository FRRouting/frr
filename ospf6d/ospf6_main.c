/*
 * Copyright (C) 1999 Yasuhiro Ohara
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
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
#include <stdlib.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "memory_vty.h"
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
#include "ospf6_asbr.h"
#include "ospf6_lsa.h"
#include "ospf6_interface.h"
#include "ospf6_zebra.h"

/* Default configuration file name for ospf6d. */
#define OSPF6_DEFAULT_CONFIG       "ospf6d.conf"

/* Default port values. */
#define OSPF6_VTY_PORT             2606

/* ospf6d privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND};

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
	.cap_num_p = 2,
	.cap_num_i = 0};

/* ospf6d options, we use GNU getopt library. */
struct option longopts[] = {{0}};

/* Master of threads. */
struct thread_master *master;

static void __attribute__((noreturn)) ospf6_exit(int status)
{
	struct vrf *vrf = vrf_lookup_by_id(VRF_DEFAULT);
	struct interface *ifp;

	frr_early_fini();

	if (ospf6)
		ospf6_delete(ospf6);

	bfd_gbl_exit();

	FOR_ALL_INTERFACES (vrf, ifp)
		if (ifp->info != NULL)
			ospf6_interface_delete(ifp->info);

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

struct quagga_signal_t ospf6_signals[] = {
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

FRR_DAEMON_INFO(ospf6d, OSPF6, .vty_port = OSPF6_VTY_PORT,

		.proghelp = "Implementation of the OSPFv3 routing protocol.",

		.signals = ospf6_signals,
		.n_signals = array_size(ospf6_signals),

		.privs = &ospf6d_privs, )

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
			break;
		}
	}

	if (geteuid() != 0) {
		errno = EPERM;
		perror(ospf6d_di.progname);
		exit(1);
	}

	/* OSPF6 master init. */
	ospf6_master_init();

	/* thread master */
	master = frr_init();

	vrf_init(NULL, NULL, NULL, NULL);
	access_list_init();
	prefix_list_init();

	/* initialize ospf6 */
	ospf6_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	ospf6_exit(0);
}
