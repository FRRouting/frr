/*
 * EIGRP Main Routine.
 * Copyright (C) 2013-2015
 * Authors:
 *   Donnie Savage
 *   Jan Janovic
 *   Matej Perina
 *   Peter Orsag
 *   Peter Paluch
 *   Frantisek Gazo
 *   Tomas Hvorkovy
 *   Martin Kontsek
 *   Lukas Koribsky
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
#include "getopt.h"
#include "thread.h"
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "keychain.h"
#include "distribute.h"
#include "libfrr.h"
#include "routemap.h"
//#include "if_rmap.h"

#include "eigrpd/eigrp_structs.h"
#include "eigrpd/eigrpd.h"
#include "eigrpd/eigrp_dump.h"
#include "eigrpd/eigrp_interface.h"
#include "eigrpd/eigrp_neighbor.h"
#include "eigrpd/eigrp_packet.h"
#include "eigrpd/eigrp_vty.h"
#include "eigrpd/eigrp_zebra.h"
#include "eigrpd/eigrp_network.h"
#include "eigrpd/eigrp_snmp.h"
#include "eigrpd/eigrp_filter.h"
//#include "eigrpd/eigrp_routemap.h"

/* eigprd privileges */
zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW, ZCAP_BIND, ZCAP_NET_ADMIN,
};

struct zebra_privs_t eigrpd_privs = {
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

/* EIGRPd options. */
struct option longopts[] = {{0}};

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
	eigrp_terminate();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t eigrp_signals[] = {
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

FRR_DAEMON_INFO(eigrpd, EIGRP, .vty_port = EIGRP_VTY_PORT,

		.proghelp = "Implementation of the EIGRP routing protocol.",

		.signals = eigrp_signals,
		.n_signals = array_size(eigrp_signals),

		.privs = &eigrpd_privs, )

/* EIGRPd main routine. */
int main(int argc, char **argv, char **envp)
{
	frr_preinit(&eigrpd_di, argc, argv);
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

	eigrp_sw_version_initialize();

	/* EIGRP master init. */
	eigrp_master_init();
	eigrp_om->master = frr_init();
	master = eigrp_om->master;

	vrf_init(NULL, NULL, NULL, NULL);

	/*EIGRPd init*/
	eigrp_if_init();
	eigrp_zebra_init();
	eigrp_debug_init();

	/* Get configuration file. */
	/* EIGRP VTY inits */
	eigrp_vty_init();
	keychain_init();
	eigrp_vty_show_init();
	eigrp_vty_if_init();

#ifdef HAVE_SNMP
	eigrp_snmp_init();
#endif /* HAVE_SNMP */

	/* Access list install. */
	access_list_init();
	access_list_add_hook(eigrp_distribute_update_all_wrapper);
	access_list_delete_hook(eigrp_distribute_update_all_wrapper);

	/* Prefix list initialize.*/
	prefix_list_init();
	prefix_list_add_hook(eigrp_distribute_update_all);
	prefix_list_delete_hook(eigrp_distribute_update_all);

	/*
	 * XXX: This is just to get the CLI installed to suppress VTYSH errors.
	 * Routemaps in EIGRP are not yet functional.
	 */
	route_map_init();
	/*eigrp_route_map_init();
	  route_map_add_hook (eigrp_rmap_update);
	  route_map_delete_hook (eigrp_rmap_update);*/
	/*if_rmap_init (EIGRP_NODE);
	  if_rmap_hook_add (eigrp_if_rmap_update);
	  if_rmap_hook_delete (eigrp_if_rmap_update);*/

	/* Distribute list install. */
	distribute_list_init(EIGRP_NODE);
	distribute_list_add_hook(eigrp_distribute_update);
	distribute_list_delete_hook(eigrp_distribute_update);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return (0);
}
