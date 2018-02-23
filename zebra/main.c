/* zebra daemon main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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
#include "command.h"
#include "thread.h"
#include "filter.h"
#include "memory.h"
#include "zebra_memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "log.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "vrf.h"
#include "libfrr.h"

#include "zebra/rib.h"
#include "zebra/zserv.h"
#include "zebra/debug.h"
#include "zebra/router-id.h"
#include "zebra/irdp.h"
#include "zebra/rtadv.h"
#include "zebra/zebra_ptm.h"
#include "zebra/zebra_ns.h"
#include "zebra/redistribute.h"
#include "zebra/zebra_mpls.h"
#include "zebra/label_manager.h"

#define ZEBRA_PTM_SUPPORT

/* Zebra instance */
struct zebra_t zebrad = {
	.rtm_table_default = 0,
	.packets_to_process = ZEBRA_ZAPI_PACKETS_TO_PROCESS,
};

/* process id. */
pid_t pid;

/* Pacify zclient.o in libfrr, which expects this variable. */
struct thread_master *master;

/* Route retain mode flag. */
int retain_mode = 0;

/* Allow non-quagga entities to delete quagga routes */
int allow_delete = 0;

/* Don't delete kernel route. */
int keep_kernel_mode = 0;

#ifdef HAVE_NETLINK
/* Receive buffer size for netlink socket */
u_int32_t nl_rcvbufsize = 4194304;
#endif /* HAVE_NETLINK */

/* Command line options. */
struct option longopts[] = {{"batch", no_argument, NULL, 'b'},
			    {"allow_delete", no_argument, NULL, 'a'},
			    {"keep_kernel", no_argument, NULL, 'k'},
			    {"socket", required_argument, NULL, 'z'},
			    {"ecmp", required_argument, NULL, 'e'},
			    {"label_socket", no_argument, NULL, 'l'},
			    {"retain", no_argument, NULL, 'r'},
#ifdef HAVE_NETLINK
			    {"nl-bufsize", required_argument, NULL, 's'},
#endif /* HAVE_NETLINK */
			    {0}};

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN, ZCAP_NET_RAW,
};

/* zebra privileges to run with */
struct zebra_privs_t zserv_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0};

unsigned int multipath_num = MULTIPATH_NUM;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload of config file. */
	;
}

/* SIGINT handler. */
static void sigint(void)
{
	struct vrf *vrf;
	struct zebra_vrf *zvrf;
	struct zebra_ns *zns;

	zlog_notice("Terminating on signal");

	frr_early_fini();

	list_delete_all_node(zebrad.client_list);
	zebra_ptm_finish();

	if (retain_mode)
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = vrf->info;
			if (zvrf)
				SET_FLAG(zvrf->flags, ZEBRA_VRF_RETAIN);
		}
	vrf_terminate();

	zns = zebra_ns_lookup(NS_DEFAULT);
	zebra_ns_disable(0, (void **)&zns);

	access_list_reset();
	prefix_list_reset();
	route_map_finish();

	list_delete_and_null(&zebrad.client_list);
	work_queue_free(zebrad.ribq);
	if (zebrad.lsp_process_q)
		work_queue_free(zebrad.lsp_process_q);
	meta_queue_free(zebrad.mq);

	frr_fini();
	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t zebra_signals[] = {
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

FRR_DAEMON_INFO(
	zebra, ZEBRA, .vty_port = ZEBRA_VTY_PORT, .flags = FRR_NO_ZCLIENT,

	.proghelp =
		"Daemon which manages kernel routing table management "
		"and\nredistribution between different routing protocols.",

	.signals = zebra_signals, .n_signals = array_size(zebra_signals),

	.privs = &zserv_privs, )

/* Main startup routine. */
int main(int argc, char **argv)
{
	// int batch_mode = 0;
	char *zserv_path = NULL;
	/* Socket to external label manager */
	char *lblmgr_path = NULL;
	struct sockaddr_storage dummy;
	socklen_t dummylen;
#if defined(HANDLE_ZAPI_FUZZING)
	char *fuzzing = NULL;
#endif

	frr_preinit(&zebra_di, argc, argv);

	frr_opt_add(
		"bakz:e:l:r"
#ifdef HAVE_NETLINK
		"s:"
#endif
#if defined(HANDLE_ZAPI_FUZZING)
		"c:"
#endif
		,
		longopts,
		"  -b, --batch        Runs in batch mode\n"
		"  -a, --allow_delete Allow other processes to delete zebra routes\n"
		"  -z, --socket       Set path of zebra socket\n"
		"  -e, --ecmp         Specify ECMP to use.\n"
		"  -l, --label_socket Socket to external label manager\n"
		"  -k, --keep_kernel  Don't delete old routes which installed by zebra.\n"
		"  -r, --retain       When program terminates, retain added route by zebra.\n"
#ifdef HAVE_NETLINK
		"  -s, --nl-bufsize   Set netlink receive buffer size\n"
#endif /* HAVE_NETLINK */
#if defined(HANDLE_ZAPI_FUZZING)
		"  -c <file>          Bypass normal startup use this file for tetsting of zapi"
#endif
		);

	while (1) {
		int opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'b':
			// batch_mode = 1;
			break;
		case 'a':
			allow_delete = 1;
			break;
		case 'k':
			keep_kernel_mode = 1;
			break;
		case 'e':
			multipath_num = atoi(optarg);
			if (multipath_num > MULTIPATH_NUM
			    || multipath_num <= 0) {
				zlog_err(
					"Multipath Number specified must be less than %d and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			break;
		case 'z':
			zserv_path = optarg;
			if (!frr_zclient_addr(&dummy, &dummylen, optarg)) {
				fprintf(stderr,
					"Invalid zserv socket path: %s\n",
					optarg);
				exit(1);
			}
			break;
		case 'l':
			lblmgr_path = optarg;
			break;
		case 'r':
			retain_mode = 1;
			break;
#ifdef HAVE_NETLINK
		case 's':
			nl_rcvbufsize = atoi(optarg);
			break;
#endif /* HAVE_NETLINK */
#if defined(HANDLE_ZAPI_FUZZING)
		case 'c':
			fuzzing = optarg;
			break;
#endif
		default:
			frr_help_exit(1);
			break;
		}
	}

	vty_config_lockless();
	zebrad.master = frr_init();

	/* Zebra related initialize. */
	zserv_init();
	rib_init();
	zebra_if_init();
	zebra_debug_init();
	router_id_cmd_init();

	/*
	 * Initialize NS( and implicitly the VRF module), and make kernel
	 * routing socket. */
	zebra_ns_init();

	zebra_vty_init();
	access_list_init();
	prefix_list_init();
#if defined(HAVE_RTADV)
	rtadv_cmd_init();
#endif
/* PTM socket */
#ifdef ZEBRA_PTM_SUPPORT
	zebra_ptm_init();
#endif

	zebra_mpls_init();
	zebra_mpls_vty_init();
	zebra_pw_vty_init();

	/* For debug purpose. */
	/* SET_FLAG (zebra_debug_event, ZEBRA_DEBUG_EVENT); */

#if defined(HANDLE_ZAPI_FUZZING)
	if (fuzzing) {
		zserv_read_file(fuzzing);
		exit(0);
	}
#endif

	/* Process the configuration file. Among other configuration
	*  directives we can meet those installing static routes. Such
	*  requests will not be executed immediately, but queued in
	*  zebra->ribq structure until we enter the main execution loop.
	*  The notifications from kernel will show originating PID equal
	*  to that after daemon() completes (if ever called).
	*/
	frr_config_fork();

	/* Clean up rib -- before fork (?) */
	/* rib_weed_tables (); */

	/* After we have successfully acquired the pidfile, we can be sure
	*  about being the only copy of zebra process, which is submitting
	*  changes to the FIB.
	*  Clean up zebra-originated routes. The requests will be sent to OS
	*  immediately, so originating PID in notifications from kernel
	*  will be equal to the current getpid(). To know about such routes,
	* we have to have route_read() called before.
	*/
	if (!keep_kernel_mode)
		rib_sweep_route();

	/* Needed for BSD routing socket. */
	pid = getpid();

	/* This must be done only after locking pidfile (bug #403). */
	zebra_zserv_socket_init(zserv_path);

	/* Init label manager */
	label_manager_init(lblmgr_path);

	frr_run(zebrad.master);

	/* Not reached... */
	return 0;
}
