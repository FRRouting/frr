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
#include "routemap.h"

#include "zebra/zebra_router.h"
#include "zebra/zebra_errors.h"
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
#include "zebra/zebra_netns_notify.h"
#include "zebra/zebra_rnh.h"
#include "zebra/zebra_pbr.h"
#include "zebra/zebra_vxlan.h"

#if defined(HANDLE_NETLINK_FUZZING)
#include "zebra/kernel_netlink.h"
#endif /* HANDLE_NETLINK_FUZZING */

#define ZEBRA_PTM_SUPPORT

/* process id. */
pid_t pid;

/* Pacify zclient.o in libfrr, which expects this variable. */
struct thread_master *master;

/* Route retain mode flag. */
int retain_mode = 0;

/* Allow non-quagga entities to delete quagga routes */
int allow_delete = 0;

int graceful_restart;

bool v6_rr_semantics = false;

#ifdef HAVE_NETLINK
/* Receive buffer size for netlink socket */
uint32_t nl_rcvbufsize = 4194304;
#endif /* HAVE_NETLINK */

#define OPTION_V6_RR_SEMANTICS 2000
/* Command line options. */
struct option longopts[] = {
	{"batch", no_argument, NULL, 'b'},
	{"allow_delete", no_argument, NULL, 'a'},
	{"keep_kernel", no_argument, NULL, 'k'},
	{"socket", required_argument, NULL, 'z'},
	{"ecmp", required_argument, NULL, 'e'},
	{"retain", no_argument, NULL, 'r'},
	{"vrfdefaultname", required_argument, NULL, 'o'},
	{"graceful_restart", required_argument, NULL, 'K'},
#ifdef HAVE_NETLINK
	{"vrfwnetns", no_argument, NULL, 'n'},
	{"nl-bufsize", required_argument, NULL, 's'},
	{"v6-rr-semantics", no_argument, NULL, OPTION_V6_RR_SEMANTICS},
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
	struct listnode *ln, *nn;
	struct zserv *client;
	static bool sigint_done;

	if (sigint_done)
		return;

	sigint_done = true;

	zlog_notice("Terminating on signal");

	atomic_store_explicit(&zrouter.in_shutdown, true,
			      memory_order_relaxed);

	frr_early_fini();

	zebra_dplane_pre_finish();

	for (ALL_LIST_ELEMENTS(zrouter.client_list, ln, nn, client))
		zserv_close_client(client);

	zserv_close();
	list_delete_all_node(zrouter.client_list);

	zebra_ptm_finish();

	if (retain_mode)
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = vrf->info;
			if (zvrf)
				SET_FLAG(zvrf->flags, ZEBRA_VRF_RETAIN);
		}
	if (zrouter.lsp_process_q)
		work_queue_free_and_null(&zrouter.lsp_process_q);

	vrf_terminate();

	ns_walk_func(zebra_ns_early_shutdown);
	zebra_ns_notify_close();

	access_list_reset();
	prefix_list_reset();
	route_map_finish();

	list_delete(&zrouter.client_list);

	/* Indicate that all new dplane work has been enqueued. When that
	 * work is complete, the dataplane will enqueue an event
	 * with the 'finalize' function.
	 */
	zebra_dplane_finish();
}

/*
 * Final shutdown step for the zebra main thread. This is run after all
 * async update processing has completed.
 */
int zebra_finalize(struct thread *dummy)
{
	zlog_info("Zebra final shutdown");

	/* Final shutdown of ns resources */
	ns_walk_func(zebra_ns_final_shutdown);

	/* Stop dplane thread and finish any cleanup */
	zebra_dplane_shutdown();

	zebra_router_terminate();

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

static const struct frr_yang_module_info *zebra_yang_modules[] = {
	&frr_interface_info,
};

FRR_DAEMON_INFO(
	zebra, ZEBRA, .vty_port = ZEBRA_VTY_PORT, .flags = FRR_NO_ZCLIENT,

	.proghelp =
		"Daemon which manages kernel routing table management "
		"and\nredistribution between different routing protocols.",

	.signals = zebra_signals, .n_signals = array_size(zebra_signals),

	.privs = &zserv_privs,

	.yang_modules = zebra_yang_modules,
	.n_yang_modules = array_size(zebra_yang_modules), )

/* Main startup routine. */
int main(int argc, char **argv)
{
	// int batch_mode = 0;
	char *zserv_path = NULL;
	char *vrf_default_name_configured = NULL;
	struct sockaddr_storage dummy;
	socklen_t dummylen;
#if defined(HANDLE_ZAPI_FUZZING)
	char *zapi_fuzzing = NULL;
#endif /* HANDLE_ZAPI_FUZZING */
#if defined(HANDLE_NETLINK_FUZZING)
	char *netlink_fuzzing = NULL;
#endif /* HANDLE_NETLINK_FUZZING */

	graceful_restart = 0;
	vrf_configure_backend(VRF_BACKEND_VRF_LITE);

	frr_preinit(&zebra_di, argc, argv);

	frr_opt_add(
		"baz:e:o:rK:"
#ifdef HAVE_NETLINK
		"s:n"
#endif
#if defined(HANDLE_ZAPI_FUZZING)
		"c:"
#endif /* HANDLE_ZAPI_FUZZING */
#if defined(HANDLE_NETLINK_FUZZING)
		"w:"
#endif /* HANDLE_NETLINK_FUZZING */
		,
		longopts,
		"  -b, --batch              Runs in batch mode\n"
		"  -a, --allow_delete       Allow other processes to delete zebra routes\n"
		"  -z, --socket             Set path of zebra socket\n"
		"  -e, --ecmp               Specify ECMP to use.\n"
		"  -r, --retain             When program terminates, retain added route by zebra.\n"
		"  -o, --vrfdefaultname     Set default VRF name.\n"
		"  -K, --graceful_restart   Graceful restart at the kernel level, timer in seconds for expiration\n"
#ifdef HAVE_NETLINK
		"  -n, --vrfwnetns          Use NetNS as VRF backend\n"
		"  -s, --nl-bufsize         Set netlink receive buffer size\n"
		"      --v6-rr-semantics    Use v6 RR semantics\n"
#endif /* HAVE_NETLINK */
#if defined(HANDLE_ZAPI_FUZZING)
		"  -c <file>                Bypass normal startup and use this file for testing of zapi\n"
#endif /* HANDLE_ZAPI_FUZZING */
#if defined(HANDLE_NETLINK_FUZZING)
		"  -w <file>                Bypass normal startup and use this file for testing of netlink input\n"
#endif /* HANDLE_NETLINK_FUZZING */
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
		case 'e':
			zrouter.multipath_num = atoi(optarg);
			if (zrouter.multipath_num > MULTIPATH_NUM
			    || zrouter.multipath_num <= 0) {
				flog_err(
					EC_ZEBRA_BAD_MULTIPATH_NUM,
					"Multipath Number specified must be less than %d and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			break;
		case 'o':
			vrf_default_name_configured = optarg;
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
		case 'r':
			retain_mode = 1;
			break;
		case 'K':
			graceful_restart = atoi(optarg);
			break;
#ifdef HAVE_NETLINK
		case 's':
			nl_rcvbufsize = atoi(optarg);
			break;
		case 'n':
			vrf_configure_backend(VRF_BACKEND_NETNS);
			break;
		case OPTION_V6_RR_SEMANTICS:
			v6_rr_semantics = true;
			break;
#endif /* HAVE_NETLINK */
#if defined(HANDLE_ZAPI_FUZZING)
		case 'c':
			zapi_fuzzing = optarg;
			break;
#endif /* HANDLE_ZAPI_FUZZING */
#if defined(HANDLE_NETLINK_FUZZING)
		case 'w':
			netlink_fuzzing = optarg;
			/* This ensures we are aren't writing any of the
			 * startup netlink messages that happen when we
			 * just want to read.
			 */
			netlink_read = true;
			break;
#endif /* HANDLE_NETLINK_FUZZING */
		default:
			frr_help_exit(1);
			break;
		}
	}

	zrouter.master = frr_init();

	/* Zebra related initialize. */
	zebra_router_init();
	zserv_init();
	rib_init();
	zebra_if_init();
	zebra_debug_init();
	router_id_cmd_init();

	/*
	 * Initialize NS( and implicitly the VRF module), and make kernel
	 * routing socket. */
	zebra_ns_init((const char *)vrf_default_name_configured);
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
	zebra_pbr_init();

/* For debug purpose. */
/* SET_FLAG (zebra_debug_event, ZEBRA_DEBUG_EVENT); */

	/* Process the configuration file. Among other configuration
	*  directives we can meet those installing static routes. Such
	*  requests will not be executed immediately, but queued in
	*  zebra->ribq structure until we enter the main execution loop.
	*  The notifications from kernel will show originating PID equal
	*  to that after daemon() completes (if ever called).
	*/
	frr_config_fork();

	/* After we have successfully acquired the pidfile, we can be sure
	*  about being the only copy of zebra process, which is submitting
	*  changes to the FIB.
	*  Clean up zebra-originated routes. The requests will be sent to OS
	*  immediately, so originating PID in notifications from kernel
	*  will be equal to the current getpid(). To know about such routes,
	* we have to have route_read() called before.
	*/
	zrouter.startup_time = monotime(NULL);
	thread_add_timer(zrouter.master, rib_sweep_route,
			 NULL, graceful_restart, NULL);

	/* Needed for BSD routing socket. */
	pid = getpid();

	/* Start dataplane system */
	zebra_dplane_start();

	/* Start Zebra API server */
	zserv_start(zserv_path);

	/* Init label manager */
	label_manager_init();

	/* RNH init */
	zebra_rnh_init();

	/* Config handler Init */
	zebra_evpn_init();

	/* Error init */
	zebra_error_init();

#if defined(HANDLE_ZAPI_FUZZING)
	if (zapi_fuzzing) {
		zserv_read_file(zapi_fuzzing);
		exit(0);
	}
#endif /* HANDLE_ZAPI_FUZZING */
#if defined(HANDLE_NETLINK_FUZZING)
	if (netlink_fuzzing) {
		netlink_read_init(netlink_fuzzing);
		exit(0);
	}
#endif /* HANDLE_NETLINK_FUZZING */


	frr_run(zrouter.master);

	/* Not reached... */
	return 0;
}
