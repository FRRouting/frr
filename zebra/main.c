// SPDX-License-Identifier: GPL-2.0-or-later
/* zebra daemon main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 */

#include <zebra.h>

#ifdef GNU_LINUX
#include <linux/rtnetlink.h>
#endif

#include <lib/version.h>
#include "getopt.h"
#include "command.h"
#include "frrevent.h"
#include "filter.h"
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "plist.h"
#include "privs.h"
#include "sigevent.h"
#include "vrf.h"
#include "libfrr.h"
#include "affinitymap.h"
#include "routemap.h"
#include "routing_nb.h"
#include "mgmt_be_client.h"
#include "libagentx.h"

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
#include "zebra/zebra_routemap.h"
#include "zebra/zebra_nb.h"
#include "zebra/zebra_opaque.h"
#include "zebra/zebra_srte.h"
#include "zebra/zebra_srv6.h"
#include "zebra/zebra_srv6_vty.h"

#define ZEBRA_PTM_SUPPORT

/* process id. */
pid_t pid;

/* Pacify zclient.o in libfrr, which expects this variable. */
struct event_loop *master;

struct mgmt_be_client *mgmt_be_client;

/* Route retain mode flag. */
int retain_mode = 0;

bool fpm_pic_nexthop = false;

/* Receive buffer size for kernel control sockets */
#define RCVBUFSIZE_MIN 4194304
#ifdef HAVE_NETLINK
uint32_t rcvbufsize = RCVBUFSIZE_MIN;
#else
uint32_t rcvbufsize = 128 * 1024;
#endif

uint32_t rt_table_main_id = RT_TABLE_MAIN;

#define OPTION_V6_RR_SEMANTICS 2000
#define OPTION_ASIC_OFFLOAD    2001
#define OPTION_V6_WITH_V4_NEXTHOP 2002

/* Command line options. */
const struct option longopts[] = { { "pic", no_argument, NULL, 'p' },
				   { "batch", no_argument, NULL, 'b' },
				   { "allow_delete", no_argument, NULL, 'a' },
				   { "socket", required_argument, NULL, 'z' },
				   { "ecmp", required_argument, NULL, 'e' },
				   { "retain", no_argument, NULL, 'r' },
				   { "asic-offload", optional_argument, NULL, OPTION_ASIC_OFFLOAD },
				   { "v6-with-v4-nexthops", no_argument, NULL,
				     OPTION_V6_WITH_V4_NEXTHOP },
#ifdef HAVE_NETLINK
				   { "vrfwnetns", no_argument, NULL, 'n' },
				   { "nl-bufsize", required_argument, NULL, 's' },
				   { "v6-rr-semantics", no_argument, NULL, OPTION_V6_RR_SEMANTICS },
#endif /* HAVE_NETLINK */
				   { "routing-table", optional_argument, NULL, 'R' },
				   { 0 } };

zebra_capabilities_t _caps_p[] = {ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN,
				  ZCAP_NET_RAW,
#ifdef HAVE_DPDK
				  ZCAP_IPC_LOCK,  ZCAP_READ_SEARCH,
				  ZCAP_SYS_RAWIO
#endif
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

	nb_oper_cancel_all_walks();
	mgmt_be_client_destroy(mgmt_be_client);
	mgmt_be_client = NULL;

	atomic_store_explicit(&zrouter.in_shutdown, true,
			      memory_order_relaxed);

	/* send RA lifetime of 0 before stopping. rfc4861/6.2.5 */
	rtadv_stop_ra_all();

	frr_early_fini();

	/* Stop the opaque module pthread */
	zebra_opaque_stop();

	zebra_dplane_pre_finish();

	/* Clean up GR related info. */
	zebra_gr_stale_client_cleanup(zrouter.stale_client_list);
	list_delete_all_node(zrouter.stale_client_list);

	/* Clean up zapi clients and server module */
	for (ALL_LIST_ELEMENTS(zrouter.client_list, ln, nn, client))
		zserv_close_client(client);

	zserv_close();
	list_delete_all_node(zrouter.client_list);

	/* Once all the zclients are cleaned up, clean up the opaque module */
	zebra_opaque_finish();

	zebra_ptm_finish();

	if (retain_mode) {
		zebra_nhg_mark_keep();
		RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
			zvrf = vrf->info;
			if (zvrf)
				SET_FLAG(zvrf->flags, ZEBRA_VRF_RETAIN);
		}
	}

	if (zrouter.lsp_process_q)
		work_queue_free_and_null(&zrouter.lsp_process_q);

	access_list_reset();
	prefix_list_reset();
	/*
	 * zebra_routemap_finish will
	 * 1 set rmap upd timer to 0 so that rmap update wont be scheduled again
	 * 2 Put off the rmap update thread
	 * 3 route_map_finish
	 */
	zebra_routemap_finish();

	rib_update_finish();

	list_delete(&zrouter.client_list);
	list_delete(&zrouter.stale_client_list);

	/*
	 * Besides other clean-ups zebra's vrf_disable() also enqueues installed
	 * routes for removal from the kernel, unless ZEBRA_VRF_RETAIN is set.
	 */
	vrf_iterate(vrf_disable);

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
void zebra_finalize(struct event *dummy)
{
	zlog_info("Zebra final shutdown");

	vrf_terminate();

	/*
	 * Stop dplane thread and finish any cleanup
	 * This is before the zebra_ns_early_shutdown call
	 * because sockets that the dplane depends on are closed
	 * in those functions
	 */
	zebra_dplane_shutdown();

	ns_walk_func(zebra_ns_early_shutdown, NULL, NULL);
	zebra_ns_notify_close();

	/* Final shutdown of ns resources */
	ns_walk_func(zebra_ns_kernel_shutdown, NULL, NULL);

	zebra_rib_terminate();
	zebra_router_terminate();

	zebra_mpls_terminate();

	zebra_pw_terminate();

	zebra_srv6_terminate();

	label_manager_terminate();

	ns_walk_func(zebra_ns_final_shutdown, NULL, NULL);

	ns_terminate();
	frr_fini();
	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t zebra_signals[] = {
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
static const struct frr_yang_module_info *const zebra_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_zebra_info,
	&frr_vrf_info,
	&frr_routing_info,
	&frr_affinity_map_info,
	&frr_zebra_route_map_info,
};
/* clang-format on */

/* clang-format off */
FRR_DAEMON_INFO(zebra, ZEBRA,
	.vty_port = ZEBRA_VTY_PORT,
	.proghelp =
		"Daemon which manages kernel routing table management and\nredistribution between different routing protocols.",

	.flags = FRR_NO_ZCLIENT,

	.signals = zebra_signals,
	.n_signals = array_size(zebra_signals),

	.privs = &zserv_privs,

	.yang_modules = zebra_yang_modules,
	.n_yang_modules = array_size(zebra_yang_modules),
);
/* clang-format on */

/* Main startup routine. */
int main(int argc, char **argv)
{
	// int batch_mode = 0;
	char *zserv_path = NULL;
	struct sockaddr_storage dummy;
	socklen_t dummylen;
	bool asic_offload = false;
	bool v6_with_v4_nexthop = false;
	bool notify_on_ack = true;

	vrf_configure_backend(VRF_BACKEND_VRF_LITE);

	frr_preinit(&zebra_di, argc, argv);

	frr_opt_add("pbaz:e:rK:s:R:"
#ifdef HAVE_NETLINK
		    "n"
#endif
		    ,
		    longopts,
		    "  -p, --pic                 Runs in pic mode\n"
		    "  -b, --batch               Runs in batch mode\n"
		    "  -a, --allow_delete        Allow other processes to delete zebra routes\n"
		    "  -z, --socket              Set path of zebra socket\n"
		    "  -e, --ecmp                Specify ECMP to use.\n"
		    "  -r, --retain              When program terminates, retain added route by zebra.\n"
		    "  -A, --asic-offload        FRR is interacting with an asic underneath the linux kernel\n"
		    "      --v6-with-v4-nexthops Underlying dataplane supports v6 routes with v4 nexthops"
#ifdef HAVE_NETLINK
		    "  -s, --nl-bufsize          Set netlink receive buffer size\n"
		    "  -n, --vrfwnetns           Use NetNS as VRF backend\n"
		    "      --v6-rr-semantics     Use v6 RR semantics\n"
#else
		    "  -s,                       Set kernel socket receive buffer size\n"
#endif /* HAVE_NETLINK */
		    "  -R, --routing-table       Set kernel routing table\n");

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
			zrouter.allow_delete = true;
			break;
		case 'e': {
			unsigned long int parsed_multipath =
				strtoul(optarg, NULL, 10);
			if (parsed_multipath == 0
			    || parsed_multipath > MULTIPATH_NUM
			    || parsed_multipath > UINT32_MAX) {
				flog_err(
					EC_ZEBRA_BAD_MULTIPATH_NUM,
					"Multipath Number specified must be less than %u and greater than 0",
					MULTIPATH_NUM);
				return 1;
			}
			zrouter.multipath_num = parsed_multipath;
			break;
		}
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
		case 's':
			rcvbufsize = atoi(optarg);
			if (rcvbufsize < RCVBUFSIZE_MIN)
				fprintf(stderr,
					"Rcvbufsize is smaller than recommended value: %d\n",
					RCVBUFSIZE_MIN);
			break;
		case 'R':
			rt_table_main_id = atoi(optarg);
			break;
#ifdef HAVE_NETLINK
		case 'n':
			vrf_configure_backend(VRF_BACKEND_NETNS);
			break;
		case OPTION_V6_RR_SEMANTICS:
			zrouter.v6_rr_semantics = true;
			break;
		case OPTION_ASIC_OFFLOAD:
			if (!strcmp(optarg, "notify_on_offload"))
				notify_on_ack = false;
			if (!strcmp(optarg, "notify_on_ack"))
				notify_on_ack = true;
			asic_offload = true;
			break;
		case OPTION_V6_WITH_V4_NEXTHOP:
			v6_with_v4_nexthop = true;
			break;
#endif /* HAVE_NETLINK */
		case 'p':
			fpm_pic_nexthop = true;
			break;

		default:
			frr_help_exit(1);
		}
	}

	zrouter.master = frr_init();

	/* Zebra related initialize. */
	libagentx_init();
	zebra_router_init(asic_offload, notify_on_ack, v6_with_v4_nexthop);
	zserv_init();
	zebra_rib_init();
	zebra_if_init();
	zebra_debug_init();

	/*
	 * Initialize NS( and implicitly the VRF module), and make kernel
	 * routing socket. */
	zebra_ns_init();
	router_id_cmd_init();
	zebra_vty_init();
	mgmt_be_client = mgmt_be_client_create("zebra", NULL, 0,
					       zrouter.master);
	access_list_init_new(true);
	prefix_list_init();

	rtadv_init();
	rtadv_cmd_init();
/* PTM socket */
#ifdef ZEBRA_PTM_SUPPORT
	zebra_ptm_init();
#endif

	zebra_mpls_init();
	zebra_mpls_vty_init();
	zebra_pw_vty_init();
	zebra_pbr_init();
	zebra_opaque_init();
	zebra_srte_init();
	zebra_srv6_init();
	zebra_srv6_vty_init();

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
	*  we have to have route_read() called before.
	*  If FRR is gracefully restarting, we either wait for clients
	*  (e.g., BGP) to signal GR is complete else we wait for specified
	*  duration.
	*/
	zrouter.startup_time = monotime(NULL);
	zrouter.rib_sweep_time = 0;
	zrouter.graceful_restart = zebra_di.graceful_restart;
	if (!zrouter.graceful_restart)
		event_add_timer(zrouter.master, rib_sweep_route, NULL, 0, NULL);
	else {
		int gr_cleanup_time;

		gr_cleanup_time = zebra_di.gr_cleanup_time
					  ? zebra_di.gr_cleanup_time
					  : ZEBRA_GR_DEFAULT_RIB_SWEEP_TIME;
		event_add_timer(zrouter.master, rib_sweep_route, NULL,
				gr_cleanup_time, &zrouter.t_rib_sweep);
	}

	/* Needed for BSD routing socket. */
	pid = getpid();

	/* Start dataplane system */
	zebra_dplane_start();

	/* Start the ted module, before zserv */
	zebra_opaque_start();

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

	frr_run(zrouter.master);

	/* Not reached... */
	return 0;
}
