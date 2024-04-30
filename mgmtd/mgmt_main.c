// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Main routine of mgmt.
 *
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 */

#include <zebra.h>
#include "lib/version.h"
#include "routemap.h"
#include "filter.h"
#include "libfrr.h"
#include "frr_pthread.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_ds.h"
#include "ripd/rip_nb.h"
#include "ripngd/ripng_nb.h"
#include "routing_nb.h"
#include "affinitymap.h"
#include "zebra/zebra_cli.h"

/* mgmt options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"skip_runas", no_argument, NULL, 'S'},
	{"no_zebra", no_argument, NULL, 'Z'},
	{"socket_size", required_argument, NULL, 's'},
	{"vrfwnetns", no_argument, NULL, 'n'},
	{0}};

static void mgmt_exit(int);

/* privileges */
static zebra_capabilities_t _caps_p[] = {ZCAP_BIND, ZCAP_NET_RAW,
					 ZCAP_NET_ADMIN, ZCAP_SYS_ADMIN};

struct zebra_privs_t mgmt_privs = {
#if defined(FRR_USER) && defined(FRR_GROUP)
	.user = FRR_USER,
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = _caps_p,
	.cap_num_p = array_size(_caps_p),
	.cap_num_i = 0,
};

static struct frr_daemon_info mgmtd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received, ignoring");

	return;

	/*
	 * This is turned off for the moment.  There is all
	 * sorts of config turned off by mgmt_terminate
	 * that is not setup properly again in mgmt_reset.
	 * I see no easy way to do this nor do I see that
	 * this is a desirable way to reload config
	 * given the yang work.
	 */
	/* Terminate all thread. */
	mgmt_terminate();

	/*
	 * mgmt_reset();
	 */
	zlog_info("MGMTD restarting!");

	/*
	 * Reload config file.
	 * vty_read_config(NULL, mgmtd_di.config_file, config_default);
	 */
	/* Try to return to normal operation. */
}

/* SIGINT handler. */
static __attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");
	assert(mm->terminating == false);
	mm->terminating = true; /* global flag that shutting down */

	mgmt_terminate();

	mgmt_exit(0);

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

/*
 * Try to free up allocations we know about so that diagnostic tools such as
 * valgrind are able to better illuminate leaks.
 *
 * Zebra route removal and protocol teardown are not meant to be done here.
 * For example, "retain_mode" may be set.
 */
static __attribute__((__noreturn__)) void mgmt_exit(int status)
{
	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

	/* stop pthreads (if any) */
	frr_pthread_stop_all();

	frr_fini();
	exit(status);
}

static struct frr_signal_t mgmt_signals[] = {
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

#ifdef HAVE_STATICD
extern const struct frr_yang_module_info frr_staticd_cli_info;
#endif

/*
 * These are modules that are only needed by mgmtd and hence not included into
 * the lib and backend daemons.
 */
const struct frr_yang_module_info ietf_netconf_with_defaults_info = {
	.name = "ietf-netconf-with-defaults",
	.ignore_cfg_cbs = true,
	.nodes = { { .xpath = NULL } },
};

/*
 * These are stub info structs that are used to load the modules used by backend
 * clients into mgmtd. The modules are used by libyang in order to support
 * parsing binary data returns from the backend.
 */
const struct frr_yang_module_info zebra_route_map_info = {
	.name = "frr-zebra-route-map",
	.ignore_cfg_cbs = true,
	.nodes = { { .xpath = NULL } },
};

/*
 * List of YANG modules to be loaded in the process context of
 * MGMTd.
 */
static const struct frr_yang_module_info *const mgmt_yang_modules[] = {
	&frr_filter_cli_info,
	&frr_interface_cli_info,
	&frr_route_map_cli_info,
	&frr_routing_cli_info,
	&frr_vrf_cli_info,
	&frr_affinity_map_cli_info,

	/* mgmtd-only modules */
	&ietf_netconf_with_defaults_info,

	/*
	 * YANG module info used by backend clients get added here.
	 */

	&frr_zebra_cli_info,
	&zebra_route_map_info,

#ifdef HAVE_RIPD
	&frr_ripd_cli_info,
#endif
#ifdef HAVE_RIPNGD
	&frr_ripngd_cli_info,
#endif
#ifdef HAVE_STATICD
	&frr_staticd_cli_info,
#endif
};

/* clang-format off */
FRR_DAEMON_INFO(mgmtd, MGMTD,
	.vty_port = MGMTD_VTY_PORT,
	.proghelp = "FRR Management Daemon.",

	.signals = mgmt_signals,
	.n_signals = array_size(mgmt_signals),

	.privs = &mgmt_privs,

	.yang_modules = mgmt_yang_modules,
	.n_yang_modules = array_size(mgmt_yang_modules),

	/* avoid libfrr trying to read our config file for us */
	.flags = FRR_MANUAL_VTY_START | FRR_NO_SPLIT_CONFIG,
);
/* clang-format on */

#define DEPRECATED_OPTIONS ""

struct frr_daemon_info *mgmt_daemon_info = &mgmtd_di;

/* Main routine of mgmt. Treatment of argument and start mgmt finite
 * state machine is handled at here.
 */
int main(int argc, char **argv)
{
	int opt;
	int buffer_size = MGMTD_SOCKET_BUF_SIZE;

	frr_preinit(&mgmtd_di, argc, argv);
	frr_opt_add(
		"s:n" DEPRECATED_OPTIONS, longopts,
		"  -s, --socket_size  Set MGMTD peer socket send buffer size\n"
		"  -n, --vrfwnetns    Use NetNS as VRF backend\n");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, 0);

		if (opt && opt < 128 && strchr(DEPRECATED_OPTIONS, opt)) {
			fprintf(stderr,
				"The -%c option no longer exists.\nPlease refer to the manual.\n",
				opt);
			continue;
		}

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 's':
			buffer_size = atoi(optarg);
			break;
		case 'n':
			vrf_configure_backend(VRF_BACKEND_NETNS);
			break;
		default:
			frr_help_exit(1);
			break;
		}
	}

	/* MGMTD master init. */
	mgmt_master_init(frr_init(), buffer_size);

	/* VRF commands initialization. */
	vrf_cmd_init(NULL);

	/* Interface commands initialization. */
	if_cmd_init(NULL);

	/* MGMTD related initialization.  */
	mgmt_init();

	frr_config_fork();

	frr_run(mm->master);

	/* Not reached. */
	return 0;
}
