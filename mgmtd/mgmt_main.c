/*
 * Main routine of mgmt.
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include <pthread.h>
#include "vector.h"
#include "command.h"
#include "getopt.h"
#include "thread.h"
#include <lib/version.h>
#include "memory.h"
#include "prefix.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "routemap.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "queue.h"
#include "vrf.h"
#include "bfd.h"
#include "libfrr.h"
#include "ns.h"

#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_bcknd_adapter.h"

#include "lib/routing_nb.h"

/*
 * NOTE:
 * For each Backend client migrated to MGMTD add the
 * corresponding NB callback modules here.
 */
#include "staticd/static_nb.h"


/* mgmt options, we use GNU getopt library. */
static const struct option longopts[] = {
	{"skip_runas", no_argument, NULL, 'S'},
	{"no_zebra", no_argument, NULL, 'Z'},
	{"socket_size", required_argument, NULL, 's'},
	{0}};

/* signal definitions */
void sighup(void);
void sigint(void);
void sigusr1(void);

static void mgmt_exit(int);
static void mgmt_vrf_terminate(void);

static struct quagga_signal_t mgmt_signals[] = {
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
void sighup(void)
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
__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal");
	assert(mm->terminating == false);
	mm->terminating = true;	/* global flag that shutting down */

	mgmt_terminate();

	mgmt_exit(0);

	exit(0);
}

/* SIGUSR1 handler. */
void sigusr1(void)
{
	zlog_rotate();
}

/*
  Try to free up allocations we know about so that diagnostic tools such as
  valgrind are able to better illuminate leaks.

  Zebra route removal and protocol teardown are not meant to be done here.
  For example, "retain_mode" may be set.
*/
static __attribute__((__noreturn__)) void mgmt_exit(int status)
{
	/* it only makes sense for this to be called on a clean exit */
	assert(status == 0);

	frr_early_fini();

	/* stop pthreads (if any) */
	mgmt_pthreads_finish();

	mgmt_vrf_terminate();

	frr_fini();
	exit(status);
}

static int mgmt_vrf_new(struct vrf *vrf)
{
	zlog_debug("VRF Created: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int mgmt_vrf_delete(struct vrf *vrf)
{
	zlog_debug("VRF Deletion: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int mgmt_vrf_enable(struct vrf *vrf)
{
	zlog_debug("VRF Enable: %s(%u)", vrf->name, vrf->vrf_id);

	return 0;
}

static int mgmt_vrf_disable(struct vrf *vrf)
{
	zlog_debug("VRF Disable: %s(%u)", vrf->name, vrf->vrf_id);

	/* Note: This is a callback, the VRF will be deleted by the caller. */
	return 0;
}

static int mgmt_vrf_config_write(struct vty *vty)
{
	return 0;
}

static void mgmt_vrf_init(void)
{
	vrf_init(mgmt_vrf_new, mgmt_vrf_enable, mgmt_vrf_disable,
		 mgmt_vrf_delete, mgmt_vrf_enable);
	vrf_cmd_init(mgmt_vrf_config_write);
}

static void mgmt_vrf_terminate(void)
{
	vrf_terminate();
}

static const struct frr_yang_module_info *const mgmt_yang_modules[] = {
	// &frr_mgmt_info,
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_routing_info,
	&frr_vrf_info,
	&frr_staticd_info,
};

FRR_DAEMON_INFO(mgmtd, MGMTD, .vty_port = MGMTD_VTY_PORT,

		.proghelp = "FRR Management Daemon.",

		.signals = mgmt_signals, .n_signals = array_size(mgmt_signals),

		.privs = &mgmt_privs, .yang_modules = mgmt_yang_modules,
		.n_yang_modules = array_size(mgmt_yang_modules), 
);

#define DEPRECATED_OPTIONS ""

/* Main routine of mgmt. Treatment of argument and start mgmt finite
   state machine is handled at here. */
int main(int argc, char **argv)
{
	int opt;
	int buffer_size = MGMTD_SOCKET_BUF_SIZE;

	frr_preinit(&mgmtd_di, argc, argv);
	frr_opt_add(
		"s:" DEPRECATED_OPTIONS, longopts,
		"  -s, --socket_size  Set MGMTD peer socket send buffer size\n");

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
		default:
			frr_help_exit(1);
			break;
		}
	}

	/* MGMTD master init. */
	mgmt_master_init(frr_init(), buffer_size);

	/* VRF Initializations. */
	mgmt_vrf_init();

	/* MGMTD related initialization.  */
	mgmt_init();

	frr_config_fork();

	mgmt_pthreads_run();

	frr_run(mm->master);

	/* Not reached. */
	return 0;
}
