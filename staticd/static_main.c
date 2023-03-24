// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * STATICd - main code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 */
#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "frrevent.h"
#include "command.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "libfrr.h"
#include "vrf.h"
#include "nexthop.h"
#include "filter.h"
#include "routing_nb.h"

#include "static_vrf.h"
#include "static_vty.h"
#include "static_routes.h"
#include "static_zebra.h"
#include "static_debug.h"
#include "static_nb.h"

#include "mgmt_be_client.h"

char backup_config_file[256];

bool mpls_enabled;

zebra_capabilities_t _caps_p[] = {
};

struct zebra_privs_t static_privs = {
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

struct option longopts[] = { { 0 } };

/* Master of threads. */
struct event_loop *master;

uintptr_t mgmt_lib_hndl;

static struct frr_daemon_info staticd_di;
/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
	vty_read_config(NULL, staticd_di.config_file, config_default);
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	/* Disable BFD events to avoid wasting processing. */
	bfd_protocol_integration_set_shutdown(true);

	mgmt_be_client_lib_destroy(mgmt_lib_hndl);

	static_vrf_terminate();

	static_zebra_stop();
	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t static_signals[] = {
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

static void static_mgmt_be_client_connect(uintptr_t lib_hndl,
					  uintptr_t usr_data, bool connected)
{
	(void)usr_data;

	assert(lib_hndl == mgmt_lib_hndl);

	zlog_debug("Got %s %s MGMTD Backend Client Server",
		   connected ? "connected" : "disconnected",
		   connected ? "to" : "from");

	if (connected)
		(void)mgmt_be_subscribe_yang_data(mgmt_lib_hndl, NULL, 0);
}

#if 0
static void
static_mgmt_txn_notify(uintptr_t lib_hndl, uintptr_t usr_data,
			struct mgmt_be_client_txn_ctx *txn_ctx,
			bool destroyed)
{
	zlog_debug("Got Txn %s Notify from MGMTD server",
		   destroyed ? "DESTROY" : "CREATE");

	if (!destroyed) {
		/*
		 * TODO: Allocate and install a private scratchpad for this
		 * transaction if required
		 */
	} else {
		/*
		 * TODO: Uninstall and deallocate the private scratchpad for
		 * this transaction if installed earlier.
		 */
	}
}
#endif

static struct mgmt_be_client_params mgmt_params = {
	.name = "staticd",
	.conn_retry_intvl_sec = 3,
	.client_connect_notify = static_mgmt_be_client_connect,
	.txn_notify = NULL, /* static_mgmt_txn_notify */
};

static const struct frr_yang_module_info *const staticd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_vrf_info,
	&frr_routing_info,
	&frr_staticd_info,
};

#define STATIC_VTY_PORT 2616

FRR_DAEMON_INFO(staticd, STATIC, .vty_port = STATIC_VTY_PORT,

		.proghelp = "Implementation of STATIC.",

		.signals = static_signals,
		.n_signals = array_size(static_signals),

		.privs = &static_privs, .yang_modules = staticd_yang_modules,
		.n_yang_modules = array_size(staticd_yang_modules),
);

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&staticd_di, argc, argv);
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
		}
	}

	master = frr_init();

	static_debug_init();
	static_vrf_init();

	static_zebra_init();
	static_vty_init();

	/* Initialize MGMT backend functionalities */
	mgmt_lib_hndl = mgmt_be_client_lib_init(&mgmt_params, master);
	assert(mgmt_lib_hndl);

	hook_register(routing_conf_event,
		      routing_control_plane_protocols_name_validate);

	routing_control_plane_protocols_register_vrf_dependency();

	snprintf(backup_config_file, sizeof(backup_config_file),
		 "%s/zebra.conf", frr_sysconfdir);
	staticd_di.backup_config_file = backup_config_file;

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
