// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * RIPngd main routine.
 * Copyright (C) 1998, 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include <lib/version.h>
#include "getopt.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "memory.h"
#include "frrevent.h"
#include "log.h"
#include "prefix.h"
#include "if.h"
#include "privs.h"
#include "sigevent.h"
#include "vrf.h"
#include "if_rmap.h"
#include "libfrr.h"
#include "routemap.h"
#include "mgmt_be_client.h"

#include "ripngd/ripngd.h"
#include "ripngd/ripng_nb.h"

/* RIPngd options. */
struct option longopts[] = {{0}};

/* ripngd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

uint32_t zebra_ecmp_count = MULTIPATH_NUM;

struct zebra_privs_t ripngd_privs = {
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


/* Master of threads. */
struct event_loop *master;

struct mgmt_be_client *mgmt_be_client;

static struct frr_daemon_info ripngd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, ripngd_di.config_file, config_default);
}

/* SIGINT handler. */
static void sigint(void)
{
	struct vrf *vrf;

	zlog_notice("Terminating on signal");

	nb_oper_cancel_all_walks();
	mgmt_be_client_destroy(mgmt_be_client);
	mgmt_be_client = NULL;

	RB_FOREACH (vrf, vrf_name_head, &vrfs_by_name) {
		if (!vrf->info)
			continue;

		ripng_clean(vrf->info);
	}

	ripng_vrf_terminate();
	if_rmap_terminate();
	ripng_zebra_stop();

	route_map_finish();

	frr_fini();
	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t ripng_signals[] = {
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

static const struct frr_yang_module_info *const ripngd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_ripngd_info,
	&frr_route_map_info,
	&frr_vrf_info,
};

/* clang-format off */
FRR_DAEMON_INFO(ripngd, RIPNG,
	.vty_port = RIPNG_VTY_PORT,
	.proghelp = "Implementation of the RIPng routing protocol.",

	.signals = ripng_signals,
	.n_signals = array_size(ripng_signals),

	.privs = &ripngd_privs,

	.yang_modules = ripngd_yang_modules,
	.n_yang_modules = array_size(ripngd_yang_modules),

	/* mgmtd will load the per-daemon config file now */
	.flags = FRR_NO_SPLIT_CONFIG,
);
/* clang-format on */

#define DEPRECATED_OPTIONS ""

/* RIPngd main routine. */
int main(int argc, char **argv)
{
	frr_preinit(&ripngd_di, argc, argv);

	frr_opt_add("" DEPRECATED_OPTIONS, longopts, "");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

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
		default:
			frr_help_exit(1);
		}
	}

	master = frr_init();

	/* Library inits. */
	ripng_vrf_init();

	/* RIPngd inits. */
	ripng_init();

	mgmt_be_client = mgmt_be_client_create("ripngd", NULL, 0, master);

	zebra_init(master);

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
