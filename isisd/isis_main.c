// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * IS-IS Rout(e)ing protocol - isis_main.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 */

#include <zebra.h>

#include "getopt.h"
#include "frrevent.h"
#include "log.h"
#include <lib/version.h>
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "stream.h"
#include "if.h"
#include "privs.h"
#include "sigevent.h"
#include "filter.h"
#include "plist.h"
#include "zclient.h"
#include "vrf.h"
#include "qobj.h"
#include "libfrr.h"
#include "routemap.h"
#include "affinitymap.h"

#include "isisd/isis_affinitymap.h"
#include "isisd/isis_constants.h"
#include "isisd/isis_common.h"
#include "isisd/isis_flags.h"
#include "isisd/isis_circuit.h"
#include "isisd/isisd.h"
#include "isisd/isis_dynhn.h"
#include "isisd/isis_spf.h"
#include "isisd/isis_route.h"
#include "isisd/isis_routemap.h"
#include "isisd/isis_zebra.h"
#include "isisd/isis_te.h"
#include "isisd/isis_errors.h"
#include "isisd/isis_bfd.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_mt.h"
#include "isisd/fabricd.h"
#include "isisd/isis_nb.h"
#include "isisd/isis_ldp_sync.h"

/* Default configuration file name */
#define ISISD_DEFAULT_CONFIG "isisd.conf"

#define FABRICD_STATE_NAME "%s/fabricd.json", frr_libstatedir
#define ISISD_STATE_NAME   "%s/isisd.json", frr_libstatedir

/* The typo was there before.  Do not fix it!  The point is to load mis-saved
 * state files from older versions.
 *
 * Also fabricd was using the same file.  Sigh.
 */
#define ISISD_COMPAT_STATE_NAME "%s/isid-restart.json", frr_runstatedir

/* isisd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

struct zebra_privs_t isisd_privs = {
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

/* isisd options */
static const struct option longopts[] = {
	{"int_num", required_argument, NULL, 'I'},
	{0}};

/* Master of threads. */
struct event_loop *master;

/*
 * Prototypes.
 */
void sighup(void);
void sigint(void);
void sigterm(void);
void sigusr1(void);


static __attribute__((__noreturn__)) void terminate(int i)
{
	isis_terminate();
	isis_sr_term();
	isis_srv6_term();
	isis_zebra_stop();
	exit(i);
}

/*
 * Signal handlers
 */
#ifdef FABRICD
void sighup(void)
{
	zlog_notice("SIGHUP/reload is not implemented for fabricd");
	return;
}
#else
static struct frr_daemon_info isisd_di;
void sighup(void)
{
	zlog_info("SIGHUP received");

	/* Reload config file. */
	vty_read_config(NULL, isisd_di.config_file, config_default);
}

#endif

__attribute__((__noreturn__)) void sigint(void)
{
	zlog_notice("Terminating on signal SIGINT");
	terminate(0);
}

__attribute__((__noreturn__)) void sigterm(void)
{
	zlog_notice("Terminating on signal SIGTERM");
	terminate(0);
}

void sigusr1(void)
{
	zlog_debug("SIGUSR1 received");
	zlog_rotate();
}

struct frr_signal_t isisd_signals[] = {
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
		.handler = &sigterm,
	},
};


/* clang-format off */
static const struct frr_yang_module_info *const isisd_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
#ifndef FABRICD
	&frr_isisd_info,
#endif /* ifndef FABRICD */
	&frr_route_map_info,
	&frr_affinity_map_info,
	&frr_vrf_info,
};
/* clang-format on */


/* Max wait time for config to load before generating LSPs */
#define ISIS_PRE_CONFIG_MAX_WAIT_SECONDS 600

static void isis_config_finish(struct event *t)
{
	struct listnode *node, *inode;
	struct isis *isis;
	struct isis_area *area;

	for (ALL_LIST_ELEMENTS_RO(im->isis, inode, isis)) {
		for (ALL_LIST_ELEMENTS_RO(isis->area_list, node, area))
			config_end_lsp_generate(area);
	}
}

static void isis_config_end_timeout(struct event *t)
{
	zlog_err("IS-IS configuration end timer expired after %d seconds.",
		 ISIS_PRE_CONFIG_MAX_WAIT_SECONDS);
	isis_config_finish(t);
}

static void isis_config_start(void)
{
	EVENT_OFF(t_isis_cfg);
	event_add_timer(im->master, isis_config_end_timeout, NULL,
			ISIS_PRE_CONFIG_MAX_WAIT_SECONDS, &t_isis_cfg);
}

static void isis_config_end(void)
{
	/* If ISIS config processing thread isn't running, then
	 * we can return and rely it's properly handled.
	 */
	if (!event_is_scheduled(t_isis_cfg))
		return;

	EVENT_OFF(t_isis_cfg);
	isis_config_finish(t_isis_cfg);
}

/* actual paths filled in main() */
static char state_path[512];
static char state_compat_path[512];
static char *state_paths[] = {
	state_path,
	state_compat_path,
	NULL,
};

/* clang-format off */
FRR_DAEMON_INFO(
#ifdef FABRICD
		fabricd, OPEN_FABRIC,

	.vty_port = FABRICD_VTY_PORT,
	.proghelp = "Implementation of the OpenFabric routing protocol.",
#else
		isisd, ISIS,

	.vty_port = ISISD_VTY_PORT,
	.proghelp = "Implementation of the IS-IS routing protocol.",
#endif
	.copyright = "Copyright (c) 2001-2002 Sampo Saaristo, Ofer Wald and Hannes Gredler",

	.signals = isisd_signals,
	.n_signals = array_size(isisd_signals),

	.privs = &isisd_privs,

	.yang_modules = isisd_yang_modules,
	.n_yang_modules = array_size(isisd_yang_modules),

	.state_paths = state_paths,
);
/* clang-format on */

/*
 * Main routine of isisd. Parse arguments and handle IS-IS state machine.
 */
int main(int argc, char **argv, char **envp)
{
	int opt;
	int instance = 1;

#ifdef FABRICD
	frr_preinit(&fabricd_di, argc, argv);
#else
	frr_preinit(&isisd_di, argc, argv);
#endif
	frr_opt_add(
		"I:", longopts,
		"  -I, --int_num      Set instance number (label-manager)\n");

	/* Command line argument treatment. */
	while (1) {
		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case 0:
			break;
		case 'I':
			instance = atoi(optarg);
			if (instance < 1 || instance > (unsigned short)-1)
				zlog_err("Instance %i out of range (1..%u)",
					 instance, (unsigned short)-1);
			break;
		default:
			frr_help_exit(1);
		}
	}

#ifdef FABRICD
	snprintf(state_path, sizeof(state_path), FABRICD_STATE_NAME);
#else
	snprintf(state_path, sizeof(state_path), ISISD_STATE_NAME);
#endif
	snprintf(state_compat_path, sizeof(state_compat_path),
		 ISISD_COMPAT_STATE_NAME);

	/* thread master */
	isis_master_init(frr_init());
	master = im->master;
	/*
	 *  initializations
	 */
	cmd_init_config_callbacks(isis_config_start, isis_config_end);
	isis_error_init();
	access_list_init();
	access_list_add_hook(isis_filter_update);
	access_list_delete_hook(isis_filter_update);
	isis_vrf_init();
	prefix_list_init();
	prefix_list_add_hook(isis_prefix_list_update);
	prefix_list_delete_hook(isis_prefix_list_update);
	isis_init();
	isis_circuit_init();
#ifdef FABRICD
	isis_vty_daemon_init();
#endif /* FABRICD */
#ifndef FABRICD
	isis_cli_init();
#endif /* ifndef FABRICD */
	isis_spf_init();
	isis_redist_init();
	isis_route_map_init();
	isis_mpls_te_init();
	isis_sr_init();
	isis_srv6_init();
	lsp_init();
	mt_init();

#ifndef FABRICD
	isis_affinity_map_init();
#endif /* ifndef FABRICD */

	isis_zebra_init(master, instance);
	isis_bfd_init(master);
	isis_ldp_sync_init();
	fabricd_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	exit(0);
}
