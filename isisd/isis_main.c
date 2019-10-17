/*
 * IS-IS Rout(e)ing protocol - isis_main.c
 *
 * Copyright (C) 2001,2002   Sampo Saaristo
 *                           Tampere University of Technology
 *                           Institute of Communications Engineering
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public Licenseas published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "getopt.h"
#include "thread.h"
#include "log.h"
#include <lib/version.h>
#include "command.h"
#include "vty.h"
#include "memory.h"
#include "memory_vty.h"
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

/* Default configuration file name */
#define ISISD_DEFAULT_CONFIG "isisd.conf"
/* Default vty port */
#define ISISD_VTY_PORT       2608
#define FABRICD_VTY_PORT     2618

/* isisd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND};

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
struct option longopts[] = {{0}};

/* Master of threads. */
struct thread_master *master;

/*
 * Prototypes.
 */
void sighup(void);
void sigint(void);
void sigterm(void);
void sigusr1(void);


static __attribute__((__noreturn__)) void terminate(int i)
{
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

struct quagga_signal_t isisd_signals[] = {
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


static const struct frr_yang_module_info *isisd_yang_modules[] = {
	&frr_interface_info,
#ifndef FABRICD
	&frr_isisd_info,
#endif /* ifndef FABRICD */
};

#ifdef FABRICD
FRR_DAEMON_INFO(fabricd, OPEN_FABRIC, .vty_port = FABRICD_VTY_PORT,

		.proghelp = "Implementation of the OpenFabric routing protocol.",
#else
FRR_DAEMON_INFO(isisd, ISIS, .vty_port = ISISD_VTY_PORT,

		.proghelp = "Implementation of the IS-IS routing protocol.",
#endif
		.copyright =
			"Copyright (c) 2001-2002 Sampo Saaristo,"
			" Ofer Wald and Hannes Gredler",

		.signals = isisd_signals,
		.n_signals = array_size(isisd_signals),

		.privs = &isisd_privs, .yang_modules = isisd_yang_modules,
		.n_yang_modules = array_size(isisd_yang_modules), )

/*
 * Main routine of isisd. Parse arguments and handle IS-IS state machine.
 */
int main(int argc, char **argv, char **envp)
{
	int opt;

#ifdef FABRICD
	frr_preinit(&fabricd_di, argc, argv);
#else
	frr_preinit(&isisd_di, argc, argv);
#endif
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

	/* thread master */
	master = frr_init();

	/*
	 *  initializations
	 */
	isis_error_init();
	access_list_init();
	vrf_init(NULL, NULL, NULL, NULL, NULL);
	prefix_list_init();
	isis_init();
	isis_circuit_init();
#ifdef FABRICD
	isis_vty_daemon_init();
#endif /* FABRICD */
#ifndef FABRICD
	isis_cli_init();
#endif /* ifdef FABRICD */
	isis_spf_cmds_init();
	isis_redist_init();
	isis_route_map_init();
	isis_mpls_te_init();
	lsp_init();
	mt_init();

	/* create the global 'isis' instance */
	isis_new(1, VRF_DEFAULT);

	isis_zebra_init(master);
	isis_bfd_init();
	fabricd_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	exit(0);
}
