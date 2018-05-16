/* RIPd main routine.
 * Copyright (C) 1997, 98 Kunihiro Ishiguro <kunihiro@zebra.org>
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
#include "command.h"
#include "memory.h"
#include "memory_vty.h"
#include "prefix.h"
#include "filter.h"
#include "keychain.h"
#include "log.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "vrf.h"
#include "libfrr.h"

#include "ripd/ripd.h"

/* ripd options. */
#if CONFDATE > 20190521
	CPP_NOTICE("-r / --retain has reached deprecation EOL, remove")
#endif
static struct option longopts[] = {{"retain", no_argument, NULL, 'r'}, {0}};

/* ripd privileges */
zebra_capabilities_t _caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND};

struct zebra_privs_t ripd_privs = {
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
	.cap_num_p = 2,
	.cap_num_i = 0};

/* Master of threads. */
struct thread_master *master;

static struct frr_daemon_info ripd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
	rip_clean();
	rip_reset();
	zlog_info("ripd restarting!");

	/* Reload config file. */
	vty_read_config(ripd_di.config_file, config_default);

	/* Try to return to normal operation. */
}

/* SIGINT handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	rip_clean();

	rip_zclient_stop();
	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

static struct quagga_signal_t ripd_signals[] = {
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

FRR_DAEMON_INFO(ripd, RIP, .vty_port = RIP_VTY_PORT,

		.proghelp = "Implementation of the RIP routing protocol.",

		.signals = ripd_signals, .n_signals = array_size(ripd_signals),

		.privs = &ripd_privs, )

#if CONFDATE > 20190521
CPP_NOTICE("-r / --retain has reached deprecation EOL, remove")
#endif
#define DEPRECATED_OPTIONS "r"

/* Main routine of ripd. */
int main(int argc, char **argv)
{
	frr_preinit(&ripd_di, argc, argv);

	frr_opt_add("" DEPRECATED_OPTIONS, longopts, "");

	/* Command line option parse. */
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
			break;
		}
	}

	/* Prepare master thread. */
	master = frr_init();

	/* Library initialization. */
	keychain_init();
	vrf_init(NULL, NULL, NULL, NULL);

	/* RIP related initialization. */
	rip_init();
	rip_if_init();
	rip_zclient_init(master);
	rip_peer_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return (0);
}
