/*
 * PBR - main code
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *               Donald Sharp
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
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
#include "prefix.h"
#include "linklist.h"
#include "if.h"
#include "vector.h"
#include "vty.h"
#include "command.h"
#include "filter.h"
#include "plist.h"
#include "stream.h"
#include "log.h"
#include "memory.h"
#include "privs.h"
#include "sigevent.h"
#include "zclient.h"
#include "keychain.h"
#include "distribute.h"
#include "libfrr.h"
#include "routemap.h"
#include "nexthop.h"
#include "nexthop_group.h"

#include "pbr_nht.h"
#include "pbr_map.h"
#include "pbr_zebra.h"
#include "pbr_vty.h"
#include "pbr_debug.h"
#include "pbr_vrf.h"

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW, ZCAP_BIND, ZCAP_NET_ADMIN,
};

struct zebra_privs_t pbr_privs = {
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
struct thread_master *master;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");
}

/* SIGINT / SIGTERM handler. */
static void sigint(void)
{
	zlog_notice("Terminating on signal");

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t pbr_signals[] = {
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

#define PBR_VTY_PORT 2615

static const struct frr_yang_module_info *pbrd_yang_modules[] = {
	&frr_interface_info,
};

FRR_DAEMON_INFO(pbrd, PBR, .vty_port = PBR_VTY_PORT,

		.proghelp = "Implementation of PBR.",

		.signals = pbr_signals,
		.n_signals = array_size(pbr_signals),

		.privs = &pbr_privs,

		.yang_modules = pbrd_yang_modules,
		.n_yang_modules = array_size(pbrd_yang_modules), )

int main(int argc, char **argv, char **envp)
{
	frr_preinit(&pbrd_di, argc, argv);
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
			break;
		}
	}

	master = frr_init();

	pbr_debug_init();

	nexthop_group_init(pbr_nhgroup_add_cb,
			   pbr_nhgroup_add_nexthop_cb,
			   pbr_nhgroup_del_nexthop_cb,
			   pbr_nhgroup_delete_cb);

	/*
	 * So we safely ignore these commands since
	 * we are getting them at this point in time
	 */
	access_list_init();
	pbr_nht_init();
	pbr_map_init();
	if_zapi_callbacks(pbr_ifp_create, pbr_ifp_up,
			  pbr_ifp_down, pbr_ifp_destroy);
	pbr_zebra_init();
	pbr_vrf_init();
	pbr_vty_init();

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
