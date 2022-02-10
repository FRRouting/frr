/*
 * PIMv6 main()
 * Copyright (C) 2021  David Lamparter for NetDEF, Inc.
 * Copyright (C) 2008  Everton da Silva Marques (pim_main.c)
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

#include "lib/vrf.h"
#include "lib/filter.h"
#include "lib/plist.h"
#include "lib/routemap.h"
#include "lib/routing_nb.h"

#include "lib/privs.h"
#include "lib/sigevent.h"
#include "lib/libfrr.h"
#include "lib/version.h"

#include "pimd.h"
#include "pim_instance.h"
#include "pim_errors.h"
#include "pim_iface.h"
#include "pim_zebra.h"

zebra_capabilities_t _caps_p[] = {
	ZCAP_SYS_ADMIN,
	ZCAP_NET_ADMIN,
	ZCAP_NET_RAW,
	ZCAP_BIND,
};

/* pimd privileges to run with */
struct zebra_privs_t pimd_privs = {
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

static void pim6_terminate(void);

static void pim6_sighup(void)
{
	zlog_info("SIGHUP received, ignoring");
}

static void pim6_sigint(void)
{
	zlog_notice("Terminating on signal SIGINT");
	pim6_terminate();
	exit(1);
}

static void pim6_sigterm(void)
{
	zlog_notice("Terminating on signal SIGTERM");
	pim6_terminate();
	exit(1);
}

static void pim6_sigusr1(void)
{
	zlog_rotate();
}

struct frr_signal_t pim6d_signals[] = {
	{
		.signal = SIGHUP,
		.handler = &pim6_sighup,
	},
	{
		.signal = SIGUSR1,
		.handler = &pim6_sigusr1,
	},
	{
		.signal = SIGINT,
		.handler = &pim6_sigint,
	},
	{
		.signal = SIGTERM,
		.handler = &pim6_sigterm,
	},
};

static const struct frr_yang_module_info *const pim6d_yang_modules[] = {
	&frr_filter_info,
	&frr_interface_info,
	&frr_route_map_info,
	&frr_vrf_info,
	&frr_routing_info,
};

/* clang-format off */
FRR_DAEMON_INFO(pim6d, PIM6,
	.vty_port = 0,
	.flags = FRR_NO_SPLIT_CONFIG,

	.proghelp = "Protocol Independent Multicast (RFC7761) for IPv6",

	.signals = pim6d_signals,
	.n_signals = array_size(pim6d_signals),

	.privs = &pimd_privs,

	.yang_modules = pim6d_yang_modules,
	.n_yang_modules = array_size(pim6d_yang_modules),
);
/* clang-format on */


int main(int argc, char **argv, char **envp)
{
	static struct option longopts[] = {
		{},
	};

	frr_preinit(&pim6d_di, argc, argv);
	frr_opt_add("", longopts, "");

	/* this while just reads the options */
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

	pim_router_init();
	/* TODO PIM6: temporary enable all debugs, remove later in PIMv6 work */
	router->debugs = ~0U;

	access_list_init();
	prefix_list_init();

	/*
	 * Initializations
	 */
	pim_error_init();
	pim_vrf_init();
#if 0
	prefix_list_add_hook(pim_prefix_list_update);
	prefix_list_delete_hook(pim_prefix_list_update);

	pim_route_map_init();
	pim_init();
#endif

	/*
	 * Initialize zclient "update" and "lookup" sockets
	 */
	pim_iface_init();

	/* TODO PIM6: next line is temporary since pim_cmd_init is disabled */
	if_cmd_init(NULL);

#if 0
	pim_zebra_init();
	pim_bfd_init();
	pim_mlag_init();

	hook_register(routing_conf_event,
		      routing_control_plane_protocols_name_validate);

	routing_control_plane_protocols_register_vrf_dependency();
#endif

	frr_config_fork();
	frr_run(router->master);

	/* never reached */
	return 0;
}

static void pim6_terminate(void)
{
	pim_vrf_terminate();
	pim_router_terminate();

	prefix_list_reset();
	access_list_reset();

	frr_fini();
}
