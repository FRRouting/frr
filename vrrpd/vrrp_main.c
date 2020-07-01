/*
 * VRRP entry point.
 * Copyright (C) 2018-2019 Cumulus Networks, Inc.
 * Quentin Young
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

#include <lib/version.h>

#include "lib/command.h"
#include "lib/filter.h"
#include "lib/getopt.h"
#include "lib/if.h"
#include "lib/libfrr.h"
#include "lib/log.h"
#include "lib/memory.h"
#include "lib/nexthop.h"
#include "lib/privs.h"
#include "lib/sigevent.h"
#include "lib/thread.h"
#include "lib/vrf.h"
#include "lib/vty.h"

#include "vrrp.h"
#include "vrrp_debug.h"
#include "vrrp_vty.h"
#include "vrrp_zebra.h"

DEFINE_MGROUP(VRRPD, "vrrpd")

char backup_config_file[256];

zebra_capabilities_t _caps_p[] = {
	ZCAP_NET_RAW,
};

struct zebra_privs_t vrrp_privs = {
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

struct option longopts[] = { {0} };

/* Master of threads. */
struct thread_master *master;

static struct frr_daemon_info vrrpd_di;

/* SIGHUP handler. */
static void sighup(void)
{
	zlog_info("SIGHUP received");

	vty_read_config(NULL, vrrpd_di.config_file, config_default);
}

/* SIGINT / SIGTERM handler. */
static void __attribute__((noreturn)) sigint(void)
{
	zlog_notice("Terminating on signal");

	vrrp_fini();

	frr_fini();

	exit(0);
}

/* SIGUSR1 handler. */
static void sigusr1(void)
{
	zlog_rotate();
}

struct quagga_signal_t vrrp_signals[] = {
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

static const struct frr_yang_module_info *const vrrp_yang_modules[] = {
	&frr_filter_info,
	&frr_vrf_info,
	&frr_interface_info,
	&frr_vrrpd_info,
};

#define VRRP_VTY_PORT 2619

FRR_DAEMON_INFO(vrrpd, VRRP, .vty_port = VRRP_VTY_PORT,
		.proghelp = "Virtual Router Redundancy Protocol",
		.signals = vrrp_signals,
		.n_signals = array_size(vrrp_signals),
		.privs = &vrrp_privs,
		.yang_modules = vrrp_yang_modules,
		.n_yang_modules = array_size(vrrp_yang_modules),
)

#ifdef FUZZING

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size);

static bool FuzzingInit(void)
{
	const char *name[] = { "vrrpd" };

	frr_preinit(&vrrpd_di, 1, (char **) name);

	master = frr_init();

	access_list_init();
	vrrp_debug_init();
	vrrp_zebra_init();
	vrrp_vty_init();
	vrrp_init();


	return true;
}

static struct vrrp_vrouter *FuzzingCreateVr(void)
{
	struct interface *ifp;
	struct prefix p;

	ifp = if_create_ifindex(69, 0, NULL);
	ifp->mtu = 68;
	str2prefix("11.0.2.1/24", &p);
	connected_add_by_prefix(ifp, &p, NULL);

	struct vrrp_vrouter *vr = vrrp_vrouter_create(ifp, 10, 3);
	vr->v4->fsm.state = VRRP_STATE_MASTER;
	vr->v6->fsm.state = VRRP_STATE_MASTER;

	vrrp_debug_set(NULL, 0, CONFIG_NODE, 1, 1, 1, 1, 1, 1, 1, 1);

	return vr;
}

bool FuzzingInitialized;
struct vrrp_vrouter *FuzzingVr;

int LLVMFuzzerTestOneInput(uint8_t *data, size_t size)
{
	if (!FuzzingInitialized) {
		FuzzingInit();
		FuzzingInitialized = true;
		FuzzingVr = FuzzingCreateVr();
	}

	struct thread t;
	struct vrrp_vrouter *vr;

#ifdef FUZZING_LIBFUZZER
	vr = FuzzingVr;
#else
	vr = FuzzingVr;
#endif

#define FUZZING_ZAPI 1

#ifndef FUZZING_ZAPI
	/* set input size */
	vr->v4->fuzzing_input_size = size;
	/* some info to fake msghdr with */
	memcpy(vr->v4->ibuf, data, MIN(size, sizeof(vr->v4->ibuf)));
	vr->v4->fuzzing_sa.sin_family = AF_INET;
	inet_pton(AF_INET, "11.0.2.3", &vr->v4->fuzzing_sa.sin_addr);

	t.arg = vr->v4;

	vrrp_read(&t);
#else
	zclient_read_fuzz(zclient, data, size);
#endif

	return 0;
}

#endif

#ifndef FUZZING_LIBFUZZER
int main(int argc, char **argv, char **envp)
{
#ifdef FUZZING
	FuzzingInit();
	FuzzingInitialized = true;

#ifdef __AFL_HAVE_MANUAL_CONTROL
	__AFL_INIT();
#endif /* AFL_HAVE_MANUAL_CONTROL */

	uint8_t *input;
	int r = frrfuzz_read_input(&input);

	if (r < 0)
		return 0;

	return LLVMFuzzerTestOneInput(input, r);
#endif
	frr_preinit(&vrrpd_di, argc, argv);
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

	access_list_init();
	vrrp_debug_init();
	vrrp_zebra_init();
	vrrp_vty_init();
	vrrp_init();

	snprintf(backup_config_file, sizeof(backup_config_file),
		 "%s/vrrpd.conf", frr_sysconfdir);
	vrrpd_di.backup_config_file = backup_config_file;

	frr_config_fork();
	frr_run(master);

	/* Not reached. */
	return 0;
}
#endif
