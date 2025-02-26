// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * September 9 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 */

#include <lib/libfrr.h>
#include <lib/zebra.h>
#include <lib/privs.h>
#include <lib/version.h>
#include "mgmt_be_client.h"

extern void *_rust_preinit(struct frr_daemon_info *daemon);
extern void *_rust_init(struct event_loop *master, void *arg);
extern void *_rust_run(struct event_loop *master, void *arg);
extern void _rust_fini(struct event_loop *master, void *arg);
extern void bridge_rust_logging(void);
extern struct frr_daemon_info *rust_get_daemon_info(void);
static void sighup(void);
static void sigint(void);
static void sigusr1(void);

struct event_loop *master;
struct mgmt_be_client *mgmt_be_client;
void *rust_fini_arg;

static struct option __longopts[] = { { 0 } };

static zebra_capabilities_t __caps_p[] = {ZCAP_NET_RAW, ZCAP_BIND, ZCAP_SYS_ADMIN};

static struct zebra_privs_t __privs = {
#if defined(FRR_USER)
	.user = FRR_USER,
#endif
#if defined FRR_GROUP
	.group = FRR_GROUP,
#endif
#ifdef VTY_GROUP
	.vty_group = VTY_GROUP,
#endif
	.caps_p = __caps_p,
	.cap_num_p = array_size(__caps_p),
	.cap_num_i = 0
};

static struct frr_signal_t __signals[] = {
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

static const struct frr_yang_module_info *const __yang_modules[] = {};

/* clang-format off */
FRR_DAEMON_INFO(rustlibd, RUST,
		.vty_port = RUSTLIBD_VTY_PORT,
		.proghelp = "Implementation of the RUST daemon template.",

		.signals = __signals,
		.n_signals = array_size(__signals),

		.privs = &__privs,

		.yang_modules = __yang_modules,
		.n_yang_modules = array_size(__yang_modules),

		/* mgmtd will load the per-daemon config file now */
		.flags = FRR_NO_SPLIT_CONFIG,
	);
/* clang-format on */

struct frr_daemon_info *rust_get_daemon_info(void)
{
	return &rustlibd_di;
}

static void sighup(void)
{
	zlog_info("SIGHUP received and ignored");
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");

	nb_oper_cancel_all_walks();

	_rust_fini(master, rust_fini_arg);

	mgmt_be_client_destroy(mgmt_be_client);
	mgmt_be_client = NULL;
	frr_fini();
	exit(0);
}

static void sigusr1(void)
{
	zlog_rotate();
}

/* Main routine of ripd. */
int main(int argc, char **argv)
{
	void *rust_arg;

	frr_preinit(&rustlibd_di, argc, argv);

	bridge_rust_logging();

	rust_arg = _rust_preinit(&rustlibd_di);

	frr_opt_add("", __longopts, "");

	/* Command line option parse. */
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

	/* Prepare master thread. */
	master = frr_init();
	rust_arg = _rust_init(master, rust_arg);
	mgmt_be_client = mgmt_be_client_create("rustlibd", NULL, 0, master);

	frr_config_fork();

	rust_fini_arg = _rust_run(master, rust_arg);
	frr_run(master);

	/* Not reached. */
	return 0;
}
