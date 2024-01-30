// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * January 29 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 *
 */

#include <zebra.h>
#include <lib/version.h>
#include "libfrr.h"
#include "mgmt_be_client.h"

/* ---------------- */
/* Local Prototypes */
/* ---------------- */

static void ripd_notification(struct mgmt_be_client *client, uintptr_t usr_data,
			      struct mgmt_be_client_notification_cb *this,
			      const char *notif_data);

static void sigusr1(void);
static void sigint(void);

/* ----------- */
/* Global Data */
/* ----------- */

/* privileges */
static zebra_capabilities_t _caps_p[] = {};

struct zebra_privs_t __privs = {
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

struct option longopts[] = {{0}};

/* Master of threads. */
struct event_loop *master;

struct mgmt_be_client *mgmt_be_client;

static struct frr_daemon_info mgmtd_testc_di;

struct frr_signal_t __signals[] = {
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

#define MGMTD_TESTC_VTY_PORT 2624

/* clang-format off */
FRR_DAEMON_INFO(mgmtd_testc, MGMTD_TESTC,
		.proghelp = "FRR Management Daemon Test Client.",

		.signals = __signals,
		.n_signals = array_size(__signals),

		.privs = &__privs,

		// .yang_modules = mgmt_yang_modules,
		// .n_yang_modules = array_size(mgmt_yang_modules),

		/* avoid libfrr trying to read our config file for us */
		.flags = FRR_MANUAL_VTY_START,
	);
/* clang-format on */

struct mgmt_be_client_notification_cb __notify_cbs[] = { {
	.xpath = "frr-ripd",
	.format = LYD_JSON,
	.callback = ripd_notification,
} };

struct mgmt_be_client_cbs __client_cbs = {
	.notify_cbs = __notify_cbs,
	.nnotify_cbs = array_size(__notify_cbs),
};


/* --------- */
/* Functions */
/* --------- */


static void sigusr1(void)
{
	zlog_rotate();
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");
	frr_fini();
	exit(0);
}

static void ripd_notification(struct mgmt_be_client *client, uintptr_t usr_data,
			      struct mgmt_be_client_notification_cb *this,
			      const char *notif_data)
{
	zlog_notice("Received RIPd notification");
}

int main(int argc, char **argv)
{
	frr_preinit(&mgmtd_testc_di, argc, argv);
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

	mgmt_be_client = mgmt_be_client_create("mgmtd-testc", &__client_cbs, 0,
					       master);

	frr_config_fork();
	frr_run(master);

	/* Reached. */
	return 0;
}
