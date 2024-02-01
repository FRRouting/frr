// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * January 29 2024, Christian Hopps <chopps@labn.net>
 *
 * Copyright (c) 2024, LabN Consulting, L.L.C.
 *
 */

#include <zebra.h>
#include <lib/version.h>
#include "darr.h"
#include "libfrr.h"
#include "mgmt_be_client.h"

/* ---------------- */
/* Local Prototypes */
/* ---------------- */

static void async_notification(struct mgmt_be_client *client, uintptr_t usr_data,
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

#define OPTION_LISTEN	   2000
#define OPTION_NOTIF_COUNT 2001
#define OPTION_TIMEOUT	   2002
const struct option longopts[] = {
	{ "listen", no_argument, NULL, OPTION_LISTEN },
	{ "notif-count", required_argument, NULL, OPTION_NOTIF_COUNT },
	{ "timeout", required_argument, NULL, OPTION_TIMEOUT },
	{ 0 }
};


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

struct mgmt_be_client_notification_cb *__notify_cbs;

struct mgmt_be_client_cbs __client_cbs = {};
struct event *event_timeout;

int o_notif_count = 1;
int o_timeout;

/* --------- */
/* Functions */
/* --------- */


static void sigusr1(void)
{
	zlog_rotate();
}

static void quit(int exit_code)
{
	EVENT_OFF(event_timeout);
	frr_fini();
	darr_free(__client_cbs.notify_cbs);
	exit(exit_code);
}

static void sigint(void)
{
	zlog_notice("Terminating on signal");
	quit(0);
}

static void timeout(struct event *event)
{
	zlog_notice("Timeout, exiting");
	quit(1);
}

static void async_notification(struct mgmt_be_client *client, uintptr_t usr_data,
			       struct mgmt_be_client_notification_cb *this,
			       const char *notif_data)
{
	zlog_notice("Received YANG notification");

	printf("%s\n", notif_data);

	if (o_notif_count && !--o_notif_count)
		quit(0);
}

int main(int argc, char **argv)
{
	int f_listen = 0;
	int i;

	frr_preinit(&mgmtd_testc_di, argc, argv);
	frr_opt_add("", longopts, "");

	while (1) {
		int opt;

		opt = frr_getopt(argc, argv, NULL);

		if (opt == EOF)
			break;

		switch (opt) {
		case OPTION_LISTEN:
			f_listen = 1;
			break;
		case OPTION_NOTIF_COUNT:
			o_notif_count = atoi(optarg);
			break;
		case OPTION_TIMEOUT:
			o_timeout = atoi(optarg);
			break;
		case 0:
			break;
		default:
			frr_help_exit(1);
		}
	}

	master = frr_init();

	/*
	 * Setup notification listen
	 */
	argv += optind;
	argc -= optind;
	if (!argc && f_listen) {
		fprintf(stderr,
			"Must specify at least one notification xpath to listen to\n");
		exit(1);
	}
	if (argc && f_listen) {
		struct mgmt_be_client_notification_cb *cb;

		for (i = 0; i < argc; i++) {
			zlog_notice("Listen on xpath: %s", argv[i]);
			cb = darr_append(__notify_cbs);
			cb->xpath = argv[i];
			cb->format = LYD_JSON;
			cb->callback = async_notification;
		}
		__client_cbs.notify_cbs = __notify_cbs;
		__client_cbs.nnotify_cbs = darr_len(__notify_cbs);
	}

	mgmt_be_client = mgmt_be_client_create("mgmtd-testc", &__client_cbs, 0,
					       master);

	frr_config_fork();

	if (o_timeout)
		event_add_timer(master, timeout, NULL, o_timeout, &event_timeout);

	frr_run(master);

	/* Reached. */
	return 0;
}
