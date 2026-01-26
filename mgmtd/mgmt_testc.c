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
#include "debug.h"
#include "libfrr.h"
#include "mgmt_be_client.h"
#include "mgmt_msg_native.h"
#include "northbound.h"

/* ---------------- */
/* Local Prototypes */
/* ---------------- */

static void async_notification(struct nb_cb_notify_args *args);
static int rpc_callback(struct nb_cb_rpc_args *args);

static void sigusr1(void);
static void sigint(void);

/* ----------- */
/* Global Data */
/* ----------- */

/* privileges */
static zebra_capabilities_t _caps_p[] = {};

static struct zebra_privs_t _privs = {
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

#define OPTION_DATASTORE   2000
#define OPTION_LISTEN	   2001
#define OPTION_NOTIF_COUNT 2002
#define OPTION_TIMEOUT	   2003
const struct option longopts[] = { { "datastore", no_argument, NULL, OPTION_DATASTORE },
				   { "listen", no_argument, NULL, OPTION_LISTEN },
				   { "notify-count", required_argument, NULL, OPTION_NOTIF_COUNT },
				   { "timeout", required_argument, NULL, OPTION_TIMEOUT },
				   { 0 } };


/* Master of threads. */
struct event_loop *master;

struct mgmt_be_client *mgmt_be_client;

static struct frr_daemon_info mgmtd_testc_di;

struct frr_signal_t _signals[] = {
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
static const struct frr_yang_module_info frr_if_info = {
	.name = "frr-interface",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-interface:lib",
			.cbs.notify = async_notification,
		},
		{
			.xpath = NULL,
		}
	}
};

static const struct frr_yang_module_info frr_ripd_info = {
	.name = "frr-ripd",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/frr-ripd:authentication-failure",
			.cbs.notify = async_notification,
		},
		{
			.xpath = "/frr-ripd:clear-rip-route",
			.cbs.rpc = rpc_callback,
		},
		{
			.xpath = NULL,
		}
	}
};

static const struct frr_yang_module_info *const mgmt_yang_modules[] = {
	&frr_backend_info,
	&frr_if_info,
	&frr_ripd_info,
};

FRR_DAEMON_INFO(mgmtd_testc, MGMTD_TESTC,
		.proghelp = "FRR Management Daemon Test Client.",

		.signals = _signals,
		.n_signals = array_size(_signals),

		.privs = &_privs,

		.yang_modules = mgmt_yang_modules,
		.n_yang_modules = array_size(mgmt_yang_modules),

		/* avoid libfrr trying to read our config file for us */
		.flags = FRR_MANUAL_VTY_START,
	);
/* clang-format on */

const char **_notif_xpaths;
const char **_rpc_xpaths;
const char **_oper_xpaths;

struct mgmt_be_client_cbs _client_cbs = {};
struct event *event_timeout;

int f_datastore;
int o_notif_count = 1;
int o_timeout;

/* --------- */
/* Functions */
/* --------- */


static void sigusr1(void)
{
	zlog_rotate();
}

static FRR_NORETURN void quit(int exit_code)
{
	mgmt_be_client_destroy(mgmt_be_client);

	event_cancel(&event_timeout);
	darr_free(_client_cbs.config_xpaths);
	darr_free(_client_cbs.oper_xpaths);
	darr_free(_client_cbs.notify_xpaths);
	darr_free(_client_cbs.rpc_xpaths);

	frr_fini();

	exit(exit_code);
}

static FRR_NORETURN void sigint(void)
{
	zlog_notice("Terminating on signal");
	quit(0);
}

static FRR_NORETURN void timeout(struct event *event)
{
	zlog_notice("Timeout, exiting");
	quit(1);
}

static FRR_NORETURN void success(struct event *event)
{
	zlog_notice("Success, exiting");
	quit(0);
}

static void _ds_notification(struct nb_cb_notify_args *args)
{
	uint8_t *output = NULL;

	zlog_notice("Received YANG datastore notification: op %u", args->op);

	if (args->op == NOTIFY_OP_NOTIFICATION) {
		zlog_warn("ignoring non-datastore op notification: %s", args->xpath);
		return;
	}

	/* datastore notification */
	switch (args->op) {
	case NOTIFY_OP_DS_REPLACE:
		printfrr("#OP=REPLACE: %s\n", args->xpath);
		break;
	case NOTIFY_OP_DS_DELETE:
		printfrr("#OP=DELETE: %s\n", args->xpath);
		break;
	case NOTIFY_OP_DS_PATCH:
		printfrr("#OP=PATCH: %s\n", args->xpath);
		break;
	case NOTIFY_OP_DS_GET_SYNC:
		printfrr("#OP=SYNC: %s\n", args->xpath);
		break;
	default:
		printfrr("#OP=%u: unknown notify op\n", args->op);
		quit(1);
	}

	if (args->dnode && args->op != NOTIFY_OP_DS_DELETE) {
		output = yang_print_tree(args->dnode, LYD_JSON, LYD_PRINT_SHRINK);
		if (output) {
			printfrr("%s\n", output);
			darr_free(output);
		}
	}
	fflush(stdout);

	if (o_notif_count && !--o_notif_count)
		quit(0);
}

static void _notification(struct nb_cb_notify_args *args)
{
	zlog_notice("Received YANG notification: op: %u", args->op);

	if (args->op != NOTIFY_OP_NOTIFICATION) {
		zlog_warn("ignoring datastore notification: op: %u: path %s", args->op, args->xpath);
		return;
	}

	/* bogus, we should print the actual data */
	printf("{\"frr-ripd:authentication-failure\": {\"interface-name\": \"%s\"}}\n",
	       yang_dnode_get_string(args->dnode, "interface-name"));

	if (o_notif_count && !--o_notif_count)
		quit(0);
}

static void async_notification(struct nb_cb_notify_args *args)
{
	if (f_datastore)
		_ds_notification(args);
	else
		_notification(args);
}

static int rpc_callback(struct nb_cb_rpc_args *args)
{
	const char *vrf = NULL;

	zlog_notice("Received YANG RPC");

	if (yang_dnode_exists(args->input, "vrf"))
		vrf = yang_dnode_get_string(args->input, "vrf");

	printf("{\"frr-ripd:clear-rip-route\": {\"vrf\": \"%s\"}}\n", vrf);

	event_cancel(&event_timeout);
	event_add_timer(master, success, NULL, 1, NULL);

	return 0;
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
		case OPTION_DATASTORE:
			f_datastore = 1;
			break;
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

	mgmt_be_client_lib_vty_init();
	mgmt_dbg_be_client.flags = DEBUG_MODE_ALL;

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
		for (i = 0; i < argc; i++) {
			zlog_notice("Listen on xpath: %s", argv[i]);
			darr_push(_notif_xpaths, argv[i]);
		}
		_client_cbs.notify_xpaths = _notif_xpaths;
		_client_cbs.nnotify_xpaths = darr_len(_notif_xpaths);
	}

	darr_push(_oper_xpaths, "/frr-backend:clients");
	_client_cbs.oper_xpaths = _oper_xpaths;
	_client_cbs.noper_xpaths = darr_len(_oper_xpaths);

	darr_push(_rpc_xpaths, "/frr-ripd:clear-rip-route");
	_client_cbs.rpc_xpaths = _rpc_xpaths;
	_client_cbs.nrpc_xpaths = darr_len(_rpc_xpaths);

	mgmt_be_client = mgmt_be_client_create("mgmtd-testc", &_client_cbs, 0, master);

	frr_config_fork();

	if (o_timeout)
		event_add_timer(master, timeout, NULL, o_timeout, &event_timeout);

	frr_run(master);

	/* Reached. */
	return 0;
}
