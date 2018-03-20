/*
 * BFD daemon code
 * Copyright (C) 2018 Network Device Education Foundation, Inc. ("NetDEF")
 *
 * This file is part of FRR.
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
 * You should have received a copy of the GNU General Public License
 * along with FRR; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "lib/bfdd_adapter.h"
#include "bfdd_frr.h"

#include <lib/version.h>
#include <lib/libfrr.h>

/*
 * This is not an actual implementation of BFD, but a daemon that will
 * talk with the actual BFDd daemon which lives outside of FRR for now.
 */

/*
 * FRR related code.
 */
/* Master of threads. */
struct thread_master *master;

static struct frr_daemon_info bfdd_di;

/* BFDd privileges */
static zebra_capabilities_t _caps_p[] = {ZCAP_BIND};

struct zebra_privs_t bfdd_privs = {
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

static void sigpipe_handler(void)
{
	/* NOTHING */
}

static void sigusr1_handler(void)
{
	zlog_rotate();
}

static struct quagga_signal_t bfd_signals[] = {
	{
		.signal = SIGPIPE,
		.handler = &sigpipe_handler,
	},
	{
		.signal = SIGUSR1,
		.handler = &sigusr1_handler,
	},
};

FRR_DAEMON_INFO(bfdd, BFD, .vty_port = 2613,
		.proghelp = "Implementation of the BFD protocol.",
		.signals = bfd_signals, .n_signals = array_size(bfd_signals),
		.privs = &bfdd_privs)

#define OPTION_CTLSOCK 1001
static struct option longopts[] = {
	{"bfdctl", required_argument, NULL, OPTION_CTLSOCK},
	{0}
};

DEFINE_QOBJ_TYPE(bpc_node);


/*
 * Adapter daemon code.
 */
struct bfdd_config bc;

static int bfdd_reconfigure(int csock, void *arg)
{
	struct bfdd_config *bc = (struct bfdd_config *)arg;
	struct bpc_node *bn;
	struct json_object *jo;
	const char *jsonstr;
	uint64_t notifications;
	int rv;

	bc->bc_csock = csock;

	/* Enable notifications. */
	notifications = BCM_NOTIFY_PEER_STATE | BCM_NOTIFY_CONFIG;
	rv = bfd_control_call(&bac, BMT_NOTIFY, &notifications,
			      sizeof(notifications));
	if (rv == -1) {
		zlog_err(
			"failed to enable notifications, some features will not work");
	}

	TAILQ_FOREACH (bn, &bc->bc_bnlist, bn_entry) {
		/* Create the request data and send. */
		jo = bfd_ctrl_new_json();
		if (jo == NULL) {
			zlog_err("%s:%d: not enough memory", __func__,
				 __LINE__);
			return -1;
		}

		bfd_ctrl_add_peer(jo, &bn->bn_bpc);
		jsonstr = json_object_to_json_string_ext(
			jo, BFDD_JSON_CONV_OPTIONS);

		rv = bfd_control_call(&bac, BMT_REQUEST_ADD, jsonstr,
				      strlen(jsonstr));
		json_object_put(jo);
		if (rv == -1)
			return -1;
	}

	return 0;
}

struct bfdd_adapter_ctx bac = {
	.bac_read = bfdd_receive_notification,
	.bac_read_arg = &bc,
	.bac_reconfigure = bfdd_reconfigure,
	.bac_reconfigure_arg = &bc,
};

int main(int argc, char *argv[])
{
	const char *ctl_path = BFD_CONTROL_SOCK_PATH;
	int opt;

	frr_preinit(&bfdd_di, argc, argv);
	frr_opt_add("", longopts,
		    "      --bfdctl       Specify bfdd control socket\n");

	while (true) {
		opt = frr_getopt(argc, argv, NULL);
		if (opt == EOF)
			break;

		switch (opt) {
		case OPTION_CTLSOCK:
			ctl_path = optarg;
			break;

		default:
			frr_help_exit(1);
			break;
		}
	}

	/* Configure the control socket path. */
	strlcpy(bac.bac_ctlpath, ctl_path, sizeof(bac.bac_ctlpath));

	openzlog(bfdd_di.progname, "BFD", 0, LOG_CONS | LOG_NDELAY | LOG_PID,
		 LOG_DAEMON);

	/* Initialize FRR infrastructure. */
	master = frr_init();

	bfdd_vty_init();

	/* Handle BFDd control socket. */
	bac.bac_master = master;
	bfd_adapter_init(&bac);

	/* read configuration file and daemonize  */
	frr_config_fork();

	frr_run(master);
	/* NOTREACHED */

	return 0;
}
