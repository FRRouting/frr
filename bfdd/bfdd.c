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
static zebra_capabilities_t _caps_p[] = {
	ZCAP_BIND
};

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
	.cap_num_i = 0
};

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

FRR_DAEMON_INFO(
	bfdd, BFD,
	.vty_port = 2613,
	.proghelp = "Implementation of the BFD protocol.",
	.signals = bfd_signals,
	.n_signals = array_size(bfd_signals),
	.privs = &bfdd_privs
)

DEFINE_QOBJ_TYPE(bpc_node);


/*
 * Adapter daemon code.
 */

/* Prototypes */
int bfdd_csock_read(struct thread *thread);

/* Definitions */
struct bfdd_config bc;

int bfdd_csock_read(struct thread *thread)
{
	struct bfdd_config *bc = THREAD_ARG(thread);

	/* Schedule next read. */
	bc->bc_threcv = NULL;
	thread_add_read(master, bfdd_csock_read, bc, bc->bc_csock,
			&bc->bc_threcv);

	/* Receive and handle the current packet. */
	bfd_control_recv(bc->bc_csock, bfdd_receive_notification, NULL);

	return 0;
}

int main(int argc, char *argv[])
{
	int opt, csock;

	frr_preinit(&bfdd_di, argc, argv);

	while (true) {
		opt = frr_getopt(argc, argv, NULL);
		if (opt == EOF)
			break;

		switch (opt) {
		default:
			frr_help_exit(1);
			break;
		}
	}

	openzlog(bfdd_di.progname, "BFD", 0, LOG_CONS | LOG_NDELAY | LOG_PID,
		 LOG_DAEMON);

	csock = bfd_control_init();
	if (csock == -1)
		exit(1);

	/* Initialize FRR infrastructure. */
	master = frr_init();

	bfdd_vty_init();

	/* read configuration file and daemonize  */
	frr_config_fork();

	/* Handle BFDd control socket. */
	memset(&bc, 0, sizeof(bc));
	bc.bc_csock = csock;
	thread_add_read(master, bfdd_csock_read, &bc, csock, &bc.bc_threcv);

	/* Enable notifications. */
	do {
		uint16_t reqid;
		uint64_t notifications;

		notifications = BCM_NOTIFY_PEER_STATE | BCM_NOTIFY_CONFIG;
		reqid = bfd_control_send(csock, BMT_NOTIFY, &notifications,
					 sizeof(notifications));
		if (reqid == 0) {
			zlog_err(
				"failed to enable notifications, some features will not work");
			break;
		}

		if (bfd_control_recv(csock, bfdd_receive_id, &reqid) != 0) {
			zlog_err(
				"failed to enable notifications, some features will not work");
		}
	} while (0);

	frr_run(master);
	/* NOTREACHED */

	return 0;
}
