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
#define CSOCK_RECONNECT_TIMEOUT (4000) /* milliseconds */

/* Prototypes */
int bfdd_csock_reinit(struct thread *thread);
int bfdd_csock_read(struct thread *thread);

/* Definitions */
struct bfdd_config bc;

static int fd_is_valid(int fd)
{
	return fcntl(fd, F_GETFD) == -1 && errno == EBADF;
}

static int bfdd_reconfigure(int csock)
{
	struct bpc_node *bn;
	struct json_object *jo;
	const char *jsonstr;
	uint16_t id;

	TAILQ_FOREACH (bn, &bc.bc_bnlist, bn_entry) {
		/* Create the request data and send. */
		jo = bfd_ctrl_new_json();
		if (jo == NULL) {
			zlog_err("%s:%d: not enough memory", __FUNCTION__,
				 __LINE__);
			return -1;
		}

		bfd_ctrl_add_peer(jo, &bn->bn_bpc);
		jsonstr = json_object_to_json_string_ext(jo, 0);
		id = bfd_control_send(csock, BMT_REQUEST_ADD, jsonstr,
				      strlen(jsonstr));
		if (id == 0) {
			zlog_err("%s:%d: Failed to reconfigure peer",
				 __FUNCTION__, __LINE__);
			json_object_put(jo);
			return -1;
		}

		if (bfd_control_recv(csock, bfdd_receive_id, &id) != 0) {
			zlog_err("%s:%d: Failed to reconfigure peer",
				 __FUNCTION__, __LINE__);
			json_object_put(jo);
			return -1;
		}

		json_object_put(jo);
	}

	return 0;
}

int bfdd_csock_reinit(struct thread *thread)
{
	struct bfdd_config *bc = THREAD_ARG(thread);
	int csock;
	uint16_t reqid;
	uint64_t notifications;

	bc->bc_thinit = NULL;

	csock = bfd_control_init();
	if (csock == -1) {
		thread_add_timer_msec(master, bfdd_csock_reinit, bc,
				      CSOCK_RECONNECT_TIMEOUT, &bc->bc_thinit);
		return 0;
	}

	/* Enable notifications. */
	notifications = BCM_NOTIFY_PEER_STATE | BCM_NOTIFY_CONFIG;
	reqid = bfd_control_send(csock, BMT_NOTIFY, &notifications,
				 sizeof(notifications));
	if (reqid == 0) {
		zlog_err(
			"failed to enable notifications, some features will not work");
		goto skip_recv_id;
	}

	if (bfd_control_recv(csock, bfdd_receive_id, &reqid) != 0) {
		zlog_err(
			"failed to enable notifications, some features will not work");
		if (!fd_is_valid(csock)) {
			goto close_and_retry;
		}
	}

	if (bfdd_reconfigure(csock) != 0) {
		goto close_and_retry;
	}

skip_recv_id:
	bc->bc_csock = csock;
	thread_add_read(master, bfdd_csock_read, bc, bc->bc_csock,
			&bc->bc_threcv);

	return 0;

close_and_retry:
	close(csock);
	thread_add_timer_msec(master, bfdd_csock_reinit, bc,
			      CSOCK_RECONNECT_TIMEOUT, &bc->bc_thinit);
	return 0;
}

int bfdd_csock_read(struct thread *thread)
{
	struct bfdd_config *bc = THREAD_ARG(thread);

	bc->bc_threcv = NULL;

	/* Receive and handle the current packet. */
	if (bfd_control_recv(bc->bc_csock, bfdd_receive_notification, NULL) != 0
	    && !fd_is_valid(bc->bc_csock)) {
		close(bc->bc_csock);
		bc->bc_csock = -1;
		thread_add_timer_msec(master, bfdd_csock_reinit, bc,
				      CSOCK_RECONNECT_TIMEOUT, &bc->bc_thinit);
		return 0;
	}

	/* Schedule next read. */
	thread_add_read(master, bfdd_csock_read, bc, bc->bc_csock,
			&bc->bc_threcv);

	return 0;
}

int main(int argc, char *argv[])
{
	int opt;

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

	/* Initialize FRR infrastructure. */
	master = frr_init();

	bfdd_vty_init();

	/* read configuration file and daemonize  */
	frr_config_fork();

	/* Handle BFDd control socket. */
	memset(&bc, 0, sizeof(bc));
	thread_add_timer_msec(master, bfdd_csock_reinit, &bc, 1, &bc.bc_thinit);

	frr_run(master);
	/* NOTREACHED */

	return 0;
}
