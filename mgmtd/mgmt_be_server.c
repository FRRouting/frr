/*
 * MGMTD Backend Server
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar <spushpasis@vmware.com>
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
#include "network.h"
#include "libfrr.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_be_server.h"
#include "mgmtd/mgmt_be_adapter.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_BE_SRVR_DBG(fmt, ...)                                         \
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_BE_SRVR_ERR(fmt, ...)                                         \
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_BE_SRVR_DBG(fmt, ...)                                         \
	do {                                                                   \
		if (mgmt_debug_be)                                          \
			zlog_err("%s: " fmt, __func__, ##__VA_ARGS__);         \
	} while (0)
#define MGMTD_BE_SRVR_ERR(fmt, ...)                                         \
	zlog_err("%s: ERROR: " fmt, __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

static int mgmt_be_listen_fd;
static struct thread_master *mgmt_be_listen_tm;
static struct thread *mgmt_be_listen_ev;
static void mgmt_be_server_register_event(enum mgmt_be_event event);

static void mgmt_be_conn_accept(struct thread *thread)
{
	int client_conn_fd;
	union sockunion su;

	if (mgmt_be_listen_fd < 0)
		return;

	/* We continue hearing server listen socket. */
	mgmt_be_server_register_event(MGMTD_BE_SERVER);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	client_conn_fd = sockunion_accept(mgmt_be_listen_fd, &su);
	if (client_conn_fd < 0) {
		MGMTD_BE_SRVR_ERR(
			"Failed to accept MGMTD Backend client connection : %s",
			safe_strerror(errno));
		return;
	}
	set_nonblocking(client_conn_fd);
	set_cloexec(client_conn_fd);

	MGMTD_BE_SRVR_DBG("Got a new MGMTD Backend connection");

	mgmt_be_create_adapter(client_conn_fd, &su);
}

static void mgmt_be_server_register_event(enum mgmt_be_event event)
{
	if (event == MGMTD_BE_SERVER) {
		thread_add_read(mgmt_be_listen_tm, mgmt_be_conn_accept,
				NULL, mgmt_be_listen_fd,
				&mgmt_be_listen_ev);
		assert(mgmt_be_listen_ev);
	} else {
		assert(!"mgmt_be_server_post_event() called incorrectly");
	}
}

static void mgmt_be_server_start(const char *hostname)
{
	int ret;
	int sock;
	struct sockaddr_un addr;
	mode_t old_mask;

	/* Set umask */
	old_mask = umask(0077);

	sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	if (sock < 0) {
		MGMTD_BE_SRVR_ERR("Failed to create server socket: %s",
				     safe_strerror(errno));
		goto mgmt_be_server_start_failed;
	}

	addr.sun_family = AF_UNIX,
	strlcpy(addr.sun_path, MGMTD_BE_SERVER_PATH, sizeof(addr.sun_path));
	unlink(addr.sun_path);
	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		MGMTD_BE_SRVR_ERR(
			"Failed to bind server socket to '%s'. Err: %s",
			addr.sun_path, safe_strerror(errno));
		goto mgmt_be_server_start_failed;
	}

	ret = listen(sock, MGMTD_BE_MAX_CONN);
	if (ret < 0) {
		MGMTD_BE_SRVR_ERR("Failed to listen on server socket: %s",
				     safe_strerror(errno));
		goto mgmt_be_server_start_failed;
	}

	/* Restore umask */
	umask(old_mask);

	mgmt_be_listen_fd = sock;
	mgmt_be_server_register_event(MGMTD_BE_SERVER);

	MGMTD_BE_SRVR_DBG("Started MGMTD Backend Server!");
	return;

mgmt_be_server_start_failed:
	if (sock)
		close(sock);

	mgmt_be_listen_fd = -1;
	exit(-1);
}

int mgmt_be_server_init(struct thread_master *master)
{
	if (mgmt_be_listen_tm) {
		MGMTD_BE_SRVR_DBG("MGMTD Backend Server already running!");
		return 0;
	}

	mgmt_be_listen_tm = master;

	mgmt_be_server_start("localhost");

	return 0;
}

void mgmt_be_server_destroy(void)
{
	if (mgmt_be_listen_tm) {
		MGMTD_BE_SRVR_DBG("Closing MGMTD Backend Server!");

		if (mgmt_be_listen_ev) {
			THREAD_OFF(mgmt_be_listen_ev);
			mgmt_be_listen_ev = NULL;
		}

		if (mgmt_be_listen_fd >= 0) {
			close(mgmt_be_listen_fd);
			mgmt_be_listen_fd = -1;
		}

		mgmt_be_listen_tm = NULL;
	}
}
