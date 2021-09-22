/*
 * MGMTD Frontend Server
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

#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "mgmtd/mgmt.h"
#include "mgmtd/mgmt_frntnd_server.h"
#include "mgmtd/mgmt_frntnd_adapter.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define MGMTD_FRNTND_SRVR_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define MGMTD_FRNTND_SRVR_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define MGMTD_FRNTND_SRVR_DBG(fmt, ...)				\
	if (mgmt_debug_bcknd)					\
		zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define MGMTD_FRNTND_SRVR_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

static int mgmt_frntnd_listen_fd = 0;
static struct thread_master *mgmt_frntnd_listen_tm = NULL;
static struct thread *mgmt_frntnd_listen_ev = NULL;
static void mgmt_frntnd_server_register_event(mgmt_event_t event);

static int mgmt_frntnd_conn_accept(struct thread *thread)
{
	int client_conn_fd;
	union sockunion su;
	// int ret;
	// unsigned int on;
	// struct prefix p;

	if (!mgmt_frntnd_listen_fd || !mgmt_frntnd_listen_ev)
		return -1;

	/* We continue hearing server listen socket. */
	mgmt_frntnd_server_register_event(MGMTD_FRNTND_SERVER);

	memset(&su, 0, sizeof(union sockunion));

	/* We can handle IPv4 or IPv6 socket. */
	client_conn_fd = sockunion_accept(mgmt_frntnd_listen_fd, &su);
	if (client_conn_fd < 0) {
		MGMTD_FRNTND_SRVR_ERR("Failed to accept MGMTD Frontend client connection : %s",
			 safe_strerror(errno));
		return -1;
	}
	set_nonblocking(client_conn_fd);
	set_cloexec(client_conn_fd);

	MGMTD_FRNTND_SRVR_DBG("Got a new MGMTD Frontend connection");

	mgmt_frntnd_create_adapter(client_conn_fd, &su);

	return 0;
}

static void mgmt_frntnd_server_register_event(mgmt_event_t event)
{
	switch (event) {
	case MGMTD_FRNTND_SERVER:
		mgmt_frntnd_listen_ev = 
			thread_add_read(mgmt_frntnd_listen_tm,
				mgmt_frntnd_conn_accept, NULL, 
				mgmt_frntnd_listen_fd, NULL);
		// vector_set_index(Vvty_serv_thread, sock, vty_serv_thread);
		break;
	default:
		assert(!"mgmt_frntnd_server_post_event() called incorrectly");
	}
}

static void mgmt_frntnd_server_start(const char *hostname)
{
	int ret;
	int sock;
	struct sockaddr_un addr;
	mode_t old_mask;

	/* Set umask */
	old_mask = umask(0077);

	sock = socket(AF_UNIX, SOCK_STREAM, PF_UNSPEC);
	if (sock < 0) {
		MGMTD_FRNTND_SRVR_ERR("Failed to create server socket: %s",
			safe_strerror(errno));
		goto mgmt_frntnd_server_start_failed;
	}

	// sockopt_v6only(AF_UNIX, sock);
	// sockopt_reuseaddr(sock);
	// sockopt_reuseport(sock);
	// set_cloexec(sock);

	// setsockopt_so_recvbuf(sock, 1048576);
	// setsockopt_so_sendbuf(sock, 1048576);

	addr.sun_family = AF_UNIX,
	strlcpy(addr.sun_path, MGMTD_FRNTND_SERVER_PATH, sizeof(addr.sun_path));
	unlink(addr.sun_path);
	ret = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (ret < 0) {
		MGMTD_FRNTND_SRVR_ERR("Failed to bind server socket to '%s'. Err: %s",
			addr.sun_path, safe_strerror(errno));
		goto mgmt_frntnd_server_start_failed;
	}

	ret = listen(sock, MGMTD_FRNTND_MAX_CONN);
	if (ret < 0) {
		MGMTD_FRNTND_SRVR_ERR("Failed to listen on server socket: %s",
			safe_strerror(errno));
		goto mgmt_frntnd_server_start_failed;
	}

	/* Restore umask */
	umask(old_mask);

	mgmt_frntnd_listen_fd = sock;
	mgmt_frntnd_server_register_event(MGMTD_FRNTND_SERVER);

	MGMTD_FRNTND_SRVR_DBG("Started MGMTD Frontend Server!");
	return;

mgmt_frntnd_server_start_failed:
	if (sock) {
		close(sock);
	}
	mgmt_frntnd_listen_fd = 0;
	exit(-1);
}

int mgmt_frntnd_server_init(struct thread_master *master)
{
	if (mgmt_frntnd_listen_tm) {
		MGMTD_FRNTND_SRVR_DBG("MGMTD Frontend Server already running!");
		return 0;
	}

	mgmt_frntnd_listen_tm = master;

	mgmt_frntnd_server_start("localhost");

	return 0;
}

void mgmt_frntnd_server_destroy(void)
{
	if (mgmt_frntnd_listen_tm) {
		MGMTD_FRNTND_SRVR_DBG("Closing MGMTD Frontend Server!");

		if (mgmt_frntnd_listen_ev) {
			THREAD_OFF(mgmt_frntnd_listen_ev);
			mgmt_frntnd_listen_ev = NULL;
		}

		if (mgmt_frntnd_listen_fd) {
			close(mgmt_frntnd_listen_fd);
			mgmt_frntnd_listen_fd = 0;
		}

		mgmt_frntnd_listen_tm = NULL;
	}
}
