/*
 * CMGD Backend Client Library api interfaces
 * Copyright (C) 2021  Vmware, Inc.
 *		       Pushpasis Sarkar
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

#include "northbound.h"
#include "libfrr.h"
#include "lib/cmgd_bcknd_client.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_BCKND_CLNT_DBG(fmt, ...)					\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_BCKND_CLNT_ERR(fmt, ...)					\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_BCKND_CLNT_DBG(fmt, ...)					\
	zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_BCKND_CLNT_ERR(fmt, ...)					\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

typedef struct cmgd_bcknd_client_ctxt_ {
	int conn_fd;
	struct thread_master *tm;
	struct thread *conn_retry_tmr;
	struct thread *conn_read_ev;
	struct thread *conn_write_ev;
	cmgd_bcknd_client_params_t client_params;
} cmgd_bcknd_client_ctxt_t;

static cmgd_bcknd_client_ctxt_t cmgd_bcknd_clntctxt = { 0 };

/* Forward declarations */
static void cmgd_bcknd_client_schedule_conn_retry(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs);

static void cmgd_bcknd_server_disconnect(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, bool reconnect)
{
	if (clnt_ctxt->conn_fd) {
		close(clnt_ctxt->conn_fd);
		clnt_ctxt->conn_fd = 0;
	}

	THREAD_OFF(clnt_ctxt->conn_read_ev);
	THREAD_OFF(clnt_ctxt->conn_retry_tmr);

	if (reconnect)
		cmgd_bcknd_client_schedule_conn_retry(
			clnt_ctxt, clnt_ctxt->client_params.conn_retry_intvl_sec);
}

static int cmgd_bcknd_server_process_msg(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	uint8_t *bkcnd_msg, int bytes_read)
{
	(void) bkcnd_msg;
	(void) clnt_ctxt;

	CMGD_BCKND_CLNT_DBG(
		"Got message of %d bytes from CMGD Backend Server", bytes_read);

	return 0;
}

static int cmgd_bkcnd_client_read(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;
	uint8_t bkcnd_msg[CMGD_BCKND_MSG_MAX_LEN];
	int bytes_read;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	bytes_read = read(clnt_ctxt->conn_fd, bkcnd_msg, sizeof(bkcnd_msg));
	if (bytes_read <= 0) {
		CMGD_BCKND_CLNT_ERR(
			"Got %s from CMGD Backend server socket. Err: '%s'", 
			!bytes_read ? "error while reading" : "disconnected", 
			safe_strerror(errno));
		cmgd_bcknd_server_disconnect(clnt_ctxt, true);
	}

	return cmgd_bcknd_server_process_msg(clnt_ctxt, bkcnd_msg, bytes_read);
}

static int cmgd_bcknd_server_connect(cmgd_bcknd_client_ctxt_t *clnt_ctxt)
{
	int ret, sock, len;
	struct sockaddr_un addr;

	CMGD_BCKND_CLNT_DBG("Trying to connect to CMGD Backend server at %s",
		CMGD_BCKND_SERVER_PATH);

	assert(!clnt_ctxt->conn_fd);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		CMGD_BCKND_CLNT_ERR("Failed to create socket");
		goto cmgd_bcknd_server_connect_failed;
	}

	CMGD_BCKND_CLNT_DBG("Created CMGD Backend server socket successfully!");

	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	strlcpy(addr.sun_path, CMGD_BCKND_SERVER_PATH, sizeof(addr.sun_path));
#ifdef HAVE_STRUCT_SOCKADDR_UN_SUN_LEN
	len = addr.sun_len = SUN_LEN(&addr);
#else
	len = sizeof(addr.sun_family) + strlen(addr.sun_path);
#endif /* HAVE_STRUCT_SOCKADDR_UN_SUN_LEN */

	ret = connect(sock, (struct sockaddr *)&addr, len);
	if (ret < 0) {
		CMGD_BCKND_CLNT_ERR(
			"Failed to connect to CMGD Backend Server at %s. Err: %s",
			addr.sun_path, safe_strerror(errno));
		close(sock);
		goto cmgd_bcknd_server_connect_failed;
	}

	CMGD_BCKND_CLNT_DBG("Connected to CMGD Backend Server at %s successfully!",
		addr.sun_path);
	clnt_ctxt->conn_fd = sock;

	thread_add_read(clnt_ctxt->tm, cmgd_bkcnd_client_read,
		(void *)&cmgd_bcknd_clntctxt, clnt_ctxt->conn_fd,
		&clnt_ctxt->conn_read_ev);

	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void) (*clnt_ctxt->client_params.conn_notify_cb)(
			(cmgd_lib_hndl_t)clnt_ctxt, 
			clnt_ctxt->client_params.user_data, true);

	return 0;

cmgd_bcknd_server_connect_failed:
	if (sock && sock != clnt_ctxt->conn_fd) {
		close(sock);
	}
	cmgd_bcknd_server_disconnect(clnt_ctxt, true);
	return -1;
}

static int cmgd_bcknd_client_conn_timeout(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt);

	clnt_ctxt->conn_retry_tmr = NULL;
	return cmgd_bcknd_server_connect(clnt_ctxt);
}

static void cmgd_bcknd_client_schedule_conn_retry(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, unsigned long intvl_secs)
{
	CMGD_BCKND_CLNT_DBG("Scheduling CMGD Backend server connection retry after %lu seconds",
		intvl_secs);
	clnt_ctxt->conn_retry_tmr = thread_add_timer(
		clnt_ctxt->tm, cmgd_bcknd_client_conn_timeout,
		(void *)clnt_ctxt, intvl_secs, NULL);
}

/*
 * Initialize library and try connecting with CMGD.
 */
cmgd_lib_hndl_t cmgd_bcknd_client_lib_init(
	cmgd_bcknd_client_params_t *params, 
	struct thread_master *master_thread)
{
	assert(master_thread && params && 
		strlen(params->name) && !cmgd_bcknd_clntctxt.tm);

	cmgd_bcknd_clntctxt.tm = master_thread;
	memcpy(&cmgd_bcknd_clntctxt.client_params, params, 
		sizeof(cmgd_bcknd_clntctxt.client_params));
	if (!cmgd_bcknd_clntctxt.client_params.conn_retry_intvl_sec) 
		cmgd_bcknd_clntctxt.client_params.conn_retry_intvl_sec = 
			CMGD_BCKND_DEFAULT_CONN_RETRY_INTVL_SEC;

	/* Start trying to connect to CMGD backend server immediately */
	cmgd_bcknd_client_schedule_conn_retry(&cmgd_bcknd_clntctxt, 1);

	CMGD_BCKND_CLNT_DBG("Initialized client '%s'", params->name);

	return (cmgd_lib_hndl_t)&cmgd_bcknd_clntctxt;
}

/*
 * Subscribe with CMGD for one or more YANG subtree(s).
 */
cmgd_result_t cmgd_bcknd_subscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, struct nb_yang_xpath *xpaths[],
	int num_xpaths)
{
	return CMGD_SUCCESS;
}

/*
 * Send one or more YANG notifications to CMGD daemon.
 */
cmgd_result_t cmgd_bcknd_send_yang_notify(
	cmgd_lib_hndl_t lib_hndl, struct nb_yang_xpath_elem *elems[],
	int num_elems)
{
	return CMGD_SUCCESS;
}

/*
 * Destroy library and cleanup everything.
 */
void cmgd_bcknd_client_lib_destroy(cmgd_lib_hndl_t lib_hndl)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	assert(clnt_ctxt);

	cmgd_bcknd_server_disconnect(clnt_ctxt, false);
}
