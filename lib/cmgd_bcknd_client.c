/*
 * CMGD Backend Client Library api interfaces
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

#include "northbound.h"
#include "libfrr.h"
#include "lib/cmgd_bcknd_client.h"
#include "lib/cmgd_pb.h"
#include "lib/network.h"
#include "lib/stream.h"

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

const char *cmgd_bcknd_client_names[] = {CMGD_BCKND_CLIENT_STATICD, CMGD_BCKND_CLIENT_BGPD};

typedef struct cmgd_bcknd_client_ctxt_ {
	int conn_fd;
	struct thread_master *tm;
	struct thread *conn_retry_tmr;
	struct thread *conn_read_ev;
	struct thread *conn_write_ev;
	struct thread *msg_proc_ev;

	struct stream_fifo *ibuf_fifo;
	struct stream *ibuf_work;
	// struct stream_fifo *obuf_fifo;
	// struct stream *obuf_work;

	cmgd_bcknd_client_params_t client_params;
} cmgd_bcknd_client_ctxt_t;

static cmgd_bcknd_client_ctxt_t cmgd_bcknd_clntctxt = { 0 };

/* Forward declarations */
static void cmgd_bcknd_client_register_event(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_event_t event);
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
	THREAD_OFF(clnt_ctxt->msg_proc_ev);

	if (reconnect)
		cmgd_bcknd_client_schedule_conn_retry(
			clnt_ctxt, clnt_ctxt->client_params.conn_retry_intvl_sec);
}

static int cmgd_bcknd_client_process_msg(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	uint8_t *bcknd_msg, int bytes_read)
{
	(void) bcknd_msg;
	(void) clnt_ctxt;

	CMGD_BCKND_CLNT_DBG(
		"Got message of %d bytes from CMGD Backend Server", bytes_read);

	return 0;
}

static int cmgd_bcknd_client_proc_msgbufs(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;
	struct stream *work;
	int processed = 0;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	for ( ; processed < CMGD_BCKND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(clnt_ctxt->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_bcknd_client_process_msg(
			clnt_ctxt, STREAM_DATA(work), stream_get_endp(work));

		if (work != clnt_ctxt->ibuf_work) {
			/* Free it up */
			stream_free(work);
		} else {
			/* Reset stream buffer for next read */
			stream_reset(work);
		}
	}

	/*
	 * If we have more to process, reschedule for processing it.
	 */
	if (stream_fifo_head(clnt_ctxt->ibuf_fifo))
		cmgd_bcknd_client_register_event(
			clnt_ctxt, CMGD_BCKND_PROC_MSG);
	
	return 0;
}

static int cmgd_bcknd_client_read(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	cmgd_bcknd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(clnt_ctxt->ibuf_work) - 
		stream_get_endp(clnt_ctxt->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				clnt_ctxt->ibuf_work, clnt_ctxt->conn_fd, bytes_left);
		CMGD_BCKND_CLNT_DBG(
			"Got %d bytes of message from CMGD Backend daemon", 
			bytes_read);
		if (bytes_read <= 0) {
			if (!total_bytes) {
				/* Looks like connection closed */
				CMGD_BCKND_CLNT_ERR(
					"Got error (%d) while reading from CMGD Backend adapter daemon. Err: '%s'", 
					bytes_read, safe_strerror(errno));
				cmgd_bcknd_server_disconnect(clnt_ctxt, true);
				return -1;
			}
			break;
		}

		total_bytes += bytes_read;
		bytes_left -= bytes_read;
	}

	/*
	 * Check if we would have read incomplete messages or not.
	 */
	stream_set_getp(clnt_ctxt->ibuf_work, 0);
	total_bytes = 0;
	msg_cnt = 0;
	bytes_left = stream_get_endp(clnt_ctxt->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_bcknd_msg_hdr_t *)
			(STREAM_DATA(clnt_ctxt->ibuf_work) + total_bytes);
		if (msg_hdr->marker != CMGD_BCKND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			cmgd_bcknd_server_disconnect(clnt_ctxt, true);
			return -1;
		}
		if (msg_hdr->len > bytes_left) {
			/* 
			 * Incomplete message. Terminate the current buffer
			 * and add it to process fifo. And then copy the rest
			 * to a new Ibuf 
			 */
			incomplete = true;
			stream_set_endp(clnt_ctxt->ibuf_work, total_bytes);
			stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);

			clnt_ctxt->ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
			stream_put(clnt_ctxt->ibuf_work, msg_hdr, bytes_left);
			stream_set_endp(clnt_ctxt->ibuf_work, bytes_left);
			break;
		}

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
		msg_cnt++;
	}

	/* 
	 * We would have read one or several messages.
	 * Schedule processing them now.
	 */
	if (!incomplete)
		stream_fifo_push(clnt_ctxt->ibuf_fifo, clnt_ctxt->ibuf_work);
	if (msg_cnt)
		cmgd_bcknd_client_register_event(clnt_ctxt, CMGD_BCKND_PROC_MSG);

	cmgd_bcknd_client_register_event(clnt_ctxt, CMGD_BCKND_CONN_READ);

	return 0;
}

static int cmgd_bcknd_client_write(struct thread *thread)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)THREAD_ARG(thread);
	assert(clnt_ctxt && clnt_ctxt->conn_fd);

	return 0;
}

static int cmgd_bcknd_client_send_msg(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	Cmgd__BckndMessage *bcknd_msg)
{
	int bytes_written;
	size_t msg_size;
	uint8_t msg_buf[CMGD_BCKND_MSG_MAX_LEN];
	cmgd_bcknd_msg_t *msg;

	msg_size = cmgd__bcknd_message__get_packed_size(bcknd_msg);
	msg_size += CMGD_BCKND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		CMGD_BCKND_CLNT_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (cmgd_bcknd_msg_t *)msg_buf;
	msg->hdr.marker = CMGD_BCKND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	cmgd__bcknd_message__pack(bcknd_msg, msg->payload);

	bytes_written = write(clnt_ctxt->conn_fd, (void *)msg_buf, msg_size);
	if (bytes_written != (int) msg_size) {
		CMGD_BCKND_CLNT_ERR(
			"Could not write all %d bytes (wrote: %d) to CMGD Backend server socket. Err: '%s'", 
			(int) msg_size, bytes_written, safe_strerror(errno));
		cmgd_bcknd_server_disconnect(clnt_ctxt, true);
		return -1;
	}

	CMGD_BCKND_CLNT_DBG(
		"Wrote %d bytes of message to CMGD Backend server socket.'", 
		bytes_written);
	return 0;
}

static int cmgd_bcknd_send_subscr_req(cmgd_bcknd_client_ctxt_t *clnt_ctxt, 
	bool subscr_xpaths, uint16_t num_reg_xpaths, char **reg_xpaths)
{
	Cmgd__BckndMessage bcknd_msg;
	Cmgd__BckndSubscribeReq subscr_req;

	cmgd__bcknd_subscribe_req__init(&subscr_req);
	subscr_req.client_name = clnt_ctxt->client_params.name;
	subscr_req.n_xpath_reg = num_reg_xpaths;
	if (num_reg_xpaths)
		subscr_req.xpath_reg = reg_xpaths;
	else
		subscr_req.xpath_reg = NULL;
	subscr_req.subscribe_xpaths = subscr_xpaths;

	cmgd__bcknd_message__init(&bcknd_msg);
	bcknd_msg.type = CMGD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REQ;
	bcknd_msg.message_case = CMGD__BCKND_MESSAGE__MESSAGE_SUBSCR_REQ;
	bcknd_msg.subscr_req = &subscr_req;

	return cmgd_bcknd_client_send_msg(clnt_ctxt, &bcknd_msg);
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

	/* Make client socket non-blocking.  */
	set_nonblocking(sock);

	cmgd_bcknd_client_register_event(clnt_ctxt, CMGD_BCKND_CONN_READ);

	/* Notify client through registered callback (if any) */
	if (clnt_ctxt->client_params.conn_notify_cb)
		(void) (*clnt_ctxt->client_params.conn_notify_cb)(
			(cmgd_lib_hndl_t)clnt_ctxt, 
			clnt_ctxt->client_params.user_data, true);

	/* Send SUBSCRIBE_REQ message */
	if (cmgd_bcknd_send_subscr_req(clnt_ctxt, false, 0, NULL) != 0)
		goto cmgd_bcknd_server_connect_failed;

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

static void cmgd_bcknd_client_register_event(
	cmgd_bcknd_client_ctxt_t *clnt_ctxt, cmgd_event_t event)
{
	switch (event) {
	case CMGD_BCKND_CONN_READ:
		clnt_ctxt->conn_read_ev = 
			thread_add_read(clnt_ctxt->tm,
				cmgd_bcknd_client_read, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case CMGD_BCKND_CONN_WRITE:
		clnt_ctxt->conn_write_ev = 
			thread_add_write(clnt_ctxt->tm,
				cmgd_bcknd_client_write, clnt_ctxt,
				clnt_ctxt->conn_fd, NULL);
		break;
	case CMGD_BCKND_PROC_MSG:
		clnt_ctxt->msg_proc_ev = 
			thread_add_timer_msec(clnt_ctxt->tm,
				cmgd_bcknd_client_proc_msgbufs, clnt_ctxt,
				CMGD_BCKND_MSG_PROC_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_bcknd_clnt_ctxt_post_event() called incorrectly");
	}
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

	assert(!cmgd_bcknd_clntctxt.ibuf_fifo &&
		!cmgd_bcknd_clntctxt.ibuf_work/* &&
		!cmgd_bcknd_clntctxt.obuf_fifo &&
		!cmgd_bcknd_clntctxt.obuf_work*/);
	
	cmgd_bcknd_clntctxt.ibuf_fifo = stream_fifo_new();
	cmgd_bcknd_clntctxt.ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
	// cmgd_bcknd_clntctxt.obuf_fifo = stream_fifo_new();
	// cmgd_bcknd_clntctxt.obuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);

	/* Start trying to connect to CMGD backend server immediately */
	cmgd_bcknd_client_schedule_conn_retry(&cmgd_bcknd_clntctxt, 1);

	CMGD_BCKND_CLNT_DBG("Initialized client '%s'", params->name);

	return (cmgd_lib_hndl_t)&cmgd_bcknd_clntctxt;
}

/*
 * Subscribe with CMGD for one or more YANG subtree(s).
 */
cmgd_result_t cmgd_bcknd_subscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_reg_xpaths)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt) {
		return CMGD_INVALID_PARAM;
	}

	if (cmgd_bcknd_send_subscr_req(
		clnt_ctxt, true, num_reg_xpaths, reg_yang_xpaths) != 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Unsubscribe with CMGD for one or more YANG subtree(s).
 */
cmgd_result_t cmgd_bcknd_unsubscribe_yang_data(
	cmgd_lib_hndl_t lib_hndl, char *reg_yang_xpaths[],
	int num_reg_xpaths)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;


	if (cmgd_bcknd_send_subscr_req(
		clnt_ctxt, false, num_reg_xpaths, reg_yang_xpaths) < 0)
		return CMGD_INTERNAL_ERROR;

	return CMGD_SUCCESS;
}

/*
 * Send one or more YANG notifications to CMGD daemon.
 */
cmgd_result_t cmgd_bcknd_send_yang_notify(
	cmgd_lib_hndl_t lib_hndl, cmgd_yang_data_t *data_elems[],
	int num_elems)
{
	cmgd_bcknd_client_ctxt_t *clnt_ctxt;

	clnt_ctxt = (cmgd_bcknd_client_ctxt_t *)lib_hndl;
	if (!clnt_ctxt)
		return CMGD_INVALID_PARAM;

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

	CMGD_BCKND_CLNT_DBG("Destroying CMGD Backend Client '%s'", 
		clnt_ctxt->client_params.name);

	cmgd_bcknd_server_disconnect(clnt_ctxt, false);

	assert(cmgd_bcknd_clntctxt.ibuf_fifo &&
		cmgd_bcknd_clntctxt.ibuf_work/* &&
		cmgd_bcknd_clntctxt.obuf_fifo &&
		cmgd_bcknd_clntctxt.obuf_work*/);
	
	stream_fifo_free(cmgd_bcknd_clntctxt.ibuf_fifo);
	stream_free(cmgd_bcknd_clntctxt.ibuf_work);
	// stream_fifo_free(cmgd_bcknd_clntctxt.obuf_fifo);
	// stream_free(cmgd_bcknd_clntctxt.obuf_work);
}
