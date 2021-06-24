/*
 * CMGD Backend Client Connection Adapter
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

#include "thread.h"
#include "sockunion.h"
#include "prefix.h"
#include "network.h"
#include "lib/libfrr.h"
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_bcknd_client.h"
#include "cmgd/cmgd_bcknd_adapter.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_BCKND_ADPTR_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_BCKND_ADPTR_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_BCKND_ADPTR_DBG(fmt, ...)				\
	zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_BCKND_ADPTR_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADPTR_IN_LIST(adptr)						\
	for ((adptr) = cmgd_adptr_list_first(&cmgd_bcknd_adptrs); (adptr);	\
		(adptr) = cmgd_adptr_list_next(&cmgd_bcknd_adptrs, (adptr)))

static struct thread_master *cmgd_bcknd_adptr_tm = NULL;

static struct cmgd_adptr_list_head cmgd_bcknd_adptrs = {0};

static void cmgd_bcknd_adptr_register_event(
	cmgd_bcknd_client_adapter_t *adptr, cmgd_bcknd_event_t event);

static cmgd_bcknd_client_adapter_t *cmgd_bcknd_find_adapter_by_fd(int conn_fd)
{
	cmgd_bcknd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (adptr->conn_fd == conn_fd) 
			return adptr;
	}

	return NULL;
}

static cmgd_bcknd_client_adapter_t *cmgd_bcknd_find_adapter_by_name(const char *name)
{
	cmgd_bcknd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (!strncmp(adptr->name, name, sizeof(adptr->name)))
			return adptr;
	}

	return NULL;
}

static void cmgd_bcknd_adapter_disconnect(cmgd_bcknd_client_adapter_t *adptr)
{
	if (adptr->conn_fd) {
		close(adptr->conn_fd);
		adptr->conn_fd = 0;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */

	cmgd_adptr_list_del(&cmgd_bcknd_adptrs, adptr);

	cmgd_bcknd_adapter_unlock(&adptr);
}

static void cmgd_bcknd_adapter_cleanup_old_conn(
	cmgd_bcknd_client_adapter_t *adptr)
{
	cmgd_bcknd_client_adapter_t *old;

	FOREACH_ADPTR_IN_LIST(old) {
		if (old != adptr &&
			!strncmp(adptr->name, old->name, sizeof(adptr->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			CMGD_BCKND_ADPTR_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adptr->name, adptr->conn_fd, old->conn_fd);
			cmgd_bcknd_adapter_disconnect(old);
		}
	}
}

static int cmgd_bcknd_adapter_handle_msg(
	cmgd_bcknd_client_adapter_t *adptr, Cmgd__BckndMessage *bcknd_msg)
{
	switch(bcknd_msg->type) {
	case CMGD__BCKND_MESSAGE__TYPE__SUBSCRIBE_REQ:
		assert(bcknd_msg->message_case == CMGD__BCKND_MESSAGE__MESSAGE_SUBSCR_REQ);
		CMGD_BCKND_ADPTR_DBG(
			"Got Subscribe Req Msg from '%s' to %sregister %u xpaths", 
			bcknd_msg->subscr_req->client_name, 
			!bcknd_msg->subscr_req->subscribe_xpaths && 
			bcknd_msg->subscr_req->n_xpath_reg ? "de" : "", 
			(uint32_t)bcknd_msg->subscr_req->n_xpath_reg);

		if (strlen(bcknd_msg->subscr_req->client_name)) {
			strlcpy(adptr->name, bcknd_msg->subscr_req->client_name, 
				sizeof(adptr->name));
			cmgd_bcknd_adapter_cleanup_old_conn(adptr);
		}
		break;
	default:
		break;
	}

	return 0;
}

static uint16_t cmgd_bcknd_adapter_process_msg(
	cmgd_bcknd_client_adapter_t *adptr, uint8_t *msg_buf, uint16_t bytes_read)
{
	Cmgd__BckndMessage *bcknd_msg;
	cmgd_bcknd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	bytes_left = bytes_read;
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (cmgd_bcknd_msg_t *)msg_buf;
		if (msg->hdr.marker != CMGD_BCKND_MSG_MARKER) {
			CMGD_BCKND_ADPTR_DBG(
				"Marker not found in message from CMGD Backend adapter '%s'", 
				adptr->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			CMGD_BCKND_ADPTR_DBG(
				"Incomplete message of %d bytes (epxected: %u) from CMGD Backend adapter '%s'", 
				bytes_left, msg->hdr.len, adptr->name);
			break;
		}

		bcknd_msg = cmgd__bcknd_message__unpack(
			NULL, (size_t) (msg->hdr.len - CMGD_BCKND_MSG_HDR_LEN), 
			msg->payload);
		if (!bcknd_msg) {
			CMGD_BCKND_ADPTR_DBG(
				"Failed to decode %d bytes from CMGD Backend adapter '%s'", 
				msg->hdr.len, adptr->name);
			continue;
		}

		(void) cmgd_bcknd_adapter_handle_msg(adptr, bcknd_msg);
		cmgd__bcknd_message__free_unpacked(bcknd_msg, NULL);
		processed++;
	}

	return processed;
}

static int cmgd_bcknd_adapter_proc_msgbufs(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	struct stream *work;
	int processed = 0;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	for ( ; processed < CMGD_BCKND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(adptr->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_bcknd_adapter_process_msg(
			adptr, STREAM_DATA(work), stream_get_endp(work));

		if (work != adptr->ibuf_work) {
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
	if (stream_fifo_head(adptr->ibuf_fifo))
		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_PROC_MSG);
	
	return 0;
}

static int cmgd_bcknd_adapter_read(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	int bytes_read;
	size_t total_bytes, bytes_left;
	cmgd_bcknd_msg_hdr_t *msg_hdr;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adptr->ibuf_work) - 
		stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				adptr->ibuf_work, adptr->conn_fd, bytes_left);
		CMGD_BCKND_ADPTR_DBG(
			"Got %d bytes of message from CMGD Backend adapter '%s'", 
			bytes_read, adptr->name);
		if (bytes_read <= 0) {
			if (!total_bytes) {
				/* Looks like connection closed */
				CMGD_BCKND_ADPTR_ERR(
					"Got error (%d) while reading from CMGD Backend adapter '%s'. Err: '%s'", 
					bytes_read, adptr->name, safe_strerror(errno));
				cmgd_bcknd_adapter_disconnect(adptr);
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
	stream_set_getp(adptr->ibuf_work, 0);
	total_bytes = 0;
	bytes_left = stream_get_endp(adptr->ibuf_work) - 
			stream_get_getp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_BCKND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_bcknd_msg_hdr_t *)
			(STREAM_DATA(adptr->ibuf_work) + 
			stream_get_getp(adptr->ibuf_work));
		if (msg_hdr->marker != CMGD_BCKND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			cmgd_bcknd_adapter_disconnect(adptr);
			return -1;
		}
		if (msg_hdr->len > bytes_left) {
			/* 
			 * Incomplete message. Terminate the current buffer
			 * and add it to process fifo. And then copy the rest
			 * to a new Ibuf 
			 */
			stream_set_endp(adptr->ibuf_work, total_bytes);
			stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);
			adptr->ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
			stream_put(adptr->ibuf_work, msg_hdr, bytes_left);

			cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_READ);
		}

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
	}

	/* 
	 * We would have read one or several messages.
	 * Schedule processing them now.
	 */
	stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);
	cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_PROC_MSG);

	return 0;
}

static int cmgd_bcknd_adapter_write(struct thread *thread)
{
	cmgd_bcknd_client_adapter_t *adptr;
	// uint8_t bkcnd_msg[CMGD_BCKND_MSG_MAX_LEN];
	//int bytes_read;

	adptr = (cmgd_bcknd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	return 0;
}

static void cmgd_bcknd_adptr_register_event(
	cmgd_bcknd_client_adapter_t *adptr, cmgd_bcknd_event_t event)
{
	switch (event) {
	case CMGD_BCKND_CONN_READ:
		adptr->conn_read_ev = 
			thread_add_read(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_read, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_BCKND_CONN_WRITE:
		adptr->conn_read_ev = 
			thread_add_write(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_write, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_BCKND_PROC_MSG:
		adptr->proc_msg_ev = 
			thread_add_timer_msec(cmgd_bcknd_adptr_tm,
				cmgd_bcknd_adapter_proc_msgbufs, adptr,
				CMGD_BCKND_MSG_PROC_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_bcknd_adptr_post_event() called incorrectly");
	}
}

void cmgd_bcknd_adapter_lock(cmgd_bcknd_client_adapter_t *adptr)
{
	adptr->refcount++;
}

extern void cmgd_bcknd_adapter_unlock(cmgd_bcknd_client_adapter_t **adptr)
{
	assert(*adptr && (*adptr)->refcount);

	(*adptr)->refcount--;
	if (!(*adptr)->refcount) {
		cmgd_adptr_list_del(&cmgd_bcknd_adptrs, *adptr);

		stream_fifo_free((*adptr)->ibuf_fifo);
		stream_free((*adptr)->ibuf_work);
		// stream_fifo_free((*adptr)->obuf_fifo);
		// stream_free((*adptr)->obuf_work);

		XFREE(MTYPE_CMGD_BCKND_ADPATER, *adptr);
	}

	*adptr = NULL;
}

int cmgd_bcknd_adapter_init(struct thread_master *tm)
{
	if (!cmgd_bcknd_adptr_tm) {
		cmgd_bcknd_adptr_tm = tm;
		cmgd_adptr_list_init(&cmgd_bcknd_adptrs);
	}

	return 0;
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_create_adapter(
	int conn_fd, union sockunion *from)
{
	cmgd_bcknd_client_adapter_t *adptr = NULL;

	adptr = cmgd_bcknd_find_adapter_by_fd(conn_fd);
	if (!adptr) {
		adptr = XMALLOC(MTYPE_CMGD_BCKND_ADPATER, 
				sizeof(cmgd_bcknd_client_adapter_t));
		assert(adptr);

		adptr->conn_fd = conn_fd;
		memcpy(&adptr->conn_su, from, sizeof(adptr->conn_su));
		snprintf(adptr->name, sizeof(adptr->name), "Unknown-FD-%d", adptr->conn_fd);
		adptr->ibuf_fifo = stream_fifo_new();
		adptr->ibuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
		// adptr->obuf_fifo = stream_fifo_new();
		// adptr->obuf_work = stream_new(CMGD_BCKND_MSG_MAX_LEN);
		cmgd_bcknd_adapter_lock(adptr);

		cmgd_bcknd_adptr_register_event(adptr, CMGD_BCKND_CONN_READ);
		cmgd_adptr_list_add_tail(&cmgd_bcknd_adptrs, adptr);

		CMGD_BCKND_ADPTR_DBG(
			"Added new CMGD Backend adapter '%s'", adptr->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adptr->conn_fd);

	return adptr;
}

cmgd_bcknd_client_adapter_t *cmgd_bcknd_get_adapter(const char *name)
{
	return cmgd_bcknd_find_adapter_by_name(name);
}

int cmgd_bcknd_create_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id)
{
	return 0;
}

int cmgd_bcknd_destroy_trxn(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id)
{
	return 0;
}

int cmgd_bcknd_send_cfg_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_cfgreq_t *cfg_req)
{
	return 0;
}

int cmgd_bcknd_send_get_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req)
{
	return 0;
}

int cmgd_bcknd_send_get_next_data_req(
        cmgd_bcknd_client_adapter_t *adptr, cmgd_trxn_id_t trxn_id,
        cmgd_trxn_batch_id_t batch_id, cmgd_bcknd_datareq_t *data_req)
{
	return 0;
}

void cmgd_bcknd_adapter_status_write(struct vty *vty)
{
	cmgd_bcknd_client_adapter_t *adptr;
	uint8_t indx;

	vty_out(vty, "CMGD Backend Adpaters\n");

	FOREACH_ADPTR_IN_LIST(adptr) {
		vty_out(vty, "  Client: \t\t\t%s\n", adptr->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adptr->conn_fd);
		vty_out(vty, "    Total Xpaths Registered: \t%u\n", 
			adptr->num_xpath_reg);
		for (indx = 0; indx < adptr->num_xpath_reg; indx++)
			if (strlen(adptr->xpath_reg[indx]))
				vty_out(vty, "    [%u] %s\n", 
					indx, adptr->xpath_reg[indx]);
	}
	vty_out(vty, "  Total: %d\n", 
		(int) cmgd_adptr_list_count(&cmgd_bcknd_adptrs));
}
