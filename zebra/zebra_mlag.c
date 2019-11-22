/* Zebra Mlag Code.
 * Copyright (C) 2018 Cumulus Networks, Inc.
 *                    Donald Sharp
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
#include "zebra.h"

#include "command.h"
#include "hook.h"
#include "frr_pthread.h"
#include "mlag.h"

#include "zebra/zebra_mlag.h"
#include "zebra/zebra_mlag_private.h"
#include "zebra/zebra_router.h"
#include "zebra/zebra_memory.h"
#include "zebra/zapi_msg.h"
#include "zebra/debug.h"

#ifndef VTYSH_EXTRACT_PL
#include "zebra/zebra_mlag_clippy.c"
#endif

#define ZEBRA_MLAG_METADATA_LEN 4
#define ZEBRA_MLAG_MSG_BCAST 0xFFFFFFFF

uint8_t mlag_wr_buffer[ZEBRA_MLAG_BUF_LIMIT];
uint8_t mlag_rd_buffer[ZEBRA_MLAG_BUF_LIMIT];
uint32_t mlag_rd_buf_offset;

static bool test_mlag_in_progress;

static int zebra_mlag_signal_write_thread(void);
static int zebra_mlag_terminate_pthread(struct thread *event);
static int zebra_mlag_post_data_from_main_thread(struct thread *thread);
static void zebra_mlag_publish_process_state(struct zserv *client,
					     zebra_message_types_t msg_type);

/**********************MLAG Interaction***************************************/

/*
 * API to post the Registration to MLAGD
 * MLAG will not process any messages with out the registration
 */
void zebra_mlag_send_register(void)
{
	struct stream *s = NULL;

	s = stream_new(sizeof(struct mlag_msg));

	stream_putl(s, MLAG_REGISTER);
	stream_putw(s, MLAG_MSG_NULL_PAYLOAD);
	stream_putw(s, MLAG_MSG_NO_BATCH);
	stream_fifo_push_safe(zrouter.mlag_info.mlag_fifo, s);
	zebra_mlag_signal_write_thread();

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Enqueued MLAG Register to MLAG Thread ",
			   __func__);
}

/*
 * API to post the De-Registration to MLAGD
 * MLAG will not process any messages after the de-registration
 */
void zebra_mlag_send_deregister(void)
{
	struct stream *s = NULL;

	s = stream_new(sizeof(struct mlag_msg));

	stream_putl(s, MLAG_DEREGISTER);
	stream_putw(s, MLAG_MSG_NULL_PAYLOAD);
	stream_putw(s, MLAG_MSG_NO_BATCH);
	stream_fifo_push_safe(zrouter.mlag_info.mlag_fifo, s);
	zebra_mlag_signal_write_thread();

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Enqueued MLAG De-Register to MLAG Thread ",
			   __func__);
}

/*
 * API To handle MLAG Received data
 * Decodes the data using protobuf and enqueue to main thread
 * main thread publish this to clients based on client subscription
 */
void zebra_mlag_process_mlag_data(uint8_t *data, uint32_t len)
{
	struct stream *s = NULL;
	struct stream *s1 = NULL;
	int msg_type = 0;

	s = stream_new(ZEBRA_MAX_PACKET_SIZ);
	msg_type = zebra_mlag_protobuf_decode_message(s, data, len);

	if (msg_type <= 0) {
		/* Something went wrong in decoding */
		stream_free(s);
		zlog_err("%s: failed to process mlag data-%d, %u", __func__,
			 msg_type, len);
		return;
	}

	/*
	 * additional four bytes are for message type
	 */
	s1 = stream_new(stream_get_endp(s) + ZEBRA_MLAG_METADATA_LEN);
	stream_putl(s1, msg_type);
	stream_put(s1, s->data, stream_get_endp(s));
	thread_add_event(zrouter.master, zebra_mlag_post_data_from_main_thread,
			 s1, 0, NULL);
	stream_free(s);
}

/**********************End of MLAG Interaction********************************/

/************************MLAG Thread Processing*******************************/

/*
 * after posting every 'ZEBRA_MLAG_POST_LIMIT' packets, MLAG Thread will be
 * yielded to give CPU for other threads
 */
#define ZEBRA_MLAG_POST_LIMIT 100

/*
 * This thread reads the clients data from the Global queue and encodes with
 * protobuf and pass on to the MLAG socket.
 */
static int zebra_mlag_client_msg_handler(struct thread *event)
{
	struct stream *s;
	uint32_t wr_count = 0;
	uint32_t msg_type = 0;
	uint32_t max_count = 0;
	int len = 0;

	wr_count = stream_fifo_count_safe(zrouter.mlag_info.mlag_fifo);
	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug(":%s: Processing MLAG write, %u messages in queue",
			   __func__, wr_count);

	max_count = MIN(wr_count, ZEBRA_MLAG_POST_LIMIT);

	for (wr_count = 0; wr_count < max_count; wr_count++) {
		s = stream_fifo_pop_safe(zrouter.mlag_info.mlag_fifo);
		if (!s) {
			zlog_debug(":%s: Got a NULL Messages, some thing wrong",
				   __func__);
			break;
		}

		/*
		 * Encode the data now
		 */
		len = zebra_mlag_protobuf_encode_client_data(s, &msg_type);

		/*
		 * write to MCLAGD
		 */
		if (len > 0) {
			zebra_mlag_private_write_data(mlag_wr_buffer, len);

			/*
			 * If message type is De-register, send a signal to main
			 * thread, so that necessary cleanup will be done by
			 * main thread.
			 */
			if (msg_type == MLAG_DEREGISTER) {
				thread_add_event(zrouter.master,
						 zebra_mlag_terminate_pthread,
						 NULL, 0, NULL);
			}
		}

		stream_free(s);
	}

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug(":%s: Posted  %d messages to MLAGD", __func__,
			   wr_count);
	/*
	 * Currently there is only message write task is enqueued to this
	 * thread, yielding was added for future purpose, so that this thread
	 * can server other tasks also and in case FIFO is empty, this task will
	 * be schedule when main thread adds some messages
	 */
	if (wr_count >= ZEBRA_MLAG_POST_LIMIT)
		zebra_mlag_signal_write_thread();
	return 0;
}

/*
 * API to handle the process state.
 * In case of Down, Zebra keep monitoring the MLAG state.
 * all the state Notifications will be published to clients
 */
void zebra_mlag_handle_process_state(enum zebra_mlag_state state)
{
	if (state == MLAG_UP) {
		zrouter.mlag_info.connected = true;
		zebra_mlag_publish_process_state(NULL, ZEBRA_MLAG_PROCESS_UP);
		zebra_mlag_send_register();
	} else if (state == MLAG_DOWN) {
		zrouter.mlag_info.connected = false;
		zebra_mlag_publish_process_state(NULL, ZEBRA_MLAG_PROCESS_DOWN);
		zebra_mlag_private_monitor_state();
	}
}

/***********************End of MLAG Thread processing*************************/

/*************************Multi-entratnt Api's********************************/

/*
 * Provider api to signal that work/events are available
 * for the Zebra MLAG Write pthread.
 * This API is called from 2 pthreads..
 * 1) by main thread when client posts a MLAG Message
 * 2) by MLAG Thread, in case of yield
 * though this api, is called from two threads we don't need any locking
 * because Thread task enqueue is thread safe means internally it had
 * necessary protection
 */
static int zebra_mlag_signal_write_thread(void)
{
	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug(":%s: Scheduling MLAG write", __func__);
	/*
	 * This api will be called from Both main & MLAG Threads.
	 * main thread writes, "zrouter.mlag_info.th_master" only
	 * during Zebra Init/after MLAG thread is destroyed.
	 * so it is safe to use without any locking
	 */
	thread_add_event(zrouter.mlag_info.th_master,
			 zebra_mlag_client_msg_handler, NULL, 0,
			 &zrouter.mlag_info.t_write);
	return 0;
}

/*
 * API will be used to publish the MLAG state to interested clients
 * In case client is passed, state is posted only for that client,
 * otherwise to all interested clients
 * this api can be called from two threads.
 * 1) from main thread: when client is passed
 * 2) from MLAG Thread: when client is NULL
 *
 * In second case, to avoid global data access data will be post to Main
 * thread, so that actual posting to clients will happen from Main thread.
 */
static void zebra_mlag_publish_process_state(struct zserv *client,
					     zebra_message_types_t msg_type)
{
	struct stream *s;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Publishing MLAG process state:%s to %s Client",
			   __func__,
			   (msg_type == ZEBRA_MLAG_PROCESS_UP) ? "UP" : "DOWN",
			   (client) ? "one" : "all");

	if (client) {
		s = stream_new(ZEBRA_HEADER_SIZE);
		zclient_create_header(s, msg_type, VRF_DEFAULT);
		zserv_send_message(client, s);
		return;
	}


	/*
	 * additional four bytes are for mesasge type
	 */
	s = stream_new(ZEBRA_HEADER_SIZE + ZEBRA_MLAG_METADATA_LEN);
	stream_putl(s, ZEBRA_MLAG_MSG_BCAST);
	zclient_create_header(s, msg_type, VRF_DEFAULT);
	thread_add_event(zrouter.master, zebra_mlag_post_data_from_main_thread,
			 s, 0, NULL);
}

/**************************End of Multi-entrant Apis**************************/

/***********************Zebra Main thread processing**************************/

/*
 * To avoid data corruption, messages will be post to clients only from
 * main thread, because for that access was needed for clients list.
 * so instead of forcing the locks, messages will be posted from main thread.
 */
static int zebra_mlag_post_data_from_main_thread(struct thread *thread)
{
	struct stream *s = THREAD_ARG(thread);
	struct stream *zebra_s = NULL;
	struct listnode *node;
	struct zserv *client;
	uint32_t msg_type = 0;
	uint32_t msg_len = 0;

	if (!s)
		return -1;

	STREAM_GETL(s, msg_type);
	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug(
			"%s: Posting MLAG data for msg_type:0x%x to interested cleints",
			__func__, msg_type);

	msg_len = s->endp - ZEBRA_MLAG_METADATA_LEN;
	for (ALL_LIST_ELEMENTS_RO(zrouter.client_list, node, client)) {
		if (client->mlag_updates_interested == true) {
			if (msg_type != ZEBRA_MLAG_MSG_BCAST
			    && !CHECK_FLAG(client->mlag_reg_mask1,
					   (1 << msg_type))) {
				continue;
			}

			if (IS_ZEBRA_DEBUG_MLAG)
				zlog_debug(
					"%s: Posting MLAG data of length-%d to client:%d ",
					__func__, msg_len, client->proto);

			zebra_s = stream_new(msg_len);
			STREAM_GET(zebra_s->data, s, msg_len);
			zebra_s->endp = msg_len;
			stream_putw_at(zebra_s, 0, msg_len);

			/*
			 * This stream will be enqueued to client_obuf, it will
			 * be freed after posting to client socket.
			 */
			zserv_send_message(client, zebra_s);
			zebra_s = NULL;
		}
	}

	stream_free(s);
	return 0;
stream_failure:
	stream_free(s);
	if (zebra_s)
		stream_free(zebra_s);
	return 0;
}

/*
 * Start the MLAG Thread, this will be used to write client data on to
 * MLAG Process and to read the data from MLAG and post to cleints.
 * when all clients are un-registered, this Thread will be
 * suspended.
 */
static void zebra_mlag_spawn_pthread(void)
{
	/* Start MLAG write pthread */

	struct frr_pthread_attr pattr = {.start =
						 frr_pthread_attr_default.start,
					 .stop = frr_pthread_attr_default.stop};

	zrouter.mlag_info.zebra_pth_mlag =
		frr_pthread_new(&pattr, "Zebra MLAG thread", "Zebra MLAG");

	zrouter.mlag_info.th_master = zrouter.mlag_info.zebra_pth_mlag->master;


	/* Enqueue an initial event to the Newly spawn MLAG pthread */
	zebra_mlag_signal_write_thread();

	frr_pthread_run(zrouter.mlag_info.zebra_pth_mlag, NULL);
}

/*
 * all clients are un-registered for MLAG Updates, terminate the
 * MLAG write thread
 */
static int zebra_mlag_terminate_pthread(struct thread *event)
{
	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Zebra MLAG write thread terminate called");

	if (zrouter.mlag_info.clients_interested_cnt) {
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug(
				"Zebra MLAG: still some clients are interested");
		return 0;
	}

	frr_pthread_stop(zrouter.mlag_info.zebra_pth_mlag, NULL);

	/* Destroy pthread */
	frr_pthread_destroy(zrouter.mlag_info.zebra_pth_mlag);
	zrouter.mlag_info.zebra_pth_mlag = NULL;
	zrouter.mlag_info.th_master = NULL;
	zrouter.mlag_info.t_read = NULL;
	zrouter.mlag_info.t_write = NULL;

	/*
	 * Send Notification to clean private data
	 */
	zebra_mlag_private_cleanup_data();
	return 0;
}

/*
 * API to register zebra client for MLAG Updates
 */
void zebra_mlag_client_register(ZAPI_HANDLER_ARGS)
{
	struct stream *s;
	uint32_t reg_mask = 0;
	int rc = 0;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Received MLAG Registration from client-proto:%d",
			   client->proto);


	/* Get input stream.  */
	s = msg;

	/* Get data. */
	STREAM_GETL(s, reg_mask);

	if (client->mlag_updates_interested == true) {

		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug(
				"Client is registered, existing mask: 0x%x, new mask: 0x%x",
				client->mlag_reg_mask1, reg_mask);
		if (client->mlag_reg_mask1 != reg_mask)
			client->mlag_reg_mask1 = reg_mask;
		/*
		 * Client might missed MLAG-UP Notification, post-it again
		 */
		zebra_mlag_publish_process_state(client, ZEBRA_MLAG_PROCESS_UP);
		return;
	}


	client->mlag_updates_interested = true;
	client->mlag_reg_mask1 = reg_mask;
	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Registering for MLAG Updates with mask: 0x%x, ",
			   client->mlag_reg_mask1);

	zrouter.mlag_info.clients_interested_cnt++;

	if (zrouter.mlag_info.clients_interested_cnt == 1) {
		/*
		 * First-client for MLAG Updates,open the communication channel
		 * with MLAG
		 */
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug(
				"First client, opening the channel with MLAG");

		zebra_mlag_spawn_pthread();
		rc = zebra_mlag_private_open_channel();
		if (rc < 0) {
			/*
			 * For some reason, zebra not able to open the
			 * comm-channel with MLAG, so post MLAG-DOWN to client.
			 * later when the channel is open, zebra will send
			 * MLAG-UP
			 */
			if (IS_ZEBRA_DEBUG_MLAG)
				zlog_debug(
					"Fail to open channel with MLAG,rc:%d, post Proto-down",
					rc);
			zebra_mlag_publish_process_state(
				client, ZEBRA_MLAG_PROCESS_DOWN);
		}
	}

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Client Registered successfully for MLAG Updates");

	if (zrouter.mlag_info.connected == true)
		zebra_mlag_publish_process_state(client, ZEBRA_MLAG_PROCESS_UP);
stream_failure:
	return;
}

/*
 * API to un-register for MLAG Updates
 */
void zebra_mlag_client_unregister(ZAPI_HANDLER_ARGS)
{
	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Received MLAG De-Registration from client-proto:%d",
			   client->proto);

	if (client->mlag_updates_interested == false)
		/* Unexpected */
		return;

	client->mlag_updates_interested = false;
	client->mlag_reg_mask1 = 0;
	zrouter.mlag_info.clients_interested_cnt--;

	if (zrouter.mlag_info.clients_interested_cnt == 0) {
		/*
		 * No-client is interested for MLAG Updates,close the
		 * communication channel with MLAG
		 */
		if (IS_ZEBRA_DEBUG_MLAG)
			zlog_debug("Last client for MLAG, close the channel ");

		/*
		 * Clean up flow:
		 * =============
		 * 1) main thread calls socket close which posts De-register
		 * to MLAG write thread
		 * 2) after MLAG write thread posts De-register it sends a
		 * signal back to main thread to do the thread cleanup
		 * this was mainly to make sure De-register is posted to MCLAGD.
		 */
		zebra_mlag_private_close_channel();
	}

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug(
			"Client De-Registered successfully for MLAG Updates");
}

/*
 * Does following things.
 * 1) allocated new local stream, and copies the client data and enqueue
 *    to MLAG Thread
 *  2) MLAG Thread after dequeing, encode the client data using protobuf
 *     and write on to MLAG
 */
void zebra_mlag_forward_client_msg(ZAPI_HANDLER_ARGS)
{
	struct stream *zebra_s;
	struct stream *mlag_s;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Received Client MLAG Data from client-proto:%d",
			   client->proto);

	/* Get input stream.  */
	zebra_s = msg;
	mlag_s = stream_new(zebra_s->endp);

	/*
	 * Client data is | Zebra Header + MLAG Data |
	 * we need to enqueue only the MLAG data, skipping Zebra Header
	 */
	stream_put(mlag_s, zebra_s->data + zebra_s->getp,
		   STREAM_READABLE(zebra_s));
	stream_fifo_push_safe(zrouter.mlag_info.mlag_fifo, mlag_s);
	zebra_mlag_signal_write_thread();

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Enqueued Client:%d data to MLAG Thread ",
			   __func__, client->proto);
}

/***********************End of Zebra Main thread processing*************/

enum mlag_role zebra_mlag_get_role(void)
{
	return zrouter.mlag_info.role;
}

DEFUN_HIDDEN (show_mlag,
	      show_mlag_cmd,
	      "show zebra mlag",
	      SHOW_STR
	      ZEBRA_STR
	      "The mlag role on this machine\n")
{
	char buf[MLAG_ROLE_STRSIZE];

	vty_out(vty, "MLag is configured to: %s\n",
		mlag_role2str(zrouter.mlag_info.role, buf, sizeof(buf)));

	return CMD_SUCCESS;
}

DEFPY_HIDDEN(test_mlag, test_mlag_cmd,
	     "test zebra mlag <none$none|primary$primary|secondary$secondary>",
	     "Test code\n"
	     ZEBRA_STR
	     "Modify the Mlag state\n"
	     "Mlag is not setup on the machine\n"
	     "Mlag is setup to be primary\n"
	     "Mlag is setup to be the secondary\n")
{
	enum mlag_role orig = zrouter.mlag_info.role;
	char buf1[MLAG_ROLE_STRSIZE], buf2[MLAG_ROLE_STRSIZE];

	if (none)
		zrouter.mlag_info.role = MLAG_ROLE_NONE;
	if (primary)
		zrouter.mlag_info.role = MLAG_ROLE_PRIMARY;
	if (secondary)
		zrouter.mlag_info.role = MLAG_ROLE_SECONDARY;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("Test: Changing role from %s to %s",
			   mlag_role2str(orig, buf1, sizeof(buf1)),
			   mlag_role2str(orig, buf2, sizeof(buf2)));

	if (orig != zrouter.mlag_info.role) {
		zsend_capabilities_all_clients();
		if (zrouter.mlag_info.role != MLAG_ROLE_NONE) {
			if (zrouter.mlag_info.clients_interested_cnt == 0
			    && test_mlag_in_progress == false) {
				if (zrouter.mlag_info.zebra_pth_mlag == NULL)
					zebra_mlag_spawn_pthread();
				zrouter.mlag_info.clients_interested_cnt++;
				test_mlag_in_progress = true;
				zebra_mlag_private_open_channel();
			}
		} else {
			if (test_mlag_in_progress == true) {
				test_mlag_in_progress = false;
				zrouter.mlag_info.clients_interested_cnt--;
				zebra_mlag_private_close_channel();
			}
		}
	}

	return CMD_SUCCESS;
}

void zebra_mlag_init(void)
{
	install_element(VIEW_NODE, &show_mlag_cmd);
	install_element(ENABLE_NODE, &test_mlag_cmd);

	/*
	 * Intialiaze the MLAG Global variables
	 * write thread will be created during actual registration with MCLAG
	 */
	zrouter.mlag_info.clients_interested_cnt = 0;
	zrouter.mlag_info.connected = false;
	zrouter.mlag_info.timer_running = false;
	zrouter.mlag_info.mlag_fifo = stream_fifo_new();
	zrouter.mlag_info.zebra_pth_mlag = NULL;
	zrouter.mlag_info.th_master = NULL;
	zrouter.mlag_info.t_read = NULL;
	zrouter.mlag_info.t_write = NULL;
	test_mlag_in_progress = false;
	zebra_mlag_reset_read_buffer();
}

void zebra_mlag_terminate(void)
{
}


/*
 *
 *  ProtoBuf Encoding APIs
 */

#ifdef HAVE_PROTOBUF

DEFINE_MTYPE_STATIC(ZEBRA, MLAG_PBUF, "ZEBRA MLAG PROTOBUF")

int zebra_mlag_protobuf_encode_client_data(struct stream *s, uint32_t *msg_type)
{
	ZebraMlagHeader hdr = ZEBRA_MLAG__HEADER__INIT;
	struct mlag_msg mlag_msg;
	uint8_t tmp_buf[ZEBRA_MLAG_BUF_LIMIT];
	int len = 0;
	int n_len = 0;
	int rc = 0;
	char buf[ZLOG_FILTER_LENGTH_MAX];

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Entering..", __func__);

	rc = mlag_lib_decode_mlag_hdr(s, &mlag_msg);
	if (rc)
		return rc;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Mlag ProtoBuf encoding of message:%s, len:%d",
			   __func__,
			   mlag_lib_msgid_to_str(mlag_msg.msg_type, buf,
						 sizeof(buf)),
			   mlag_msg.data_len);
	*msg_type = mlag_msg.msg_type;
	switch (mlag_msg.msg_type) {
	case MLAG_MROUTE_ADD: {
		struct mlag_mroute_add msg;
		ZebraMlagMrouteAdd pay_load = ZEBRA_MLAG_MROUTE_ADD__INIT;
		uint32_t vrf_name_len = 0;

		rc = mlag_lib_decode_mroute_add(s, &msg);
		if (rc)
			return rc;
		vrf_name_len = strlen(msg.vrf_name) + 1;
		pay_load.vrf_name = XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);
		strlcpy(pay_load.vrf_name, msg.vrf_name, vrf_name_len);
		pay_load.source_ip = msg.source_ip;
		pay_load.group_ip = msg.group_ip;
		pay_load.cost_to_rp = msg.cost_to_rp;
		pay_load.owner_id = msg.owner_id;
		pay_load.am_i_dr = msg.am_i_dr;
		pay_load.am_i_dual_active = msg.am_i_dual_active;
		pay_load.vrf_id = msg.vrf_id;

		if (msg.owner_id == MLAG_OWNER_INTERFACE) {
			vrf_name_len = strlen(msg.intf_name) + 1;
			pay_load.intf_name =
				XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);
			strlcpy(pay_load.intf_name, msg.intf_name,
				vrf_name_len);
		}

		len = zebra_mlag_mroute_add__pack(&pay_load, tmp_buf);
		XFREE(MTYPE_MLAG_PBUF, pay_load.vrf_name);
		if (msg.owner_id == MLAG_OWNER_INTERFACE)
			XFREE(MTYPE_MLAG_PBUF, pay_load.intf_name);
	} break;
	case MLAG_MROUTE_DEL: {
		struct mlag_mroute_del msg;
		ZebraMlagMrouteDel pay_load = ZEBRA_MLAG_MROUTE_DEL__INIT;
		uint32_t vrf_name_len = 0;

		rc = mlag_lib_decode_mroute_del(s, &msg);
		if (rc)
			return rc;
		vrf_name_len = strlen(msg.vrf_name) + 1;
		pay_load.vrf_name = XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);
		strlcpy(pay_load.vrf_name, msg.vrf_name, vrf_name_len);
		pay_load.source_ip = msg.source_ip;
		pay_load.group_ip = msg.group_ip;
		pay_load.owner_id = msg.owner_id;
		pay_load.vrf_id = msg.vrf_id;

		if (msg.owner_id == MLAG_OWNER_INTERFACE) {
			vrf_name_len = strlen(msg.intf_name) + 1;
			pay_load.intf_name =
				XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);
			strlcpy(pay_load.intf_name, msg.intf_name,
				vrf_name_len);
		}

		len = zebra_mlag_mroute_del__pack(&pay_load, tmp_buf);
		XFREE(MTYPE_MLAG_PBUF, pay_load.vrf_name);
		if (msg.owner_id == MLAG_OWNER_INTERFACE)
			XFREE(MTYPE_MLAG_PBUF, pay_load.intf_name);
	} break;
	case MLAG_MROUTE_ADD_BULK: {
		struct mlag_mroute_add msg;
		ZebraMlagMrouteAddBulk Bulk_msg =
			ZEBRA_MLAG_MROUTE_ADD_BULK__INIT;
		ZebraMlagMrouteAdd **pay_load = NULL;
		int i;
		bool cleanup = false;

		Bulk_msg.n_mroute_add = mlag_msg.msg_cnt;
		pay_load = XMALLOC(MTYPE_MLAG_PBUF, sizeof(ZebraMlagMrouteAdd *)
							    * mlag_msg.msg_cnt);

		for (i = 0; i < mlag_msg.msg_cnt; i++) {

			uint32_t vrf_name_len = 0;

			rc = mlag_lib_decode_mroute_add(s, &msg);
			if (rc) {
				cleanup = true;
				break;
			}
			pay_load[i] = XMALLOC(MTYPE_MLAG_PBUF,
					      sizeof(ZebraMlagMrouteAdd));
			zebra_mlag_mroute_add__init(pay_load[i]);

			vrf_name_len = strlen(msg.vrf_name) + 1;
			pay_load[i]->vrf_name =
				XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);
			strlcpy(pay_load[i]->vrf_name, msg.vrf_name,
				vrf_name_len);
			pay_load[i]->source_ip = msg.source_ip;
			pay_load[i]->group_ip = msg.group_ip;
			pay_load[i]->cost_to_rp = msg.cost_to_rp;
			pay_load[i]->owner_id = msg.owner_id;
			pay_load[i]->am_i_dr = msg.am_i_dr;
			pay_load[i]->am_i_dual_active = msg.am_i_dual_active;
			pay_load[i]->vrf_id = msg.vrf_id;
			if (msg.owner_id == MLAG_OWNER_INTERFACE) {
				vrf_name_len = strlen(msg.intf_name) + 1;
				pay_load[i]->intf_name =
					XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);

				strlcpy(pay_load[i]->intf_name, msg.intf_name,
					vrf_name_len);
			}
		}
		if (cleanup == false) {
			Bulk_msg.mroute_add = pay_load;
			len = zebra_mlag_mroute_add_bulk__pack(&Bulk_msg,
							       tmp_buf);
		}

		for (i = 0; i < mlag_msg.msg_cnt; i++) {
			if (pay_load[i]->vrf_name)
				XFREE(MTYPE_MLAG_PBUF, pay_load[i]->vrf_name);
			if (pay_load[i]->owner_id == MLAG_OWNER_INTERFACE
			    && pay_load[i]->intf_name)
				XFREE(MTYPE_MLAG_PBUF, pay_load[i]->intf_name);
			if (pay_load[i])
				XFREE(MTYPE_MLAG_PBUF, pay_load[i]);
		}
		XFREE(MTYPE_MLAG_PBUF, pay_load);
		if (cleanup == true)
			return -1;
	} break;
	case MLAG_MROUTE_DEL_BULK: {
		struct mlag_mroute_del msg;
		ZebraMlagMrouteDelBulk Bulk_msg =
			ZEBRA_MLAG_MROUTE_DEL_BULK__INIT;
		ZebraMlagMrouteDel **pay_load = NULL;
		int i;
		bool cleanup = false;

		Bulk_msg.n_mroute_del = mlag_msg.msg_cnt;
		pay_load = XMALLOC(MTYPE_MLAG_PBUF, sizeof(ZebraMlagMrouteDel *)
							    * mlag_msg.msg_cnt);

		for (i = 0; i < mlag_msg.msg_cnt; i++) {

			uint32_t vrf_name_len = 0;

			rc = mlag_lib_decode_mroute_del(s, &msg);
			if (rc) {
				cleanup = true;
				break;
			}

			pay_load[i] = XMALLOC(MTYPE_MLAG_PBUF,
					      sizeof(ZebraMlagMrouteDel));
			zebra_mlag_mroute_del__init(pay_load[i]);

			vrf_name_len = strlen(msg.vrf_name) + 1;
			pay_load[i]->vrf_name =
				XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);

			strlcpy(pay_load[i]->vrf_name, msg.vrf_name,
				vrf_name_len);
			pay_load[i]->source_ip = msg.source_ip;
			pay_load[i]->group_ip = msg.group_ip;
			pay_load[i]->owner_id = msg.owner_id;
			pay_load[i]->vrf_id = msg.vrf_id;
			if (msg.owner_id == MLAG_OWNER_INTERFACE) {
				vrf_name_len = strlen(msg.intf_name) + 1;
				pay_load[i]->intf_name =
					XMALLOC(MTYPE_MLAG_PBUF, vrf_name_len);

				strlcpy(pay_load[i]->intf_name, msg.intf_name,
					vrf_name_len);
			}
		}
		if (!cleanup) {
			Bulk_msg.mroute_del = pay_load;
			len = zebra_mlag_mroute_del_bulk__pack(&Bulk_msg,
							       tmp_buf);
		}

		for (i = 0; i < mlag_msg.msg_cnt; i++) {
			if (pay_load[i]->vrf_name)
				XFREE(MTYPE_MLAG_PBUF, pay_load[i]->vrf_name);
			if (pay_load[i]->owner_id == MLAG_OWNER_INTERFACE
			    && pay_load[i]->intf_name)
				XFREE(MTYPE_MLAG_PBUF, pay_load[i]->intf_name);
			if (pay_load[i])
				XFREE(MTYPE_MLAG_PBUF, pay_load[i]);
		}
		XFREE(MTYPE_MLAG_PBUF, pay_load);
		if (cleanup)
			return -1;
	} break;
	default:
		break;
	}

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: length of Mlag ProtoBuf encoded message:%s, %d",
			   __func__,
			   mlag_lib_msgid_to_str(mlag_msg.msg_type, buf,
						 sizeof(buf)),
			   len);
	hdr.type = (ZebraMlagHeader__MessageType)mlag_msg.msg_type;
	if (len != 0) {
		hdr.data.len = len;
		hdr.data.data = XMALLOC(MTYPE_MLAG_PBUF, len);
		memcpy(hdr.data.data, tmp_buf, len);
	}

	/*
	 * ProtoBuf Infra will not support to demarc the pointers whem multiple
	 * messages are posted inside a single Buffer.
	 * 2 -solutions exist to solve this
	 * 1. add Unenoced length at the beginning of every message, this will
	 *    be used to point to next message in the buffer
	 * 2. another solution is defining all messages insides another message
	 *    But this will permit only 32 messages. this can be extended with
	 *    multiple levels.
	 * for simplicity we are going with solution-1.
	 */
	len = zebra_mlag__header__pack(&hdr,
				       (mlag_wr_buffer + ZEBRA_MLAG_LEN_SIZE));
	n_len = htonl(len);
	memcpy(mlag_wr_buffer, &n_len, ZEBRA_MLAG_LEN_SIZE);
	len += ZEBRA_MLAG_LEN_SIZE;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug(
			"%s: length of Mlag ProtoBuf message:%s with Header  %d",
			__func__,
			mlag_lib_msgid_to_str(mlag_msg.msg_type, buf,
					      sizeof(buf)),
			len);
	if (hdr.data.data)
		XFREE(MTYPE_MLAG_PBUF, hdr.data.data);

	return len;
}

int zebra_mlag_protobuf_decode_message(struct stream *s, uint8_t *data,
				       uint32_t len)
{
	uint32_t msg_type;
	ZebraMlagHeader *hdr;
	char buf[80];

	hdr = zebra_mlag__header__unpack(NULL, len, data);
	if (hdr == NULL)
		return -1;

	/*
	 * ADD The MLAG Header
	 */
	zclient_create_header(s, ZEBRA_MLAG_FORWARD_MSG, VRF_DEFAULT);

	msg_type = hdr->type;

	if (IS_ZEBRA_DEBUG_MLAG)
		zlog_debug("%s: Mlag ProtoBuf decoding of message:%s", __func__,
			   mlag_lib_msgid_to_str(msg_type, buf, 80));

	/*
	 * Internal MLAG Message-types & MLAG.proto message types should
	 * always match, otherwise there can be decoding errors
	 * To avoid exposing clients with Protobuf flags, using internal
	 * message-types
	 */
	stream_putl(s, hdr->type);

	if (hdr->data.len == 0) {
		/* NULL Payload */
		stream_putw(s, MLAG_MSG_NULL_PAYLOAD);
		/* No Batching */
		stream_putw(s, MLAG_MSG_NO_BATCH);
	} else {
		switch (msg_type) {
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_STATUS_UPDATE: {
			ZebraMlagStatusUpdate *msg = NULL;

			msg = zebra_mlag_status_update__unpack(
				NULL, hdr->data.len, hdr->data.data);
			if (msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, sizeof(struct mlag_status));
			/* No Batching */
			stream_putw(s, MLAG_MSG_NO_BATCH);
			/* Actual Data */
			stream_put(s, msg->peerlink, INTERFACE_NAMSIZ);
			stream_putl(s, msg->my_role);
			stream_putl(s, msg->peer_state);
			zebra_mlag_status_update__free_unpacked(msg, NULL);
		} break;
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_VXLAN_UPDATE: {
			ZebraMlagVxlanUpdate *msg = NULL;

			msg = zebra_mlag_vxlan_update__unpack(
				NULL, hdr->data.len, hdr->data.data);
			if (msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, sizeof(struct mlag_vxlan));
			/* No Batching */
			stream_putw(s, MLAG_MSG_NO_BATCH);
			/* Actual Data */
			stream_putl(s, msg->anycast_ip);
			stream_putl(s, msg->local_ip);
			zebra_mlag_vxlan_update__free_unpacked(msg, NULL);
		} break;
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_MROUTE_ADD: {
			ZebraMlagMrouteAdd *msg = NULL;

			msg = zebra_mlag_mroute_add__unpack(NULL, hdr->data.len,
							    hdr->data.data);
			if (msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, sizeof(struct mlag_mroute_add));
			/* No Batching */
			stream_putw(s, MLAG_MSG_NO_BATCH);
			/* Actual Data */
			stream_put(s, msg->vrf_name, VRF_NAMSIZ);

			stream_putl(s, msg->source_ip);
			stream_putl(s, msg->group_ip);
			stream_putl(s, msg->cost_to_rp);
			stream_putl(s, msg->owner_id);
			stream_putc(s, msg->am_i_dr);
			stream_putc(s, msg->am_i_dual_active);
			stream_putl(s, msg->vrf_id);
			if (msg->owner_id == MLAG_OWNER_INTERFACE)
				stream_put(s, msg->intf_name, INTERFACE_NAMSIZ);
			else
				stream_put(s, NULL, INTERFACE_NAMSIZ);
			zebra_mlag_mroute_add__free_unpacked(msg, NULL);
		} break;
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_MROUTE_DEL: {
			ZebraMlagMrouteDel *msg = NULL;

			msg = zebra_mlag_mroute_del__unpack(NULL, hdr->data.len,
							    hdr->data.data);
			if (msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, sizeof(struct mlag_mroute_del));
			/* No Batching */
			stream_putw(s, MLAG_MSG_NO_BATCH);
			/* Actual Data */
			stream_put(s, msg->vrf_name, VRF_NAMSIZ);

			stream_putl(s, msg->source_ip);
			stream_putl(s, msg->group_ip);
			stream_putl(s, msg->group_ip);
			stream_putl(s, msg->owner_id);
			stream_putl(s, msg->vrf_id);
			if (msg->owner_id == MLAG_OWNER_INTERFACE)
				stream_put(s, msg->intf_name, INTERFACE_NAMSIZ);
			else
				stream_put(s, NULL, INTERFACE_NAMSIZ);
			zebra_mlag_mroute_del__free_unpacked(msg, NULL);
		} break;
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_MROUTE_ADD_BULK: {
			ZebraMlagMrouteAddBulk *Bulk_msg = NULL;
			ZebraMlagMrouteAdd *msg = NULL;
			size_t i;

			Bulk_msg = zebra_mlag_mroute_add_bulk__unpack(
				NULL, hdr->data.len, hdr->data.data);
			if (Bulk_msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, (Bulk_msg->n_mroute_add
					* sizeof(struct mlag_mroute_add)));
			/* No. of msgs in Batch */
			stream_putw(s, Bulk_msg->n_mroute_add);

			/* Actual Data */
			for (i = 0; i < Bulk_msg->n_mroute_add; i++) {

				msg = Bulk_msg->mroute_add[i];

				stream_put(s, msg->vrf_name, VRF_NAMSIZ);
				stream_putl(s, msg->source_ip);
				stream_putl(s, msg->group_ip);
				stream_putl(s, msg->cost_to_rp);
				stream_putl(s, msg->owner_id);
				stream_putc(s, msg->am_i_dr);
				stream_putc(s, msg->am_i_dual_active);
				stream_putl(s, msg->vrf_id);
				if (msg->owner_id == MLAG_OWNER_INTERFACE)
					stream_put(s, msg->intf_name,
						   INTERFACE_NAMSIZ);
				else
					stream_put(s, NULL, INTERFACE_NAMSIZ);
			}
			zebra_mlag_mroute_add_bulk__free_unpacked(Bulk_msg,
								  NULL);
		} break;
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_MROUTE_DEL_BULK: {
			ZebraMlagMrouteDelBulk *Bulk_msg = NULL;
			ZebraMlagMrouteDel *msg = NULL;
			size_t i;

			Bulk_msg = zebra_mlag_mroute_del_bulk__unpack(
				NULL, hdr->data.len, hdr->data.data);
			if (Bulk_msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, (Bulk_msg->n_mroute_del
					* sizeof(struct mlag_mroute_del)));
			/* No. of msgs in Batch */
			stream_putw(s, Bulk_msg->n_mroute_del);

			/* Actual Data */
			for (i = 0; i < Bulk_msg->n_mroute_del; i++) {

				msg = Bulk_msg->mroute_del[i];

				stream_put(s, msg->vrf_name, VRF_NAMSIZ);
				stream_putl(s, msg->source_ip);
				stream_putl(s, msg->group_ip);
				stream_putl(s, msg->owner_id);
				stream_putl(s, msg->vrf_id);
				if (msg->owner_id == MLAG_OWNER_INTERFACE)
					stream_put(s, msg->intf_name,
						   INTERFACE_NAMSIZ);
				else
					stream_put(s, NULL, INTERFACE_NAMSIZ);
			}
			zebra_mlag_mroute_del_bulk__free_unpacked(Bulk_msg,
								  NULL);
		} break;
		case ZEBRA_MLAG__HEADER__MESSAGE_TYPE__ZEBRA_MLAG_ZEBRA_STATUS_UPDATE: {
			ZebraMlagZebraStatusUpdate *msg = NULL;

			msg = zebra_mlag_zebra_status_update__unpack(
				NULL, hdr->data.len, hdr->data.data);
			if (msg == NULL) {
				zebra_mlag__header__free_unpacked(hdr, NULL);
				return -1;
			}
			/* Payload len */
			stream_putw(s, sizeof(struct mlag_frr_status));
			/* No Batching */
			stream_putw(s, MLAG_MSG_NO_BATCH);
			/* Actual Data */
			stream_putl(s, msg->peer_frrstate);
			zebra_mlag_zebra_status_update__free_unpacked(msg,
								      NULL);
		} break;
		default:
			break;
		}
	}
	zebra_mlag__header__free_unpacked(hdr, NULL);
	return msg_type;
}

#else
int zebra_mlag_protobuf_encode_client_data(struct stream *s, uint32_t *msg_type)
{
	return 0;
}

int zebra_mlag_protobuf_decode_message(struct stream *s, uint8_t *data,
				       uint32_t len)
{
	return 0;
}
#endif
