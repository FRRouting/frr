/*
 * CMGD Frontend Client Connection Adapter
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
#include "lib/thread.h"
#include "cmgd/cmgd.h"
#include "cmgd/cmgd_memory.h"
#include "lib/cmgd_frntnd_client.h"
#include "cmgd/cmgd_frntnd_adapter.h"
#include "lib/cmgd_pb.h"
#include "lib/vty.h"

#ifdef REDIRECT_DEBUG_TO_STDERR
#define CMGD_FRNTND_ADPTR_DBG(fmt, ...)				\
	fprintf(stderr, "%s: " fmt "\n", __func__, ##__VA_ARGS__)
#define CMGD_FRNTND_ADPTR_ERR(fmt, ...)				\
	fprintf(stderr, "%s: ERROR, " fmt "\n", __func__, ##__VA_ARGS__)
#else /* REDIRECT_DEBUG_TO_STDERR */
#define CMGD_FRNTND_ADPTR_DBG(fmt, ...)				\
	zlog_err("%s: " fmt , __func__, ##__VA_ARGS__)
#define CMGD_FRNTND_ADPTR_ERR(fmt, ...)				\
	zlog_err("%s: ERROR: " fmt , __func__, ##__VA_ARGS__)
#endif /* REDIRECT_DEBUG_TO_STDERR */

#define FOREACH_ADPTR_IN_LIST(adptr)							\
	for ((adptr) = cmgd_frntnd_adptr_list_first(&cmgd_frntnd_adptrs); (adptr);	\
		(adptr) = cmgd_frntnd_adptr_list_next(&cmgd_frntnd_adptrs, (adptr)))

typedef struct cmgd_frntnd_sessn_ctxt_ {
	struct cmgd_frntnd_client_adapter_ *adptr;
        cmgd_client_id_t client_id;
	cmgd_trxn_id_t	trxn_id;
	cmgd_trxn_id_t	cfg_trxn_id;
	bool db_write_locked[CMGD_DB_MAX_ID];

	struct cmgd_frntnd_sessn_list_item list_linkage;
} cmgd_frntnd_sessn_ctxt_t;

DECLARE_LIST(cmgd_frntnd_sessn_list, cmgd_frntnd_sessn_ctxt_t, list_linkage);

#define FOREACH_SESSN_IN_LIST(adptr, sessn)						\
	for ((sessn) = cmgd_frntnd_sessn_list_first(&(adptr)->frntnd_sessns); (sessn);	\
		(sessn) = cmgd_frntnd_sessn_list_next(&(adptr)->frntnd_sessns, (sessn)))

static struct thread_master *cmgd_frntnd_adptr_tm = NULL;
static struct cmgd_master *cmgd_frntnd_adptr_cm = NULL;

static struct cmgd_frntnd_adptr_list_head cmgd_frntnd_adptrs = {0};

/* Forward declarations */
static void cmgd_frntnd_adptr_register_event(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_event_t event);
static void cmgd_frntnd_adapter_disconnect(
	cmgd_frntnd_client_adapter_t *adptr);

static void cmgd_frntnd_cleanup_session(cmgd_frntnd_sessn_ctxt_t *sessn)
{
	if (sessn->adptr) {
		/* TODO: Cleanup transaction (if any) */

		cmgd_frntnd_sessn_list_del(&sessn->adptr->frntnd_sessns, sessn);
		cmgd_frntnd_adapter_unlock(&sessn->adptr);
	}

	XFREE(MTYPE_CMGD_FRNTND_SESSN, sessn);
}

static cmgd_frntnd_sessn_ctxt_t *cmgd_frntnd_find_session_by_id(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_client_id_t client_id)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	FOREACH_SESSN_IN_LIST(adptr, sessn) {
		if (sessn->client_id == client_id)
			return sessn;
	}

	return NULL;
}

static cmgd_frntnd_sessn_ctxt_t *cmgd_frntnd_create_session(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_client_id_t client_id)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = cmgd_frntnd_find_session_by_id(adptr, client_id);
	if (sessn) {
		cmgd_frntnd_cleanup_session(sessn);
	}

	sessn = XMALLOC(MTYPE_CMGD_FRNTND_SESSN, sizeof(cmgd_frntnd_sessn_ctxt_t));
	assert(sessn);
	sessn->client_id = client_id;
	sessn->adptr = adptr;
	sessn->trxn_id = CMGD_TRXN_ID_NONE;
	sessn->cfg_trxn_id = CMGD_TRXN_ID_NONE;
	cmgd_frntnd_adapter_lock(adptr);
	cmgd_frntnd_sessn_list_add_tail(&adptr->frntnd_sessns, sessn);

	return sessn;
}

static void cmgd_frntnd_cleanup_sessions(cmgd_frntnd_client_adapter_t *adptr)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	FOREACH_SESSN_IN_LIST(adptr, sessn) {
		cmgd_frntnd_cleanup_session(sessn);
	}
}

static int cmgd_frntnd_adapter_send_msg(cmgd_frntnd_client_adapter_t *adptr, 
	Cmgd__FrntndMessage *frntnd_msg)
{
	int bytes_written;
	size_t msg_size;
	uint8_t msg_buf[CMGD_FRNTND_MSG_MAX_LEN];
	cmgd_frntnd_msg_t *msg;

	msg_size = cmgd__frntnd_message__get_packed_size(frntnd_msg);
	msg_size += CMGD_FRNTND_MSG_HDR_LEN;
	if (msg_size > sizeof(msg_buf)) {
		CMGD_FRNTND_ADPTR_ERR(
			"Message size %d more than max size'%d. Not sending!'", 
			(int) msg_size, (int)sizeof(msg_buf));
		return -1;
	}
	
	msg = (cmgd_frntnd_msg_t *)msg_buf;
	msg->hdr.marker = CMGD_FRNTND_MSG_MARKER;
	msg->hdr.len = (uint16_t) msg_size;
	cmgd__frntnd_message__pack(frntnd_msg, msg->payload);

	bytes_written = write(adptr->conn_fd, (void *)msg_buf, msg_size);
	if (bytes_written != (int) msg_size) {
		CMGD_FRNTND_ADPTR_ERR(
			"Could not write all %d bytes (wrote: %d) to CMGD Frontend client '%s'. Err: '%s'", 
			(int) msg_size, bytes_written, adptr->name, safe_strerror(errno));
		cmgd_frntnd_adapter_disconnect(adptr);
		return -1;
	}

	CMGD_FRNTND_ADPTR_DBG(
		"Wrote %d bytes of message to CMGD Frontend client '%s'.'", 
		bytes_written, adptr->name);
	return 0;
}

static int cmgd_frntnd_send_session_reply(cmgd_frntnd_client_adapter_t *adptr,
	cmgd_frntnd_sessn_ctxt_t *sessn, bool create, bool success)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndSessionReply sessn_reply;

	cmgd__frntnd_session_reply__init(&sessn_reply);
	sessn_reply.create = create;
	if (create) {
		sessn_reply.has_client_conn_id = 1;
		sessn_reply.client_conn_id = sessn->client_id;
	}
	sessn_reply.session_id = (uint64_t) sessn;
	sessn_reply.success = success;

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__SESSION_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_SESSN_REPLY;
	frntnd_msg.sessn_reply = &sessn_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending SESSION_REPLY message to CMGD Frontend client '%s'",
		adptr->name);

	return cmgd_frntnd_adapter_send_msg(adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_setcfg_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t db_id, cmgd_client_req_id_t req_id,
	bool success, const char *error_if_any)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndSetConfigReply setcfg_reply;

	assert(sessn->adptr);

	cmgd__frntnd_set_config_reply__init(&setcfg_reply);
	setcfg_reply.session_id = (uint64_t) sessn;
	setcfg_reply.db_id = db_id;
	setcfg_reply.req_id = req_id;
	setcfg_reply.success = success;
	if (error_if_any) {
		setcfg_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_SETCFG_REPLY;
	frntnd_msg.setcfg_reply = &setcfg_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending SET_CONFIG_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static int cmgd_frntnd_send_commitcfg_reply(cmgd_frntnd_sessn_ctxt_t *sessn,
	cmgd_database_id_t src_db_id, cmgd_database_id_t dst_db_id,
	cmgd_client_req_id_t req_id, bool success, bool validate_only,
	const char *error_if_any)
{
	Cmgd__FrntndMessage frntnd_msg;
	Cmgd__FrntndCommitConfigReply commcfg_reply;

	assert(sessn->adptr);

	cmgd__frntnd_commit_config_reply__init(&commcfg_reply);
	commcfg_reply.session_id = (uint64_t) sessn;
	commcfg_reply.src_db_id = src_db_id;
	commcfg_reply.dst_db_id = dst_db_id;
	commcfg_reply.req_id = req_id;
	commcfg_reply.success = success;
	if (error_if_any) {
		commcfg_reply.error_if_any = (char *) error_if_any;
	}

	cmgd__frntnd_message__init(&frntnd_msg);
	frntnd_msg.type = CMGD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REPLY;
	frntnd_msg.message_case = CMGD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REPLY;
	frntnd_msg.commcfg_reply = &commcfg_reply;

	CMGD_FRNTND_ADPTR_DBG("Sending COMMIT_CONFIG_REPLY message to CMGD Frontend client '%s'",
		sessn->adptr->name);

	return cmgd_frntnd_adapter_send_msg(sessn->adptr, &frntnd_msg);
}

static cmgd_frntnd_client_adapter_t *cmgd_frntnd_find_adapter_by_fd(int conn_fd)
{
	cmgd_frntnd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (adptr->conn_fd == conn_fd) 
			return adptr;
	}

	return NULL;
}

static cmgd_frntnd_client_adapter_t *cmgd_frntnd_find_adapter_by_name(const char *name)
{
	cmgd_frntnd_client_adapter_t *adptr;

	FOREACH_ADPTR_IN_LIST(adptr) {
		if (!strncmp(adptr->name, name, sizeof(adptr->name)))
			return adptr;
	}

	return NULL;
}

static void cmgd_frntnd_adapter_disconnect(cmgd_frntnd_client_adapter_t *adptr)
{
	if (adptr->conn_fd) {
		close(adptr->conn_fd);
		adptr->conn_fd = 0;
	}

	/* TODO: notify about client disconnect for appropriate cleanup */
	cmgd_frntnd_cleanup_sessions(adptr);
	cmgd_frntnd_sessn_list_fini(&adptr->frntnd_sessns);
	cmgd_frntnd_adptr_list_del(&cmgd_frntnd_adptrs, adptr);

	cmgd_frntnd_adapter_unlock(&adptr);
}

static void cmgd_frntnd_adapter_cleanup_old_conn(
	cmgd_frntnd_client_adapter_t *adptr)
{
	cmgd_frntnd_client_adapter_t *old;

	FOREACH_ADPTR_IN_LIST(old) {
		if (old != adptr &&
			!strncmp(adptr->name, old->name, sizeof(adptr->name))) {
			/*
			 * We have a Zombie lingering around
			 */
			CMGD_FRNTND_ADPTR_DBG(
				"Client '%s' (FD:%d) seems to have reconnected. Removing old connection (FD:%d)!",
				adptr->name, adptr->conn_fd, old->conn_fd);
			cmgd_frntnd_adapter_disconnect(old);
		}
	}
}

static int cmgd_frntnd_session_handle_config_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndSetConfigReq *setcfg_req)
{
	cmgd_session_id_t cfg_sessn_id;
	cmgd_db_hndl_t db_hndl;

	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (setcfg_req->db_id != CMGD_DB_CANDIDATE) {
		cmgd_frntnd_send_setcfg_reply(sessn,
			setcfg_req->db_id, setcfg_req->req_id, false,
			"Set-Config on databases other than Candidate DB not permitted!");
		return 0;
	}

	if (sessn->cfg_trxn_id == CMGD_TRXN_ID_NONE) {
		/*
		 * Check first if the current session can run a CONFIG
		 * transaction or not. Report failure if a CONFIG transaction
		 * from another session is already in progress.
		 */
		cfg_sessn_id = cmgd_config_trxn_in_progress();
		if (cfg_sessn_id != CMGD_SESSION_ID_NONE &&
			cfg_sessn_id != (cmgd_session_id_t) sessn) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"Configuration already in-progress through a different user session!");
			return 0;
		}

		/*
		 * TODO: Try taking write-lock on the requested DB (if not already).
		 */
		db_hndl = cmgd_db_get_hndl_by_id(
				cmgd_frntnd_adptr_cm, setcfg_req->db_id);
		if (!db_hndl) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"No such DB exists!");
			return 0;
		}

		if (!sessn->db_write_locked[setcfg_req->db_id]) { 
			if (cmgd_db_write_lock(db_hndl) != 0) {
				cmgd_frntnd_send_setcfg_reply(sessn,
					setcfg_req->db_id, setcfg_req->req_id, false,
					"Failed to lock the DB!");
				return 0;
			}

			sessn->db_write_locked[setcfg_req->db_id] = true;
		}

		/*
		 * Start a CONFIG Transaction (if not started already)
		 */
		sessn->cfg_trxn_id = cmgd_create_trxn(
			(cmgd_session_id_t) sessn, CMGD_TRXN_TYPE_CONFIG);
		if (sessn->cfg_trxn_id == CMGD_SESSION_ID_NONE) {
			cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"Failed to create a Configuration session!");
			return 0;
		}

		CMGD_FRNTND_ADPTR_DBG("Created new Config Trxn 0x%lx for session 0x%p",
			sessn->cfg_trxn_id, sessn);
	} else {
		CMGD_FRNTND_ADPTR_DBG("Config Trxn 0x%lx for session 0x%p already created",
			sessn->cfg_trxn_id, sessn);
	}

	if (cmgd_trxn_send_set_config_req(
		sessn->cfg_trxn_id, setcfg_req->req_id, setcfg_req->db_id,
		setcfg_req->data, setcfg_req->n_data) != 0)
	{
		cmgd_frntnd_send_setcfg_reply(sessn,
				setcfg_req->db_id, setcfg_req->req_id, false,
				"Request processing for SET-CONFIG failed!");
		return 0;
	}

	return 0;
}

static int cmgd_frntnd_session_handle_commit_config_req_msg(
	cmgd_frntnd_sessn_ctxt_t *sessn,
	Cmgd__FrntndCommitConfigReq *commcfg_req)
{
	/*
	 * Next check first if the SET_CONFIG_REQ is for Candidate DB 
	 * or not. Report failure if its not. CMGD currently only
	 * supports editing the Candidate DB.
	 */
	if (commcfg_req->dst_db_id != CMGD_DB_RUNNING) {
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"Set-Config on databases other than Running DB not permitted!");
		return 0;
	}

	if (sessn->cfg_trxn_id == CMGD_TRXN_ID_NONE) {
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"No config commands has been entered after last commit!");
		return 0;
	}

	if (cmgd_trxn_send_commit_config_req(
		sessn->cfg_trxn_id, commcfg_req->req_id, commcfg_req->src_db_id,
		commcfg_req->src_db_id, commcfg_req->validate_only) != 0)
	{
		cmgd_frntnd_send_commitcfg_reply(sessn,
			commcfg_req->src_db_id, commcfg_req->dst_db_id,
			commcfg_req->req_id, false, commcfg_req->validate_only,
			"Request processing for COMMIT-CONFIG failed!");
		return 0;
	}

	return 0;
}

static int cmgd_frntnd_adapter_handle_msg(
	cmgd_frntnd_client_adapter_t *adptr, Cmgd__FrntndMessage *frntnd_msg)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	switch(frntnd_msg->type) {
	case CMGD__FRNTND_MESSAGE__TYPE__REGISTER_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_REGISTER_REQ);
		CMGD_FRNTND_ADPTR_DBG(
			"Got Register Req Msg from '%s'", 
			frntnd_msg->register_req->client_name);

		if (strlen(frntnd_msg->register_req->client_name)) {
			strlcpy(adptr->name, frntnd_msg->register_req->client_name, 
				sizeof(adptr->name));
			cmgd_frntnd_adapter_cleanup_old_conn(adptr);
		}
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__SESSION_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_SESSN_REQ);
		if (frntnd_msg->sessn_req->create && 
			frntnd_msg->sessn_req->id_case == 
			CMGD__FRNTND_SESSION_REQ__ID_CLIENT_CONN_ID) {
			CMGD_FRNTND_ADPTR_DBG(
				"Got Session Create Req Msg for client-id %llu from '%s'", 
				frntnd_msg->sessn_req->client_conn_id, adptr->name);

			sessn = cmgd_frntnd_create_session(adptr,
				frntnd_msg->sessn_req->client_conn_id);
			cmgd_frntnd_send_session_reply(
				adptr, sessn, true, sessn ? true : false);
		} else if (!frntnd_msg->sessn_req->create && 
			frntnd_msg->sessn_req->id_case == 
			CMGD__FRNTND_SESSION_REQ__ID_SESSION_ID) {
			CMGD_FRNTND_ADPTR_DBG(
				"Got Session Destroy Req Msg for session-id %llu from '%s'", 
				frntnd_msg->sessn_req->session_id, adptr->name);

			sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->sessn_req->session_id;
			cmgd_frntnd_send_session_reply(
				adptr, sessn, false, true);
		}
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__SET_CONFIG_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_SETCFG_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->setcfg_req->session_id;
		CMGD_FRNTND_ADPTR_DBG(
				"Got Set Config Req Msg (%d Xpaths) on DB:%d for session-id %llu from '%s'", 
				(int) frntnd_msg->setcfg_req->n_data,
				frntnd_msg->setcfg_req->db_id,
				frntnd_msg->setcfg_req->session_id, adptr->name);

		cmgd_frntnd_session_handle_config_req_msg(
				sessn, frntnd_msg->setcfg_req);
		break;
	case CMGD__FRNTND_MESSAGE__TYPE__COMMIT_CONFIG_REQ:
		assert(frntnd_msg->message_case == CMGD__FRNTND_MESSAGE__MESSAGE_COMMCFG_REQ);
		sessn = (cmgd_frntnd_sessn_ctxt_t *)
				frntnd_msg->commcfg_req->session_id;
		CMGD_FRNTND_ADPTR_DBG(
				"Got Commit Config Req Msg for src-DB:%d dst-DB:%d on session-id %llu from '%s'", 
				frntnd_msg->commcfg_req->src_db_id,
				frntnd_msg->commcfg_req->dst_db_id,
				frntnd_msg->commcfg_req->session_id, adptr->name);
		cmgd_frntnd_session_handle_commit_config_req_msg(
			sessn, frntnd_msg->commcfg_req);
		break;
	default:
		break;
	}

	return 0;
}

static uint16_t cmgd_frntnd_adapter_process_msg(
	cmgd_frntnd_client_adapter_t *adptr, uint8_t *msg_buf, uint16_t bytes_read)
{
	Cmgd__FrntndMessage *frntnd_msg;
	cmgd_frntnd_msg_t *msg;
	uint16_t bytes_left;
	uint16_t processed = 0;

	CMGD_FRNTND_ADPTR_DBG("Have %u bytes of messages from client '%s' to process",
		bytes_read, adptr->name);

	bytes_left = bytes_read;
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN;
		bytes_left -= msg->hdr.len, msg_buf += msg->hdr.len) {
		msg = (cmgd_frntnd_msg_t *)msg_buf;
		if (msg->hdr.marker != CMGD_FRNTND_MSG_MARKER) {
			CMGD_FRNTND_ADPTR_DBG(
				"Marker not found in message from CMGD Frontend adapter '%s'", 
				adptr->name);
			break;
		}

		if (bytes_left < msg->hdr.len) {
			CMGD_FRNTND_ADPTR_DBG(
				"Incomplete message of %d bytes (epxected: %u) from CMGD Frontend adapter '%s'", 
				bytes_left, msg->hdr.len, adptr->name);
			break;
		}

		frntnd_msg = cmgd__frntnd_message__unpack(
			NULL, (size_t) (msg->hdr.len - CMGD_FRNTND_MSG_HDR_LEN), 
			msg->payload);
		if (!frntnd_msg) {
			CMGD_FRNTND_ADPTR_DBG(
				"Failed to decode %d bytes from CMGD Frontend adapter '%s'", 
				msg->hdr.len, adptr->name);
			continue;
		}

		CMGD_FRNTND_ADPTR_DBG(
			"Decoded %d bytes of message(type: %u/%u) from CMGD Frontend adapter '%s'", 
			msg->hdr.len, frntnd_msg->type,
			frntnd_msg->message_case, adptr->name);

		(void) cmgd_frntnd_adapter_handle_msg(adptr, frntnd_msg);

		cmgd__frntnd_message__free_unpacked(frntnd_msg, NULL);
		processed++;
	}

	return processed;
}

static int cmgd_frntnd_adapter_proc_msgbufs(struct thread *thread)
{
	cmgd_frntnd_client_adapter_t *adptr;
	struct stream *work;
	int processed = 0;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	CMGD_FRNTND_ADPTR_DBG("Have %d ibufs for client '%s' to process",
		(int) stream_fifo_count_safe(adptr->ibuf_fifo), adptr->name);

	for ( ; processed < CMGD_FRNTND_MAX_NUM_MSG_PROC ; ) {
		work = stream_fifo_pop_safe(adptr->ibuf_fifo);
		if (!work) {
			break;
		}

		processed += cmgd_frntnd_adapter_process_msg(
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
		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_PROC_MSG);
	
	return 0;
}

static int cmgd_frntnd_adapter_read(struct thread *thread)
{
	cmgd_frntnd_client_adapter_t *adptr;
	int bytes_read, msg_cnt;
	size_t total_bytes, bytes_left;
	cmgd_frntnd_msg_hdr_t *msg_hdr;
	bool incomplete = false;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	total_bytes = 0;
	bytes_left = STREAM_SIZE(adptr->ibuf_work) - 
		stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN; ) {
		bytes_read = stream_read_try(
				adptr->ibuf_work, adptr->conn_fd, bytes_left);
		CMGD_FRNTND_ADPTR_DBG(
			"Got %d bytes of message from CMGD Frontend adapter '%s'", 
			bytes_read, adptr->name);
		if (bytes_read <= 0) {
			if (!total_bytes) {
				/* Looks like connection closed */
				CMGD_FRNTND_ADPTR_ERR(
					"Got error (%d) while reading from CMGD Frontend adapter '%s'. Err: '%s'", 
					bytes_read, adptr->name, safe_strerror(errno));
				cmgd_frntnd_adapter_disconnect(adptr);
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
	msg_cnt = 0;
	bytes_left = stream_get_endp(adptr->ibuf_work);
	for ( ; bytes_left > CMGD_FRNTND_MSG_HDR_LEN; ) {
		msg_hdr = (cmgd_frntnd_msg_hdr_t *)
			(STREAM_DATA(adptr->ibuf_work) + total_bytes);
		if (msg_hdr->marker != CMGD_FRNTND_MSG_MARKER) {
			/* Corrupted buffer. Force disconnect?? */
			cmgd_frntnd_adapter_disconnect(adptr);
			return -1;
		}
		if (msg_hdr->len > bytes_left) {
			/* 
			 * Incomplete message. Terminate the current buffer
			 * and add it to process fifo. And then copy the rest
			 * to a new Ibuf 
			 */
			incomplete = true;
			stream_set_endp(adptr->ibuf_work, total_bytes);
			stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);

			CMGD_FRNTND_ADPTR_DBG("Incomplete message of %d bytes (epxected: %u) found", 
				(int) bytes_left, msg_hdr->len);

			adptr->ibuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
			stream_put(adptr->ibuf_work, msg_hdr, bytes_left);
			stream_set_endp(adptr->ibuf_work, bytes_left);
			break;
		}

		CMGD_FRNTND_ADPTR_DBG("Got message (len: %u) from client '%s'",
			msg_hdr->len, adptr->name);

		total_bytes += msg_hdr->len;
		bytes_left -= msg_hdr->len;
		msg_cnt++;
	}

	CMGD_FRNTND_ADPTR_DBG("Got %d complete messages from client '%s'",
		msg_cnt, adptr->name);

	/* 
	 * We would have read one or several messages.
	 * Schedule processing them now.
	 */
	if (!incomplete)
		stream_fifo_push(adptr->ibuf_fifo, adptr->ibuf_work);
	if (msg_cnt)
		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_PROC_MSG);

	cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_READ);

	return 0;
}

static int cmgd_frntnd_adapter_write(struct thread *thread)
{
	cmgd_frntnd_client_adapter_t *adptr;
	// uint8_t bkcnd_msg[CMGD_FRNTND_MSG_MAX_LEN];
	//int bytes_read;

	adptr = (cmgd_frntnd_client_adapter_t *)THREAD_ARG(thread);
	assert(adptr && adptr->conn_fd);

	return 0;
}

static void cmgd_frntnd_adptr_register_event(
	cmgd_frntnd_client_adapter_t *adptr, cmgd_event_t event)
{
	switch (event) {
	case CMGD_FRNTND_CONN_READ:
		adptr->conn_read_ev = 
			thread_add_read(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_read, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_FRNTND_CONN_WRITE:
		adptr->conn_read_ev = 
			thread_add_write(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_write, adptr,
				adptr->conn_fd, NULL);
		break;
	case CMGD_FRNTND_PROC_MSG:
		adptr->proc_msg_ev = 
			thread_add_timer_msec(cmgd_frntnd_adptr_tm,
				cmgd_frntnd_adapter_proc_msgbufs, adptr,
				CMGD_FRNTND_MSG_PROC_DELAY_MSEC, NULL);
		break;
	default:
		assert(!"cmgd_frntnd_adptr_post_event() called incorrectly");
		break;
	}
}

void cmgd_frntnd_adapter_lock(cmgd_frntnd_client_adapter_t *adptr)
{
	adptr->refcount++;
}

extern void cmgd_frntnd_adapter_unlock(cmgd_frntnd_client_adapter_t **adptr)
{
	assert(*adptr && (*adptr)->refcount);

	(*adptr)->refcount--;
	if (!(*adptr)->refcount) {
		cmgd_frntnd_adptr_list_del(&cmgd_frntnd_adptrs, *adptr);

		stream_fifo_free((*adptr)->ibuf_fifo);
		stream_free((*adptr)->ibuf_work);
		// stream_fifo_free((*adptr)->obuf_fifo);
		// stream_free((*adptr)->obuf_work);

		XFREE(MTYPE_CMGD_FRNTND_ADPATER, *adptr);
	}

	*adptr = NULL;
}

int cmgd_frntnd_adapter_init(struct thread_master *tm, struct cmgd_master *cm)
{
	if (!cmgd_frntnd_adptr_tm) {
		cmgd_frntnd_adptr_tm = tm;
		cmgd_frntnd_adptr_cm = cm;
		cmgd_frntnd_adptr_list_init(&cmgd_frntnd_adptrs);
	}

	return 0;
}

cmgd_frntnd_client_adapter_t *cmgd_frntnd_create_adapter(
	int conn_fd, union sockunion *from)
{
	cmgd_frntnd_client_adapter_t *adptr = NULL;

	adptr = cmgd_frntnd_find_adapter_by_fd(conn_fd);
	if (!adptr) {
		adptr = XMALLOC(MTYPE_CMGD_FRNTND_ADPATER, 
				sizeof(cmgd_frntnd_client_adapter_t));
		assert(adptr);

		adptr->conn_fd = conn_fd;
		memcpy(&adptr->conn_su, from, sizeof(adptr->conn_su));
		snprintf(adptr->name, sizeof(adptr->name), "Unknown-FD-%d", adptr->conn_fd);
		cmgd_frntnd_sessn_list_init(&adptr->frntnd_sessns);
		adptr->ibuf_fifo = stream_fifo_new();
		adptr->ibuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
		// adptr->obuf_fifo = stream_fifo_new();
		// adptr->obuf_work = stream_new(CMGD_FRNTND_MSG_MAX_LEN);
		cmgd_frntnd_adapter_lock(adptr);

		cmgd_frntnd_adptr_register_event(adptr, CMGD_FRNTND_CONN_READ);
		cmgd_frntnd_adptr_list_add_tail(&cmgd_frntnd_adptrs, adptr);

		CMGD_FRNTND_ADPTR_DBG(
			"Added new CMGD Frontend adapter '%s'", adptr->name);
	}

	/* Make client socket non-blocking.  */
	set_nonblocking(adptr->conn_fd);

	return adptr;
}

cmgd_frntnd_client_adapter_t *cmgd_frntnd_get_adapter(const char *name)
{
	return cmgd_frntnd_find_adapter_by_name(name);
}

int cmgd_frntnd_send_set_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
	const char *error_if_any)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->cfg_trxn_id != trxn_id)
		return -1;

	return cmgd_frntnd_send_setcfg_reply(sessn, db_id, req_id,
		result == CMGD_SUCCESS ? true : false, error_if_any);
}

int cmgd_frntnd_send_commit_cfg_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t src_db_id,
        cmgd_database_id_t dst_db_id, cmgd_client_req_id_t req_id,
	bool validate_only, cmgd_result_t result,
	const char *error_if_any)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->cfg_trxn_id != trxn_id)
		return -1;

	return cmgd_frntnd_send_commitcfg_reply(sessn,
			src_db_id, dst_db_id, req_id, result == CMGD_SUCCESS,
			validate_only, error_if_any);
}

int cmgd_frntnd_send_get_data_reply(cmgd_session_id_t session_id,
        cmgd_trxn_id_t trxn_id, cmgd_database_id_t db_id,
        cmgd_client_req_id_t req_id, cmgd_result_t result,
        cmgd_yang_data_t *data_resp[], int num_data,
	const char *error_if_any)
{
	cmgd_frntnd_sessn_ctxt_t *sessn;

	sessn = (cmgd_frntnd_sessn_ctxt_t *)session_id;
	if (!sessn || sessn->trxn_id != trxn_id)
		return -1;

	return 0;
}

int cmgd_frntnd_send_data_notify(
        cmgd_database_id_t db_id, cmgd_yang_data_t *data_resp[], int num_data)
{
	// cmgd_frntnd_sessn_ctxt_t *sessn;

	return 0;
}

void cmgd_frntnd_adapter_status_write(struct vty *vty)
{
	cmgd_frntnd_client_adapter_t *adptr;
	cmgd_frntnd_sessn_ctxt_t *sessn;

	vty_out(vty, "CMGD Frontend Adpaters\n");

	FOREACH_ADPTR_IN_LIST(adptr) {
		vty_out(vty, "  Client: \t\t\t%s\n", adptr->name);
		vty_out(vty, "    Conn-FD: \t\t\t%d\n", adptr->conn_fd);
		vty_out(vty, "    Sessions\n");
		FOREACH_SESSN_IN_LIST(adptr, sessn) {
			vty_out(vty, "      Client-Id: \t\t0x%lx\n",
				sessn->client_id);
			vty_out(vty, "      Session-Id: \t\t%p\n", sessn);
		}
		vty_out(vty, "    Total: %d\n",
			(int) cmgd_frntnd_sessn_list_count(&adptr->frntnd_sessns));
	}
	vty_out(vty, "  Total: %d\n", 
		(int) cmgd_frntnd_adptr_list_count(&cmgd_frntnd_adptrs));
}
