// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

#include "pcep_msg_encoding.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

#define TIMER_OPEN_KEEP_ALIVE_SECONDS 1

/* Session Logic Handle managed in pcep_session_logic.c */
extern pcep_event_queue *session_logic_event_queue_;
void send_keep_alive(pcep_session *session);
void send_pcep_error_with_object(pcep_session *session,
				 enum pcep_error_type error_type,
				 enum pcep_error_value error_value,
				 struct pcep_object_header *object);
void reset_dead_timer(pcep_session *session);
bool verify_pcep_open_object(pcep_session *session,
			     struct pcep_object_open *open_object);
void send_reconciled_pcep_open(pcep_session *session,
			       struct pcep_message *error_msg);
bool handle_pcep_update(pcep_session *session, struct pcep_message *upd_msg);
bool handle_pcep_initiate(pcep_session *session, struct pcep_message *init_msg);
bool check_and_send_open_keep_alive(pcep_session *session);
void log_pcc_pce_connection(pcep_session *session);
bool handle_pcep_open(pcep_session *session, struct pcep_message *open_msg);

/*
 * util functions called by the state handling below
 */

void send_keep_alive(pcep_session *session)
{
	struct pcep_message *keep_alive_msg = pcep_msg_create_keepalive();

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic send keep_alive message for session [%d]",
		__func__, time(NULL), pthread_self(), session->session_id);

	session_send_message(session, keep_alive_msg);

	/* The keep alive timer will be (re)set once the message
	 * is sent in session_logic_message_sent_handler() */
}


/* Send an error message with the corrected or offending object */
void send_pcep_error_with_object(pcep_session *session,
				 enum pcep_error_type error_type,
				 enum pcep_error_value error_value,
				 struct pcep_object_header *object)
{
	double_linked_list *obj_list = dll_initialize();
	dll_append(obj_list, object);
	struct pcep_message *error_msg = pcep_msg_create_error_with_objects(
		error_type, error_value, obj_list);

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic send error message with object [%d][%d] for session [%d]",
		__func__, time(NULL), pthread_self(), error_type, error_value,
		session->session_id);

	session_send_message(session, error_msg);
}


void send_pcep_error(pcep_session *session, enum pcep_error_type error_type,
		     enum pcep_error_value error_value)
{
	struct pcep_message *error_msg =
		pcep_msg_create_error(error_type, error_value);

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic send error message [%d][%d] for session [%d]",
		__func__, time(NULL), pthread_self(), error_type, error_value,
		session->session_id);

	session_send_message(session, error_msg);
}


void reset_dead_timer(pcep_session *session)
{
	/* Default to configured dead_timer if its not set yet or set to 0 by
	 * the PCE */
	int dead_timer_seconds =
		(session->pcc_config.dead_timer_pce_negotiated_seconds == 0)
			? session->pcc_config.dead_timer_seconds
			: session->pcc_config.dead_timer_pce_negotiated_seconds;

	if (session->timer_id_dead_timer == TIMER_ID_NOT_SET) {
		session->timer_id_dead_timer =
			create_timer(dead_timer_seconds, session);
		pcep_log(
			LOG_INFO,
			"%s: [%ld-%ld] pcep_session_logic set dead timer [%d secs] id [%d] for session [%d]",
			__func__, time(NULL), pthread_self(),
			dead_timer_seconds, session->timer_id_dead_timer,
			session->session_id);
	} else {
		pcep_log(
			LOG_INFO,
			"%s: [%ld-%ld] pcep_session_logic reset dead timer [%d secs] id [%d] for session [%d]",
			__func__, time(NULL), pthread_self(),
			dead_timer_seconds, session->timer_id_dead_timer,
			session->session_id);
		reset_timer(session->timer_id_dead_timer);
	}
}


void enqueue_event(pcep_session *session, pcep_event_type event_type,
		   struct pcep_message *message)
{
	if (event_type == MESSAGE_RECEIVED && message == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: enqueue_event cannot enqueue a NULL message session [%d]",
			__func__, session->session_id);
		return;
	}

	pcep_event *event = pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_event));
	memset(event, 0, sizeof(pcep_event));

	event->session = session;
	event->event_type = event_type;
	event->event_time = time(NULL);
	event->message = message;

	pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
	if (session_logic_event_queue_->event_callback != NULL) {
		session_logic_event_queue_->event_callback(
			session_logic_event_queue_->event_callback_data, event);
	} else {
		queue_enqueue(session_logic_event_queue_->event_queue, event);
	}
	pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);
}

/* Verify the received PCEP Open object parameters are acceptable. If not,
 * update the unacceptable value(s) with an acceptable value so it can be sent
 * back to the sender. */
bool verify_pcep_open_object(pcep_session *session,
			     struct pcep_object_open *open_object)
{
	int retval = true;

	if (open_object->open_keepalive
	    < session->pcc_config.min_keep_alive_seconds) {
		pcep_log(
			LOG_INFO,
			"%s: Rejecting unsupported Open Keep Alive value [%d] min [%d]",
			__func__, open_object->open_keepalive,
			session->pcc_config.min_keep_alive_seconds);
		open_object->open_keepalive =
			session->pcc_config.min_keep_alive_seconds;
		retval = false;
	} else if (open_object->open_keepalive
		   > session->pcc_config.max_keep_alive_seconds) {
		pcep_log(
			LOG_INFO,
			"%s: Rejecting unsupported Open Keep Alive value [%d] max [%d]",
			__func__, open_object->open_keepalive,
			session->pcc_config.max_keep_alive_seconds);
		open_object->open_keepalive =
			session->pcc_config.max_keep_alive_seconds;
		retval = false;
	}

	if (open_object->open_deadtimer
	    < session->pcc_config.min_dead_timer_seconds) {
		pcep_log(LOG_INFO,
			 "%s: Rejecting unsupported Open Dead Timer value [%d]",
			 __func__, open_object->open_deadtimer);
		open_object->open_deadtimer =
			session->pcc_config.min_dead_timer_seconds;
		retval = false;
	} else if (open_object->open_deadtimer
		   > session->pcc_config.max_dead_timer_seconds) {
		pcep_log(LOG_INFO,
			 "%s: Rejecting unsupported Open Dead Timer value [%d]",
			 __func__, open_object->open_deadtimer);
		open_object->open_deadtimer =
			session->pcc_config.max_dead_timer_seconds;
		retval = false;
	}

	/* Check for Open Object TLVs */
	if (pcep_object_has_tlvs((struct pcep_object_header *)open_object)
	    == false) {
		/* There are no TLVs, all done */
		return retval;
	}

	double_linked_list_node *tlv_node = open_object->header.tlv_list->head;
	while (tlv_node != NULL) {
		struct pcep_object_tlv_header *tlv = tlv_node->data;
		tlv_node = tlv_node->next_node;

		/* Supported Open Object TLVs */
		switch (tlv->type) {
		case PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION:
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY:
		case PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID:
		case PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY:
		case PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY:
			break;

		case PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR:
		case PCEP_OBJ_TLV_TYPE_OBJECTIVE_FUNCTION_LIST:
		case PCEP_OBJ_TLV_TYPE_VENDOR_INFO:
		case PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME:
		case PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS:
		case PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS:
		case PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE:
		case PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC:
		case PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE:
		case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID:
		case PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME:
		case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID:
		case PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE:
		case PCEP_OBJ_TLV_TYPE_UNKNOWN:
		case PCEP_OBJ_TYPE_CISCO_BSID:
		case PCEP_OBJ_TLV_TYPE_ARBITRARY:
			/* TODO how to handle unrecognized TLV ?? */
			pcep_log(
				LOG_INFO,
				"%s: Unhandled OPEN Object TLV type: %d, length %d",
				__func__, tlv->type, tlv->encoded_tlv_length);
			break;
		}

		/* Verify the STATEFUL-PCE-CAPABILITY TLV */
		if (tlv->type == PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY) {
			struct pcep_object_tlv_stateful_pce_capability
				*pce_cap_tlv =
					(struct
					 pcep_object_tlv_stateful_pce_capability
						 *)tlv;

			/* If the U flag is set, then the PCE is
			 * capable of updating LSP parameters */
			if (pce_cap_tlv->flag_u_lsp_update_capability) {
				if (session->pce_config
					    .support_stateful_pce_lsp_update
				    == false) {
					/* Turn off the U bit, as it is not
					 * supported */
					pcep_log(
						LOG_INFO,
						"%s: Rejecting unsupported Open STATEFUL-PCE-CAPABILITY TLV U flag",
						__func__);
					pce_cap_tlv
						->flag_u_lsp_update_capability =
						false;
					retval = false;
				} else {
					session->stateful_pce = true;
					pcep_log(
						LOG_INFO,
						"%s: Setting PCEP session [%d] STATEFUL to support LSP updates",
						__func__, session->session_id);
				}
			}
			/* TODO the rest of the flags are not implemented yet */
			else if (pce_cap_tlv->flag_s_include_db_version) {
				pcep_log(
					LOG_INFO,
					"%s: Ignoring Open STATEFUL-PCE-CAPABILITY TLV S Include DB Version flag",
					__func__);
			} else if (
				pce_cap_tlv
					->flag_i_lsp_instantiation_capability) {
				pcep_log(
					LOG_INFO,
					"%s: Ignoring Open STATEFUL-PCE-CAPABILITY TLV I LSP Instantiation Capability flag",
					__func__);
			} else if (pce_cap_tlv->flag_t_triggered_resync) {
				pcep_log(
					LOG_INFO,
					"%s: Ignoring Open STATEFUL-PCE-CAPABILITY TLV T Triggered Resync flag",
					__func__);
			} else if (pce_cap_tlv->flag_d_delta_lsp_sync) {
				pcep_log(
					LOG_INFO,
					"%s: Ignoring Open STATEFUL-PCE-CAPABILITY TLV D Delta LSP Sync flag",
					__func__);
			} else if (pce_cap_tlv->flag_f_triggered_initial_sync) {
				pcep_log(
					LOG_INFO,
					"%s: Ignoring Open STATEFUL-PCE-CAPABILITY TLV F Triggered Initial Sync flag",
					__func__);
			}
		} else if (tlv->type == PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION) {
			if (session->pce_config.support_include_db_version
			    == false) {
				pcep_log(
					LOG_INFO,
					"%s: Rejecting unsupported Open LSP DB VERSION TLV",
					__func__);
				/* Remove this TLV from the list */
				dll_delete_node(open_object->header.tlv_list,
						tlv_node);
				retval = false;
			}
		}
	}

	return retval;
}


bool handle_pcep_open(pcep_session *session, struct pcep_message *open_msg)
{
	/* Open Message validation and errors according to:
	 * https://tools.ietf.org/html/rfc5440#section-7.15 */

	if (session->session_state != SESSION_STATE_PCEP_CONNECTING
	    && session->session_state != SESSION_STATE_INITIALIZED) {
		pcep_log(
			LOG_INFO,
			"%s: Received unexpected OPEN, current session state [%d, replying with error]",
			__func__, session->session_state);
		send_pcep_error(session,
				PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION,
				PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
		return false;
	}

	if (session->pce_open_received == true
	    && session->pce_open_rejected == false) {
		pcep_log(LOG_INFO,
			 "%s: Received duplicate OPEN, replying with error",
			 __func__);
		send_pcep_error(session,
				PCEP_ERRT_ATTEMPT_TO_ESTABLISH_2ND_PCEP_SESSION,
				PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
		return false;
	}

	struct pcep_object_open *open_object =
		(struct pcep_object_open *)pcep_obj_get(open_msg->obj_list,
							PCEP_OBJ_CLASS_OPEN);
	if (open_object == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Received OPEN message with no OPEN object, replying with error",
			__func__);
		send_pcep_error(session, PCEP_ERRT_SESSION_FAILURE,
				PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
		return false;
	}

	/* Check for additional Open Msg objects */
	if (open_msg->obj_list->num_entries > 1) {
		pcep_log(
			LOG_INFO,
			"%s: Found additional unsupported objects in the Open message, replying with error",
			__func__);
		send_pcep_error(session, PCEP_ERRT_SESSION_FAILURE,
				PCEP_ERRV_RECVD_INVALID_OPEN_MSG);
		return false;
	}

	session->pce_open_received = true;

	/* Verify the open object parameters and TLVs */
	if (verify_pcep_open_object(session, open_object) == false) {
		enqueue_event(session, PCC_RCVD_INVALID_OPEN, NULL);
		if (session->pce_open_rejected) {
			/* The Open message was already rejected once, so
			 * according to the spec, send an error message and
			 * close the TCP connection. */
			pcep_log(
				LOG_INFO,
				"%s: Received 2 consecutive unsupported Open messages, closing the connection.",
				__func__);
			send_pcep_error(
				session, PCEP_ERRT_SESSION_FAILURE,
				PCEP_ERRV_RECVD_SECOND_OPEN_MSG_UNACCEPTABLE);
			socket_comm_session_close_tcp_after_write(
				session->socket_comm_session);
			session->session_state = SESSION_STATE_INITIALIZED;
			enqueue_event(session, PCC_CONNECTION_FAILURE, NULL);
		} else {
			session->pce_open_rejected = true;
			/* Clone the object here, since the encapsulating
			 * message will be deleted in handle_socket_comm_event()
			 * most likely before this error message is sent */
			struct pcep_object_open *cloned_open_object =
				pceplib_malloc(PCEPLIB_MESSAGES,
					       sizeof(struct pcep_object_open));
			memcpy(cloned_open_object, open_object,
			       sizeof(struct pcep_object_open));
			open_object->header.tlv_list = NULL;
			cloned_open_object->header.encoded_object = NULL;
			cloned_open_object->header.encoded_object_length = 0;
			send_pcep_error_with_object(
				session, PCEP_ERRT_SESSION_FAILURE,
				PCEP_ERRV_UNACCEPTABLE_OPEN_MSG_NEG,
				&cloned_open_object->header);
		}

		return false;
	}

	/*
	 * Open Message accepted
	 * Sending the keep-alive response will be managed the function caller
	 */

	session->timer_id_open_keep_alive =
		create_timer(TIMER_OPEN_KEEP_ALIVE_SECONDS, session);
	session->pcc_config.dead_timer_pce_negotiated_seconds =
		(int)open_object->open_deadtimer;
	/* Cancel the timer so we can change the dead_timer value */
	cancel_timer(session->timer_id_dead_timer);
	session->timer_id_dead_timer = TIMER_ID_NOT_SET;
	reset_dead_timer(session);

	return true;
}


/* The original PCEP Open message sent to the PCE was rejected,
 * try to reconcile the differences and re-send a new Open. */
void send_reconciled_pcep_open(pcep_session *session,
			       struct pcep_message *error_msg)
{
	struct pcep_message *open_msg = create_pcep_open(session);

	struct pcep_object_open *error_open_obj =
		(struct pcep_object_open *)pcep_obj_get(error_msg->obj_list,
							PCEP_OBJ_CLASS_OPEN);
	if (error_open_obj == NULL) {
		/* Nothing to reconcile, send the same Open message again */
		pcep_log(
			LOG_INFO,
			"%s: No Open object received in Error, sending the same Open message",
			__func__);
		session_send_message(session, open_msg);
		return;
	}

	struct pcep_object_open *open_obj =
		(struct pcep_object_open *)pcep_obj_get(open_msg->obj_list,
							PCEP_OBJ_CLASS_OPEN);
	// open_msg can not have empty obj_list
	assert(open_obj != NULL);

	if (error_open_obj->open_deadtimer
	    != session->pce_config.dead_timer_seconds) {
		if (error_open_obj->open_deadtimer
			    >= session->pce_config.min_dead_timer_seconds
		    && error_open_obj->open_deadtimer
			       <= session->pce_config.max_dead_timer_seconds) {
			open_obj->open_deadtimer =
				error_open_obj->open_deadtimer;
			session->pcc_config.dead_timer_pce_negotiated_seconds =
				error_open_obj->open_deadtimer;
			pcep_log(
				LOG_INFO,
				"%s: Open deadtimer value [%d] rejected, using PCE value [%d]",
				__func__,
				session->pcc_config.dead_timer_seconds,
				session->pcc_config
					.dead_timer_pce_negotiated_seconds);
			/* Reset the timer with the new value */
			cancel_timer(session->timer_id_dead_timer);
			session->timer_id_dead_timer = TIMER_ID_NOT_SET;
			reset_dead_timer(session);
		} else {
			pcep_log(
				LOG_INFO,
				"%s: Can not reconcile Open with suggested deadtimer [%d]",
				__func__, error_open_obj->open_deadtimer);
		}
	}

	if (error_open_obj->open_keepalive
	    != session->pce_config.keep_alive_seconds) {
		if (error_open_obj->open_keepalive
			    >= session->pce_config.min_keep_alive_seconds
		    && error_open_obj->open_keepalive
			       <= session->pce_config.max_keep_alive_seconds) {
			open_obj->open_keepalive =
				error_open_obj->open_keepalive;
			session->pcc_config
				.keep_alive_pce_negotiated_timer_seconds =
				error_open_obj->open_keepalive;
			pcep_log(
				LOG_INFO,
				"%s: Open keep alive value [%d] rejected, using PCE value [%d]",
				__func__,
				session->pcc_config.keep_alive_seconds,
				session->pcc_config
					.keep_alive_pce_negotiated_timer_seconds);
			/* Cancel the timer, the timer will be set again with
			 * the new value when this open message is sent */
			cancel_timer(session->timer_id_keep_alive);
			session->timer_id_keep_alive = TIMER_ID_NOT_SET;
		} else {
			pcep_log(
				LOG_INFO,
				"%s: Can not reconcile Open with suggested keepalive [%d]",
				__func__, error_open_obj->open_keepalive);
		}
	}

	/* TODO reconcile the TLVs */

	session_send_message(session, open_msg);
	reset_timer(session->timer_id_open_keep_alive);
}


bool handle_pcep_update(pcep_session *session, struct pcep_message *upd_msg)
{
	/* Update Message validation and errors according to:
	 * https://tools.ietf.org/html/rfc8231#section-6.2 */

	if (upd_msg->obj_list == NULL) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PcUpd message: Message has no objects",
			 __func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_SRP_OBJECT_MISSING);
		return false;
	}

	/* Verify the mandatory objects are present */
	struct pcep_object_header *obj =
		pcep_obj_get(upd_msg->obj_list, PCEP_OBJ_CLASS_SRP);
	if (obj == NULL) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PcUpd message: Missing SRP object",
			 __func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_SRP_OBJECT_MISSING);
		return false;
	}

	obj = pcep_obj_get(upd_msg->obj_list, PCEP_OBJ_CLASS_LSP);
	if (obj == NULL) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PcUpd message: Missing LSP object",
			 __func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_LSP_OBJECT_MISSING);
		return false;
	}

	obj = pcep_obj_get(upd_msg->obj_list, PCEP_OBJ_CLASS_ERO);
	if (obj == NULL) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PcUpd message: Missing ERO object",
			 __func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_ERO_OBJECT_MISSING);
		return false;
	}

	/* Verify the objects are are in the correct order */
	double_linked_list_node *node = upd_msg->obj_list->head;
	struct pcep_object_srp *srp_object =
		(struct pcep_object_srp *)node->data;
	if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PcUpd message: First object must be an SRP, found [%d]",
			__func__, srp_object->header.object_class);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_SRP_OBJECT_MISSING);
		return false;
	}

	node = node->next_node;
	struct pcep_object_lsp *lsp_object =
		(struct pcep_object_lsp *)node->data;
	if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PcUpd message: Second object must be an LSP, found [%d]",
			__func__, lsp_object->header.object_class);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_LSP_OBJECT_MISSING);
		return false;
	}

	node = node->next_node;
	struct pcep_object_ro *ero_object = node->data;
	if (ero_object->header.object_class != PCEP_OBJ_CLASS_ERO) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PcUpd message: Third object must be an ERO, found [%d]",
			__func__, ero_object->header.object_class);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_ERO_OBJECT_MISSING);
		return false;
	}

	return true;
}

bool handle_pcep_initiate(pcep_session *session, struct pcep_message *init_msg)
{
	/* Instantiate Message validation and errors according to:
	 * https://tools.ietf.org/html/rfc8281#section-5 */

	if (init_msg->obj_list == NULL) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PcInitiate message: Message has no objects",
			__func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_SRP_OBJECT_MISSING);
		return false;
	}

	/* Verify the mandatory objects are present */
	struct pcep_object_header *obj =
		pcep_obj_get(init_msg->obj_list, PCEP_OBJ_CLASS_SRP);
	if (obj == NULL) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PcInitiate message: Missing SRP object",
			 __func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_SRP_OBJECT_MISSING);
		return false;
	}

	obj = pcep_obj_get(init_msg->obj_list, PCEP_OBJ_CLASS_LSP);
	if (obj == NULL) {
		pcep_log(LOG_INFO,
			 "%s: Invalid PcInitiate message: Missing LSP object",
			 __func__);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_LSP_OBJECT_MISSING);
		return false;
	}

	/* Verify the objects are are in the correct order */
	double_linked_list_node *node = init_msg->obj_list->head;
	struct pcep_object_srp *srp_object =
		(struct pcep_object_srp *)node->data;
	if (srp_object->header.object_class != PCEP_OBJ_CLASS_SRP) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PcInitiate message: First object must be an SRP, found [%d]",
			__func__, srp_object->header.object_class);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_SRP_OBJECT_MISSING);
		return false;
	}

	node = node->next_node;
	struct pcep_object_lsp *lsp_object =
		(struct pcep_object_lsp *)node->data;
	if (lsp_object->header.object_class != PCEP_OBJ_CLASS_LSP) {
		pcep_log(
			LOG_INFO,
			"%s: Invalid PcInitiate message: Second object must be an LSP, found [%d]",
			__func__, lsp_object->header.object_class);
		send_pcep_error(session, PCEP_ERRT_MANDATORY_OBJECT_MISSING,
				PCEP_ERRV_LSP_OBJECT_MISSING);
		return false;
	}

	/* There may be more optional objects */
	return true;
}

void increment_unknown_message(pcep_session *session)
{
	/* https://tools.ietf.org/html/rfc5440#section-6.9
	 * If a PCC/PCE receives unrecognized messages at a rate equal or
	 * greater than MAX-UNKNOWN-MESSAGES unknown message requests per
	 * minute, the PCC/PCE MUST send a PCEP CLOSE message */

	time_t *unknown_message_time =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(time_t));
	*unknown_message_time = time(NULL);
	time_t expire_time = *unknown_message_time + 60;
	queue_enqueue(session->num_unknown_messages_time_queue,
		      unknown_message_time);

	/* Purge any entries older than 1 minute. The oldest entries are at the
	 * queue head */
	queue_node *time_node = session->num_unknown_messages_time_queue->head;
	while (time_node != NULL) {
		if (*((time_t *)time_node->data) > expire_time) {
			pceplib_free(
				PCEPLIB_INFRA,
				queue_dequeue(
					session->num_unknown_messages_time_queue));
			time_node =
				session->num_unknown_messages_time_queue->head;
		} else {
			time_node = NULL;
		}
	}

	if ((int)session->num_unknown_messages_time_queue->num_entries
	    >= session->pcc_config.max_unknown_messages) {
		pcep_log(
			LOG_INFO,
			"%s: [%ld-%ld] Max unknown messages reached [%d] closing session [%d]",
			__func__, time(NULL), pthread_self(),
			session->pcc_config.max_unknown_messages,
			session->session_id);

		close_pcep_session_with_reason(session,
					       PCEP_CLOSE_REASON_UNREC_MSG);
		enqueue_event(session, PCC_RCVD_MAX_UNKOWN_MSGS, NULL);
	}
}

bool check_and_send_open_keep_alive(pcep_session *session)
{
	if (session->pce_open_received == true
	    && session->pce_open_rejected == false
	    && session->pce_open_keep_alive_sent == false) {
		/* Send the PCE Open keep-alive response if it hasnt been sent
		 * yet */
		cancel_timer(session->timer_id_open_keep_alive);
		session->timer_id_open_keep_alive = TIMER_ID_NOT_SET;
		send_keep_alive(session);
		session->pce_open_keep_alive_sent = true;

		return true;
	}

	return false;
}

void log_pcc_pce_connection(pcep_session *session)
{
	if (session->socket_comm_session == NULL) {
		/* This only happens in UT */
		return;
	}

	char src_ip_buf[40] = {0}, dst_ip_buf[40] = {0};
	uint16_t src_port, dst_port;

	if (session->socket_comm_session->is_ipv6) {
		inet_ntop(AF_INET6,
			  &session->socket_comm_session->src_sock_addr
				   .src_sock_addr_ipv6.sin6_addr,
			  src_ip_buf, sizeof(src_ip_buf));
		inet_ntop(AF_INET6,
			  &session->socket_comm_session->dest_sock_addr
				   .dest_sock_addr_ipv6.sin6_addr,
			  dst_ip_buf, sizeof(dst_ip_buf));
		src_port = htons(session->socket_comm_session->src_sock_addr
					 .src_sock_addr_ipv6.sin6_port);
		dst_port = htons(session->socket_comm_session->dest_sock_addr
					 .dest_sock_addr_ipv6.sin6_port);
	} else {
		inet_ntop(AF_INET,
			  &session->socket_comm_session->src_sock_addr
				   .src_sock_addr_ipv4.sin_addr,
			  src_ip_buf, sizeof(src_ip_buf));
		inet_ntop(AF_INET,
			  &session->socket_comm_session->dest_sock_addr
				   .dest_sock_addr_ipv4.sin_addr,
			  dst_ip_buf, sizeof(dst_ip_buf));
		src_port = htons(session->socket_comm_session->src_sock_addr
					 .src_sock_addr_ipv4.sin_port);
		dst_port = htons(session->socket_comm_session->dest_sock_addr
					 .dest_sock_addr_ipv4.sin_port);
	}

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] Successful PCC [%s:%d] connection to PCE [%s:%d] session [%d] fd [%d]",
		__func__, time(NULL), pthread_self(), src_ip_buf, src_port,
		dst_ip_buf, dst_port, session->session_id,
		session->socket_comm_session->socket_fd);
}

/*
 * these functions are called by session_logic_loop() from
 * pcep_session_logic_loop.c these functions are executed in the
 * session_logic_loop thread, and the mutex is locked before calling these
 * functions, so they are thread safe.
 */

/* state machine handling for expired timers */
void handle_timer_event(pcep_session_event *event)
{
	if (event == NULL) {
		pcep_log(LOG_INFO, "%s: handle_timer_event NULL event",
			 __func__);
		return;
	}

	pcep_session *session = event->session;

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic handle_timer_event: session [%d] event timer_id [%d] session timers [OKW, OKA, DT, KA] [%d, %d, %d, %d]",
		__func__, time(NULL), pthread_self(), session->session_id,
		event->expired_timer_id, session->timer_id_open_keep_wait,
		session->timer_id_open_keep_alive, session->timer_id_dead_timer,
		session->timer_id_keep_alive);

	/*
	 * these timer expirations are independent of the session state
	 */
	if (event->expired_timer_id == session->timer_id_dead_timer) {
		session->timer_id_dead_timer = TIMER_ID_NOT_SET;
		increment_event_counters(session,
					 PCEP_EVENT_COUNTER_ID_TIMER_DEADTIMER);
		close_pcep_session_with_reason(session,
					       PCEP_CLOSE_REASON_DEADTIMER);
		enqueue_event(session, PCE_DEAD_TIMER_EXPIRED, NULL);
		return;
	} else if (event->expired_timer_id == session->timer_id_keep_alive) {
		session->timer_id_keep_alive = TIMER_ID_NOT_SET;
		increment_event_counters(session,
					 PCEP_EVENT_COUNTER_ID_TIMER_KEEPALIVE);
		send_keep_alive(session);
		return;
	}

	/*
	 * handle timers that depend on the session state
	 */
	switch (session->session_state) {
	case SESSION_STATE_PCEP_CONNECTING:
		if (event->expired_timer_id
		    == session->timer_id_open_keep_wait) {
			/* close the TCP session */
			pcep_log(
				LOG_INFO,
				"%s: handle_timer_event open_keep_wait timer expired for session [%d]",
				__func__, session->session_id);
			increment_event_counters(
				session,
				PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPWAIT);
			socket_comm_session_close_tcp_after_write(
				session->socket_comm_session);
			session->session_state = SESSION_STATE_INITIALIZED;
			session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
			enqueue_event(session, PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED,
				      NULL);
		}

		if (event->expired_timer_id
		    == session->timer_id_open_keep_alive) {
			increment_event_counters(
				session,
				PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPALIVE);
			session->timer_id_open_keep_alive = TIMER_ID_NOT_SET;
			if (check_and_send_open_keep_alive(session) == true) {
				if (session->pcc_open_accepted == true
				    && session->session_state
					       != SESSION_STATE_PCEP_CONNECTED) {
					log_pcc_pce_connection(session);
					session->session_state =
						SESSION_STATE_PCEP_CONNECTED;
					increment_event_counters(
						session,
						PCEP_EVENT_COUNTER_ID_PCE_CONNECT);
					enqueue_event(session,
						      PCC_CONNECTED_TO_PCE,
						      NULL);
				}
			}
			return;
		}
		break;

	case SESSION_STATE_INITIALIZED:
	case SESSION_STATE_PCEP_CONNECTED:
	case SESSION_STATE_UNKNOWN:
		pcep_log(
			LOG_INFO,
			"%s: handle_timer_event unrecognized state transition, timer_id [%d] state [%d] session [%d]",
			__func__, event->expired_timer_id,
			session->session_state, session->session_id);
		break;
	}
}

/* State machine handling for received messages.
 * This event was created in session_logic_msg_ready_handler() in
 * pcep_session_logic_loop.c */
void handle_socket_comm_event(pcep_session_event *event)
{
	if (event == NULL) {
		pcep_log(LOG_INFO, "%s: handle_socket_comm_event NULL event",
			 __func__);
		return;
	}

	pcep_session *session = event->session;

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic handle_socket_comm_event: session [%d] num messages [%d] socket_closed [%d]",
		__func__, time(NULL), pthread_self(), session->session_id,
		(event->received_msg_list == NULL
			 ? -1
			 : (int)event->received_msg_list->num_entries),
		event->socket_closed);

	/*
	 * independent of the session state
	 */
	if (event->socket_closed) {
		pcep_log(
			LOG_INFO,
			"%s: handle_socket_comm_event socket closed for session [%d]",
			__func__, session->session_id);
		socket_comm_session_close_tcp(session->socket_comm_session);
		enqueue_event(session, PCE_CLOSED_SOCKET, NULL);
		if (session->session_state == SESSION_STATE_PCEP_CONNECTING) {
			enqueue_event(session, PCC_CONNECTION_FAILURE, NULL);
		}
		session->session_state = SESSION_STATE_INITIALIZED;
		increment_event_counters(session,
					 PCEP_EVENT_COUNTER_ID_PCE_DISCONNECT);
		return;
	}

	reset_dead_timer(session);

	if (event->received_msg_list == NULL) {
		return;
	}

	/* Message received on socket */
	double_linked_list_node *msg_node;
	for (msg_node = event->received_msg_list->head; msg_node != NULL;
	     msg_node = msg_node->next_node) {
		bool message_enqueued = false;
		struct pcep_message *msg =
			(struct pcep_message *)msg_node->data;
		pcep_log(LOG_INFO, "%s: \t %s message", __func__,
			 get_message_type_str(msg->msg_header->type));

		increment_message_rx_counters(session, msg);

		switch (msg->msg_header->type) {
		case PCEP_TYPE_OPEN:
			/* handle_pcep_open() checks session state, and for
			 * duplicate erroneous open messages, and replies with
			 * error messages as needed. It also sets
			 * pce_open_received. */
			if (handle_pcep_open(session, msg) == true) {
				/* PCE Open Message Accepted */
				enqueue_event(session, MESSAGE_RECEIVED, msg);
				message_enqueued = true;
				session->pce_open_accepted = true;
				session->pce_open_rejected = false;
				if (session->pcc_open_accepted) {
					/* If both the PCC and PCE Opens are
					 * accepted, then the session is
					 * connected */

					check_and_send_open_keep_alive(session);
					log_pcc_pce_connection(session);
					session->session_state =
						SESSION_STATE_PCEP_CONNECTED;
					increment_event_counters(
						session,
						PCEP_EVENT_COUNTER_ID_PCE_CONNECT);
					enqueue_event(session,
						      PCC_CONNECTED_TO_PCE,
						      NULL);
				}
			}
			break;

		case PCEP_TYPE_KEEPALIVE:
			if (session->session_state
			    == SESSION_STATE_PCEP_CONNECTING) {
				/* PCC Open Message Accepted */
				cancel_timer(session->timer_id_open_keep_wait);
				session->timer_id_open_keep_wait =
					TIMER_ID_NOT_SET;
				session->pcc_open_accepted = true;
				session->pcc_open_rejected = false;
				check_and_send_open_keep_alive(session);

				if (session->pce_open_accepted) {
					/* If both the PCC and PCE Opens are
					 * accepted, then the session is
					 * connected */
					log_pcc_pce_connection(session);
					session->session_state =
						SESSION_STATE_PCEP_CONNECTED;
					increment_event_counters(
						session,
						PCEP_EVENT_COUNTER_ID_PCC_CONNECT);
					enqueue_event(session,
						      PCC_CONNECTED_TO_PCE,
						      NULL);
				}
			}
			/* The dead_timer was already reset above, so nothing
			 * extra to do here */
			break;

		case PCEP_TYPE_PCREP:
			enqueue_event(session, MESSAGE_RECEIVED, msg);
			message_enqueued = true;
			break;

		case PCEP_TYPE_CLOSE:
			session->session_state = SESSION_STATE_INITIALIZED;
			socket_comm_session_close_tcp(
				session->socket_comm_session);
			/* TODO should we also enqueue the message, so they can
			 * see the reasons?? */
			enqueue_event(session, PCE_SENT_PCEP_CLOSE, NULL);
			/* TODO could this duplicate the disconnect counter with
			 * socket close ?? */
			increment_event_counters(
				session, PCEP_EVENT_COUNTER_ID_PCE_DISCONNECT);
			break;

		case PCEP_TYPE_PCREQ:
			/* The PCC does not support receiving PcReq messages */
			send_pcep_error(session,
					PCEP_ERRT_CAPABILITY_NOT_SUPPORTED,
					PCEP_ERRV_UNASSIGNED);
			break;

		case PCEP_TYPE_REPORT:
			/* The PCC does not support receiving Report messages */
			send_pcep_error(session,
					PCEP_ERRT_CAPABILITY_NOT_SUPPORTED,
					PCEP_ERRV_UNASSIGNED);
			break;

		case PCEP_TYPE_UPDATE:
			/* Should reply with a PcRpt */
			if (handle_pcep_update(session, msg) == true) {
				enqueue_event(session, MESSAGE_RECEIVED, msg);
				message_enqueued = true;
			}
			break;

		case PCEP_TYPE_INITIATE:
			/* Should reply with a PcRpt */
			if (handle_pcep_initiate(session, msg) == true) {
				enqueue_event(session, MESSAGE_RECEIVED, msg);
				message_enqueued = true;
			}
			break;

		case PCEP_TYPE_PCNOTF:
			enqueue_event(session, MESSAGE_RECEIVED, msg);
			message_enqueued = true;
			break;

		case PCEP_TYPE_ERROR:
			if (msg->obj_list != NULL
			    && msg->obj_list->num_entries > 0) {
				struct pcep_object_header *obj_hdr =
					pcep_obj_get(msg->obj_list,
						     PCEP_OBJ_CLASS_ERROR);
				if (obj_hdr != NULL) {
					struct pcep_object_error *error_obj =
						(struct pcep_object_error *)
							obj_hdr;
					pcep_log(
						LOG_DEBUG,
						"%s: Error object [type, value] = [%s, %s]",
						__func__,
						get_error_type_str(
							error_obj->error_type),
						get_error_value_str(
							error_obj->error_type,
							error_obj
								->error_value));
				}
			}

			if (session->session_state
			    == SESSION_STATE_PCEP_CONNECTING) {
				/* A PCC_CONNECTION_FAILURE event will be sent
				 * when the socket is closed, if the state is
				 * SESSION_STATE_PCEP_CONNECTING, in case the
				 * PCE allows more than 2 failed open messages.
				 */
				pcep_log(LOG_INFO,
					 "%s: PCC Open message rejected by PCE",
					 __func__);
				session->pcc_open_rejected = true;
				send_reconciled_pcep_open(session, msg);
				enqueue_event(session, PCC_SENT_INVALID_OPEN,
					      NULL);
			}
			enqueue_event(session, MESSAGE_RECEIVED, msg);
			message_enqueued = true;
			break;

		case PCEP_TYPE_START_TLS:
		case PCEP_TYPE_MAX:
			pcep_log(LOG_INFO, "%s: \t UnSupported message",
				 __func__);
			send_pcep_error(session,
					PCEP_ERRT_CAPABILITY_NOT_SUPPORTED,
					PCEP_ERRV_UNASSIGNED);
			increment_unknown_message(session);
			break;
		}

		/* if the message was enqueued, dont free it yet */
		if (message_enqueued == false) {
			pcep_msg_free_message(msg);
		}
	}
	dll_destroy(event->received_msg_list);
}
