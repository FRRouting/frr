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

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "pcep_msg_encoding.h"
#include "pcep_session_logic.h"
#include "pcep_session_logic_internals.h"
#include "pcep_timers.h"
#include "pcep_utils_counters.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

/*
 * public API function implementations for the session_logic
 */

pcep_session_logic_handle *session_logic_handle_ = NULL;
pcep_event_queue *session_logic_event_queue_ = NULL;
int session_id_ = 0;

void send_pcep_open(pcep_session *session); /* forward decl */

static bool run_session_logic_common(void)
{
	if (session_logic_handle_ != NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Session Logic is already initialized.", __func__);
		return false;
	}

	session_logic_handle_ = pceplib_malloc(
		PCEPLIB_INFRA, sizeof(pcep_session_logic_handle));
	memset(session_logic_handle_, 0, sizeof(pcep_session_logic_handle));

	session_logic_handle_->active = true;
	session_logic_handle_->session_list =
		ordered_list_initialize(pointer_compare_function);
	session_logic_handle_->session_event_queue = queue_initialize();

	/* Initialize the event queue */
	session_logic_event_queue_ =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_event_queue));
	session_logic_event_queue_->event_queue = queue_initialize();
	if (pthread_mutex_init(&(session_logic_event_queue_->event_queue_mutex),
			       NULL)
	    != 0) {
		pcep_log(
			LOG_ERR,
			"%s: Cannot initialize session_logic event queue mutex.",
			__func__);
		return false;
	}

	pthread_cond_init(&(session_logic_handle_->session_logic_cond_var),
			  NULL);

	if (pthread_mutex_init(&(session_logic_handle_->session_logic_mutex),
			       NULL)
	    != 0) {
		pcep_log(LOG_ERR, "%s: Cannot initialize session_logic mutex.",
			 __func__);
		return false;
	}

	pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
	session_logic_handle_->session_logic_condition = true;
	pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
	pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));

	if (pthread_mutex_init(&(session_logic_handle_->session_list_mutex),
			       NULL)
	    != 0) {
		pcep_log(LOG_ERR, "%s: Cannot initialize session_list mutex.",
			 __func__);
		return false;
	}

	return true;
}


bool run_session_logic(void)
{
	if (!run_session_logic_common()) {
		return false;
	}

	if (pthread_create(&(session_logic_handle_->session_logic_thread), NULL,
			   session_logic_loop, session_logic_handle_)) {
		pcep_log(LOG_ERR, "%s: Cannot initialize session_logic thread.",
			 __func__);
		return false;
	}

	if (!initialize_timers(session_logic_timer_expire_handler)) {
		pcep_log(LOG_ERR, "%s: Cannot initialize session_logic timers.",
			 __func__);
		return false;
	}

	/* No need to call initialize_socket_comm_loop() since it will be
	 * called internally when the first socket_comm_session is created. */

	return true;
}


bool run_session_logic_with_infra(pceplib_infra_config *infra_config)
{
	if (infra_config == NULL) {
		return run_session_logic();
	}

	/* Initialize the memory infrastructure before anything gets allocated
	 */
	if (infra_config->pceplib_infra_mt != NULL
	    && infra_config->pceplib_messages_mt != NULL) {
		pceplib_memory_initialize(
			infra_config->pceplib_infra_mt,
			infra_config->pceplib_messages_mt,
			infra_config->malloc_func, infra_config->calloc_func,
			infra_config->realloc_func, infra_config->strdup_func,
			infra_config->free_func);
	}

	if (!run_session_logic_common()) {
		return false;
	}

	/* Create the pcep_session_logic pthread so it can be managed externally
	 */
	if (infra_config->pthread_create_func != NULL) {
		if (infra_config->pthread_create_func(
			    &(session_logic_handle_->session_logic_thread),
			    NULL, session_logic_loop, session_logic_handle_,
			    "pcep_session_logic")) {
			pcep_log(
				LOG_ERR,
				"%s: Cannot initialize external session_logic thread.",
				__func__);
			return false;
		}
	} else {
		if (pthread_create(
			    &(session_logic_handle_->session_logic_thread),
			    NULL, session_logic_loop, session_logic_handle_)) {
			pcep_log(LOG_ERR,
				 "%s: Cannot initialize session_logic thread.",
				 __func__);
			return false;
		}
	}

	session_logic_event_queue_->event_callback =
		infra_config->pcep_event_func;
	session_logic_event_queue_->event_callback_data =
		infra_config->external_infra_data;

	if (!initialize_timers_external_infra(
		    session_logic_timer_expire_handler,
		    infra_config->external_infra_data,
		    infra_config->timer_create_func,
		    infra_config->timer_cancel_func,
		    infra_config->pthread_create_func)) {
		pcep_log(
			LOG_ERR,
			"%s: Cannot initialize session_logic timers with infra.",
			__func__);
		return false;
	}

	/* We found a problem with the FRR sockets, where not all the KeepAlive
	 * messages were received, so if the pthread_create_func is set, the
	 * internal PCEPlib socket infrastructure will be used. */

	/* For the SocketComm, the socket_read/write_func and the
	 * pthread_create_func are mutually exclusive. */
	if (infra_config->pthread_create_func != NULL) {
		if (!initialize_socket_comm_external_infra(
			    infra_config->external_infra_data, NULL, NULL,
			    infra_config->pthread_create_func)) {
			pcep_log(
				LOG_ERR,
				"%s: Cannot initialize session_logic socket comm with infra.",
				__func__);
			return false;
		}
	} else if (infra_config->socket_read_func != NULL
		   && infra_config->socket_write_func != NULL) {
		if (!initialize_socket_comm_external_infra(
			    infra_config->external_infra_data,
			    infra_config->socket_read_func,
			    infra_config->socket_write_func, NULL)) {
			pcep_log(
				LOG_ERR,
				"%s: Cannot initialize session_logic socket comm with infra.",
				__func__);
			return false;
		}
	}

	return true;
}

bool run_session_logic_wait_for_completion(void)
{
	if (!run_session_logic()) {
		return false;
	}

	/* Blocking call, waits for session logic thread to complete */
	pthread_join(session_logic_handle_->session_logic_thread, NULL);

	return true;
}


bool stop_session_logic(void)
{
	if (session_logic_handle_ == NULL) {
		pcep_log(LOG_WARNING, "%s: Session logic already stopped",
			 __func__);
		return false;
	}

	session_logic_handle_->active = false;
	teardown_timers();

	pthread_mutex_lock(&(session_logic_handle_->session_logic_mutex));
	session_logic_handle_->session_logic_condition = true;
	pthread_cond_signal(&(session_logic_handle_->session_logic_cond_var));
	pthread_mutex_unlock(&(session_logic_handle_->session_logic_mutex));
	pthread_join(session_logic_handle_->session_logic_thread, NULL);

	pthread_mutex_destroy(&(session_logic_handle_->session_logic_mutex));
	pthread_mutex_destroy(&(session_logic_handle_->session_list_mutex));
	ordered_list_destroy(session_logic_handle_->session_list);
	queue_destroy(session_logic_handle_->session_event_queue);

	/* destroy the event_queue */
	pthread_mutex_destroy(&(session_logic_event_queue_->event_queue_mutex));
	queue_destroy(session_logic_event_queue_->event_queue);
	pceplib_free(PCEPLIB_INFRA, session_logic_event_queue_);

	/* Explicitly stop the socket comm loop started by the pcep_sessions */
	destroy_socket_comm_loop();

	pceplib_free(PCEPLIB_INFRA, session_logic_handle_);
	session_logic_handle_ = NULL;

	return true;
}


void close_pcep_session(pcep_session *session)
{
	close_pcep_session_with_reason(session, PCEP_CLOSE_REASON_NO);
}

void close_pcep_session_with_reason(pcep_session *session,
				    enum pcep_close_reason reason)
{
	struct pcep_message *close_msg = pcep_msg_create_close(reason);

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic send pcep_close message for session [%d]",
		__func__, time(NULL), pthread_self(), session->session_id);

	session_send_message(session, close_msg);
	socket_comm_session_close_tcp_after_write(session->socket_comm_session);
	session->session_state = SESSION_STATE_INITIALIZED;
}


void destroy_pcep_session(pcep_session *session)
{
	if (session == NULL) {
		pcep_log(LOG_WARNING, "%s: Cannot destroy NULL session",
			 __func__);
		return;
	}

	/* Remove the session from the session_list and synchronize session
	 * destroy with the session_logic_loop, so that no in-flight events
	 * will be handled now that the session is destroyed. */
	pthread_mutex_lock(&(session_logic_handle_->session_list_mutex));
	ordered_list_remove_first_node_equals(
		session_logic_handle_->session_list, session);
	pcep_log(LOG_DEBUG,
		 "%s: destroy_pcep_session delete session_list sessionPtr %p",
		 __func__, session);

	pcep_session_cancel_timers(session);
	delete_counters_group(session->pcep_session_counters);
	queue_destroy_with_data(session->num_unknown_messages_time_queue);
	socket_comm_session_teardown(session->socket_comm_session);

	if (session->pcc_config.pcep_msg_versioning != NULL) {
		pceplib_free(PCEPLIB_INFRA,
			     session->pcc_config.pcep_msg_versioning);
	}

	if (session->pce_config.pcep_msg_versioning != NULL) {
		pceplib_free(PCEPLIB_INFRA,
			     session->pce_config.pcep_msg_versioning);
	}

	int session_id = session->session_id;
	pceplib_free(PCEPLIB_INFRA, session);
	pcep_log(LOG_INFO, "%s: [%ld-%ld] session [%d] destroyed", __func__,
		 time(NULL), pthread_self(), session_id);
	pthread_mutex_unlock(&(session_logic_handle_->session_list_mutex));
}

void pcep_session_cancel_timers(pcep_session *session)
{
	if (session == NULL) {
		return;
	}

	if (session->timer_id_dead_timer != TIMER_ID_NOT_SET) {
		cancel_timer(session->timer_id_dead_timer);
	}

	if (session->timer_id_keep_alive != TIMER_ID_NOT_SET) {
		cancel_timer(session->timer_id_keep_alive);
	}

	if (session->timer_id_open_keep_wait != TIMER_ID_NOT_SET) {
		cancel_timer(session->timer_id_open_keep_wait);
	}

	if (session->timer_id_open_keep_alive != TIMER_ID_NOT_SET) {
		cancel_timer(session->timer_id_open_keep_alive);
	}
}

/* Internal util function */
static int get_next_session_id(void)
{
	if (session_id_ == INT_MAX) {
		session_id_ = 0;
	}

	return session_id_++;
}

/* Internal util function */
static pcep_session *create_pcep_session_pre_setup(pcep_configuration *config)
{
	if (config == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot create pcep session with NULL config",
			 __func__);
		return NULL;
	}

	pcep_session *session =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_session));
	memset(session, 0, sizeof(pcep_session));
	session->session_id = get_next_session_id();
	session->session_state = SESSION_STATE_INITIALIZED;
	session->timer_id_open_keep_wait = TIMER_ID_NOT_SET;
	session->timer_id_open_keep_alive = TIMER_ID_NOT_SET;
	session->timer_id_dead_timer = TIMER_ID_NOT_SET;
	session->timer_id_keep_alive = TIMER_ID_NOT_SET;
	session->stateful_pce = false;
	session->num_unknown_messages_time_queue = queue_initialize();
	session->pce_open_received = false;
	session->pce_open_rejected = false;
	session->pce_open_keep_alive_sent = false;
	session->pcc_open_rejected = false;
	session->pce_open_accepted = false;
	session->pcc_open_accepted = false;
	session->destroy_session_after_write = false;
	session->lsp_db_version = config->lsp_db_version;
	memcpy(&(session->pcc_config), config, sizeof(pcep_configuration));
	/* copy the pcc_config to the pce_config until we receive the open
	 * keep_alive response */
	memcpy(&(session->pce_config), config, sizeof(pcep_configuration));
	if (config->pcep_msg_versioning != NULL) {
		session->pcc_config.pcep_msg_versioning = pceplib_malloc(
			PCEPLIB_INFRA, sizeof(struct pcep_versioning));
		memcpy(session->pcc_config.pcep_msg_versioning,
		       config->pcep_msg_versioning,
		       sizeof(struct pcep_versioning));
		session->pce_config.pcep_msg_versioning = pceplib_malloc(
			PCEPLIB_INFRA, sizeof(struct pcep_versioning));
		memcpy(session->pce_config.pcep_msg_versioning,
		       config->pcep_msg_versioning,
		       sizeof(struct pcep_versioning));
	}

	pthread_mutex_lock(&(session_logic_handle_->session_list_mutex));
	ordered_list_add_node(session_logic_handle_->session_list, session);
	pcep_log(
		LOG_DEBUG,
		"%s: create_pcep_session_pre_setup add session_list sessionPtr %p",
		__func__, session);
	pthread_mutex_unlock(&(session_logic_handle_->session_list_mutex));

	return session;
}

/* Internal util function */
static bool create_pcep_session_post_setup(pcep_session *session)
{
	if (!socket_comm_session_connect_tcp(session->socket_comm_session)) {
		pcep_log(LOG_WARNING, "%s: Cannot establish TCP socket.",
			 __func__);
		destroy_pcep_session(session);

		return false;
	}

	session->time_connected = time(NULL);
	create_session_counters(session);

	send_pcep_open(session);

	session->session_state = SESSION_STATE_PCEP_CONNECTING;
	session->timer_id_open_keep_wait =
		create_timer(session->pcc_config.keep_alive_seconds, session);
	// session->session_state = SESSION_STATE_OPENED;

	return true;
}

pcep_session *create_pcep_session(pcep_configuration *config,
				  struct in_addr *pce_ip)
{
	if (pce_ip == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot create pcep session with NULL pce_ip",
			 __func__);
		return NULL;
	}

	pcep_session *session = create_pcep_session_pre_setup(config);
	if (session == NULL) {
		return NULL;
	}

	session->socket_comm_session = socket_comm_session_initialize_with_src(
		NULL, session_logic_msg_ready_handler,
		session_logic_message_sent_handler,
		session_logic_conn_except_notifier, &(config->src_ip.src_ipv4),
		((config->src_pcep_port == 0) ? PCEP_TCP_PORT
					      : config->src_pcep_port),
		pce_ip,
		((config->dst_pcep_port == 0) ? PCEP_TCP_PORT
					      : config->dst_pcep_port),
		config->socket_connect_timeout_millis,
		config->tcp_authentication_str, config->is_tcp_auth_md5,
		session);
	if (session->socket_comm_session == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot establish socket_comm_session.", __func__);
		destroy_pcep_session(session);

		return NULL;
	}

	if (create_pcep_session_post_setup(session) == false) {
		return NULL;
	}

	return session;
}

pcep_session *create_pcep_session_ipv6(pcep_configuration *config,
				       struct in6_addr *pce_ip)
{
	if (pce_ip == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot create pcep session with NULL pce_ip",
			 __func__);
		return NULL;
	}

	pcep_session *session = create_pcep_session_pre_setup(config);
	if (session == NULL) {
		return NULL;
	}

	session->socket_comm_session =
		socket_comm_session_initialize_with_src_ipv6(
			NULL, session_logic_msg_ready_handler,
			session_logic_message_sent_handler,
			session_logic_conn_except_notifier,
			&(config->src_ip.src_ipv6),
			((config->src_pcep_port == 0) ? PCEP_TCP_PORT
						      : config->src_pcep_port),
			pce_ip,
			((config->dst_pcep_port == 0) ? PCEP_TCP_PORT
						      : config->dst_pcep_port),
			config->socket_connect_timeout_millis,
			config->tcp_authentication_str, config->is_tcp_auth_md5,
			session);
	if (session->socket_comm_session == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot establish ipv6 socket_comm_session.",
			 __func__);
		destroy_pcep_session(session);

		return NULL;
	}

	if (create_pcep_session_post_setup(session) == false) {
		return NULL;
	}

	return session;
}


void session_send_message(pcep_session *session, struct pcep_message *message)
{
	pcep_encode_message(message, session->pcc_config.pcep_msg_versioning);
	socket_comm_session_send_message(session->socket_comm_session,
					 (char *)message->encoded_message,
					 message->encoded_message_length, true);

	increment_message_tx_counters(session, message);

	/* The message->encoded_message will be freed in
	 * socket_comm_session_send_message() once sent.
	 * Setting to NULL here so pcep_msg_free_message() does not free it */
	message->encoded_message = NULL;
	pcep_msg_free_message(message);
}


/* This function is also used in pcep_session_logic_states.c */
struct pcep_message *create_pcep_open(pcep_session *session)
{
	/* create and send PCEP open
	 * with PCEP, the PCC sends the config the PCE should use in the open
	 * message,
	 * and the PCE will send an open with the config the PCC should use. */
	double_linked_list *tlv_list = dll_initialize();
	if (session->pcc_config.support_stateful_pce_lsp_update
	    || session->pcc_config.support_pce_lsp_instantiation
	    || session->pcc_config.support_include_db_version
	    || session->pcc_config.support_lsp_triggered_resync
	    || session->pcc_config.support_lsp_delta_sync
	    || session->pcc_config.support_pce_triggered_initial_sync) {
		/* Prepend this TLV as the first in the list */
		dll_append(
			tlv_list,
			pcep_tlv_create_stateful_pce_capability(
				/* U flag */
				session->pcc_config
					.support_stateful_pce_lsp_update,
				/* S flag */
				session->pcc_config.support_include_db_version,
				/* I flag */
				session->pcc_config
					.support_pce_lsp_instantiation,
				/* T flag */
				session->pcc_config
					.support_lsp_triggered_resync,
				/* D flag */
				session->pcc_config.support_lsp_delta_sync,
				/* F flag */
				session->pcc_config
					.support_pce_triggered_initial_sync));
	}

	if (session->pcc_config.support_include_db_version) {
		if (session->pcc_config.lsp_db_version != 0) {
			dll_append(tlv_list,
				   pcep_tlv_create_lsp_db_version(
					   session->pcc_config.lsp_db_version));
		}
	}

	if (session->pcc_config.support_sr_te_pst) {
		bool flag_n = false;
		bool flag_x = false;
		if (session->pcc_config.pcep_msg_versioning
			    ->draft_ietf_pce_segment_routing_07
		    == false) {
			flag_n = session->pcc_config.pcc_can_resolve_nai_to_sid;
			flag_x = (session->pcc_config.max_sid_depth == 0);
		}

		struct pcep_object_tlv_sr_pce_capability *sr_pce_cap_tlv =
			pcep_tlv_create_sr_pce_capability(
				flag_n, flag_x,
				session->pcc_config.max_sid_depth);

		double_linked_list *sub_tlv_list = NULL;
		if (session->pcc_config.pcep_msg_versioning
			    ->draft_ietf_pce_segment_routing_07
		    == true) {
			/* With draft07, send the sr_pce_cap_tlv as a normal TLV
			 */
			dll_append(tlv_list, sr_pce_cap_tlv);
		} else {
			/* With draft16, send the sr_pce_cap_tlv as a sub-TLV in
			 * the path_setup_type_capability TLV */
			sub_tlv_list = dll_initialize();
			dll_append(sub_tlv_list, sr_pce_cap_tlv);
		}

		uint8_t *pst =
			pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint8_t));
		*pst = SR_TE_PST;
		double_linked_list *pst_list = dll_initialize();
		dll_append(pst_list, pst);
		dll_append(tlv_list, pcep_tlv_create_path_setup_type_capability(
					     pst_list, sub_tlv_list));
	}

	struct pcep_message *open_msg = pcep_msg_create_open_with_tlvs(
		session->pcc_config.keep_alive_seconds,
		session->pcc_config.dead_timer_seconds, session->session_id,
		tlv_list);

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] pcep_session_logic create open message: TLVs [%d] for session [%d]",
		__func__, time(NULL), pthread_self(), tlv_list->num_entries,
		session->session_id);

	return (open_msg);
}


void send_pcep_open(pcep_session *session)
{
	session_send_message(session, create_pcep_open(session));
}

/* This is a blocking call, since it is synchronized with destroy_pcep_session()
 * and session_logic_loop(). It may be possible that the session has been
 * deleted but API users havent been informed yet.
 */
bool session_exists(pcep_session *session)
{
	if (session_logic_handle_ == NULL) {
		pcep_log(LOG_DEBUG,
			 "%s: session_exists session_logic_handle_ is NULL",
			 __func__);
		return false;
	}

	pthread_mutex_lock(&(session_logic_handle_->session_list_mutex));
	bool retval =
		(ordered_list_find(session_logic_handle_->session_list, session)
		 != NULL);
	pthread_mutex_unlock(&(session_logic_handle_->session_list_mutex));

	return retval;
}
