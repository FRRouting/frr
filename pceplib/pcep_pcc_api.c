/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * Public PCEPlib PCC API implementation
 */

#include <zebra.h>

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pcep_msg_messages.h"
#include "pcep_pcc_api.h"
#include "pcep_utils_counters.h"
#include "pcep_utils_logging.h"

/* Not using an array here since the enum pcep_event_type indeces go into the
 * 100's */
const char MESSAGE_RECEIVED_STR[] = "MESSAGE_RECEIVED";
const char PCE_CLOSED_SOCKET_STR[] = "PCE_CLOSED_SOCKET";
const char PCE_SENT_PCEP_CLOSE_STR[] = "PCE_SENT_PCEP_CLOSE";
const char PCE_DEAD_TIMER_EXPIRED_STR[] = "PCE_DEAD_TIMER_EXPIRED";
const char PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED_STR[] =
	"PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED";
const char PCC_CONNECTED_TO_PCE_STR[] = "PCC_CONNECTED_TO_PCE";
const char PCC_PCEP_SESSION_CLOSED_STR[] = "PCC_PCEP_SESSION_CLOSED";
const char PCC_RCVD_INVALID_OPEN_STR[] = "PCC_RCVD_INVALID_OPEN";
const char PCC_RCVD_MAX_INVALID_MSGS_STR[] = "PCC_RCVD_MAX_INVALID_MSGS";
const char PCC_RCVD_MAX_UNKOWN_MSGS_STR[] = "PCC_RCVD_MAX_UNKOWN_MSGS";
const char UNKNOWN_EVENT_STR[] = "UNKNOWN Event Type";

/* Session Logic Handle managed in pcep_session_logic.c */
extern pcep_event_queue *session_logic_event_queue_;

bool initialize_pcc(void)
{
	if (!run_session_logic()) {
		pcep_log(LOG_ERR, "%s: Error initializing PCC session logic.",
			 __func__);
		return false;
	}

	return true;
}


bool initialize_pcc_infra(struct pceplib_infra_config *infra_config)
{
	if (infra_config == NULL) {
		return initialize_pcc();
	}

	if (!run_session_logic_with_infra(infra_config)) {
		pcep_log(LOG_ERR,
			 "%s: Error initializing PCC session logic with infra.",
			 __func__);
		return false;
	}

	return true;
}


/* this function is blocking */
bool initialize_pcc_wait_for_completion(void)
{
	return run_session_logic_wait_for_completion();
}


bool destroy_pcc(void)
{
	if (!stop_session_logic()) {
		pcep_log(LOG_WARNING, "%s: Error stopping PCC session logic.",
			 __func__);
		return false;
	}

	return true;
}


pcep_configuration *create_default_pcep_configuration(void)
{
	pcep_configuration *config =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_configuration));
	memset(config, 0, sizeof(pcep_configuration));

	config->keep_alive_seconds = DEFAULT_CONFIG_KEEP_ALIVE;
	/* This value will possibly be overwritten later with PCE config data */
	config->keep_alive_pce_negotiated_timer_seconds =
		DEFAULT_CONFIG_KEEP_ALIVE;
	config->min_keep_alive_seconds = DEFAULT_MIN_CONFIG_KEEP_ALIVE;
	config->max_keep_alive_seconds = DEFAULT_MAX_CONFIG_KEEP_ALIVE;

	config->dead_timer_seconds = DEFAULT_CONFIG_DEAD_TIMER;
	/* This value will be overwritten later with PCE config data */
	config->dead_timer_pce_negotiated_seconds = DEFAULT_CONFIG_DEAD_TIMER;
	config->min_dead_timer_seconds = DEFAULT_MIN_CONFIG_DEAD_TIMER;
	config->max_dead_timer_seconds = DEFAULT_MAX_CONFIG_DEAD_TIMER;

	config->request_time_seconds = DEFAULT_CONFIG_REQUEST_TIME;
	config->max_unknown_messages = DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES;
	config->max_unknown_requests = DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS;

	config->socket_connect_timeout_millis =
		DEFAULT_TCP_CONNECT_TIMEOUT_MILLIS;
	config->support_stateful_pce_lsp_update = true;
	config->support_pce_lsp_instantiation = true;
	config->support_include_db_version = true;
	config->lsp_db_version = 0;
	config->support_lsp_triggered_resync = true;
	config->support_lsp_delta_sync = true;
	config->support_pce_triggered_initial_sync = true;
	config->support_sr_te_pst = true;
	config->pcc_can_resolve_nai_to_sid = true;
	config->max_sid_depth = 0;
	config->dst_pcep_port = 0;
	config->src_pcep_port = 0;
	config->src_ip.src_ipv4.s_addr = INADDR_ANY;
	config->is_src_ipv6 = false;
	config->pcep_msg_versioning = create_default_pcep_versioning();
	config->tcp_authentication_str[0] = '\0';
	config->is_tcp_auth_md5 = true;

	return config;
}

void destroy_pcep_configuration(pcep_configuration *config)
{
	destroy_pcep_versioning(config->pcep_msg_versioning);
	pceplib_free(PCEPLIB_INFRA, config);
}

pcep_session *connect_pce(pcep_configuration *config, struct in_addr *pce_ip)
{
	return create_pcep_session(config, pce_ip);
}

pcep_session *connect_pce_ipv6(pcep_configuration *config,
			       struct in6_addr *pce_ip)
{
	return create_pcep_session_ipv6(config, pce_ip);
}

void disconnect_pce(pcep_session *session)
{
	if (session_exists(session) == false) {
		pcep_log(
			LOG_WARNING,
			"%s: disconnect_pce session [%p] has already been deleted",
			__func__, session);
		return;
	}

	if (session->socket_comm_session == NULL
	    || session->socket_comm_session->socket_fd < 0) {
		/* If the socket has already been closed, just destroy the
		 * session */
		destroy_pcep_session(session);
	} else {
		/* This will cause the session to be destroyed AFTER the close
		 * message is sent */
		session->destroy_session_after_write = true;

		/* Send a PCEP close message */
		close_pcep_session(session);
	}
}

void send_message(pcep_session *session, struct pcep_message *msg,
		  bool free_after_send)
{
	if (session == NULL || msg == NULL) {
		pcep_log(LOG_DEBUG,
			 "%s: send_message NULL params session [%p] msg [%p]",
			 __func__, session, msg);

		return;
	}

	if (session_exists(session) == false) {
		pcep_log(
			LOG_WARNING,
			"%s: send_message session [%p] has already been deleted",
			__func__, session);
		return;
	}

	pcep_encode_message(msg, session->pcc_config.pcep_msg_versioning);
	socket_comm_session_send_message(
		session->socket_comm_session, (char *)msg->encoded_message,
		msg->encoded_message_length, free_after_send);

	increment_message_tx_counters(session, msg);

	if (free_after_send == true) {
		/* The encoded_message will be deleted once sent, so everything
		 * else in the message will be freed */
		msg->encoded_message = NULL;
		pcep_msg_free_message(msg);
	}
}

/* Returns true if the queue is empty, false otherwise */
bool event_queue_is_empty(void)
{
	if (session_logic_event_queue_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: event_queue_is_empty Session Logic is not initialized yet",
			__func__);
		return false;
	}

	pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
	bool is_empty =
		(session_logic_event_queue_->event_queue->num_entries == 0);
	pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

	return is_empty;
}


/* Return the number of events on the queue, 0 if empty */
uint32_t event_queue_num_events_available(void)
{
	if (session_logic_event_queue_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: event_queue_num_events_available Session Logic is not initialized yet",
			__func__);
		return 0;
	}

	pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
	uint32_t num_events =
		session_logic_event_queue_->event_queue->num_entries;
	pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

	return num_events;
}


/* Return the next event on the queue, NULL if empty */
struct pcep_event *event_queue_get_event(void)
{
	if (session_logic_event_queue_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: event_queue_get_event Session Logic is not initialized yet",
			__func__);
		return NULL;
	}

	pthread_mutex_lock(&session_logic_event_queue_->event_queue_mutex);
	struct pcep_event *event = (struct pcep_event *)queue_dequeue(
		session_logic_event_queue_->event_queue);
	pthread_mutex_unlock(&session_logic_event_queue_->event_queue_mutex);

	return event;
}


/* Free the PCEP Event resources, including the PCEP message */
void destroy_pcep_event(struct pcep_event *event)
{
	if (event == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: destroy_pcep_event cannot destroy NULL event",
			 __func__);
		return;
	}

	if (event->event_type == MESSAGE_RECEIVED && event->message != NULL) {
		pcep_msg_free_message(event->message);
	}

	pceplib_free(PCEPLIB_INFRA, event);
}

const char *get_event_type_str(int event_type)
{
	switch (event_type) {
	case MESSAGE_RECEIVED:
		return MESSAGE_RECEIVED_STR;
		break;
	case PCE_CLOSED_SOCKET:
		return PCE_CLOSED_SOCKET_STR;
		break;
	case PCE_SENT_PCEP_CLOSE:
		return PCE_SENT_PCEP_CLOSE_STR;
		break;
	case PCE_DEAD_TIMER_EXPIRED:
		return PCE_DEAD_TIMER_EXPIRED_STR;
		break;
	case PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED:
		return PCE_OPEN_KEEP_WAIT_TIMER_EXPIRED_STR;
		break;
	case PCC_CONNECTED_TO_PCE:
		return PCC_CONNECTED_TO_PCE_STR;
		break;
	case PCC_PCEP_SESSION_CLOSED:
		return PCC_PCEP_SESSION_CLOSED_STR;
		break;
	case PCC_RCVD_INVALID_OPEN:
		return PCC_RCVD_INVALID_OPEN_STR;
		break;
	case PCC_RCVD_MAX_INVALID_MSGS:
		return PCC_RCVD_MAX_INVALID_MSGS_STR;
		break;
	case PCC_RCVD_MAX_UNKOWN_MSGS:
		return PCC_RCVD_MAX_UNKOWN_MSGS_STR;
		break;
	default:
		return UNKNOWN_EVENT_STR;
		break;
	}
}

void dump_pcep_session_counters(pcep_session *session)
{
	if (session_exists(session) == false) {
		pcep_log(
			LOG_WARNING,
			"%s: dump_pcep_session_counters session [%p] has already been deleted",
			__func__, session);
		return;
	}

	/* Update the counters group name so that the PCE session connected time
	 * is accurate */
	time_t now = time(NULL);
	char counters_name[MAX_COUNTER_STR_LENGTH] = {0};
	char ip_str[40] = {0};
	if (session->socket_comm_session->is_ipv6) {
		inet_ntop(AF_INET6,
			  &session->socket_comm_session->dest_sock_addr
				   .dest_sock_addr_ipv6.sin6_addr,
			  ip_str, 40);
	} else {
		inet_ntop(AF_INET,
			  &session->socket_comm_session->dest_sock_addr
				   .dest_sock_addr_ipv4.sin_addr,
			  ip_str, 40);
	}
	snprintf(counters_name, MAX_COUNTER_STR_LENGTH,
		 "PCEP Session [%d], connected to [%s] for [%u seconds]",
		 session->session_id, ip_str,
		 (uint32_t)(now - session->time_connected));
	strlcpy(session->pcep_session_counters->counters_group_name,
		counters_name,
		sizeof(session->pcep_session_counters->counters_group_name));

	dump_counters_group_to_log(session->pcep_session_counters);
}

void reset_pcep_session_counters(pcep_session *session)
{
	if (session_exists(session) == false) {
		pcep_log(
			LOG_WARNING,
			"%s: reset_pcep_session_counters session [%p] has already been deleted",
			session);
		return;
	}

	reset_group_counters(session->pcep_session_counters);
}
