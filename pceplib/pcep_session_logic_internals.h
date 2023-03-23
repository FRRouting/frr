// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * Internal Session Logic declarations, not intended to be in the public API.
 */

#ifndef SRC_PCEPSESSIONLOGICINTERNALS_H_
#define SRC_PCEPSESSIONLOGICINTERNALS_H_


#include <pthread.h>
#include <stdbool.h>

#include "pcep_msg_tools.h"

#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_queue.h"


typedef struct pcep_session_logic_handle_ {
	pthread_t session_logic_thread;
	pthread_mutex_t session_logic_mutex;
	pthread_cond_t session_logic_cond_var;
	bool session_logic_condition;
	bool active;

	ordered_list_handle *session_list;
	pthread_mutex_t session_list_mutex;
	/* Internal timers and socket events */
	queue_handle *session_event_queue;

} pcep_session_logic_handle;


/* Used internally for Session events: message received, timer expired,
 * or socket closed */
typedef struct pcep_session_event_ {
	pcep_session *session;
	int expired_timer_id;
	double_linked_list *received_msg_list;
	bool socket_closed;

} pcep_session_event;

/* Event Counters counter-id definitions */
typedef enum pcep_session_counters_event_counter_ids {
	PCEP_EVENT_COUNTER_ID_PCC_CONNECT = 0,
	PCEP_EVENT_COUNTER_ID_PCE_CONNECT = 1,
	PCEP_EVENT_COUNTER_ID_PCC_DISCONNECT = 2,
	PCEP_EVENT_COUNTER_ID_PCE_DISCONNECT = 3,
	PCEP_EVENT_COUNTER_ID_TIMER_KEEPALIVE = 4,
	PCEP_EVENT_COUNTER_ID_TIMER_DEADTIMER = 5,
	PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPWAIT = 6,
	PCEP_EVENT_COUNTER_ID_TIMER_OPENKEEPALIVE = 7

} pcep_session_counters_event_counter_ids;

/* functions implemented in pcep_session_logic_loop.c */
void *session_logic_loop(void *data);
int session_logic_msg_ready_handler(void *data, int socket_fd);
void session_logic_message_sent_handler(void *data, int socket_fd);
void session_logic_conn_except_notifier(void *data, int socket_fd);
void session_logic_timer_expire_handler(void *data, int timer_id);

void handle_timer_event(pcep_session_event *event);
void handle_socket_comm_event(pcep_session_event *event);
void session_send_message(pcep_session *session, struct pcep_message *message);

/* defined in pcep_session_logic_states.c */
void send_pcep_error(pcep_session *session, enum pcep_error_type error_type,
		     enum pcep_error_value error_value);
void enqueue_event(pcep_session *session, pcep_event_type event_type,
		   struct pcep_message *message);
void increment_unknown_message(pcep_session *session);

/* defined in pcep_session_logic_counters.c */
void create_session_counters(pcep_session *session);
void increment_event_counters(
	pcep_session *session,
	pcep_session_counters_event_counter_ids counter_id);
void increment_message_rx_counters(pcep_session *session,
				   struct pcep_message *message);

/* defined in pcep_session_logic.c, also used in pcep_session_logic_states.c */
struct pcep_message *create_pcep_open(pcep_session *session);

#endif /* SRC_PCEPSESSIONLOGICINTERNALS_H_ */
