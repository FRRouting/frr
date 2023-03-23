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
 * Public PCEPlib PCC API
 */

#ifndef PCEPPCC_INCLUDE_PCEPPCCAPI_H_
#define PCEPPCC_INCLUDE_PCEPPCCAPI_H_

#include <stdbool.h>

#include "pcep_session_logic.h"
#include "pcep_timers.h"

#define DEFAULT_PCEP_TCP_PORT 4189
#define DEFAULT_CONFIG_KEEP_ALIVE 30
#define DEFAULT_CONFIG_DEAD_TIMER DEFAULT_CONFIG_KEEP_ALIVE * 4
#define DEFAULT_CONFIG_REQUEST_TIME 30
#define DEFAULT_CONFIG_MAX_UNKNOWN_REQUESTS 5
#define DEFAULT_CONFIG_MAX_UNKNOWN_MESSAGES 5
#define DEFAULT_TCP_CONNECT_TIMEOUT_MILLIS 250

/* Acceptable MIN and MAX values used in deciding if the PCEP
 * Open received from a PCE should be accepted or rejected. */
#define DEFAULT_MIN_CONFIG_KEEP_ALIVE 5
#define DEFAULT_MAX_CONFIG_KEEP_ALIVE 120
#define DEFAULT_MIN_CONFIG_DEAD_TIMER DEFAULT_MIN_CONFIG_KEEP_ALIVE * 4
#define DEFAULT_MAX_CONFIG_DEAD_TIMER DEFAULT_MAX_CONFIG_KEEP_ALIVE * 4

/*
 * PCEP PCC library initialization/teardown functions
 */

/* Later when this is integrated with FRR pathd, it will be changed
 * to just initialize_pcc(struct pceplib_infra_config *infra_config) */
bool initialize_pcc(void);
bool initialize_pcc_infra(struct pceplib_infra_config *infra_config);
/* this function is blocking */
bool initialize_pcc_wait_for_completion(void);
bool destroy_pcc(void);


/*
 * PCEP session functions
 */

pcep_configuration *create_default_pcep_configuration(void);
void destroy_pcep_configuration(pcep_configuration *config);

/* Uses the standard PCEP TCP src and dest port = 4189.
 * To use a specific dest or src port, set them other than 0 in the
 * pcep_configuration. If src_ip is not set, INADDR_ANY will be used. */
pcep_session *connect_pce(pcep_configuration *config, struct in_addr *pce_ip);
pcep_session *connect_pce_ipv6(pcep_configuration *config,
			       struct in6_addr *pce_ip);
void disconnect_pce(pcep_session *session);
void send_message(pcep_session *session, struct pcep_message *msg,
		  bool free_after_send);

void dump_pcep_session_counters(pcep_session *session);
void reset_pcep_session_counters(pcep_session *session);

/*
 * Event Queue functions
 */

/* Returns true if the queue is empty, false otherwise */
bool event_queue_is_empty(void);

/* Return the number of events on the queue, 0 if empty */
uint32_t event_queue_num_events_available(void);

/* Return the next event on the queue, NULL if empty */
struct pcep_event *event_queue_get_event(void);

/* Free the PCEP Event resources, including the PCEP message */
void destroy_pcep_event(struct pcep_event *event);

const char *get_event_type_str(int event_type);


#endif /* PCEPPCC_INCLUDE_PCEPPCCAPI_H_ */
