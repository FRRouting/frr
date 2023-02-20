// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifndef SRC_PCEPSOCKETCOMMINTERNALS_H_
#define SRC_PCEPSOCKETCOMMINTERNALS_H_

#include <pthread.h>
#include <stdbool.h>

#include "pcep_utils_ordered_list.h"
#include "pcep_socket_comm.h"


typedef struct pcep_socket_comm_handle_ {
	bool active;
	pthread_t socket_comm_thread;
	pthread_mutex_t socket_comm_mutex;
	fd_set read_master_set;
	fd_set write_master_set;
	fd_set except_master_set;
	/* ordered_list of socket_descriptors to read from */
	ordered_list_handle *read_list;
	/* ordered_list of socket_descriptors to write to */
	ordered_list_handle *write_list;
	ordered_list_handle *session_list;
	int num_active_sessions;
	void *external_infra_data;
	ext_socket_write socket_write_func;
	ext_socket_read socket_read_func;

} pcep_socket_comm_handle;


typedef struct pcep_socket_comm_queued_message_ {
	const char *encoded_message;
	int msg_length;
	bool free_after_send;

} pcep_socket_comm_queued_message;


/* Functions implemented in pcep_socket_comm_loop.c */
void *socket_comm_loop(void *data);
bool comm_session_exists(pcep_socket_comm_handle *socket_comm_handle,
			 pcep_socket_comm_session *socket_comm_session);
bool comm_session_exists_locking(pcep_socket_comm_handle *socket_comm_handle,
				 pcep_socket_comm_session *socket_comm_session);

#endif /* SRC_PCEPSOCKETCOMMINTERNALS_H_ */
