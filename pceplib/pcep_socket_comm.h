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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 *  Declaration of public API functions.
 */

#ifndef INCLUDE_PCEPSOCKETCOMM_H_
#define INCLUDE_PCEPSOCKETCOMM_H_

#include "pcep.h"
#include <arpa/inet.h> // sockaddr_in
#include <netinet/tcp.h>
#include <stdbool.h>

#include "pcep_utils_queue.h"

#define MAX_RECVD_MSG_SIZE 2048

/*
 * A socket_comm_session can be initialized with 1 of 2 types of mutually
 * exclusive message callbacks:
 * - message_received_handler : the socket_comm library reads the message and
 * calls the callback with the message_data and message_length. this callback
 * should be used for smaller/simpler messages.
 * - message_ready_to_read_handler : the socket_comm library will call this
 * callback when a message is ready to be read on a socket_fd. this callback
 * should be used if the
 */

/* message received handler that receives the message data and message length */
typedef void (*message_received_handler)(void *session_data,
					 const char *message_data,
					 unsigned int message_length);
/* message ready received handler that should read the message on socket_fd
 * and return the number of bytes read */
typedef int (*message_ready_to_read_handler)(void *session_data, int socket_fd);
/* callback handler called when a messages is sent */
typedef void (*message_sent_notifier)(void *session_data, int socket_fd);
/* callback handler called when the socket is closed */
typedef void (*connection_except_notifier)(void *session_data, int socket_fd);

/* Function pointers when an external socket infrastructure is used */
typedef int (*ext_socket_write)(void *infra_data, void **infra_socket_data,
				int fd, void *data);
typedef int (*ext_socket_read)(void *infra_data, void **infra_socket_data,
			       int fd, void *data);
typedef int (*ext_socket_pthread_create_callback)(
	pthread_t *pthread_id, const pthread_attr_t *attr,
	void *(*start_routine)(void *), void *data, const char *thread_name);

typedef struct pcep_socket_comm_session_ {
	message_received_handler message_handler;
	message_ready_to_read_handler message_ready_to_read_handler;
	message_sent_notifier message_sent_handler;
	connection_except_notifier conn_except_notifier;
	union src_sock_addr {
		struct sockaddr_in src_sock_addr_ipv4;
		struct sockaddr_in6 src_sock_addr_ipv6;
	} src_sock_addr;
	union dest_sock_addr {
		struct sockaddr_in dest_sock_addr_ipv4;
		struct sockaddr_in6 dest_sock_addr_ipv6;
	} dest_sock_addr;
	bool is_ipv6;
	uint32_t connect_timeout_millis;
	int socket_fd;
	void *session_data;
	queue_handle *message_queue;
	char received_message[MAX_RECVD_MSG_SIZE];
	int received_bytes;
	bool close_after_write;
	void *external_socket_data; /* used for external socket infra */
	/* should be used with is_tcp_auth_md5 flag */
	char tcp_authentication_str[PCEP_MD5SIG_MAXKEYLEN + 1];

	bool is_tcp_auth_md5; /* flag to distinguish between rfc 2385 (md5) and
				 rfc 5925 (tcp-ao) */

} pcep_socket_comm_session;


/* Need to document that when the msg_rcv_handler is called, the data needs
 * to be handled in the same function call, else it may be overwritten by
 * the next read from this socket */


/* Initialize the Socket Comm infrastructure, with either an internal pthread
 * or with an external infrastructure.
 * If an internal pthread infrastructure is to be used, then it is not necessary
 * to explicitly call initialize_socket_comm_loop() as it will be called
 * internally when a socket comm session is initialized. */

/* Initialize the Socket Comm infrastructure with an internal pthread */
bool initialize_socket_comm_loop(void);
/* Initialize the Socket Comm infrastructure with an external infrastructure.
 * Notice: If the thread_create_func is set, then both the socket_read_cb
 *         and the socket_write_cb SHOULD be NULL. */
bool initialize_socket_comm_external_infra(
	void *external_infra_data, ext_socket_read socket_read_cb,
	ext_socket_write socket_write_cb,
	ext_socket_pthread_create_callback thread_create_func);

/* The msg_rcv_handler and msg_ready_handler are mutually exclusive, and only
 * one can be set (as explained above), else NULL will be returned. */
pcep_socket_comm_session *
socket_comm_session_initialize(message_received_handler msg_rcv_handler,
			       message_ready_to_read_handler msg_ready_handler,
			       message_sent_notifier msg_sent_notifier,
			       connection_except_notifier notifier,
			       struct in_addr *dst_ip, short dst_port,
			       uint32_t connect_timeout_millis,
			       const char *tcp_authentication_str,
			       bool is_tcp_auth_md5, void *session_data);

pcep_socket_comm_session *socket_comm_session_initialize_ipv6(
	message_received_handler msg_rcv_handler,
	message_ready_to_read_handler msg_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in6_addr *dst_ip,
	short dst_port, uint32_t connect_timeout_millis,
	const char *tcp_authentication_str, bool is_tcp_auth_md5,
	void *session_data);

pcep_socket_comm_session *socket_comm_session_initialize_with_src(
	message_received_handler msg_rcv_handler,
	message_ready_to_read_handler msg_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in_addr *src_ip,
	short src_port, struct in_addr *dst_ip, short dst_port,
	uint32_t connect_timeout_millis, const char *tcp_authentication_str,
	bool is_tcp_auth_md5, void *session_data);

pcep_socket_comm_session *socket_comm_session_initialize_with_src_ipv6(
	message_received_handler msg_rcv_handler,
	message_ready_to_read_handler msg_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in6_addr *src_ip,
	short src_port, struct in6_addr *dst_ip, short dst_port,
	uint32_t connect_timeout_millis, const char *tcp_authentication_str,
	bool is_tcp_auth_md5, void *session_data);

bool socket_comm_session_teardown(
	pcep_socket_comm_session *socket_comm_session);

bool socket_comm_session_connect_tcp(
	pcep_socket_comm_session *socket_comm_session);

/* Immediately close the TCP connection, irregardless if there are pending
 * messages to be sent. */
bool socket_comm_session_close_tcp(
	pcep_socket_comm_session *socket_comm_session);

/* Sets a flag to close the TCP connection either after all the pending messages
 * are written, or if there are no pending messages, the next time the socket is
 * checked to be writeable. */
bool socket_comm_session_close_tcp_after_write(
	pcep_socket_comm_session *socket_comm_session);

void socket_comm_session_send_message(
	pcep_socket_comm_session *socket_comm_session,
	const char *encoded_message, unsigned int msg_length,
	bool free_after_send);

/* If an external Socket infra like FRR is used, then these functions will
 * be called when a socket is ready to read/write in the external infra.
 * Implemented in pcep_socket_comm_loop.c */
int pceplib_external_socket_read(int fd, void *payload);
int pceplib_external_socket_write(int fd, void *payload);

/* the socket comm loop is started internally by
 * socket_comm_session_initialize()
 * but needs to be explicitly stopped with this call. */
bool destroy_socket_comm_loop(void);

int socket_fd_node_compare(void *list_entry, void *new_entry);

#endif /* INCLUDE_PCEPSOCKETCOMM_H_ */
