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
 *  Implementation of public API functions.
 */

#include <zebra.h>

#include <errno.h>
#include <fcntl.h>
#include <netdb.h> // gethostbyname
#include <stdbool.h>
#include <string.h>
#include <unistd.h> // close

#include <arpa/inet.h>	// sockets etc.
#include <sys/types.h>	// sockets etc.
#include <sys/socket.h> // sockets etc.

#include "pcep.h"
#include "pcep_socket_comm.h"
#include "pcep_socket_comm_internals.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_queue.h"

bool initialize_socket_comm_pre(void);
bool socket_comm_session_initialize_post(
	pcep_socket_comm_session *socket_comm_session);

pcep_socket_comm_handle *socket_comm_handle_ = NULL;


/* simple compare method callback used by pcep_utils_ordered_list
 * for ordered list insertion. */
int socket_fd_node_compare(void *list_entry, void *new_entry)
{
	return ((pcep_socket_comm_session *)new_entry)->socket_fd
	       - ((pcep_socket_comm_session *)list_entry)->socket_fd;
}


bool initialize_socket_comm_pre(void)
{
	socket_comm_handle_ =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_socket_comm_handle));
	memset(socket_comm_handle_, 0, sizeof(pcep_socket_comm_handle));

	socket_comm_handle_->active = true;
	socket_comm_handle_->num_active_sessions = 0;
	socket_comm_handle_->read_list =
		ordered_list_initialize(socket_fd_node_compare);
	socket_comm_handle_->write_list =
		ordered_list_initialize(socket_fd_node_compare);
	socket_comm_handle_->session_list =
		ordered_list_initialize(pointer_compare_function);
	FD_ZERO(&socket_comm_handle_->except_master_set);
	FD_ZERO(&socket_comm_handle_->read_master_set);
	FD_ZERO(&socket_comm_handle_->write_master_set);

	if (pthread_mutex_init(&(socket_comm_handle_->socket_comm_mutex), NULL)
	    != 0) {
		pcep_log(LOG_ERR, "%s: Cannot initialize socket_comm mutex.",
			 __func__);
		pceplib_free(PCEPLIB_INFRA, socket_comm_handle_);
		socket_comm_handle_ = NULL;

		return false;
	}

	return true;
}

bool initialize_socket_comm_external_infra(
	void *external_infra_data, ext_socket_read socket_read_cb,
	ext_socket_write socket_write_cb,
	ext_socket_pthread_create_callback thread_create_func)
{
	if (socket_comm_handle_ != NULL) {
		/* already initialized */
		return true;
	}

	if (initialize_socket_comm_pre() == false) {
		return false;
	}

	/* Notice: If the thread_create_func is set, then both the
	 * socket_read_cb and the socket_write_cb SHOULD be NULL. */
	if (thread_create_func != NULL) {
		if (thread_create_func(
			    &(socket_comm_handle_->socket_comm_thread), NULL,
			    socket_comm_loop, socket_comm_handle_,
			    "pceplib_timers")) {
			pcep_log(
				LOG_ERR,
				"%s: Cannot initialize external socket_comm thread.",
				__func__);
			return false;
		}
	}

	socket_comm_handle_->external_infra_data = external_infra_data;
	socket_comm_handle_->socket_write_func = socket_write_cb;
	socket_comm_handle_->socket_read_func = socket_read_cb;

	return true;
}

bool initialize_socket_comm_loop(void)
{
	if (socket_comm_handle_ != NULL) {
		/* already initialized */
		return true;
	}

	if (initialize_socket_comm_pre() == false) {
		return false;
	}

	/* Launch socket comm loop pthread */
	if (pthread_create(&(socket_comm_handle_->socket_comm_thread), NULL,
			   socket_comm_loop, socket_comm_handle_)) {
		pcep_log(LOG_ERR, "%s: Cannot initialize socket_comm thread.",
			 __func__);
		return false;
	}

	return true;
}


bool destroy_socket_comm_loop(void)
{
	socket_comm_handle_->active = false;

	pthread_join(socket_comm_handle_->socket_comm_thread, NULL);
	ordered_list_destroy(socket_comm_handle_->read_list);
	ordered_list_destroy(socket_comm_handle_->write_list);
	ordered_list_destroy(socket_comm_handle_->session_list);
	pthread_mutex_destroy(&(socket_comm_handle_->socket_comm_mutex));

	pceplib_free(PCEPLIB_INFRA, socket_comm_handle_);
	socket_comm_handle_ = NULL;

	return true;
}

/* Internal common init function */
static pcep_socket_comm_session *socket_comm_session_initialize_pre(
	message_received_handler message_handler,
	message_ready_to_read_handler message_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, uint32_t connect_timeout_millis,
	const char *tcp_authentication_str, bool is_tcp_auth_md5,
	void *session_data)
{
	/* check that not both message handlers were set */
	if (message_handler != NULL && message_ready_handler != NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: Only one of <message_received_handler | message_ready_to_read_handler> can be set.",
			__func__);
		return NULL;
	}

	/* check that at least one message handler was set */
	if (message_handler == NULL && message_ready_handler == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: At least one of <message_received_handler | message_ready_to_read_handler> must be set.",
			__func__);
		return NULL;
	}

	if (!initialize_socket_comm_loop()) {
		pcep_log(LOG_WARNING,
			 "%s: ERROR: cannot initialize socket_comm_loop.",
			 __func__);

		return NULL;
	}

	/* initialize everything for a pcep_session socket_comm */

	pcep_socket_comm_session *socket_comm_session =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_socket_comm_session));
	memset(socket_comm_session, 0, sizeof(pcep_socket_comm_session));

	socket_comm_handle_->num_active_sessions++;
	socket_comm_session->close_after_write = false;
	socket_comm_session->session_data = session_data;
	socket_comm_session->message_handler = message_handler;
	socket_comm_session->message_ready_to_read_handler =
		message_ready_handler;
	socket_comm_session->message_sent_handler = msg_sent_notifier;
	socket_comm_session->conn_except_notifier = notifier;
	socket_comm_session->message_queue = queue_initialize();
	socket_comm_session->connect_timeout_millis = connect_timeout_millis;
	socket_comm_session->external_socket_data = NULL;
	if (tcp_authentication_str != NULL) {
		socket_comm_session->is_tcp_auth_md5 = is_tcp_auth_md5;
		strlcpy(socket_comm_session->tcp_authentication_str,
			tcp_authentication_str,
			sizeof(socket_comm_session->tcp_authentication_str));
	}

	return socket_comm_session;
}

/* Internal common init function */
bool socket_comm_session_initialize_post(
	pcep_socket_comm_session *socket_comm_session)
{
	/* If we dont use SO_REUSEADDR, the socket will take 2 TIME_WAIT
	 * periods before being closed in the kernel if bind() was called */
	int reuse_addr = 1;
	if (setsockopt(socket_comm_session->socket_fd, SOL_SOCKET, SO_REUSEADDR,
		       &reuse_addr, sizeof(int))
	    < 0) {
		pcep_log(
			LOG_WARNING,
			"%s: Error in setsockopt() SO_REUSEADDR errno [%d %s].",
			__func__, errno, strerror(errno));
		socket_comm_session_teardown(socket_comm_session);

		return false;
	}

	struct sockaddr *src_sock_addr =
		(socket_comm_session->is_ipv6
			 ? (struct sockaddr *)&(
				 socket_comm_session->src_sock_addr
					 .src_sock_addr_ipv6)
			 : (struct sockaddr *)&(
				 socket_comm_session->src_sock_addr
					 .src_sock_addr_ipv4));
	int addr_len = (socket_comm_session->is_ipv6
				? sizeof(socket_comm_session->src_sock_addr
						 .src_sock_addr_ipv6)
				: sizeof(socket_comm_session->src_sock_addr
						 .src_sock_addr_ipv4));
	if (bind(socket_comm_session->socket_fd, src_sock_addr, addr_len)
	    == -1) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot bind address to socket errno [%d %s].",
			 __func__, errno, strerror(errno));
		socket_comm_session_teardown(socket_comm_session);

		return false;
	}

	/* Register the session as active with the Socket Comm Loop */
	pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
	ordered_list_add_node(socket_comm_handle_->session_list,
			      socket_comm_session);
	pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

	/* dont connect to the destination yet, since the PCE will have a timer
	 * for max time between TCP connect and PCEP open. we'll connect later
	 * when we send the PCEP open. */

	return true;
}


pcep_socket_comm_session *socket_comm_session_initialize(
	message_received_handler message_handler,
	message_ready_to_read_handler message_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in_addr *dest_ip,
	short dest_port, uint32_t connect_timeout_millis,
	const char *tcp_authentication_str, bool is_tcp_auth_md5,
	void *session_data)
{
	return socket_comm_session_initialize_with_src(
		message_handler, message_ready_handler, msg_sent_notifier,
		notifier, NULL, 0, dest_ip, dest_port, connect_timeout_millis,
		tcp_authentication_str, is_tcp_auth_md5, session_data);
}

pcep_socket_comm_session *socket_comm_session_initialize_ipv6(
	message_received_handler message_handler,
	message_ready_to_read_handler message_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in6_addr *dest_ip,
	short dest_port, uint32_t connect_timeout_millis,
	const char *tcp_authentication_str, bool is_tcp_auth_md5,
	void *session_data)
{
	return socket_comm_session_initialize_with_src_ipv6(
		message_handler, message_ready_handler, msg_sent_notifier,
		notifier, NULL, 0, dest_ip, dest_port, connect_timeout_millis,
		tcp_authentication_str, is_tcp_auth_md5, session_data);
}


pcep_socket_comm_session *socket_comm_session_initialize_with_src(
	message_received_handler message_handler,
	message_ready_to_read_handler message_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in_addr *src_ip,
	short src_port, struct in_addr *dest_ip, short dest_port,
	uint32_t connect_timeout_millis, const char *tcp_authentication_str,
	bool is_tcp_auth_md5, void *session_data)
{
	if (dest_ip == NULL) {
		pcep_log(LOG_WARNING, "%s: dest_ipv4 is NULL", __func__);
		return NULL;
	}

	pcep_socket_comm_session *socket_comm_session =
		socket_comm_session_initialize_pre(
			message_handler, message_ready_handler,
			msg_sent_notifier, notifier, connect_timeout_millis,
			tcp_authentication_str, is_tcp_auth_md5, session_data);
	if (socket_comm_session == NULL) {
		return NULL;
	}

	socket_comm_session->socket_fd =
		socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socket_comm_session->socket_fd == -1) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot create ipv4 socket errno [%d %s].",
			 __func__, errno, strerror(errno));
		socket_comm_session_teardown(
			socket_comm_session); // socket_comm_session freed
					      // inside fn so NOLINT next.

		return NULL; // NOLINT(clang-analyzer-unix.Malloc)
	}

	socket_comm_session->is_ipv6 = false;
	socket_comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_family =
		AF_INET;
	socket_comm_session->src_sock_addr.src_sock_addr_ipv4.sin_family =
		AF_INET;
	socket_comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_port =
		htons(dest_port);
	socket_comm_session->src_sock_addr.src_sock_addr_ipv4.sin_port =
		htons(src_port);
	socket_comm_session->dest_sock_addr.dest_sock_addr_ipv4.sin_addr
		.s_addr = dest_ip->s_addr;
	if (src_ip != NULL) {
		socket_comm_session->src_sock_addr.src_sock_addr_ipv4.sin_addr
			.s_addr = src_ip->s_addr;
	} else {
		socket_comm_session->src_sock_addr.src_sock_addr_ipv4.sin_addr
			.s_addr = INADDR_ANY;
	}

	if (socket_comm_session_initialize_post(socket_comm_session) == false) {
		return NULL;
	}

	return socket_comm_session;
}

pcep_socket_comm_session *socket_comm_session_initialize_with_src_ipv6(
	message_received_handler message_handler,
	message_ready_to_read_handler message_ready_handler,
	message_sent_notifier msg_sent_notifier,
	connection_except_notifier notifier, struct in6_addr *src_ip,
	short src_port, struct in6_addr *dest_ip, short dest_port,
	uint32_t connect_timeout_millis, const char *tcp_authentication_str,
	bool is_tcp_auth_md5, void *session_data)
{
	if (dest_ip == NULL) {
		pcep_log(LOG_WARNING, "%s: dest_ipv6 is NULL", __func__);
		return NULL;
	}

	pcep_socket_comm_session *socket_comm_session =
		socket_comm_session_initialize_pre(
			message_handler, message_ready_handler,
			msg_sent_notifier, notifier, connect_timeout_millis,
			tcp_authentication_str, is_tcp_auth_md5, session_data);
	if (socket_comm_session == NULL) {
		return NULL;
	}

	socket_comm_session->socket_fd =
		socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	if (socket_comm_session->socket_fd == -1) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot create ipv6 socket errno [%d %s].",
			 __func__, errno, strerror(errno));
		socket_comm_session_teardown(
			socket_comm_session); // socket_comm_session freed
					      // inside fn so NOLINT next.

		return NULL; // NOLINT(clang-analyzer-unix.Malloc)
	}

	socket_comm_session->is_ipv6 = true;
	socket_comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_family =
		AF_INET6;
	socket_comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_family =
		AF_INET6;
	socket_comm_session->dest_sock_addr.dest_sock_addr_ipv6.sin6_port =
		htons(dest_port);
	socket_comm_session->src_sock_addr.src_sock_addr_ipv6.sin6_port =
		htons(src_port);
	memcpy(&socket_comm_session->dest_sock_addr.dest_sock_addr_ipv6
			.sin6_addr,
	       dest_ip, sizeof(struct in6_addr));
	if (src_ip != NULL) {
		memcpy(&socket_comm_session->src_sock_addr.src_sock_addr_ipv6
				.sin6_addr,
		       src_ip, sizeof(struct in6_addr));
	} else {
		socket_comm_session->src_sock_addr.src_sock_addr_ipv6
			.sin6_addr = in6addr_any;
	}

	if (socket_comm_session_initialize_post(socket_comm_session) == false) {
		return NULL;
	}

	return socket_comm_session;
}


bool socket_comm_session_connect_tcp(
	pcep_socket_comm_session *socket_comm_session)
{
	if (socket_comm_session == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: socket_comm_session_connect_tcp NULL socket_comm_session.",
			__func__);
		return NULL;
	}

	/* Set the socket to non-blocking, so connect() does not block */
	int fcntl_arg;
	if ((fcntl_arg = fcntl(socket_comm_session->socket_fd, F_GETFL, NULL))
	    < 0) {
		pcep_log(LOG_WARNING, "%s: Error fcntl(..., F_GETFL) [%d %s]",
			 __func__, errno, strerror(errno));
		return false;
	}

	fcntl_arg |= O_NONBLOCK;
	if (fcntl(socket_comm_session->socket_fd, F_SETFL, fcntl_arg) < 0) {
		pcep_log(LOG_WARNING, "%s: Error fcntl(..., F_SETFL) [%d %s]",
			 __func__, errno, strerror(errno));
		return false;
	}

#if HAVE_DECL_TCP_MD5SIG
	/* TCP authentication, currently only TCP MD5 RFC2385 is supported */
	if (socket_comm_session->tcp_authentication_str[0] != '\0') {
#if defined(linux) || defined(GNU_LINUX)
		struct tcp_md5sig sig;
		memset(&sig, 0, sizeof(sig));
		if (socket_comm_session->is_ipv6) {
			memcpy(&sig.tcpm_addr,
			       &socket_comm_session->dest_sock_addr
					.dest_sock_addr_ipv6,
			       sizeof(struct sockaddr_in6));
		} else {
			memcpy(&sig.tcpm_addr,
			       &socket_comm_session->dest_sock_addr
					.dest_sock_addr_ipv4,
			       sizeof(struct sockaddr_in));
		}
		sig.tcpm_keylen =
			strlen(socket_comm_session->tcp_authentication_str);
		memcpy(sig.tcpm_key,
		       socket_comm_session->tcp_authentication_str,
		       sig.tcpm_keylen);
#else
		int sig = 1;
#endif
		if (setsockopt(socket_comm_session->socket_fd, IPPROTO_TCP,
			       TCP_MD5SIG, &sig, sizeof(sig))
		    == -1) {
			pcep_log(LOG_ERR, "%s: Failed to setsockopt(): [%d %s]",
				 __func__, errno, strerror(errno));
			return false;
		}
	}
#endif

	int connect_result = 0;
	if (socket_comm_session->is_ipv6) {
		connect_result = connect(
			socket_comm_session->socket_fd,
			(struct sockaddr *)&(socket_comm_session->dest_sock_addr
						     .dest_sock_addr_ipv6),
			sizeof(socket_comm_session->dest_sock_addr
				       .dest_sock_addr_ipv6));
	} else {
		connect_result = connect(
			socket_comm_session->socket_fd,
			(struct sockaddr *)&(socket_comm_session->dest_sock_addr
						     .dest_sock_addr_ipv4),
			sizeof(socket_comm_session->dest_sock_addr
				       .dest_sock_addr_ipv4));
	}

	if (connect_result < 0) {
		if (errno == EINPROGRESS) {
			/* Calculate the configured timeout in seconds and
			 * microseconds */
			struct timeval tv;
			if (socket_comm_session->connect_timeout_millis
			    > 1000) {
				tv.tv_sec = socket_comm_session
						    ->connect_timeout_millis
					    / 1000;
				tv.tv_usec = (socket_comm_session
						      ->connect_timeout_millis
					      - (tv.tv_sec * 1000))
					     * 1000;
			} else {
				tv.tv_sec = 0;
				tv.tv_usec = socket_comm_session
						     ->connect_timeout_millis
					     * 1000;
			}

			/* Use select to wait a max timeout for connect
			 * https://stackoverflow.com/questions/2597608/c-socket-connection-timeout
			 */
			fd_set fdset;
			FD_ZERO(&fdset);
			FD_SET(socket_comm_session->socket_fd, &fdset);
			if (select(socket_comm_session->socket_fd + 1, NULL,
				   &fdset, NULL, &tv)
			    > 0) {
				int so_error;
				socklen_t len = sizeof(so_error);
				getsockopt(socket_comm_session->socket_fd,
					   SOL_SOCKET, SO_ERROR, &so_error,
					   &len);
				if (so_error) {
					pcep_log(
						LOG_WARNING,
						"%s: TCP connect failed on socket_fd [%d].",
						__func__,
						socket_comm_session->socket_fd);
					return false;
				}
			} else {
				pcep_log(
					LOG_WARNING,
					"%s: TCP connect timed-out on socket_fd [%d].",
					__func__,
					socket_comm_session->socket_fd);
				return false;
			}
		} else {
			pcep_log(
				LOG_WARNING,
				"%s: TCP connect, error connecting on socket_fd [%d] errno [%d %s]",
				__func__, socket_comm_session->socket_fd, errno,
				strerror(errno));
			return false;
		}
	}

	pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
	/* once the TCP connection is open, we should be ready to read at any
	 * time */
	ordered_list_add_node(socket_comm_handle_->read_list,
			      socket_comm_session);

	if (socket_comm_handle_->socket_read_func != NULL) {
		socket_comm_handle_->socket_read_func(
			socket_comm_handle_->external_infra_data,
			&socket_comm_session->external_socket_data,
			socket_comm_session->socket_fd, socket_comm_handle_);
	}
	pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

	return true;
}


bool socket_comm_session_close_tcp(
	pcep_socket_comm_session *socket_comm_session)
{
	if (socket_comm_session == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: socket_comm_session_close_tcp NULL socket_comm_session.",
			__func__);
		return false;
	}

	pcep_log(LOG_DEBUG,
		 "%s: socket_comm_session_close_tcp close() socket fd [%d]",
		 __func__, socket_comm_session->socket_fd);

	pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
	ordered_list_remove_first_node_equals(socket_comm_handle_->read_list,
					      socket_comm_session);
	ordered_list_remove_first_node_equals(socket_comm_handle_->write_list,
					      socket_comm_session);
	// TODO should it be close() or shutdown()??
	close(socket_comm_session->socket_fd);
	socket_comm_session->socket_fd = -1;
	pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

	return true;
}


bool socket_comm_session_close_tcp_after_write(
	pcep_socket_comm_session *socket_comm_session)
{
	if (socket_comm_session == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: socket_comm_session_close_tcp_after_write NULL socket_comm_session.",
			__func__);
		return false;
	}

	pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
	socket_comm_session->close_after_write = true;
	pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

	return true;
}


bool socket_comm_session_teardown(pcep_socket_comm_session *socket_comm_session)
{
	if (socket_comm_handle_ == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot teardown NULL socket_comm_handle",
			 __func__);
		return false;
	}

	if (socket_comm_session == NULL) {
		pcep_log(LOG_WARNING, "%s: Cannot teardown NULL session",
			 __func__);
		return false;
	}

	if (comm_session_exists_locking(socket_comm_handle_,
					socket_comm_session)
	    == false) {
		pcep_log(LOG_WARNING,
			 "%s: Cannot teardown session that does not exist",
			 __func__);
		return false;
	}

	if (socket_comm_session->socket_fd >= 0) {
		shutdown(socket_comm_session->socket_fd, SHUT_RDWR);
		close(socket_comm_session->socket_fd);
	}

	pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));
	queue_destroy(socket_comm_session->message_queue);
	ordered_list_remove_first_node_equals(socket_comm_handle_->session_list,
					      socket_comm_session);
	ordered_list_remove_first_node_equals(socket_comm_handle_->read_list,
					      socket_comm_session);
	ordered_list_remove_first_node_equals(socket_comm_handle_->write_list,
					      socket_comm_session);
	socket_comm_handle_->num_active_sessions--;
	pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));

	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] socket_comm_session fd [%d] destroyed, [%d] sessions remaining",
		__func__, time(NULL), pthread_self(),
		socket_comm_session->socket_fd,
		socket_comm_handle_->num_active_sessions);

	pceplib_free(PCEPLIB_INFRA, socket_comm_session);

	/* It would be nice to call destroy_socket_comm_loop() here if
	 * socket_comm_handle_->num_active_sessions == 0, but this function
	 * will usually be called from the message_sent_notifier callback,
	 * which gets called in the middle of the socket_comm_loop, and that
	 * is dangerous, so destroy_socket_comm_loop() must be called upon
	 * application exit. */

	return true;
}


void socket_comm_session_send_message(
	pcep_socket_comm_session *socket_comm_session,
	const char *encoded_message, unsigned int msg_length,
	bool free_after_send)
{
	if (socket_comm_session == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: socket_comm_session_send_message NULL socket_comm_session.",
			__func__);
		return;
	}

	pcep_socket_comm_queued_message *queued_message = pceplib_malloc(
		PCEPLIB_MESSAGES, sizeof(pcep_socket_comm_queued_message));
	queued_message->encoded_message = encoded_message;
	queued_message->msg_length = msg_length;
	queued_message->free_after_send = free_after_send;

	pthread_mutex_lock(&(socket_comm_handle_->socket_comm_mutex));

	/* Do not proceed if the socket_comm_session has been deleted */
	if (ordered_list_find(socket_comm_handle_->session_list,
			      socket_comm_session)
	    == NULL) {
		/* Should never get here, only if the session was deleted and
		 * someone still tries to write on it */
		pcep_log(
			LOG_WARNING,
			"%s: Cannot write a message on a deleted socket comm session, discarding message",
			__func__);
		pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));
		pceplib_free(PCEPLIB_MESSAGES, queued_message);

		return;
	}

	/* Do not proceed if the socket has been closed */
	if (socket_comm_session->socket_fd < 0) {
		/* Should never get here, only if the session was deleted and
		 * someone still tries to write on it */
		pcep_log(
			LOG_WARNING,
			"%s: Cannot write a message on a closed socket, discarding message",
			__func__);
		pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));
		pceplib_free(PCEPLIB_MESSAGES, queued_message);

		return;
	}

	queue_enqueue(socket_comm_session->message_queue, queued_message);

	/* Add it to the write list only if its not already there */
	if (ordered_list_find(socket_comm_handle_->write_list,
			      socket_comm_session)
	    == NULL) {
		ordered_list_add_node(socket_comm_handle_->write_list,
				      socket_comm_session);
	}

	if (socket_comm_handle_->socket_write_func != NULL) {
		socket_comm_handle_->socket_write_func(
			socket_comm_handle_->external_infra_data,
			&socket_comm_session->external_socket_data,
			socket_comm_session->socket_fd, socket_comm_handle_);
	}
	pthread_mutex_unlock(&(socket_comm_handle_->socket_comm_mutex));
}
