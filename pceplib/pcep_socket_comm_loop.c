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
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#include "pcep_socket_comm_internals.h"
#include "pcep_socket_comm_loop.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_ordered_list.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

void write_message(int socket_fd, const char *message, unsigned int msg_length);
unsigned int read_message(int socket_fd, char *received_message,
			  unsigned int max_message_size);
int build_fd_sets(pcep_socket_comm_handle *socket_comm_handle);
void handle_writes(pcep_socket_comm_handle *socket_comm_handle);
void handle_excepts(pcep_socket_comm_handle *socket_comm_handle);

bool comm_session_exists(pcep_socket_comm_handle *socket_comm_handle,
			 pcep_socket_comm_session *socket_comm_session)
{
	if (socket_comm_handle == NULL) {
		return false;
	}

	return (ordered_list_find(socket_comm_handle->session_list,
				  socket_comm_session)
		!= NULL);
}


bool comm_session_exists_locking(pcep_socket_comm_handle *socket_comm_handle,
				 pcep_socket_comm_session *socket_comm_session)
{
	if (socket_comm_handle == NULL) {
		return false;
	}

	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
	bool exists =
		comm_session_exists(socket_comm_handle, socket_comm_session);
	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

	return exists;
}


void write_message(int socket_fd, const char *message, unsigned int msg_length)
{
	ssize_t bytes_sent = 0;
	unsigned int total_bytes_sent = 0;

	while ((uint32_t)bytes_sent < msg_length) {
		bytes_sent = write(socket_fd, message + total_bytes_sent,
				   msg_length);

		pcep_log(
			LOG_INFO,
			"%s: [%ld-%ld] socket_comm writing on socket fd [%d] msg_lenth [%u] bytes sent [%d]",
			__func__, time(NULL), pthread_self(), socket_fd,
			msg_length, bytes_sent);

		if (bytes_sent < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				pcep_log(LOG_WARNING, "%s: send() failure",
					 __func__);

				return;
			}
		} else {
			total_bytes_sent += bytes_sent;
		}
	}
}


unsigned int read_message(int socket_fd, char *received_message,
			  unsigned int max_message_size)
{
	/* TODO what if bytes_read == max_message_size? there could be more to
	 * read */
	unsigned int bytes_read =
		read(socket_fd, received_message, max_message_size);
	pcep_log(
		LOG_INFO,
		"%s: [%ld-%ld] socket_comm read message bytes_read [%u] on socket fd [%d]",
		__func__, time(NULL), pthread_self(), bytes_read, socket_fd);

	return bytes_read;
}


int build_fd_sets(pcep_socket_comm_handle *socket_comm_handle)
{
	int max_fd = 0;

	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));

	FD_ZERO(&socket_comm_handle->except_master_set);
	FD_ZERO(&socket_comm_handle->read_master_set);
	ordered_list_node *node = socket_comm_handle->read_list->head;
	pcep_socket_comm_session *comm_session;
	while (node != NULL) {
		comm_session = (pcep_socket_comm_session *)node->data;
		if (comm_session->socket_fd > max_fd) {
			max_fd = comm_session->socket_fd;
		} else if (comm_session->socket_fd < 0) {
			pcep_log(LOG_ERR, "%s: Negative fd", __func__);
			assert(comm_session->socket_fd > 0);
		}

		/*pcep_log(LOG_DEBUG, ld] socket_comm::build_fdSets set
		   ready_toRead
		   [%d]", __func__, time(NULL), comm_session->socket_fd);*/
		FD_SET(comm_session->socket_fd,
		       &socket_comm_handle->read_master_set);
		FD_SET(comm_session->socket_fd,
		       &socket_comm_handle->except_master_set);
		node = node->next_node;
	}

	FD_ZERO(&socket_comm_handle->write_master_set);
	node = socket_comm_handle->write_list->head;
	while (node != NULL) {
		comm_session = (pcep_socket_comm_session *)node->data;
		if (comm_session->socket_fd > max_fd) {
			max_fd = comm_session->socket_fd;
		} else if (comm_session->socket_fd < 0) {
			pcep_log(LOG_ERR, "%s: Negative fd", __func__);
			assert(comm_session->socket_fd > 0);
		}

		/*pcep_log(LOG_DEBUG, "%s: [%ld] socket_comm::build_fdSets set
		   ready_toWrite [%d]", __func__, time(NULL),
		   comm_session->socket_fd);*/
		FD_SET(comm_session->socket_fd,
		       &socket_comm_handle->write_master_set);
		FD_SET(comm_session->socket_fd,
		       &socket_comm_handle->except_master_set);
		node = node->next_node;
	}

	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

	return max_fd + 1;
}


void handle_reads(pcep_socket_comm_handle *socket_comm_handle)
{

	/*
	 * iterate all the socket_fd's in the read_list. it may be that not
	 * all of them have something to read. dont remove the socket_fd
	 * from the read_list since messages could come at any time.
	 */

	/* Notice: Only locking the mutex when accessing the read_list,
	 * since the read callbacks may end up calling back into the socket
	 * comm module to write messages which could be a deadlock. */
	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
	ordered_list_node *node = socket_comm_handle->read_list->head;
	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

	while (node != NULL) {
		pcep_socket_comm_session *comm_session =
			(pcep_socket_comm_session *)node->data;

		pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
		node = node->next_node;
		if (!comm_session_exists(socket_comm_handle, comm_session)) {
			/* This comm_session has been deleted, move on to the
			 * next one */
			pthread_mutex_unlock(
				&(socket_comm_handle->socket_comm_mutex));
			continue;
		}

		int is_set = FD_ISSET(comm_session->socket_fd,
				      &(socket_comm_handle->read_master_set));
		/* Upon read failure, the comm_session might be free'd, so we
		 * cant store the received_bytes in the comm_session, until we
		 * know the read was successful. */
		int received_bytes = 0;
		pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

		if (is_set) {
			FD_CLR(comm_session->socket_fd,
			       &(socket_comm_handle->read_master_set));

			/* either read the message locally, or call the
			 * message_ready_handler to read it */
			if (comm_session->message_handler != NULL) {
				received_bytes = read_message(
					comm_session->socket_fd,
					comm_session->received_message,
					MAX_RECVD_MSG_SIZE);
				if (received_bytes > 0) {
					/* Send the received message to the
					 * handler */
					comm_session->received_bytes =
						received_bytes;
					comm_session->message_handler(
						comm_session->session_data,
						comm_session->received_message,
						comm_session->received_bytes);
				}
			} else {
				/* Tell the handler a message is ready to be
				 * read. The comm_session may be destroyed in
				 * this call, if
				 * there is an error reading or if the socket is
				 * closed. */
				received_bytes =
					comm_session
						->message_ready_to_read_handler(
							comm_session
								->session_data,
							comm_session
								->socket_fd);
			}

			/* handle the read results */
			if (received_bytes == 0) {
				if (comm_session_exists_locking(
					    socket_comm_handle, comm_session)) {
					comm_session->received_bytes = 0;
					/* the socket was closed */
					/* TODO should we define a socket except
					 * enum? or will the only time we call
					 * this is when the socket is closed??
					 */
					if (comm_session->conn_except_notifier
					    != NULL) {
						comm_session->conn_except_notifier(
							comm_session
								->session_data,
							comm_session
								->socket_fd);
					}

					/* stop reading from the socket if its
					 * closed */
					pthread_mutex_lock(
						&(socket_comm_handle
							  ->socket_comm_mutex));
					ordered_list_remove_first_node_equals(
						socket_comm_handle->read_list,
						comm_session);
					pthread_mutex_unlock(
						&(socket_comm_handle
							  ->socket_comm_mutex));
				}
			} else if (received_bytes < 0) {
				/* TODO should we call conn_except_notifier()
				 * here ? */
				pcep_log(
					LOG_WARNING,
					"%s: Error on socket fd [%d] : errno [%d][%s]",
					__func__, comm_session->socket_fd,
					errno, strerror(errno));
			} else {
				comm_session->received_bytes = received_bytes;
			}
		}
	}
}


void handle_writes(pcep_socket_comm_handle *socket_comm_handle)
{
	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));

	/*
	 * iterate all the socket_fd's in the write_list. it may be that not
	 * all of them are ready to be written to. only remove the socket_fd
	 * from the list if it is ready to be written to.
	 */

	ordered_list_node *node = socket_comm_handle->write_list->head;
	pcep_socket_comm_session *comm_session;
	bool msg_written;
	while (node != NULL) {
		comm_session = (pcep_socket_comm_session *)node->data;
		node = node->next_node;
		msg_written = false;

		if (!comm_session_exists(socket_comm_handle, comm_session)) {
			/* This comm_session has been deleted, move on to the
			 * next one */
			continue;
		}

		if (FD_ISSET(comm_session->socket_fd,
			     &(socket_comm_handle->write_master_set))) {
			/* only remove the entry from the list, if it is written
			 * to */
			ordered_list_remove_first_node_equals(
				socket_comm_handle->write_list, comm_session);
			FD_CLR(comm_session->socket_fd,
			       &(socket_comm_handle->write_master_set));

			/* dequeue all the comm_session messages and send them
			 */
			pcep_socket_comm_queued_message *queued_message =
				queue_dequeue(comm_session->message_queue);
			while (queued_message != NULL) {
				msg_written = true;
				write_message(comm_session->socket_fd,
					      queued_message->encoded_message,
					      queued_message->msg_length);
				if (queued_message->free_after_send) {
					pceplib_free(PCEPLIB_MESSAGES,
						     (void *)queued_message
							     ->encoded_message);
				}
				pceplib_free(PCEPLIB_MESSAGES, queued_message);
				queued_message = queue_dequeue(
					comm_session->message_queue);
			}
		}

		/* check if the socket should be closed after writing */
		if (comm_session->close_after_write == true) {
			if (comm_session->message_queue->num_entries == 0) {
				/* TODO check to make sure modifying the
				 * write_list while iterating it doesn't cause
				 * problems. */
				pcep_log(
					LOG_DEBUG,
					"%s: handle_writes close() socket fd [%d]",
					__func__, comm_session->socket_fd);
				ordered_list_remove_first_node_equals(
					socket_comm_handle->read_list,
					comm_session);
				ordered_list_remove_first_node_equals(
					socket_comm_handle->write_list,
					comm_session);
				close(comm_session->socket_fd);
				comm_session->socket_fd = -1;
			}
		}

		if (comm_session->message_sent_handler != NULL
		    && msg_written == true) {
			/* Unlocking to allow the message_sent_handler to
			 * make calls like destroy_socket_comm_session */
			pthread_mutex_unlock(
				&(socket_comm_handle->socket_comm_mutex));
			comm_session->message_sent_handler(
				comm_session->session_data,
				comm_session->socket_fd);
			pthread_mutex_lock(
				&(socket_comm_handle->socket_comm_mutex));
		}
	}

	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));
}


void handle_excepts(pcep_socket_comm_handle *socket_comm_handle)
{
	/* TODO finish this */
	(void)socket_comm_handle;
}


/* pcep_socket_comm::initialize_socket_comm_loop() will create a thread and
 * invoke this method */
void *socket_comm_loop(void *data)
{
	if (data == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: Cannot start socket_comm_loop with NULL pcep_socketcomm_handle",
			__func__);
		return NULL;
	}

	pcep_log(LOG_NOTICE, "%s: [%ld-%ld] Starting socket_comm_loop thread",
		 __func__, time(NULL), pthread_self());

	pcep_socket_comm_handle *socket_comm_handle =
		(pcep_socket_comm_handle *)data;
	struct timeval timer;
	int max_fd;

	while (socket_comm_handle->active) {
		/* check the FD's every 1/4 sec, 250 milliseconds */
		timer.tv_sec = 0;
		timer.tv_usec = 250000;
		max_fd = build_fd_sets(socket_comm_handle);

		if (select(max_fd, &(socket_comm_handle->read_master_set),
			   &(socket_comm_handle->write_master_set),
			   &(socket_comm_handle->except_master_set), &timer)
		    < 0) {
			/* TODO handle the error */
			pcep_log(
				LOG_WARNING,
				"%s: ERROR socket_comm_loop on select : errno [%d][%s]",
				__func__, errno, strerror(errno));
		}

		handle_reads(socket_comm_handle);
		handle_writes(socket_comm_handle);
		handle_excepts(socket_comm_handle);
	}

	pcep_log(LOG_NOTICE, "%s: [%ld-%ld] Finished socket_comm_loop thread",
		 __func__, time(NULL), pthread_self());

	return NULL;
}

int pceplib_external_socket_read(int fd, void *payload)
{
	pcep_socket_comm_handle *socket_comm_handle =
		(pcep_socket_comm_handle *)payload;
	if (socket_comm_handle == NULL) {
		return -1;
	}

	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
	FD_SET(fd, &(socket_comm_handle->read_master_set));
	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

	handle_reads(socket_comm_handle);

	/* Get the socket_comm_session */
	pcep_socket_comm_session find_session = {.socket_fd = fd};
	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
	ordered_list_node *node =
		ordered_list_find(socket_comm_handle->read_list, &find_session);

	/* read again */
	if (node != NULL) {
		socket_comm_handle->socket_read_func(
			socket_comm_handle->external_infra_data,
			&((pcep_socket_comm_session *)node)
				 ->external_socket_data,
			fd, socket_comm_handle);
	}
	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

	return 0;
}

int pceplib_external_socket_write(int fd, void *payload)
{
	pcep_socket_comm_handle *socket_comm_handle =
		(pcep_socket_comm_handle *)payload;
	if (socket_comm_handle == NULL) {
		return -1;
	}

	pthread_mutex_lock(&(socket_comm_handle->socket_comm_mutex));
	FD_SET(fd, &(socket_comm_handle->write_master_set));
	pthread_mutex_unlock(&(socket_comm_handle->socket_comm_mutex));

	handle_writes(socket_comm_handle);

	/* TODO do we need to cancel this FD from writing?? */

	return 0;
}
