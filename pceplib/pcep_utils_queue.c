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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"
#include "pcep_utils_queue.h"

queue_handle *queue_initialize(void)
{
	/* Set the max_entries to 0 to disable it */
	return queue_initialize_with_size(0);
}


queue_handle *queue_initialize_with_size(unsigned int max_entries)
{
	queue_handle *handle =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(queue_handle));
	memset(handle, 0, sizeof(queue_handle));
	handle->max_entries = max_entries;

	return handle;
}


void queue_destroy(queue_handle *handle)
{
	if (handle == NULL) {
		pcep_log(
			LOG_DEBUG,
			"%s: queue_destroy, the queue has not been initialized",
			__func__);
		return;
	}

	while (queue_dequeue(handle) != NULL) {
	}
	pceplib_free(PCEPLIB_INFRA, handle);
}


void queue_destroy_with_data(queue_handle *handle)
{
	if (handle == NULL) {
		pcep_log(
			LOG_DEBUG,
			"%s: queue_destroy_with_data, the queue has not been initialized",
			__func__);
		return;
	}

	void *data = queue_dequeue(handle);
	while (data != NULL) {
		pceplib_free(PCEPLIB_INFRA, data);
		data = queue_dequeue(handle);
	}
	pceplib_free(PCEPLIB_INFRA, handle);
}


queue_node *queue_enqueue(queue_handle *handle, void *data)
{
	if (handle == NULL) {
		pcep_log(
			LOG_DEBUG,
			"%s: queue_enqueue, the queue has not been initialized",
			__func__);
		return NULL;
	}

	if (handle->max_entries > 0
	    && handle->num_entries >= handle->max_entries) {
		pcep_log(
			LOG_DEBUG,
			"%s: queue_enqueue, cannot enqueue: max entries hit [%u]",
			handle->num_entries);
		return NULL;
	}

	queue_node *new_node =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(queue_node));
	memset(new_node, 0, sizeof(queue_node));
	new_node->data = data;
	new_node->next_node = NULL;

	(handle->num_entries)++;
	if (handle->head == NULL) {
		/* its the first entry in the queue */
		handle->head = handle->tail = new_node;
	} else {
		handle->tail->next_node = new_node;
		handle->tail = new_node;
	}

	return new_node;
}


void *queue_dequeue(queue_handle *handle)
{
	if (handle == NULL) {
		pcep_log(
			LOG_DEBUG,
			"%s: queue_dequeue, the queue has not been initialized",
			__func__);
		return NULL;
	}

	if (handle->head == NULL) {
		return NULL;
	}

	void *node_data = handle->head->data;
	queue_node *node = handle->head;
	(handle->num_entries)--;
	if (handle->head == handle->tail) {
		/* its the last entry in the queue */
		handle->head = handle->tail = NULL;
	} else {
		handle->head = node->next_node;
	}

	pceplib_free(PCEPLIB_INFRA, node);

	return node_data;
}
