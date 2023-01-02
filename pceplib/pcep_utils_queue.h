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


#ifndef INCLUDE_PCEPUTILSQUEUE_H_
#define INCLUDE_PCEPUTILSQUEUE_H_

typedef struct queue_node_ {
	struct queue_node_ *next_node;
	void *data;

} queue_node;

typedef struct queue_handle_ {
	queue_node *head;
	queue_node *tail;
	unsigned int num_entries;
	/* Set to 0 to disable */
	unsigned int max_entries;

} queue_handle;

queue_handle *queue_initialize(void);
queue_handle *queue_initialize_with_size(unsigned int max_entries);
void queue_destroy(queue_handle *handle);
void queue_destroy_with_data(queue_handle *handle);
queue_node *queue_enqueue(queue_handle *handle, void *data);
void *queue_dequeue(queue_handle *handle);

#endif /* INCLUDE_PCEPUTILSQUEUE_H_ */
