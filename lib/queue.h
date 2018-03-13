/*
 * lists and queues implementations
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _FRR_QUEUE_H
#define _FRR_QUEUE_H

#if defined(__OpenBSD__) && !defined(STAILQ_HEAD)
#include "openbsd-queue.h"

/* Try to map FreeBSD implementation to OpenBSD one. */
#define STAILQ_HEAD(name, type)				SIMPLEQ_HEAD(name, type)
#define STAILQ_HEAD_INITIALIZER(head)			SIMPLEQ_HEAD_INITIALIZER(head)
#define STAILQ_ENTRY(entry)				SIMPLEQ_ENTRY(entry)

#define STAILQ_CONCAT(head1, head2)			SIMPLEQ_CONCAT(head1, head2)
#define STAILQ_EMPTY(head)				SIMPLEQ_EMPTY(head)
#define STAILQ_FIRST(head)				SIMPLEQ_FIRST(head)
#define STAILQ_FOREACH(var, head, field)		SIMPLEQ_FOREACH(var, head, field)
#define STAILQ_FOREACH_SAFE(var, head, field, tvar)	SIMPLEQ_FOREACH_SAFE(var, head, field, tvar)
#define STAILQ_INIT(head)				SIMPLEQ_INIT(head)
#define STAILQ_INSERT_AFTER(head, tqelm, elm, field)	SIMPLEQ_INSERT_AFTER(head, tqelm, elm, field)
#define STAILQ_INSERT_HEAD(head, elm, field)		SIMPLEQ_INSERT_HEAD(head, elm, field)
#define STAILQ_INSERT_TAIL(head, elm, field)		SIMPLEQ_INSERT_TAIL(head, elm, field)
#define STAILQ_LAST(head, type, field)                                         \
	(SIMPLEQ_EMPTY((head))                                                 \
		 ? NULL                                                        \
		 : ((struct type *)(void *)((char *)((head)->sqh_last)         \
					    - offsetof(struct type, field))))
#define STAILQ_NEXT(elm, field)				SIMPLEQ_NEXT(elm, field)
#define STAILQ_REMOVE(head, elm, type, field)                                  \
	do {                                                                   \
		if (SIMPLEQ_FIRST((head)) == (elm)) {                          \
			SIMPLEQ_REMOVE_HEAD((head), field);                    \
		} else {                                                       \
			struct type *curelm = SIMPLEQ_FIRST((head));           \
			while (SIMPLEQ_NEXT(curelm, field) != (elm))           \
				curelm = SIMPLEQ_NEXT(curelm, field);          \
			SIMPLEQ_REMOVE_AFTER(head, curelm, field);             \
		}                                                              \
	} while (0)
#define STAILQ_REMOVE_AFTER(head, elm, field)		SIMPLEQ_REMOVE_AFTER(head, elm, field)
#define STAILQ_REMOVE_HEAD(head, field)			SIMPLEQ_REMOVE_HEAD(head, field)
#define STAILQ_SWAP(head1, head2, type)                                        \
	do {                                                                   \
		struct type *swap_first = STAILQ_FIRST(head1);                 \
		struct type **swap_last = (head1)->sqh_last;                   \
		STAILQ_FIRST(head1) = STAILQ_FIRST(head2);                     \
		(head1)->sqh_last = (head2)->sqh_last;                         \
		STAILQ_FIRST(head2) = swap_first;                              \
		(head2)->sqh_last = swap_last;                                 \
		if (STAILQ_EMPTY(head1))                                       \
			(head1)->sqh_last = &STAILQ_FIRST(head1);              \
		if (STAILQ_EMPTY(head2))                                       \
			(head2)->sqh_last = &STAILQ_FIRST(head2);              \
	} while (0)
#else
#include "freebsd-queue.h"
#endif /* defined(__OpenBSD__) && !defined(STAILQ_HEAD) */

#endif /* _FRR_QUEUE_H */
