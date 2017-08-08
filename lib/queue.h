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

#ifdef __OpenBSD__
#include "openbsd-queue.h"

/* Try to map FreeBSD implementation to OpenBSD one. */
#define STAILQ_HEAD(name, type)		SIMPLEQ_HEAD(name, type)
#define STAILQ_HEAD_INITIALIZER(head)	SIMPLEQ_HEAD_INITIALIZER(head)
#define STAILQ_ENTRY(entry)		SIMPLEQ_ENTRY(entry)

#define STAILQ_CONCAT(head1, head2)	SIMPLEQ_CONCAT(head1, head2)
#define STAILQ_EMPTY(head)		SIMPLEQ_EMPTY(head)
#define STAILQ_FIRST(head)		SIMPLEQ_FIRST(head)
#define STAILQ_FOREACH(var, head, field)		SIMPLEQ_FOREACH(var, head, field)
#define STAILQ_FOREACH_SAFE(var, head, field, tvar)	SIMPLEQ_FOREACH_SAFE(var, head, field, tvar)
#define STAILQ_INIT(head)		SIMPLEQ_INIT(head)
#define STAILQ_INSERT_AFTER(head, tqelm, elm, field)	SIMPLEQ_INSERT_AFTER(head, tqelm, elm, field)
#define STAILQ_INSERT_HEAD(head, elm, field)		SIMPLEQ_INSERT_HEAD(head, elm, field)
#define STAILQ_INSERT_TAIL(head, elm, field)		SIMPLEQ_INSERT_TAIL(head, elm, field)
#define STAILQ_LAST(head, type, field)                                         \
	(STAILQ_EMPTY((head))                                                  \
		 ? NULL                                                        \
		 : ((struct type *)(void *)((char *)((head)->sqe_last)         \
					    - __offsetof(struct type,          \
							 field))))
#define STAILQ_NEXT(elm, field)				SIMPLEQ_NEXT(elm, field)
#else
#include "freebsd-queue.h"
#endif /* __OpenBSD__ */

#endif /* _FRR_QUEUE_H */
