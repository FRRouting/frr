// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * lists and queues implementations
 */

#ifndef _FRR_QUEUE_H
#define _FRR_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

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

#ifndef TAILQ_POP_FIRST
#define TAILQ_POP_FIRST(head, field)                                           \
	({  typeof((head)->tqh_first) _elm = TAILQ_FIRST(head);                \
	    if (_elm) {                                                        \
		if ((TAILQ_NEXT((_elm), field)) != NULL)                       \
			TAILQ_NEXT((_elm), field)->field.tqe_prev =            \
				&TAILQ_FIRST(head);                            \
		else                                                           \
			(head)->tqh_last = &TAILQ_FIRST(head);                 \
		TAILQ_FIRST(head) = TAILQ_NEXT((_elm), field);                 \
	}; _elm; })
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FRR_QUEUE_H */
