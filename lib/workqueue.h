/*
 * Quagga Work Queues.
 *
 * Copyright (C) 2005 Sun Microsystems, Inc.
 *
 * This file is part of Quagga.
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _QUAGGA_WORK_QUEUE_H
#define _QUAGGA_WORK_QUEUE_H

#include "memory.h"
#include "queue.h"
DECLARE_MTYPE(WORK_QUEUE)

/* Hold time for the initial schedule of a queue run, in  millisec */
#define WORK_QUEUE_DEFAULT_HOLD 50

/* action value, for use by item processor and item error handlers */
typedef enum {
	WQ_SUCCESS = 0,
	WQ_ERROR,	 /* Error, run error handler if provided */
	WQ_RETRY_NOW,     /* retry immediately */
	WQ_RETRY_LATER,   /* retry later, cease processing work queue */
	WQ_REQUEUE,       /* requeue item, continue processing work queue */
	WQ_QUEUE_BLOCKED, /* Queue cant be processed at this time.
			   * Similar to WQ_RETRY_LATER, but doesn't penalise
			   * the particular item.. */
} wq_item_status;

/* A single work queue item, unsurprisingly */
struct work_queue_item {
	STAILQ_ENTRY(work_queue_item) wq;
	void *data;	 /* opaque data */
	unsigned short ran; /* # of times item has been run */
};

#define WQ_UNPLUGGED	(1 << 0) /* available for draining */

struct work_queue {
	/* Everything but the specification struct is private
	 * the following may be read
	 */
	struct thread_master *master; /* thread master */
	struct thread *thread;	/* thread, if one is active */
	char *name;		      /* work queue name */

	/* Specification for this work queue.
	 * Public, must be set before use by caller. May be modified at will.
	 */
	struct {
		/* optional opaque user data, global to the queue. */
		void *data;

		/* work function to process items with:
		 * First argument is the workqueue queue.
		 * Second argument is the item data
		 */
		wq_item_status (*workfunc)(struct work_queue *, void *);

		/* error handling function, optional */
		void (*errorfunc)(struct work_queue *,
				  struct work_queue_item *);

		/* callback to delete user specific item data */
		void (*del_item_data)(struct work_queue *, void *);

		/* completion callback, called when queue is emptied, optional
		 */
		void (*completion_func)(struct work_queue *);

		/* max number of retries to make for item that errors */
		unsigned int max_retries;

		unsigned int hold; /* hold time for first run, in ms */

		unsigned long
			yield; /* yield time in us for associated thread */
	} spec;

	/* remaining fields should be opaque to users */
	STAILQ_HEAD(work_queue_items, work_queue_item)
	items;		      /* queue item list */
	int item_count;       /* queued items */
	unsigned long runs;   /* runs count */
	unsigned long yields; /* yields count */

	struct {
		unsigned int best;
		unsigned int granularity;
		unsigned long total;
	} cycles; /* cycle counts */

	/* private state */
	uint16_t flags; /* user set flag */
};

/* User API */

static inline int work_queue_item_count(struct work_queue *wq)
{
	return wq->item_count;
}

static inline bool work_queue_empty(struct work_queue *wq)
{
	return (wq->item_count == 0) ? true : false;
}

static inline struct work_queue_item *
work_queue_last_item(struct work_queue *wq)
{
	return STAILQ_LAST(&wq->items, work_queue_item, wq);
}

static inline void work_queue_item_enqueue(struct work_queue *wq,
					   struct work_queue_item *item)
{
	STAILQ_INSERT_TAIL(&wq->items, item, wq);
	wq->item_count++;
}

static inline void work_queue_item_dequeue(struct work_queue *wq,
					   struct work_queue_item *item)
{
	assert(wq->item_count > 0);

	wq->item_count--;
	STAILQ_REMOVE(&wq->items, item, work_queue_item, wq);
}

/* create a new work queue, of given name.
 * user must fill in the spec of the returned work queue before adding
 * anything to it
 */
extern struct work_queue *work_queue_new(struct thread_master *, const char *);

/* destroy work queue */
/*
 * The usage of work_queue_free is being transitioned to pass
 * in the double pointer to remove use after free's.
 */
#if defined(VERSION_TYPE_DEV) && CONFDATE > 20190205
CPP_NOTICE("work_queue_free without double pointer is deprecated, please fixup")
#endif
extern void work_queue_free_and_null(struct work_queue **);
extern void work_queue_free_original(struct work_queue *);
#define work_queue_free(X)                                                     \
	do {                                                                   \
		work_queue_free_original((X));                                 \
		CPP_WARN("Please use work_queue_free_and_null");               \
	} while (0)

/* Add the supplied data as an item onto the workqueue */
extern void work_queue_add(struct work_queue *, void *);

/* plug the queue, ie prevent it from being drained / processed */
extern void work_queue_plug(struct work_queue *wq);
/* unplug the queue, allow it to be drained again */
extern void work_queue_unplug(struct work_queue *wq);

bool work_queue_is_scheduled(struct work_queue *);

/* Helpers, exported for thread.c and command.c */
extern int work_queue_run(struct thread *);

extern void workqueue_cmd_init(void);

#endif /* _QUAGGA_WORK_QUEUE_H */
