// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Quagga Work Queues.
 *
 * Copyright (C) 2005 Sun Microsystems, Inc.
 */

#ifndef _QUAGGA_WORK_QUEUE_H
#define _QUAGGA_WORK_QUEUE_H

#include "memory.h"
#include "queue.h"

#ifdef __cplusplus
extern "C" {
#endif

DECLARE_MTYPE(WORK_QUEUE);

/* Hold time for the initial schedule of a queue run, in  millisec */
#define WORK_QUEUE_DEFAULT_HOLD 50

/* Retry for queue that is 'blocked' or 'retry later' */
#define WORK_QUEUE_DEFAULT_RETRY 0

/* action value, for use by item processor and item error handlers */
typedef enum {
	WQ_SUCCESS = 0,
	WQ_REQUEUE,	  /* requeue item, continue processing work queue */
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
	struct event_loop *master;    /* thread master */
	struct event *thread;	      /* thread, if one is active */
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

		uint32_t retry; /* Optional retry timeout if queue is blocked */
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

/* create a new work queue, of given name.
 * user must fill in the spec of the returned work queue before adding
 * anything to it
 */
extern struct work_queue *work_queue_new(struct event_loop *m,
					 const char *queue_name);

/* destroy work queue */
/*
 * The usage of work_queue_free is being transitioned to pass
 * in the double pointer to remove use after free's.
 */
extern void work_queue_free_and_null(struct work_queue **wqp);

/* Add the supplied data as an item onto the workqueue */
extern void work_queue_add(struct work_queue *wq, void *item);

/* plug the queue, ie prevent it from being drained / processed */
extern void work_queue_plug(struct work_queue *wq);
/* unplug the queue, allow it to be drained again */
extern void work_queue_unplug(struct work_queue *wq);

bool work_queue_is_scheduled(struct work_queue *wq);

/* Helpers, exported for thread.c and command.c */
extern void work_queue_run(struct event *thread);

/* Function to initialize the workqueue cli */
extern void workqueue_cmd_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_WORK_QUEUE_H */
