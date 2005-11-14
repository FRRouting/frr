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
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#ifndef _QUAGGA_WORK_QUEUE_H
#define _QUAGGA_WORK_QUEUE_H

/* Work queue default hold and cycle times - millisec */
#define WORK_QUEUE_DEFAULT_HOLD  50  /* hold-time between runs of a queue */
#define WORK_QUEUE_DEFAULT_DELAY 10  /* minimum delay for queue runs */
#define WORK_QUEUE_DEFAULT_FLOOD 40   /* flood factor, ~2s with prev values */

/* action value, for use by item processor and item error handlers */
typedef enum
{
  WQ_SUCCESS = 0,
  WQ_ERROR,             /* Error, run error handler if provided */
  WQ_RETRY_NOW,         /* retry immediately */
  WQ_RETRY_LATER,       /* retry later, cease processing work queue */
  WQ_REQUEUE,		/* requeue item, continue processing work queue */
  WQ_QUEUE_BLOCKED,	/* Queue cant be processed at this time.
                         * Similar to WQ_RETRY_LATER, but doesn't penalise
                         * the particular item.. */
} wq_item_status;

/* A single work queue item, unsurprisingly */
struct work_queue_item
{
  void *data;                           /* opaque data */
  unsigned short ran;			/* # of times item has been run */
};

enum work_queue_flags
{
  WQ_UNPLUGGED = 0,
  WQ_PLUGGED = 1,
};

struct work_queue
{
  /* Everything but the specification struct is private */
  struct thread_master *master;       /* thread master */
  struct thread *thread;              /* thread, if one is active */
  char *name;                         /* work queue name */
  char status;                        /* status */
#define WQ_STATE_FLOODED	(1 << 0)
  enum work_queue_flags flags;		/* flags */
  
  /* Specification for this work queue.
   * Public, must be set before use by caller. May be modified at will.
   */
  struct {
    /* work function to process items with */
    wq_item_status (*workfunc) (void *);

    /* error handling function, optional */
    void (*errorfunc) (struct work_queue *, struct work_queue_item *);
    
    /* callback to delete user specific item data */
    void (*del_item_data) (void *);
    
    /* completion callback, called when queue is emptied, optional */
    void (*completion_func) (struct work_queue *);
    
    /* max number of retries to make for item that errors */
    unsigned int max_retries;	

    unsigned int hold;	/* hold time for first run, in ms */
    unsigned int delay; /* min delay between queue runs, in ms */
    
    unsigned int flood; /* number of queue runs after which we consider
                         * queue to be flooded, where the runs are
                         * consecutive and each has used its full slot,
                         * and the queue has still not been cleared. If
                         * the queue is flooded, then we try harder to
                         * clear it by ignoring the hold and delay
                         * times. No point sparing CPU resources just
                         * to use ever more memory resources.
                         */
  } spec;
  
  /* remaining fields should be opaque to users */
  struct list *items;                 /* queue item list */
  unsigned long runs;                 /* runs count */
  unsigned int runs_since_clear;      /* number of runs since queue was
                                       * last cleared
                                       */
  
  struct {
    unsigned int best;
    unsigned int granularity;
    unsigned long total;
  } cycles;	/* cycle counts */
};

/* User API */

/* create a new work queue, of given name. 
 * user must fill in the spec of the returned work queue before adding
 * anything to it
 */
extern struct work_queue *work_queue_new (struct thread_master *,
                                          const char *);
/* destroy work queue */
extern void work_queue_free (struct work_queue *);

/* Add the supplied data as an item onto the workqueue */
extern void work_queue_add (struct work_queue *, void *);

/* plug the queue, ie prevent it from being drained / processed */
extern void work_queue_plug (struct work_queue *wq);
/* unplug the queue, allow it to be drained again */
extern void work_queue_unplug (struct work_queue *wq);

/* Helpers, exported for thread.c and command.c */
extern int work_queue_run (struct thread *);
extern struct cmd_element show_work_queues_cmd;
#endif /* _QUAGGA_WORK_QUEUE_H */
