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
#define WORK_QUEUE_DEFAULT_HOLD  50  /* hold time for initial run of a queue */
#define WORK_QUEUE_DEFAULT_DELAY 10  /* minimum delay between queue runs */

/* action value, for use by item processor and item error handlers */
typedef enum
{
  WQ_SUCCESS = 0,
  WQ_ERROR,             /* Error, run error handler if provided */
  WQ_RETRY_NOW,         /* retry immediately */
  WQ_RETRY_LATER,       /* retry later, cease processing work queue */
  WQ_REQUEUE            /* requeue item, continue processing work queue */
} wq_item_status;

/* A single work queue item, unsurprisingly */
struct work_queue_item
{
  void *data;                           /* opaque data */
  unsigned short ran;			/* # of times item has been run */
};

struct work_queue
{
  struct thread_master *master;       /* thread master */
  struct thread *thread;              /* thread, if one is active */
  char *name;                         /* work queue name */
  
  /* specification for this work queue */
  struct {
    /* work function to process items with */
    wq_item_status (*workfunc) ();

    /* error handling function, optional */
    void (*errorfunc) (struct work_queue *, struct work_queue_item *);
    
    /* callback to delete user specific item data */
    void (*del_item_data) ();
    
    /* max number of retries to make for item that errors */
    unsigned int max_retries;	

    unsigned int hold;	/* hold time for first run, in ms */
    unsigned int delay; /* min delay between queue runs, in ms */
  } spec;
  
  /* remaining fields should be opaque to users */
  struct list *items;                 /* queue item list */
  unsigned long runs;                  /* runs count */
  
  struct {
    unsigned int best;
    unsigned int granularity;
    unsigned long total;
  } cycles;	/* cycle counts */
};

/* User API */
struct work_queue *work_queue_new (struct thread_master *, const char *);
void work_queue_free (struct work_queue *);
void work_queue_add (struct work_queue *, void *);

/* Helpers, exported for thread.c and command.c */
int work_queue_run (struct thread *);
extern struct cmd_element show_work_queues_cmd;
#endif /* _QUAGGA_WORK_QUEUE_H */
