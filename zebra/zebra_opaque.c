/*
 * Zebra opaque message handler module
 * Copyright (c) 2020 Volta Networks, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */


#include <zebra.h>
#include "lib/debug.h"
#include "lib/frr_pthread.h"
#include "lib/stream.h"
#include "zebra/debug.h"
#include "zebra/zserv.h"
#include "zebra/zebra_opaque.h"

/*
 * Globals
 */
static struct zebra_opaque_globals {

	/* Sentinel for run or start of shutdown */
	_Atomic uint32_t run;

	/* Limit number of pending, unprocessed updates */
	_Atomic uint32_t max_queued_updates;

	/* Limit number of new messages dequeued at once, to pace an
	 * incoming burst.
	 */
	uint32_t msgs_per_cycle;

	/* Stats: counters of incoming messages, errors, and yields (when
	 * the limit has been reached.)
	 */
	_Atomic uint32_t msgs_in;
	_Atomic uint32_t msg_errors;
	_Atomic uint32_t yields;

	/* pthread */
	struct frr_pthread *pthread;

	/* Event-delivery context 'master' for the module */
	struct thread_master *master;

	/* Event/'thread' pointer for queued zapi messages */
	struct thread *t_msgs;

	/* Input fifo queue to the module, and lock to protect it. */
	pthread_mutex_t mutex;
	struct stream_fifo in_fifo;

} zo_info;

/* Name string for debugs/logs */
static const char LOG_NAME[] = "Zebra Opaque";

/* Prototypes */

/* Main event loop, processing incoming message queue */
static int process_messages(struct thread *event);

/*
 * Initialize the module at startup
 */
void zebra_opaque_init(void)
{
	memset(&zo_info, 0, sizeof(zo_info));

	pthread_mutex_init(&zo_info.mutex, NULL);
	stream_fifo_init(&zo_info.in_fifo);

	zo_info.msgs_per_cycle = ZEBRA_OPAQUE_MSG_LIMIT;
}

/*
 * Start the module pthread. This step is run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_opaque_start(void)
{
	struct frr_pthread_attr pattr = {
		.start = frr_pthread_attr_default.start,
		.stop = frr_pthread_attr_default.stop
	};

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module starting", LOG_NAME);

	/* Start pthread */
	zo_info.pthread = frr_pthread_new(&pattr, "Zebra Opaque thread",
					  "zebra_opaque");

	/* Associate event 'master' */
	zo_info.master = zo_info.pthread->master;

	atomic_store_explicit(&zo_info.run, 1, memory_order_relaxed);

	/* Enqueue an initial event for the pthread */
	thread_add_event(zo_info.master, process_messages, NULL, 0,
			 &zo_info.t_msgs);

	/* And start the pthread */
	frr_pthread_run(zo_info.pthread, NULL);
}

/*
 * Module stop, halting the dedicated pthread; called from the main pthread.
 */
void zebra_opaque_stop(void)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module stop", LOG_NAME);

	atomic_store_explicit(&zo_info.run, 0, memory_order_relaxed);

	frr_pthread_stop(zo_info.pthread, NULL);

	frr_pthread_destroy(zo_info.pthread);

	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module stop complete", LOG_NAME);
}

/*
 * Module final cleanup, called from the zebra main pthread.
 */
void zebra_opaque_finish(void)
{
	if (IS_ZEBRA_DEBUG_EVENT)
		zlog_debug("%s module shutdown", LOG_NAME);

	pthread_mutex_destroy(&zo_info.mutex);
	stream_fifo_deinit(&zo_info.in_fifo);
}

/*
 * Does this module handle (intercept) the specified zapi message type?
 */
bool zebra_opaque_handles_msgid(uint16_t id)
{
	bool ret = false;

	switch (id) {
	case ZEBRA_OPAQUE_MESSAGE:
	case ZEBRA_OPAQUE_REGISTER:
	case ZEBRA_OPAQUE_UNREGISTER:
		ret = true;
		break;
	default:
		break;
	}

	return ret;
}

/*
 * Enqueue a batch of messages for processing - this is the public api
 * used from the zapi processing threads.
 */
uint32_t zebra_opaque_enqueue_batch(struct stream_fifo *batch)
{
	uint32_t counter = 0;
	struct stream *msg;

	/* Dequeue messages from the incoming batch, and save them
	 * on the module fifo.
	 */
	frr_with_mutex(&zo_info.mutex) {
		msg = stream_fifo_pop(batch);
		while (msg) {
			stream_fifo_push(&zo_info.in_fifo, msg);
			counter++;
			msg = stream_fifo_pop(batch);
		}
	}

	/* Schedule module pthread to process the batch */
	if (counter > 0) {
		if (IS_ZEBRA_DEBUG_RECV)
			zlog_debug("%s: received %u messages",
				   __func__, counter);
		thread_add_event(zo_info.master, process_messages, NULL, 0,
				 &zo_info.t_msgs);
	}

	return counter;
}

/*
 * Pthread event loop, process the incoming message queue.
 */
static int process_messages(struct thread *event)
{
	struct stream_fifo fifo;
	struct stream *msg;
	uint32_t i;
	bool need_resched = false;

	stream_fifo_init(&fifo);

	/* Check for zebra shutdown */
	if (atomic_load_explicit(&zo_info.run, memory_order_relaxed) == 0)
		goto done;

	/* Dequeue some messages from the incoming queue, temporarily
	 * save them on the local fifo
	 */
	frr_with_mutex(&zo_info.mutex) {

		for (i = 0; i < zo_info.msgs_per_cycle; i++) {
			msg = stream_fifo_pop(&zo_info.in_fifo);
			if (msg == NULL)
				break;

			stream_fifo_push(&fifo, msg);
		}

		/* We may need to reschedule, if there are still
		 * queued messages
		 */
		if (stream_fifo_head(&zo_info.in_fifo) != NULL)
			need_resched = true;
	}

	/* Update stats */
	atomic_fetch_add_explicit(&zo_info.msgs_in, i, memory_order_relaxed);

	/* Check for zebra shutdown */
	if (atomic_load_explicit(&zo_info.run, memory_order_relaxed) == 0) {
		need_resched = false;
		goto done;
	}

	if (IS_ZEBRA_DEBUG_RECV)
		zlog_debug("%s: processing %u messages", __func__, i);

	/* Process the messages on the local fifo */
	/* TODO -- just discarding the messages for now */
	msg = stream_fifo_pop(&fifo);
	while (msg) {
		stream_free(msg);
		msg = stream_fifo_pop(&fifo);
	}

done:

	if (need_resched) {
		atomic_fetch_add_explicit(&zo_info.yields, 1,
					  memory_order_relaxed);
		thread_add_event(zo_info.master, process_messages, NULL, 0,
				 &zo_info.t_msgs);
	}

	/* This will also free any leftover messages, in the shutdown case */
	stream_fifo_deinit(&fifo);

	return 0;
}
