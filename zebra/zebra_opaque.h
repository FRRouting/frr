// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Zebra opaque message zapi message handler
 * Copyright (c) 2020 Volta Networks, Inc.
 */

#include <zebra.h>

#ifndef _ZEBRA_OPAQUE_H
#define _ZEBRA_OPAQUE_H 1

/* Default for number of messages to dequeue per lock cycle */
#define ZEBRA_OPAQUE_MSG_LIMIT 1000

/*
 * Initialize the module at startup
 */
void zebra_opaque_init(void);

/*
 * Start the module pthread. This step is run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_opaque_start(void);

/*
 * Does this module handle (intercept) the specified zapi message type?
 */
bool zebra_opaque_handles_msgid(uint16_t id);

/*
 * Module stop, called from the main pthread. This is synchronous:
 * once it returns, the pthread has stopped and exited.
 */
void zebra_opaque_stop(void);

/*
 * Module cleanup, called from the zebra main pthread. When it returns,
 * all module cleanup is complete.
 */
void zebra_opaque_finish(void);

/*
 * Enqueue a batch of messages for processing. Returns the number dequeued
 * from the batch fifo.
 */
uint32_t zebra_opaque_enqueue_batch(struct stream_fifo *batch);


#endif	/* _ZEBRA_OPAQUE_H */
