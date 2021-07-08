/*
 * Zebra BGP ORR zapi message handler module
 * Copyright (c) 2021 Samsung R&D Institute India - Bangalore.
 * 			Madhurilatha Kuruganti
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

#ifndef _ZEBRA_ORR_H
#define _ZEBRA_ORR_H 1

/* Default for number of messages to dequeue per lock cycle */
#define ZEBRA_ORR_MSG_LIMIT 1000

/*
 * Initialize the module at startup
 */
void zebra_orr_init(void);

/*
 * Start the module pthread. This step is run later than the
 * 'init' step, in case zebra has fork-ed.
 */
void zebra_orr_start(void);

/*
 * Does this module handle (intercept) the specified zapi message type?
 */
bool zebra_orr_handles_msgid(uint16_t id);

/*
 * Module stop, called from the main pthread. This is synchronous:
 * once it returns, the pthread has stopped and exited.
 */
void zebra_orr_stop(void);

/*
 * Module cleanup, called from the zebra main pthread. When it returns,
 * all module cleanup is complete.
 */
void zebra_orr_finish(void);

/*
 * Enqueue a batch of messages for processing. Returns the number dequeued
 * from the batch fifo.
 */
uint32_t zebra_orr_enqueue_batch(struct stream_fifo *batch);


#endif /* _ZEBRA_ORR_H */
