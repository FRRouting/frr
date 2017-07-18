/*
 * Timer Wheel
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
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
#ifndef __WHEEL_H__
#define __WHEEL_H__

struct timer_wheel {
	struct thread_master *master;
	int slots;
	long long curr_slot;
	unsigned int period;
	unsigned int nexttime;
	unsigned int slots_to_skip;

	struct list **wheel_slot_lists;
	struct thread *timer;
	/*
	 * Key to determine what slot the item belongs in
	 */
	unsigned int (*slot_key)(void *);

	void (*slot_run)(void *);
};

/*
 * Creates a timer wheel
 *
 * master - Thread master structure for the process
 * period - The Time in seconds that the timer wheel will
 *          take before it starts issuing commands again
 *          for items in each slot
 * slots  - The number of slots to have in this particular
 *          timer wheel
 * slot_key - A hashing function of some sort that will allow
 *            the timer wheel to put items into individual slots
 * slot_run - The function to run over each item in a particular slot
 *
 * Creates a timer wheel that will wake up 'slots' times over the entire
 * wheel.  Each time the timer wheel wakes up it will iterate through
 * and run the slot_run function for each item stored in that particular
 * slot.
 *
 * The timer code is 'intelligent' in that it notices if anything is
 * in a particular slot and can schedule the next timer to skip
 * the empty slot.
 *
 * The general purpose of a timer wheel is to reduce events in a system.
 * A perfect example of usage for this is say hello packets that need
 * to be sent out to all your neighbors.  Suppose a large routing protocol
 * has to send keepalive packets every Y seconds to each of it's peers.
 * At scale we can have a very large number of peers, X.
 * This means that we will have X timing events every Y seconds.
 * If you replace these events with a timer wheel that has Z slots
 * you will have at most Y/Z timer events if each slot has a work item
 * in it.
 *
 * When X is large the number of events in a system can quickly escalate
 * and cause significant amount of time handling thread events instead
 * of running your code.
 */
struct timer_wheel *wheel_init(struct thread_master *master, int period,
			       size_t slots, unsigned int (*slot_key)(void *),
			       void (*slot_run)(void *));

/*
 * Delete the specified timer wheel created
 */
void wheel_delete(struct timer_wheel *);

/*
 * Pause the Wheel from running
 */
int wheel_stop(struct timer_wheel *wheel);

/*
 * Start the wheel running again
 */
int wheel_start(struct timer_wheel *wheel);

/*
 * wheel - The Timer wheel being modified
 * item - The generic data structure that will be handed
 *        to the slot_run function.
 *
 * Add item to a slot setup by the slot_key,
 * possibly change next time pop.
 */
int wheel_add_item(struct timer_wheel *wheel, void *item);

/*
 * wheel - The Timer wheel being modified.
 * item - The item to remove from one of the slots in
 *        the timer wheel.
 *
 * Remove a item to a slot setup by the slot_key,
 * possibly change next time pop.
 */
int wheel_remove_item(struct timer_wheel *wheel, void *item);

#endif
