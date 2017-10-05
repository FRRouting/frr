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
#include "zebra.h"
#include "linklist.h"
#include "thread.h"
#include "memory.h"
#include "wheel.h"
#include "log.h"

DEFINE_MTYPE_STATIC(LIB, TIMER_WHEEL, "Timer Wheel")
DEFINE_MTYPE_STATIC(LIB, TIMER_WHEEL_LIST, "Timer Wheel Slot List")

static int debug_timer_wheel = 0;

static int wheel_timer_thread(struct thread *t)
{
	struct listnode *node, *nextnode;
	unsigned long long curr_slot;
	unsigned int slots_to_skip = 1;
	struct timer_wheel *wheel;
	void *data;

	wheel = THREAD_ARG(t);
	THREAD_OFF(wheel->timer);

	wheel->curr_slot += wheel->slots_to_skip;

	curr_slot = wheel->curr_slot % wheel->slots;

	if (debug_timer_wheel)
		zlog_debug("%s: Wheel Slot: %lld(%lld) count: %d",
			   __PRETTY_FUNCTION__, wheel->curr_slot, curr_slot,
			   listcount(wheel->wheel_slot_lists[curr_slot]));

	for (ALL_LIST_ELEMENTS(wheel->wheel_slot_lists[curr_slot], node,
			       nextnode, data))
		(*wheel->slot_run)(data);

	while (list_isempty(wheel->wheel_slot_lists[(curr_slot + slots_to_skip)
						    % wheel->slots])
	       && (curr_slot + slots_to_skip) % wheel->slots != curr_slot)
		slots_to_skip++;

	wheel->slots_to_skip = slots_to_skip;
	thread_add_timer_msec(wheel->master, wheel_timer_thread, wheel,
			      wheel->nexttime * slots_to_skip, &wheel->timer);

	return 0;
}

struct timer_wheel *wheel_init(struct thread_master *master, int period,
			       size_t slots, unsigned int (*slot_key)(void *),
			       void (*slot_run)(void *))
{
	struct timer_wheel *wheel;
	size_t i;

	wheel = XCALLOC(MTYPE_TIMER_WHEEL, sizeof(struct timer_wheel));

	wheel->slot_key = slot_key;
	wheel->slot_run = slot_run;

	wheel->period = period;
	wheel->slots = slots;
	wheel->curr_slot = 0;
	wheel->master = master;
	wheel->nexttime = period / slots;

	wheel->wheel_slot_lists = XCALLOC(MTYPE_TIMER_WHEEL_LIST,
					  slots * sizeof(struct listnode *));
	for (i = 0; i < slots; i++)
		wheel->wheel_slot_lists[i] = list_new();

	thread_add_timer_msec(wheel->master, wheel_timer_thread, wheel,
			      wheel->nexttime, &wheel->timer);

	return wheel;
}

void wheel_delete(struct timer_wheel *wheel)
{
	int i;

	for (i = 0; i < wheel->slots; i++) {
		list_delete_and_null(&wheel->wheel_slot_lists[i]);
	}

	THREAD_OFF(wheel->timer);
	XFREE(MTYPE_TIMER_WHEEL_LIST, wheel->wheel_slot_lists);
	XFREE(MTYPE_TIMER_WHEEL, wheel);
}

int wheel_stop(struct timer_wheel *wheel)
{
	THREAD_OFF(wheel->timer);
	return 0;
}

int wheel_start(struct timer_wheel *wheel)
{
	if (!wheel->timer)
		thread_add_timer_msec(wheel->master, wheel_timer_thread, wheel,
				      wheel->nexttime, &wheel->timer);

	return 0;
}

int wheel_add_item(struct timer_wheel *wheel, void *item)
{
	long long slot;

	slot = (*wheel->slot_key)(item);

	if (debug_timer_wheel)
		zlog_debug("%s: Inserting %p: %lld %lld", __PRETTY_FUNCTION__,
			   item, slot, slot % wheel->slots);
	listnode_add(wheel->wheel_slot_lists[slot % wheel->slots], item);

	return 0;
}

int wheel_remove_item(struct timer_wheel *wheel, void *item)
{
	long long slot;

	slot = (*wheel->slot_key)(item);

	if (debug_timer_wheel)
		zlog_debug("%s: Removing %p: %lld %lld", __PRETTY_FUNCTION__,
			   item, slot, slot % wheel->slots);
	listnode_delete(wheel->wheel_slot_lists[slot % wheel->slots], item);

	return 0;
}
