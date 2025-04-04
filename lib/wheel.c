// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Timer Wheel
 * Copyright (C) 2016 Cumulus Networks, Inc.
 * Donald Sharp
 */
#include "zebra.h"
#include "linklist.h"
#include "frrevent.h"
#include "memory.h"
#include "wheel.h"
#include "log.h"

DEFINE_MTYPE_STATIC(LIB, TIMER_WHEEL, "Timer Wheel");
DEFINE_MTYPE_STATIC(LIB, TIMER_WHEEL_LIST, "Timer Wheel Slot List");

static int debug_timer_wheel = 0;

static void wheel_timer_thread(struct event *t);
static void wheel_stop(struct timer_wheel *wheel);
static void wheel_start(struct timer_wheel *wheel);

static void wheel_timer_thread(struct event *t)
{
	struct listnode *node, *nextnode;
	unsigned long long curr_slot;
	int slots_to_skip = 1;
	struct timer_wheel *wheel;
	void *data;

	wheel = EVENT_ARG(t);

	wheel->curr_slot += wheel->slots_to_skip;

	curr_slot = wheel->curr_slot % wheel->slots;

	if (debug_timer_wheel)
		zlog_debug("%s: Wheel Slot: %lld(%lld) count: %d", __func__,
			   wheel->curr_slot, curr_slot,
			   listcount(wheel->wheel_slot_lists[curr_slot]));

	for (ALL_LIST_ELEMENTS(wheel->wheel_slot_lists[curr_slot], node,
			       nextnode, data))
		(*wheel->slot_run)(data);

	while (list_isempty(wheel->wheel_slot_lists[(curr_slot + slots_to_skip)
						    % wheel->slots])
	       && (curr_slot + slots_to_skip) % wheel->slots != curr_slot)
		slots_to_skip++;

	wheel->slots_to_skip = slots_to_skip;
	if ((((curr_slot + slots_to_skip) % wheel->slots) == curr_slot) &&
	    list_isempty(wheel->wheel_slot_lists[curr_slot])) {
		/* Came to back to same slot and that is empty
		 * so the wheel is empty, stop it
		 */
		if (!wheel->run_forever) {
			wheel_stop(wheel);
			if (debug_timer_wheel)
				zlog_debug("Stopped an empty  wheel %p", wheel);

			return;
		}
	}

	event_add_timer_msec(wheel->master, wheel_timer_thread, wheel,
			     wheel->nexttime * slots_to_skip, &wheel->timer);
}

struct timer_wheel *wheel_init(struct event_loop *master, int period, size_t slots, int start_wait,
			       unsigned int (*slot_key)(const void *), void (*slot_run)(void *),
			       const char *run_name, bool run_forever)
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
	wheel->start_wait = start_wait;
	wheel->run_forever = run_forever;

	wheel->wheel_slot_lists = XCALLOC(MTYPE_TIMER_WHEEL_LIST,
					  slots * sizeof(struct list *));
	for (i = 0; i < slots; i++)
		wheel->wheel_slot_lists[i] = list_new();

	if (wheel->run_forever)
		wheel_start(wheel);

	return wheel;
}

void wheel_delete(struct timer_wheel *wheel)
{
	int i;

	for (i = 0; i < wheel->slots; i++) {
		list_delete(&wheel->wheel_slot_lists[i]);
	}

	EVENT_OFF(wheel->timer);
	XFREE(MTYPE_TIMER_WHEEL_LIST, wheel->wheel_slot_lists);
	XFREE(MTYPE_TIMER_WHEEL, wheel);
}

int wheel_add_item(struct timer_wheel *wheel, void *item)
{
	long long slot;

	slot = (*wheel->slot_key)(item);

	if (debug_timer_wheel)
		zlog_debug("%s: Inserting %p: %lld %lld", __func__, item, slot,
			   slot % wheel->slots);

	/* Performance cost, but no other way to block duplicate entries,
	 * alternate data structure/blanced tree can be explored later
	 */
	if (!listnode_lookup_nocheck(wheel->wheel_slot_lists[slot % wheel->slots], item))
		listnode_add(wheel->wheel_slot_lists[slot % wheel->slots], item);

	wheel_start(wheel);
	return 0;
}

int wheel_remove_item(struct timer_wheel *wheel, void *item)
{
	long long slot;

	slot = (*wheel->slot_key)(item);

	if (debug_timer_wheel)
		zlog_debug("%s: Removing %p: %lld %lld", __func__, item, slot,
			   slot % wheel->slots);
	listnode_delete(wheel->wheel_slot_lists[slot % wheel->slots], item);

	return 0;
}

static void wheel_stop(struct timer_wheel *wheel)
{
	EVENT_OFF(wheel->timer);
}

static void wheel_start(struct timer_wheel *wheel)
{
	int first_schedule_time = wheel->nexttime;

	if (wheel->start_wait)
		first_schedule_time = wheel->start_wait;

	if (!event_is_scheduled(wheel->timer)) {
		if (debug_timer_wheel)
			zlog_debug("started a wheel timer %p", wheel);

		event_add_timer_msec(wheel->master, wheel_timer_thread, wheel, first_schedule_time,
				     &wheel->timer);
	}
}
