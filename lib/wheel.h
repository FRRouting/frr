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
 * You should have received a copy of the GNU General Public License
 * along with this program; see the file COPYING; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301 USA
 */
#ifndef __WHEEL_H__
#define __WHEEL_H__

struct timer_wheel
{
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
  unsigned int (*slot_key) (void *);

  void (*slot_run) (void *);
};

struct timer_wheel *wheel_init (struct thread_master *master, int period, size_t slots,
				unsigned int (*slot_key) (void *),
				void (*slot_run) (void *));
void wheel_delete (struct timer_wheel *);

/*
 * Pause the Wheel from running
 */
int wheel_stop (struct timer_wheel *wheel);

/*
 * Start the wheel from running again
 */
int wheel_start (struct timer_wheel *wheel);

/*
 * Add item to a slot setup by the slot_key,
 * possibly change next time pop.
 */
int wheel_add_item (struct timer_wheel *wheel, void *item);

/*
 * Remove a item to a slot setup by the slot_key,
 * possibly change next time pop.
 */
int wheel_remove_item (struct timer_wheel *wheel, void *item);

#endif
