// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 * Public API for pcep_timers
 */

#ifndef PCEPTIMERS_H_
#define PCEPTIMERS_H_

#include <pthread.h>
#include <stdbool.h>

#include "pcep_timer_internals.h"

#define TIMER_ID_NOT_SET -1

/*
 * Initialize the timers module.
 * The timer_expire_handler function pointer will be called each time a timer
 * expires. Return true for successful initialization, false otherwise.
 */
bool initialize_timers(timer_expire_handler expire_handler);

/*
 * Initialize the timers module with an external back-end infrastructure, like
 * FRR.
 */
bool initialize_timers_external_infra(
	timer_expire_handler expire_handler, void *external_timer_infra_data,
	ext_timer_create timer_create_func, ext_timer_cancel timer_cancel_func,
	ext_pthread_create_callback thread_create_func);

/*
 * Teardown the timers module.
 */
bool teardown_timers(void);

/*
 * Create a new timer for "sleep_seconds" seconds.
 * If the timer expires before being cancelled, the timer_expire_handler
 * passed to initialize_timers() will be called with the pointer to "data".
 * Returns a timer_id <= 0 that can be used to cancel_timer.
 * Returns < 0 on error.
 */
int create_timer(uint16_t sleep_seconds, void *data);

/*
 * Cancel a timer created with create_timer().
 * Returns true if the timer was found and cancelled, false otherwise.
 */
bool cancel_timer(int timer_id);

/*
 * Reset an previously created timer, maintaining the same timer_id.
 * Returns true if the timer was found and reset, false otherwise.
 */
bool reset_timer(int timer_id);

/*
 * If an external timer infra like FRR is used, then this function
 * will be called when the timers expire in the external infra.
 */
void pceplib_external_timer_expire_handler(void *data);

int timer_list_node_compare(void *list_entry, void *new_entry);
int timer_list_node_timer_id_compare(void *list_entry, void *new_entry);
int timer_list_node_timer_ptr_compare(void *list_entry, void *new_entry);
void free_all_timers(pcep_timers_context *timers_context);
int get_next_timer_id(void);

#endif /* PCEPTIMERS_H_ */
