/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


/*
 *  Implementation of public API timer functions.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <limits.h>
#include <pthread.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "pcep_timers.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"
#include "pcep_utils_ordered_list.h"

static pcep_timers_context *timers_context_ = NULL;
static int timer_id_ = 0;


/* simple compare method callback used by pcep_utils_ordered_list
 * for ordered list insertion. */
int timer_list_node_compare(void *list_entry, void *new_entry)
{
	/* return:
	 *   < 0  if new_entry < list_entry
	 *   == 0 if new_entry == list_entry (new_entry will be inserted after
	 * list_entry) > 0  if new_entry > list_entry */
	return ((pcep_timer *)new_entry)->expire_time
	       - ((pcep_timer *)list_entry)->expire_time;
}


/* simple compare method callback used by pcep_utils_ordered_list
 * ordered_list_remove_first_node_equals2 to remove a timer based on
 * its timer_id. */
int timer_list_node_timer_id_compare(void *list_entry, void *new_entry)
{
	return ((pcep_timer *)new_entry)->timer_id
	       - ((pcep_timer *)list_entry)->timer_id;
}

/* simple compare method callback used by pcep_utils_ordered_list
 * ordered_list_remove_first_node_equals2 to remove a timer based on
 * its address. */
int timer_list_node_timer_ptr_compare(void *list_entry, void *new_entry)
{
	return ((char *)new_entry - (char *)list_entry);
}

/* internal util method */
static pcep_timers_context *create_timers_context_(void)
{
	if (timers_context_ == NULL) {
		timers_context_ = pceplib_malloc(PCEPLIB_INFRA,
						 sizeof(pcep_timers_context));
		memset(timers_context_, 0, sizeof(pcep_timers_context));
		timers_context_->active = false;
	}

	return timers_context_;
}


/* Internal util function */
static bool initialize_timers_common(timer_expire_handler expire_handler)
{
	if (expire_handler == NULL) {
		/* Cannot have a NULL handler function */
		return false;
	}

	timers_context_ = create_timers_context_();

	if (timers_context_->active == true) {
		/* already initialized */
		return false;
	}

	timers_context_->active = true;
	timers_context_->timer_list =
		ordered_list_initialize(timer_list_node_compare);
	timers_context_->expire_handler = expire_handler;

	if (pthread_mutex_init(&(timers_context_->timer_list_lock), NULL)
	    != 0) {
		pcep_log(
			LOG_ERR,
			"%s: ERROR initializing timers, cannot initialize the mutex",
			__func__);
		return false;
	}

	return true;
}

bool initialize_timers(timer_expire_handler expire_handler)
{
	if (initialize_timers_common(expire_handler) == false) {
		return false;
	}

	if (pthread_create(&(timers_context_->event_loop_thread), NULL,
			   event_loop, timers_context_)) {
		pcep_log(
			LOG_ERR,
			"%s: ERROR initializing timers, cannot initialize the thread",
			__func__);
		return false;
	}

	return true;
}

bool initialize_timers_external_infra(
	timer_expire_handler expire_handler, void *external_timer_infra_data,
	ext_timer_create timer_create_func, ext_timer_cancel timer_cancel_func,
	ext_pthread_create_callback thread_create_func)
{
	if (initialize_timers_common(expire_handler) == false) {
		return false;
	}

	if (thread_create_func != NULL) {
		if (thread_create_func(&(timers_context_->event_loop_thread),
				       NULL, event_loop, timers_context_,
				       "pceplib_timers")) {
			pcep_log(
				LOG_ERR,
				"%s: Cannot initialize external timers thread.",
				__func__);
			return false;
		}
	} else {
		if (pthread_create(&(timers_context_->event_loop_thread), NULL,
				   event_loop, timers_context_)) {
			pcep_log(
				LOG_ERR,
				"%s: ERROR initializing timers, cannot initialize the thread",
				__func__);
			return false;
		}
	}

	timers_context_->external_timer_infra_data = external_timer_infra_data;
	timers_context_->timer_create_func = timer_create_func;
	timers_context_->timer_cancel_func = timer_cancel_func;

	return true;
}

/*
 * This function is only used to tear_down the timer data.
 * Only the timer data is deleted, not the list itself,
 * which is deleted by ordered_list_destroy().
 */
void free_all_timers(pcep_timers_context *timers_context)
{
	pthread_mutex_lock(&timers_context->timer_list_lock);

	ordered_list_node *timer_node = timers_context->timer_list->head;

	while (timer_node != NULL) {
		if (timer_node->data != NULL) {
			pceplib_free(PCEPLIB_INFRA, timer_node->data);
		}
		timer_node = timer_node->next_node;
	}

	pthread_mutex_unlock(&timers_context->timer_list_lock);
}


bool teardown_timers(void)
{
	if (timers_context_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: Trying to teardown the timers, but they are not initialized",
			__func__);
		return false;
	}

	if (timers_context_->active == false) {
		pcep_log(
			LOG_WARNING,
			"%s: Trying to teardown the timers, but they are not active",
			__func__);
		return false;
	}

	timers_context_->active = false;
	if (timers_context_->event_loop_thread != 0) {
		/* TODO this does not build
		 * Instead of calling pthread_join() which could block if the
		thread
		 * is blocked, try joining for at most 1 second.
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_sec += 1;
		int retval =
		pthread_timedjoin_np(timers_context_->event_loop_thread, NULL,
		&ts); if (retval != 0)
		{
		    pcep_log(LOG_WARNING, "%s: thread did not stop after 1
		second waiting on it.", __func__);
		}
		*/
		pthread_join(timers_context_->event_loop_thread, NULL);
	}

	free_all_timers(timers_context_);
	ordered_list_destroy(timers_context_->timer_list);

	if (pthread_mutex_destroy(&(timers_context_->timer_list_lock)) != 0) {
		pcep_log(
			LOG_WARNING,
			"%s: Trying to teardown the timers, cannot destroy the mutex",
			__func__);
	}

	pceplib_free(PCEPLIB_INFRA, timers_context_);
	timers_context_ = NULL;

	return true;
}


int get_next_timer_id(void)
{
	if (timer_id_ == INT_MAX) {
		timer_id_ = 0;
	}

	return timer_id_++;
}

int create_timer(uint16_t sleep_seconds, void *data)
{
	if (timers_context_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: Trying to create a timer: the timers have not been initialized",
			__func__);
		return -1;
	}

	pcep_timer *timer = pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_timer));
	memset(timer, 0, sizeof(pcep_timer));
	timer->data = data;
	timer->sleep_seconds = sleep_seconds;
	timer->expire_time = time(NULL) + sleep_seconds;

	pthread_mutex_lock(&timers_context_->timer_list_lock);
	timer->timer_id = get_next_timer_id();

	/* implemented in pcep_utils_ordered_list.c */
	if (ordered_list_add_node(timers_context_->timer_list, timer) == NULL) {
		pceplib_free(PCEPLIB_INFRA, timer);
		pthread_mutex_unlock(&timers_context_->timer_list_lock);
		pcep_log(
			LOG_WARNING,
			"%s: Trying to create a timer, cannot add the timer to the timer list",
			__func__);

		return -1;
	}

	pthread_mutex_unlock(&timers_context_->timer_list_lock);

	if (timers_context_->timer_create_func) {
		timers_context_->timer_create_func(
			timers_context_->external_timer_infra_data,
			&timer->external_timer, sleep_seconds, timer);
	}

	return timer->timer_id;
}


bool cancel_timer(int timer_id)
{
	static pcep_timer compare_timer;

	if (timers_context_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: Trying to cancel a timer: the timers have not been initialized",
			__func__);
		return false;
	}

	pthread_mutex_lock(&timers_context_->timer_list_lock);

	compare_timer.timer_id = timer_id;
	pcep_timer *timer_toRemove = ordered_list_remove_first_node_equals2(
		timers_context_->timer_list, &compare_timer,
		timer_list_node_timer_id_compare);
	if (timer_toRemove == NULL) {
		pthread_mutex_unlock(&timers_context_->timer_list_lock);
		pcep_log(
			LOG_WARNING,
			"%s: Trying to cancel a timer [%d] that does not exist",
			__func__, timer_id);
		return false;
	}

	pthread_mutex_unlock(&timers_context_->timer_list_lock);

	if (timers_context_->timer_cancel_func) {
		timers_context_->timer_cancel_func(
			&timer_toRemove->external_timer);
	}

	pceplib_free(PCEPLIB_INFRA, timer_toRemove);

	return true;
}


bool reset_timer(int timer_id)
{
	static pcep_timer compare_timer;

	if (timers_context_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: Trying to reset a timer: the timers have not been initialized",
			__func__);

		return false;
	}

	pthread_mutex_lock(&timers_context_->timer_list_lock);

	compare_timer.timer_id = timer_id;
	ordered_list_node *timer_to_reset_node =
		ordered_list_find2(timers_context_->timer_list, &compare_timer,
				   timer_list_node_timer_id_compare);
	if (timer_to_reset_node == NULL) {
		pthread_mutex_unlock(&timers_context_->timer_list_lock);
		pcep_log(LOG_WARNING,
			 "%s: Trying to reset a timer node that does not exist",
			 __func__);

		return false;
	}

	pcep_timer *timer_to_reset = timer_to_reset_node->data;
	if (timer_to_reset == NULL) {
		pthread_mutex_unlock(&timers_context_->timer_list_lock);
		pcep_log(LOG_WARNING,
			 "%s: Trying to reset a timer that does not exist",
			 __func__);

		return false;
	}

	/* First check if the timer to reset already has the same expire time,
	 * which means multiple reset_timer() calls were made on the same timer
	 * in the same second */
	time_t expire_time = time(NULL) + timer_to_reset->sleep_seconds;
	if (timer_to_reset->expire_time == expire_time) {
		pthread_mutex_unlock(&timers_context_->timer_list_lock);
		return true;
	}

	ordered_list_remove_node2(timers_context_->timer_list,
				  timer_to_reset_node);

	timer_to_reset->expire_time = expire_time;
	if (ordered_list_add_node(timers_context_->timer_list, timer_to_reset)
	    == NULL) {
		pceplib_free(PCEPLIB_INFRA, timer_to_reset);
		pthread_mutex_unlock(&timers_context_->timer_list_lock);
		pcep_log(
			LOG_WARNING,
			"%s: Trying to reset a timer, cannot add the timer to the timer list",
			__func__);

		return false;
	}

	pthread_mutex_unlock(&timers_context_->timer_list_lock);

	if (timers_context_->timer_cancel_func) {
		/* Keeping this log for now, since in older versions of FRR the
		 * timer cancellation was blocking. This allows us to see how
		 * long the it takes.*/
		pcep_log(LOG_DEBUG, "%s: Resetting timer [%d] with callback",
			 __func__, timer_to_reset->timer_id);
		timers_context_->timer_cancel_func(
			&timer_to_reset->external_timer);
		timer_to_reset->external_timer = NULL;
	}

	if (timers_context_->timer_create_func) {
		timers_context_->timer_create_func(
			timers_context_->external_timer_infra_data,
			&timer_to_reset->external_timer,
			timer_to_reset->sleep_seconds, timer_to_reset);
		/* Keeping this log for now, since in older versions of FRR the
		 * timer cancellation was blocking. This allows us to see how
		 * long the it takes.*/
		pcep_log(LOG_DEBUG, "%s: Reset timer [%d] with callback",
			 __func__, timer_to_reset->timer_id);
	}

	return true;
}


void pceplib_external_timer_expire_handler(void *data)
{
	if (timers_context_ == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: External timer expired but timers_context is not initialized",
			__func__);
		return;
	}

	if (timers_context_->expire_handler == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: External timer expired but expire_handler is not initialized",
			__func__);
		return;
	}

	if (data == NULL) {
		pcep_log(LOG_WARNING,
			 "%s: External timer expired with NULL data", __func__);
		return;
	}

	pcep_timer *timer = (pcep_timer *)data;

	pthread_mutex_lock(&timers_context_->timer_list_lock);
	ordered_list_node *timer_node =
		ordered_list_find2(timers_context_->timer_list, timer,
				   timer_list_node_timer_ptr_compare);

	/* Remove timer from list */
	if (timer_node)
		ordered_list_remove_node2(timers_context_->timer_list,
					  timer_node);

	pthread_mutex_unlock(&timers_context_->timer_list_lock);

	/* Cannot continue if the timer does not exist */
	if (timer_node == NULL) {
		pcep_log(
			LOG_WARNING,
			"%s: pceplib_external_timer_expire_handler timer [%p] id [%d] does not exist",
			__func__, timer, timer->timer_id);
		return;
	}

	timers_context_->expire_handler(timer->data, timer->timer_id);

	pceplib_free(PCEPLIB_INFRA, timer);
}
