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
 *  Timer definitions to be used internally by the pcep_timers library.
 */

#ifndef PCEPTIMERINTERNALS_H_
#define PCEPTIMERINTERNALS_H_

#include <stdint.h>
#include <pthread.h>

#include "pcep_utils_ordered_list.h"

/* Function pointer to be called when timers expire.
 * Parameters:
 *    void *data - passed into create_timer
 *    int timer_id - the timer_id returned by create_timer
 */
typedef void (*timer_expire_handler)(void *, int);

/* Function pointer when an external timer infrastructure is used */
typedef void (*ext_timer_create)(void *infra_data, void **timer, int seconds,
				 void *data);
typedef void (*ext_timer_cancel)(void **timer);
typedef int (*ext_pthread_create_callback)(pthread_t *pthread_id,
					   const pthread_attr_t *attr,
					   void *(*start_routine)(void *),
					   void *data, const char *thread_name);

typedef struct pcep_timer_ {
	time_t expire_time;
	uint16_t sleep_seconds;
	int timer_id;
	void *data;
	void *external_timer;

} pcep_timer;

typedef struct pcep_timers_context_ {
	ordered_list_handle *timer_list;
	bool active;
	timer_expire_handler expire_handler;
	pthread_t event_loop_thread;
	pthread_mutex_t timer_list_lock;
	void *external_timer_infra_data;
	ext_timer_create timer_create_func;
	ext_timer_cancel timer_cancel_func;

} pcep_timers_context;

/* functions implemented in pcep_timers_loop.c */
void *event_loop(void *context);


#endif /* PCEPTIMERINTERNALS_H_ */
