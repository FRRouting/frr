// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep_timers.h"
#include "pcep_utils_memory.h"
#include "pcep_timers_event_loop.h"
#include "pcep_timers_event_loop_test.h"


typedef struct timer_expire_handler_info_ {
	bool handler_called;
	void *data;
	int timerId;

} timer_expire_handler_info;

static pcep_timers_context *test_timers_context = NULL;
static timer_expire_handler_info expire_handler_info;
#define TEST_EVENT_LOOP_TIMER_ID 500


/* Called when a timer expires */
static void test_timer_expire_handler(void *data, int timerId)
{
	expire_handler_info.handler_called = true;
	expire_handler_info.data = data;
	expire_handler_info.timerId = timerId;
}


/* Test case setup called before each test.
 * Declared in pcep_timers_tests.c */
void pcep_timers_event_loop_test_setup()
{
	test_timers_context =
		pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_timers_context));
	memset(test_timers_context, 0, sizeof(pcep_timers_context));
	if (pthread_mutex_init(&(test_timers_context->timer_list_lock), NULL)
	    != 0) {
		fprintf(stderr,
			"ERROR initializing timers, cannot initialize the mutex\n");
	}
	test_timers_context->active = false;
	test_timers_context->expire_handler = test_timer_expire_handler;
	test_timers_context->timer_list =
		ordered_list_initialize(timer_list_node_timer_id_compare);

	expire_handler_info.handler_called = false;
	expire_handler_info.data = NULL;
	expire_handler_info.timerId = -1;
}


/* Test case teardown called after each test.
 * Declared in pcep_timers_tests.c */
void pcep_timers_event_loop_test_teardown()
{
	pthread_mutex_unlock(&test_timers_context->timer_list_lock);
	pthread_mutex_destroy(&(test_timers_context->timer_list_lock));
	ordered_list_destroy(test_timers_context->timer_list);
	pceplib_free(PCEPLIB_INFRA, test_timers_context);
	test_timers_context = NULL;
}


/*
 * Test functions
 */

void test_walk_and_process_timers_no_timers()
{
	CU_ASSERT_EQUAL(test_timers_context->timer_list->num_entries, 0);
	CU_ASSERT_PTR_NULL(test_timers_context->timer_list->head);

	walk_and_process_timers(test_timers_context);

	CU_ASSERT_FALSE(expire_handler_info.handler_called);
	CU_ASSERT_EQUAL(test_timers_context->timer_list->num_entries, 0);
	CU_ASSERT_PTR_NULL(test_timers_context->timer_list->head);
}


void test_walk_and_process_timers_timer_not_expired()
{
	pcep_timer timer;
	timer.data = &timer;
	// Set the timer to expire 100 seconds from now
	timer.expire_time = time(NULL) + 100;
	timer.timer_id = TEST_EVENT_LOOP_TIMER_ID;
	ordered_list_add_node(test_timers_context->timer_list, &timer);

	walk_and_process_timers(test_timers_context);

	/* The timer should still be in the list, since it hasnt expired yet */
	CU_ASSERT_FALSE(expire_handler_info.handler_called);
	CU_ASSERT_EQUAL(test_timers_context->timer_list->num_entries, 1);
	CU_ASSERT_PTR_NOT_NULL(test_timers_context->timer_list->head);
}


void test_walk_and_process_timers_timer_expired()
{
	/* We need to alloc it, since it will be free'd in
	 * walk_and_process_timers */
	pcep_timer *timer = pceplib_malloc(PCEPLIB_INFRA, sizeof(pcep_timer));
	timer->data = timer;
	// Set the timer to expire 10 seconds ago
	timer->expire_time = time(NULL) - 10;
	pthread_mutex_lock(&test_timers_context->timer_list_lock);
	timer->timer_id = TEST_EVENT_LOOP_TIMER_ID;
	pthread_mutex_unlock(&test_timers_context->timer_list_lock);
	ordered_list_add_node(test_timers_context->timer_list, timer);

	walk_and_process_timers(test_timers_context);

	/* Since the timer expired, the expire_handler should have been called
	 * and the timer should have been removed from the timer list */
	CU_ASSERT_TRUE(expire_handler_info.handler_called);
	CU_ASSERT_PTR_EQUAL(expire_handler_info.data, timer);
	CU_ASSERT_EQUAL(expire_handler_info.timerId, TEST_EVENT_LOOP_TIMER_ID);
	CU_ASSERT_EQUAL(test_timers_context->timer_list->num_entries, 0);
	CU_ASSERT_PTR_NULL(test_timers_context->timer_list->head);
}

void test_event_loop_null_handle()
{
	/* Verify that event_loop() correctly handles a NULL timers_context */
	event_loop(NULL);
}


void test_event_loop_not_active()
{
	/* Verify that event_loop() correctly handles an inactive timers_context
	 * flag */
	test_timers_context->active = false;
	event_loop(test_timers_context);
}
