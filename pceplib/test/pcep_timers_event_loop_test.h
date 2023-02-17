// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Javier Garcia <javier.garcia@voltanet.io>
 *
 */

/*
 *  Timer definitions to be used internally by the pcep_timers library.
 */

#ifndef PCEP_TIMERS_EVENT_LOOP_TEST_H_
#define PCEP_TIMERS_EVENT_LOOP_TEST_H_

void pcep_timers_event_loop_test_setup(void);
void pcep_timers_event_loop_test_teardown(void);
void test_walk_and_process_timers_no_timers(void);
void test_walk_and_process_timers_timer_not_expired(void);
void test_walk_and_process_timers_timer_expired(void);
void test_event_loop_null_handle(void);
void test_event_loop_not_active(void);

#endif /* PCEPTIMERINTERNALS_H_ */
