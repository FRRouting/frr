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
