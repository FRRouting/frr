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

#ifndef PCEP_TIMERS_TEST_H_
#define PCEP_TIMERS_TEST_H_

void pcep_timers_test_teardown(void);
void test_double_initialization(void);
void test_initialization_null_callback(void);
void test_not_initialized(void);
void test_create_timer(void);
void test_cancel_timer(void);
void test_cancel_timer_invalid(void);
void test_reset_timer(void);
void test_reset_timer_invalid(void);

#endif /* PCEPTIMERINTERNALS_H_ */
