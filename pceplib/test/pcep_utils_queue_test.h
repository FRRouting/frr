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

#ifndef PCEP_UTILS_QUEUE_TEST_H_
#define PCEP_UTILS_QUEUE_TEST_H_

void test_empty_queue(void);
void test_null_queue_handle(void);
void test_enqueue(void);
void test_enqueue_with_limit(void);
void test_dequeue(void);

#endif /* PCEPTIMERINTERNALS_H_ */
