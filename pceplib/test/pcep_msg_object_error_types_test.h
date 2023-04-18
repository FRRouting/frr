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

#ifndef PCEP_MSG_OBJECT_ERROR_TYPES_TEST_
#define PCEP_MSG_OBJECT_ERROR_TYPES_TEST_

int pcep_object_error_types_test_suite_setup(void);
int pcep_object_error_types_test_suite_teardown(void);
void pcep_object_error_types_test_setup(void);
void pcep_object_error_types_test_teardown(void);
void test_get_error_type_str(void);
void test_get_error_value_str(void);

#endif /* PCEPTIMERINTERNALS_H_ */
