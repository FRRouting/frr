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

#ifndef PCEP_MSG_OBJECT_ERROR_TYPES_TEST_
#define PCEP_MSG_OBJECT_ERROR_TYPES_TEST_

int pcep_object_error_types_test_suite_setup(void);
int pcep_object_error_types_test_suite_teardown(void);
void pcep_object_error_types_test_setup(void);
void pcep_object_error_types_test_teardown(void);
void test_get_error_type_str(void);
void test_get_error_value_str(void);

#endif /* PCEPTIMERINTERNALS_H_ */
