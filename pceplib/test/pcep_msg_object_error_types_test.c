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


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>

#include <CUnit/CUnit.h>

#include "pcep_msg_object_error_types.h"
#include "pcep_msg_object_error_types_test.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

int pcep_object_error_types_test_suite_setup(void)
{
	pceplib_memory_reset();
	set_logging_level(LOG_DEBUG);
	return 0;
}

int pcep_object_error_types_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

void pcep_object_error_types_test_setup(void)
{
}

void pcep_object_error_types_test_teardown(void)
{
}

void test_get_error_type_str()
{
	const char *error_type_str;
	int i = 0;
	for (; i < MAX_ERROR_TYPE; i++) {
		error_type_str = get_error_type_str(i);
		CU_ASSERT_PTR_NOT_NULL(error_type_str);
	}

	CU_ASSERT_PTR_NULL(get_error_type_str(-1));
	CU_ASSERT_PTR_NULL(get_error_type_str(MAX_ERROR_TYPE));
}

void test_get_error_value_str()
{
	const char *error_value_str;
	int i = 0, j = 0;

	for (; i < MAX_ERROR_TYPE; i++) {
		for (; j < MAX_ERROR_VALUE; j++) {
			error_value_str = get_error_value_str(i, j);
			CU_ASSERT_PTR_NOT_NULL(error_value_str);
		}
	}

	CU_ASSERT_PTR_NULL(get_error_value_str(-1, 0));
	CU_ASSERT_PTR_NULL(get_error_value_str(MAX_ERROR_TYPE, 0));
	CU_ASSERT_PTR_NULL(get_error_value_str(1, -1));
	CU_ASSERT_PTR_NULL(get_error_value_str(1, MAX_ERROR_VALUE));
}
