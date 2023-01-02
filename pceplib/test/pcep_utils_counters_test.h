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

#ifndef PCEP_UTILS_COUNTERS_TEST_H_
#define PCEP_UTILS_COUNTERS_TEST_H_

void test_create_counters_group(void);
void test_create_counters_subgroup(void);
void test_add_counters_subgroup(void);
void test_create_subgroup_counter(void);
void test_delete_counters_group(void);
void test_delete_counters_subgroup(void);
void test_reset_group_counters(void);
void test_reset_subgroup_counters(void);
void test_increment_counter(void);
void test_increment_subgroup_counter(void);
void test_dump_counters_group_to_log(void);
void test_dump_counters_subgroup_to_log(void);

#endif
