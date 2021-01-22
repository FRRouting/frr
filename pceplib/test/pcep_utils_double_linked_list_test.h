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

#ifndef PCEP_UTILS_DOUBLE_LINKED_LIST_TEST_H_
#define PCEP_UTILS_DOUBLE_LINKED_LIST_TEST_H_

void test_empty_dl_list(void);
void test_null_dl_list_handle(void);
void test_dll_prepend_data(void);
void test_dll_append_data(void);
void test_dll_delete_first_node(void);
void test_dll_delete_last_node(void);
void test_dll_delete_node(void);

#endif /* PCEPTIMERINTERNALS_H_ */
