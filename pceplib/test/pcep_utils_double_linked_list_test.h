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
