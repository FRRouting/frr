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

#ifndef PCEP_UTILS_ORDERED_LIST_TEST_H_
#define PCEP_UTILS_ORDERED_LIST_TEST_H_

void test_empty_list(void);
void test_null_list_handle(void);
void test_add_to_list(void);
void test_find(void);
void test_remove_first_node(void);
void test_remove_first_node_equals(void);
void test_remove_node(void);
int node_data_compare(void *list_entry, void *new_entry);

#endif /* PCEPTIMERINTERNALS_H_ */
