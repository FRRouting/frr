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

#ifndef PCEP_MSG_TOOLS_TEST_H_
#define PCEP_MSG_TOOLS_TEST_H_


int pcep_tools_test_suite_setup(void);
int pcep_tools_test_suite_teardown(void);
void pcep_tools_test_setup(void);
void pcep_tools_test_teardown(void);
void test_pcep_msg_read_pcep_initiate(void);
void test_pcep_msg_read_pcep_initiate2(void);
void test_pcep_msg_read_pcep_update(void);
void test_pcep_msg_read_pcep_open(void);
void test_pcep_msg_read_pcep_open_initiate(void);
void test_validate_message_header(void);
void test_validate_message_objects(void);
void test_validate_message_objects_invalid(void);
void test_pcep_msg_read_pcep_open_cisco_pce(void);
void test_pcep_msg_read_pcep_update_cisco_pce(void);
void test_pcep_msg_read_pcep_report_cisco_pcc(void);
void test_pcep_msg_read_pcep_initiate_cisco_pcc(void);

#endif /* PCEPTIMERINTERNALS_H_ */
