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

#ifndef PCEP_MSG_MSG_TEST_H_
#define PCEP_MSG_MSG_TEST_H_

/* functions to be tested from pcep-messages.c */
int pcep_messages_test_suite_setup(void);
int pcep_messages_test_suite_teardown(void);
void pcep_messages_test_setup(void);
void pcep_messages_test_teardown(void);
void test_pcep_msg_create_open(void);
void test_pcep_msg_create_request(void);
void test_pcep_msg_create_request_svec(void);
void test_pcep_msg_create_reply_nopath(void);
void test_pcep_msg_create_reply(void);
void test_pcep_msg_create_close(void);
void test_pcep_msg_create_error(void);
void test_pcep_msg_create_keepalive(void);
void test_pcep_msg_create_report(void);
void test_pcep_msg_create_update(void);
void test_pcep_msg_create_initiate(void);
void test_pcep_msg_create_notify(void);

#endif /* PCEPTIMERINTERNALS_H_ */
