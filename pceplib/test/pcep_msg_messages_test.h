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
