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

#ifndef PCEP_PCC_API_TEST_
#define PCEP_PCC_API_TEST_

int pcep_pcc_api_test_suite_setup(void);
int pcep_pcc_api_test_suite_teardown(void);
void pcep_pcc_api_test_setup(void);
void pcep_pcc_api_test_teardown(void);
void test_initialize_pcc(void);
void test_connect_pce(void);
void test_connect_pce_ipv6(void);
void test_connect_pce_with_src_ip(void);
void test_disconnect_pce(void);
void test_send_message(void);
void test_event_queue(void);
void test_get_event_type_str(void);

#endif /* PCEPTIMERINTERNALS_H_ */
