// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Javier Garcia <javier.garcia@voltanet.io>
 *
 */

#ifndef PCEP_MSG_TLVS_TEST_H_
#define PCEP_MSG_TLVS_TEST_H_

int pcep_tlvs_test_suite_setup(void);
int pcep_tlvs_test_suite_teardown(void);
void pcep_tlvs_test_setup(void);
void pcep_tlvs_test_teardown(void);
void test_pcep_tlv_create_stateful_pce_capability(void);
void test_pcep_tlv_create_speaker_entity_id(void);
void test_pcep_tlv_create_lsp_db_version(void);
void test_pcep_tlv_create_path_setup_type(void);
void test_pcep_tlv_create_path_setup_type_capability(void);
void test_pcep_tlv_create_sr_pce_capability(void);
void test_pcep_tlv_create_symbolic_path_name(void);
void test_pcep_tlv_create_ipv4_lsp_identifiers(void);
void test_pcep_tlv_create_ipv6_lsp_identifiers(void);
void test_pcep_tlv_create_lsp_error_code(void);
void test_pcep_tlv_create_rsvp_ipv4_error_spec(void);
void test_pcep_tlv_create_rsvp_ipv6_error_spec(void);
void test_pcep_tlv_create_srpag_pol_id_ipv4(void);
void test_pcep_tlv_create_srpag_pol_id_ipv6(void);
void test_pcep_tlv_create_srpag_pol_name(void);
void test_pcep_tlv_create_srpag_cp_id(void);
void test_pcep_tlv_create_srpag_cp_pref(void);
void test_pcep_tlv_create_nopath_vector(void);
void test_pcep_tlv_create_arbitrary(void);


#endif
