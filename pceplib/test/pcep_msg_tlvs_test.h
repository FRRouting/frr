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
