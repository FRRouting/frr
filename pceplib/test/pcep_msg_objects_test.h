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


#ifndef PCEP_MSG_OBJECTS_TEST_H_
#define PCEP_MSG_OBJECTS_TEST_H_

int pcep_objects_test_suite_setup(void);
int pcep_objects_test_suite_teardown(void);
void pcep_objects_test_setup(void);
void pcep_objects_test_teardown(void);
void test_pcep_obj_create_open(void);
void test_pcep_obj_create_open_with_tlvs(void);
void test_pcep_obj_create_rp(void);
void test_pcep_obj_create_nopath(void);
void test_pcep_obj_create_endpoint_ipv4(void);
void test_pcep_obj_create_endpoint_ipv6(void);
void test_pcep_obj_create_association_ipv4(void);
void test_pcep_obj_create_association_ipv6(void);
void test_pcep_obj_create_bandwidth(void);
void test_pcep_obj_create_metric(void);
void test_pcep_obj_create_lspa(void);
void test_pcep_obj_create_svec(void);
void test_pcep_obj_create_error(void);
void test_pcep_obj_create_close(void);
void test_pcep_obj_create_srp(void);
void test_pcep_obj_create_lsp(void);
void test_pcep_obj_create_vendor_info(void);
void test_pcep_obj_create_ero(void);
void test_pcep_obj_create_rro(void);
void test_pcep_obj_create_iro(void);
void test_pcep_obj_create_ro_subobj_ipv4(void);
void test_pcep_obj_create_ro_subobj_ipv6(void);
void test_pcep_obj_create_ro_subobj_unnum(void);
void test_pcep_obj_create_ro_subobj_32label(void);
void test_pcep_obj_create_ro_subobj_asn(void);
void test_pcep_obj_create_ro_subobj_sr_nonai(void);
void test_pcep_obj_create_ro_subobj_sr_ipv4_node(void);
void test_pcep_obj_create_ro_subobj_sr_ipv6_node(void);
void test_pcep_obj_create_ro_subobj_sr_ipv4_adj(void);
void test_pcep_obj_create_ro_subobj_sr_ipv6_adj(void);
void test_pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(void);
void test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(void);

#endif
