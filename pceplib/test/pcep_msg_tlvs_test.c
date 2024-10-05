// SPDX-License-Identifier: LGPL-2.1-or-later
/*
 * This file is part of the PCEPlib, a PCEP protocol library.
 *
 * Copyright (C) 2020 Volta Networks https://voltanet.io/
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef __FreeBSD__
#include <sys/endian.h>
#else
#include <endian.h>
#endif /* __FreeBSD__ */
#include <assert.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep_msg_encoding.h"
#include "pcep_msg_objects.h"
#include "pcep_msg_tlvs.h"
#include "pcep_msg_tools.h"
#include "pcep_utils_memory.h"
#include "pcep_msg_tlvs_test.h"

/*
 * Notice:
 * All of these TLV Unit Tests encode the created TLVs by explicitly calling
 * pcep_encode_tlv() thus testing the TLV creation and the TLV encoding.
 * All APIs expect IPs to be in network byte order.
 */

static struct pcep_versioning *versioning = NULL;
static uint8_t tlv_buf[2000];

void reset_tlv_buffer(void);

int pcep_tlvs_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_tlvs_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

void reset_tlv_buffer(void)
{
	memset(tlv_buf, 0, 2000);
}

void pcep_tlvs_test_setup(void)
{
	versioning = create_default_pcep_versioning();
	reset_tlv_buffer();
}

void pcep_tlvs_test_teardown(void)
{
	destroy_pcep_versioning(versioning);
}

void test_pcep_tlv_create_stateful_pce_capability(void)
{
	struct pcep_object_tlv_stateful_pce_capability *tlv =
		pcep_tlv_create_stateful_pce_capability(true, true, true, true,
							true, true);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t));
	CU_ASSERT_TRUE(tlv->flag_u_lsp_update_capability);
	CU_ASSERT_TRUE(tlv->flag_s_include_db_version);
	CU_ASSERT_TRUE(tlv->flag_i_lsp_instantiation_capability);
	CU_ASSERT_TRUE(tlv->flag_t_triggered_resync);
	CU_ASSERT_TRUE(tlv->flag_d_delta_lsp_sync);
	CU_ASSERT_TRUE(tlv->flag_f_triggered_initial_sync);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[7], 0x3f);
	/* TODO add a new function: verify_tlv_header(tlv->header.encoded_tlv)
	 * to all tests */

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_speaker_entity_id(void)
{
	struct pcep_object_tlv_speaker_entity_identifier *tlv =
		pcep_tlv_create_speaker_entity_id(NULL);
	CU_ASSERT_PTR_NULL(tlv);

	double_linked_list *list = dll_initialize();
	tlv = pcep_tlv_create_speaker_entity_id(list);
	CU_ASSERT_PTR_NULL(tlv);
	if (tlv != NULL)
		pceplib_free(PCEPLIB_INFRA, tlv);

	uint32_t *speaker_entity =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*speaker_entity = 42;
	dll_append(list, speaker_entity);
	tlv = pcep_tlv_create_speaker_entity_id(list);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SPEAKER_ENTITY_ID);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t));
	CU_ASSERT_PTR_NOT_NULL(tlv->speaker_entity_id_list);
	assert(tlv->speaker_entity_id_list != NULL);
	CU_ASSERT_EQUAL(tlv->speaker_entity_id_list->num_entries, 1);
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(*speaker_entity));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_lsp_db_version(void)
{
	uint64_t lsp_db_version = 0xf005ba11ba5eba11;
	struct pcep_object_tlv_lsp_db_version *tlv =
		pcep_tlv_create_lsp_db_version(lsp_db_version);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_LSP_DB_VERSION);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint64_t));
	CU_ASSERT_EQUAL(tlv->lsp_db_version, lsp_db_version);
	CU_ASSERT_EQUAL(*((uint64_t *)(tlv->header.encoded_tlv + 4)),
			be64toh(lsp_db_version));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_path_setup_type(void)
{
	uint8_t pst = 0x89;

	struct pcep_object_tlv_path_setup_type *tlv =
		pcep_tlv_create_path_setup_type(pst);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);
	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t));
	CU_ASSERT_EQUAL(tlv->path_setup_type, pst);
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(0x000000FF & pst));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_path_setup_type_capability(void)
{
	/* The sub_tlv list is optional */

	/* Should return NULL if pst_list is NULL */
	struct pcep_object_tlv_path_setup_type_capability *tlv =
		pcep_tlv_create_path_setup_type_capability(NULL, NULL);
	CU_ASSERT_PTR_NULL(tlv);

	/* Should return NULL if pst_list is empty */
	double_linked_list *pst_list = dll_initialize();
	tlv = pcep_tlv_create_path_setup_type_capability(pst_list, NULL);
	CU_ASSERT_PTR_NULL(tlv);
	if (tlv != NULL)
		pcep_obj_free_tlv(&tlv->header);

	/* Should still return NULL if pst_list is NULL */
	double_linked_list *sub_tlv_list = dll_initialize();
	tlv = pcep_tlv_create_path_setup_type_capability(NULL, sub_tlv_list);
	CU_ASSERT_PTR_NULL(tlv);
	if (tlv != NULL)
		pcep_obj_free_tlv(&tlv->header);

	/* Should still return NULL if pst_list is empty */
	tlv = pcep_tlv_create_path_setup_type_capability(pst_list,
							 sub_tlv_list);
	CU_ASSERT_PTR_NULL(tlv);
	if (tlv != NULL)
		pcep_obj_free_tlv(&tlv->header);

	/* Test only populating the pst list */
	uint8_t *pst1 = pceplib_malloc(PCEPLIB_MESSAGES, 1);
	uint8_t *pst2 = pceplib_malloc(PCEPLIB_MESSAGES, 1);
	uint8_t *pst3 = pceplib_malloc(PCEPLIB_MESSAGES, 1);
	*pst1 = 1;
	*pst2 = 2;
	*pst3 = 3;
	dll_append(pst_list, pst1);
	dll_append(pst_list, pst2);
	dll_append(pst_list, pst3);
	tlv = pcep_tlv_create_path_setup_type_capability(pst_list,
							 sub_tlv_list);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	if (tlv == NULL) {
		CU_ASSERT_TRUE(tlv != NULL);
		return;
	}

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t) * 2);
	CU_ASSERT_PTR_NOT_NULL(tlv->pst_list);
	assert(tlv != NULL);
	CU_ASSERT_EQUAL(tlv->pst_list->num_entries, 3);
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(0x00000003));
	CU_ASSERT_EQUAL(uint32_ptr[2], htonl(0x01020300));
	pcep_obj_free_tlv(&tlv->header);

	/* Now test populating both the pst_list and the sub_tlv_list */
	reset_tlv_buffer();
	struct pcep_object_tlv_header *sub_tlv =
		(struct pcep_object_tlv_header *)
			pcep_tlv_create_sr_pce_capability(true, true, 0);
	pst_list = dll_initialize();
	sub_tlv_list = dll_initialize();
	pst1 = pceplib_malloc(PCEPLIB_MESSAGES, 1);
	*pst1 = 1;
	dll_append(pst_list, pst1);
	dll_append(sub_tlv_list, sub_tlv);
	tlv = pcep_tlv_create_path_setup_type_capability(pst_list,
							 sub_tlv_list);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length,
			sizeof(uint32_t) * 2 + TLV_HEADER_LENGTH
				+ sub_tlv->encoded_tlv_length);
	CU_ASSERT_PTR_NOT_NULL(tlv->pst_list);
	CU_ASSERT_PTR_NOT_NULL(tlv->sub_tlv_list);
	uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	uint16_t *uint16_ptr = (uint16_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint16_ptr[0],
			htons(PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE_CAPABILITY));
	CU_ASSERT_EQUAL(uint16_ptr[1], htons(tlv->header.encoded_tlv_length));
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(0x00000001));
	CU_ASSERT_EQUAL(uint32_ptr[2], htonl(0x01000000));
	/* Verify the Sub-TLV */
	uint16_ptr = (uint16_t *)(tlv->header.encoded_tlv + 12);
	CU_ASSERT_EQUAL(uint16_ptr[0],
			htons(PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY));
	CU_ASSERT_EQUAL(uint16_ptr[1], htons(4));
	CU_ASSERT_EQUAL(uint16_ptr[2], 0);
	CU_ASSERT_EQUAL(uint16_ptr[3], htons(0x0300));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_sr_pce_capability(void)
{
	struct pcep_object_tlv_sr_pce_capability *tlv =
		pcep_tlv_create_sr_pce_capability(true, true, 8);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t));
	uint16_t *uint16_ptr = (uint16_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint16_ptr[0],
			htons(PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY));
	CU_ASSERT_EQUAL(uint16_ptr[1], htons(tlv->header.encoded_tlv_length));
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(0x00000308));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_symbolic_path_name(void)
{
	/* char *symbolic_path_name, uint16_t symbolic_path_name_length); */
	char path_name[16] = "Some Path Name";
	uint16_t path_name_length = 14;
	struct pcep_object_tlv_symbolic_path_name *tlv =
		pcep_tlv_create_symbolic_path_name(path_name, path_name_length);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, path_name_length);
	/* Test the padding is correct */
	CU_ASSERT_EQUAL(0, strncmp((char *)&(tlv->header.encoded_tlv[4]),
				   &path_name[0], 4));
	CU_ASSERT_EQUAL(0, strncmp((char *)&(tlv->header.encoded_tlv[8]),
				   &path_name[4], 4));
	CU_ASSERT_EQUAL(0, strncmp((char *)&(tlv->header.encoded_tlv[12]),
				   &path_name[8], 4));
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[16], 'm');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[17], 'e');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[18], 0);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[19], 0);
	pcep_obj_free_tlv(&tlv->header);

	reset_tlv_buffer();
	tlv = pcep_tlv_create_symbolic_path_name(path_name, 3);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	printf("El tlv es %p", tlv);
	assert(tlv != NULL); // crash si FALSE
	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 3);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[4], 'S');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[5], 'o');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[6], 'm');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[7], 0);

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_ipv4_lsp_identifiers(void)
{
	struct in_addr sender_ip, endpoint_ip;
	uint16_t lsp_id = 7;
	uint16_t tunnel_id = 16;
	struct in_addr extended_tunnel_id;
	extended_tunnel_id.s_addr = 256;
	inet_pton(AF_INET, "192.168.1.1", &sender_ip);
	inet_pton(AF_INET, "192.168.1.2", &endpoint_ip);

	struct pcep_object_tlv_ipv4_lsp_identifier *tlv =
		pcep_tlv_create_ipv4_lsp_identifiers(NULL, &endpoint_ip, lsp_id,
						     tunnel_id,
						     &extended_tunnel_id);
	CU_ASSERT_PTR_NULL(tlv);

	tlv = pcep_tlv_create_ipv4_lsp_identifiers(
		&sender_ip, NULL, lsp_id, tunnel_id, &extended_tunnel_id);
	CU_ASSERT_PTR_NULL(tlv);

	tlv = pcep_tlv_create_ipv4_lsp_identifiers(
		NULL, NULL, lsp_id, tunnel_id, &extended_tunnel_id);
	CU_ASSERT_PTR_NULL(tlv);
	assert(tlv == NULL);

	tlv = pcep_tlv_create_ipv4_lsp_identifiers(&sender_ip, &endpoint_ip,
						   lsp_id, tunnel_id,
						   &extended_tunnel_id);
	CU_ASSERT_PTR_NOT_NULL(tlv);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t) * 4);
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], sender_ip.s_addr);
	CU_ASSERT_EQUAL(uint32_ptr[2],
			(uint32_t)(htons(tunnel_id) << 16) | htons(lsp_id));
	CU_ASSERT_EQUAL(uint32_ptr[3], extended_tunnel_id.s_addr);
	CU_ASSERT_EQUAL(uint32_ptr[4], endpoint_ip.s_addr);
	pcep_obj_free_tlv(&tlv->header);

	reset_tlv_buffer();
	tlv = pcep_tlv_create_ipv4_lsp_identifiers(&sender_ip, &endpoint_ip,
						   lsp_id, tunnel_id, NULL);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t) * 4);
	uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], sender_ip.s_addr);
	CU_ASSERT_EQUAL(uint32_ptr[2],
			(uint32_t)(htons(tunnel_id) << 16) | htons(lsp_id));
	CU_ASSERT_EQUAL(uint32_ptr[3], INADDR_ANY);
	CU_ASSERT_EQUAL(uint32_ptr[4], endpoint_ip.s_addr);
	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_ipv6_lsp_identifiers(void)
{
	struct in6_addr sender_ip, endpoint_ip;
	uint16_t lsp_id = 3;
	uint16_t tunnel_id = 16;
	uint32_t extended_tunnel_id[4];

	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &sender_ip);
	inet_pton(AF_INET6, "2001:db8::8a2e:370:8446", &endpoint_ip);
	extended_tunnel_id[0] = 1;
	extended_tunnel_id[1] = 2;
	extended_tunnel_id[2] = 3;
	extended_tunnel_id[3] = 4;

	struct pcep_object_tlv_ipv6_lsp_identifier *tlv =
		pcep_tlv_create_ipv6_lsp_identifiers(
			NULL, &endpoint_ip, lsp_id, tunnel_id,
			(struct in6_addr *)&extended_tunnel_id);
	CU_ASSERT_PTR_NULL(tlv);

	tlv = pcep_tlv_create_ipv6_lsp_identifiers(
		&sender_ip, NULL, lsp_id, tunnel_id,
		(struct in6_addr *)&extended_tunnel_id);
	CU_ASSERT_PTR_NULL(tlv);

	tlv = pcep_tlv_create_ipv6_lsp_identifiers(
		NULL, NULL, lsp_id, tunnel_id,
		(struct in6_addr *)&extended_tunnel_id);
	CU_ASSERT_PTR_NULL(tlv);
	assert(tlv == NULL);

	tlv = pcep_tlv_create_ipv6_lsp_identifiers(
		&sender_ip, &endpoint_ip, lsp_id, tunnel_id,
		(struct in6_addr *)&extended_tunnel_id);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			PCEP_OBJ_TLV_TYPE_IPV6_LSP_IDENTIFIERS);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 52);
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[5],
			(uint32_t)(htons(tunnel_id) << 16) | htons(lsp_id));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_srpag_pol_id_ipv4(void)
{
	uint32_t color = 1;
	struct in_addr src;
	inet_pton(AF_INET, "192.168.1.2", &src);

	struct pcep_object_tlv_srpag_pol_id *tlv =
		pcep_tlv_create_srpag_pol_id_ipv4(color, (void *)&src);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, (PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID));
	CU_ASSERT_EQUAL(
		tlv->header.encoded_tlv_length,
		(8 /*draft-barth-pce-segment-routing-policy-cp-04#5.1*/));
	CU_ASSERT_EQUAL(tlv->color, (color));
	uint32_t aux_color = htonl(color); // Is color right encoded
	CU_ASSERT_EQUAL(0, memcmp(&tlv_buf[0] + TLV_HEADER_LENGTH, &aux_color,
				  sizeof(color)));
	CU_ASSERT_EQUAL(tlv->end_point.ipv4.s_addr, (src.s_addr));
	// Are simetrical?
	struct pcep_object_tlv_header *dec_hdr = pcep_decode_tlv(tlv_buf);
	struct pcep_object_tlv_srpag_pol_id *dec_tlv =
		(struct pcep_object_tlv_srpag_pol_id *)dec_hdr;
	CU_ASSERT_EQUAL(tlv->color, dec_tlv->color);

	pceplib_free(PCEPLIB_MESSAGES, dec_hdr);
	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_srpag_pol_id_ipv6(void)
{

	uint32_t color = 1;
	struct in6_addr src;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &src);

	struct pcep_object_tlv_srpag_pol_id *tlv =
		pcep_tlv_create_srpag_pol_id_ipv6(color, &src);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, (PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_ID));
	CU_ASSERT_EQUAL(
		tlv->header.encoded_tlv_length,
		(20 /*draft-barth-pce-segment-routing-policy-cp-04#5.1*/));
	CU_ASSERT_EQUAL(tlv->color, (color));
	CU_ASSERT_EQUAL(0, memcmp(&tlv->end_point.ipv6, &src, sizeof(src)));

	uint32_t aux_color = htonl(color);
	CU_ASSERT_EQUAL(0, memcmp(&aux_color, tlv_buf + TLV_HEADER_LENGTH,
				  sizeof(tlv->color)));
	// Are simetrical?
	struct pcep_object_tlv_header *dec_hdr = pcep_decode_tlv(tlv_buf);
	struct pcep_object_tlv_srpag_pol_id *dec_tlv =
		(struct pcep_object_tlv_srpag_pol_id *)dec_hdr;
	CU_ASSERT_EQUAL(tlv->color, dec_tlv->color);

	pceplib_free(PCEPLIB_MESSAGES, dec_hdr);
	pcep_obj_free_tlv(&tlv->header);
}
void test_pcep_tlv_create_srpag_pol_name(void)
{
	const char *pol_name = "Some Pol  Name";

	struct pcep_object_tlv_srpag_pol_name *tlv =
		pcep_tlv_create_srpag_pol_name(pol_name, strlen(pol_name));
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			(PCEP_OBJ_TLV_TYPE_SRPOLICY_POL_NAME));
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length,
			(normalize_pcep_tlv_length(strlen(pol_name))));
	CU_ASSERT_EQUAL(0, strcmp(pol_name, (char *)tlv->name));


	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_srpag_cp_id(void)
{
	// draft-ietf-spring-segment-routing-policy-06.pdf#2.3
	// 10 PCEP, 20 BGP SR Policy, 30 Via Configuration
	uint8_t proto_origin = 10;
	uint32_t ASN = 0;
	struct in6_addr with_mapped_ipv4;
	inet_pton(AF_INET6, "::ffff:192.0.2.128", &with_mapped_ipv4);
	uint32_t discriminator = 0;

	struct pcep_object_tlv_srpag_cp_id *tlv = pcep_tlv_create_srpag_cp_id(
		proto_origin, ASN, &with_mapped_ipv4, discriminator);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			(PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_ID));
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length,
			(sizeof(proto_origin) + sizeof(ASN)
			 + sizeof(with_mapped_ipv4) + sizeof(discriminator)));
	CU_ASSERT_EQUAL(tlv->proto, (proto_origin));
	CU_ASSERT_EQUAL(tlv->orig_asn, (ASN));
	CU_ASSERT_EQUAL(0, memcmp(&tlv->orig_addres, &with_mapped_ipv4,
				  sizeof(with_mapped_ipv4)));
	CU_ASSERT_EQUAL(tlv->discriminator, (discriminator));
	// Are simetrical?
	struct pcep_object_tlv_header *dec_hdr = pcep_decode_tlv(tlv_buf);
	struct pcep_object_tlv_srpag_cp_id *dec_tlv =
		(struct pcep_object_tlv_srpag_cp_id *)dec_hdr;
	CU_ASSERT_EQUAL(tlv->proto, dec_tlv->proto);

	pceplib_free(PCEPLIB_MESSAGES, dec_hdr);
	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_srpag_cp_pref(void)
{
	uint32_t preference_default = 100;

	struct pcep_object_tlv_srpag_cp_pref *tlv =
		pcep_tlv_create_srpag_cp_pref(preference_default);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type,
			(PCEP_OBJ_TLV_TYPE_SRPOLICY_CPATH_PREFERENCE));
	printf(" encoded length vs sizeof pref (%d) vs (%ld)\n",
	       tlv->header.encoded_tlv_length, sizeof(preference_default));
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length,
			sizeof(preference_default));
	CU_ASSERT_EQUAL(tlv->preference, (preference_default));
	uint32_t aux_pref = htonl(preference_default); // Is pref right encoded
	CU_ASSERT_EQUAL(0, memcmp(tlv_buf + TLV_HEADER_LENGTH, &aux_pref,
				  sizeof(preference_default)));
	// Are simetrical?
	struct pcep_object_tlv_header *dec_hdr = pcep_decode_tlv(tlv_buf);
	struct pcep_object_tlv_srpag_cp_pref *dec_tlv =
		(struct pcep_object_tlv_srpag_cp_pref *)dec_hdr;
	CU_ASSERT_EQUAL(tlv->preference, dec_tlv->preference);

	pceplib_free(PCEPLIB_MESSAGES, dec_hdr);
	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_lsp_error_code(void)
{
	struct pcep_object_tlv_lsp_error_code *tlv =
		pcep_tlv_create_lsp_error_code(
			PCEP_TLV_LSP_ERROR_CODE_RSVP_SIGNALING_ERROR);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_LSP_ERROR_CODE);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, sizeof(uint32_t));
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1],
			htonl(PCEP_TLV_LSP_ERROR_CODE_RSVP_SIGNALING_ERROR));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_rsvp_ipv4_error_spec(void)
{
	struct in_addr error_node_ip;
	inet_pton(AF_INET, "192.168.1.1", &error_node_ip);
	uint8_t error_code = 8;
	uint16_t error_value = 0xaabb;

	struct pcep_object_tlv_rsvp_error_spec *tlv =
		pcep_tlv_create_rsvp_ipv4_error_spec(NULL, error_code,
						     error_value);
	CU_ASSERT_PTR_NULL(tlv);

	tlv = pcep_tlv_create_rsvp_ipv4_error_spec(&error_node_ip, error_code,
						   error_value);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 12);

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_rsvp_ipv6_error_spec(void)
{
	struct in6_addr error_node_ip;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &error_node_ip);
	uint8_t error_code = 8;
	uint16_t error_value = 0xaabb;

	struct pcep_object_tlv_rsvp_error_spec *tlv =
		pcep_tlv_create_rsvp_ipv6_error_spec(NULL, error_code,
						     error_value);
	CU_ASSERT_PTR_NULL(tlv);

	tlv = pcep_tlv_create_rsvp_ipv6_error_spec(&error_node_ip, error_code,
						   error_value);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_RSVP_ERROR_SPEC);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 24);

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_nopath_vector(void)
{
	uint32_t enterprise_number = 0x01020304;
	uint32_t enterprise_specific_info = 0x05060708;

	struct pcep_object_tlv_vendor_info *tlv = pcep_tlv_create_vendor_info(
		enterprise_number, enterprise_specific_info);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, PCEP_OBJ_TLV_TYPE_VENDOR_INFO);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 8);
	uint32_t *uint32_ptr = (uint32_t *)tlv->header.encoded_tlv;
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(enterprise_number));
	CU_ASSERT_EQUAL(uint32_ptr[2], htonl(enterprise_specific_info));

	pcep_obj_free_tlv(&tlv->header);
}

void test_pcep_tlv_create_arbitrary(void)
{
	char data[16] = "Some Data";
	uint16_t data_length = 9;
	uint16_t tlv_id_unknown = 1; // 65505; // Whatever id to be created
	struct pcep_object_tlv_arbitrary *tlv = pcep_tlv_create_tlv_arbitrary(
		data, data_length, tlv_id_unknown);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);

	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, tlv_id_unknown);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, data_length);
	/* Test the padding is correct */
	CU_ASSERT_EQUAL(
		0, strncmp((char *)&(tlv->header.encoded_tlv[4]), &data[0], 4));
	CU_ASSERT_EQUAL(
		0, strncmp((char *)&(tlv->header.encoded_tlv[8]), &data[4], 4));
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[11], 't');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[12], 'a');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[13], 0);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[14], 0);
	pcep_obj_free_tlv(&tlv->header);

	reset_tlv_buffer();
	tlv = pcep_tlv_create_tlv_arbitrary(data, 3, tlv_id_unknown);
	CU_ASSERT_PTR_NOT_NULL(tlv);
	assert(tlv != NULL);
	pcep_encode_tlv(&tlv->header, versioning, tlv_buf);
	CU_ASSERT_EQUAL(tlv->header.type, tlv_id_unknown);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 3);
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[4], 'S');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[5], 'o');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[6], 'm');
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv[7], 0);

	pcep_obj_free_tlv(&tlv->header);
}
