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

#include <assert.h>
#include <stdlib.h>

#include <CUnit/CUnit.h>

#include "pcep_msg_encoding.h"
#include "pcep_msg_objects.h"
#include "pcep_msg_tools.h"
#include "pcep_utils_memory.h"
#include "pcep_msg_objects_test.h"

/*
 * Notice:
 * All of these object Unit Tests encode the created objects by explicitly
 * calling pcep_encode_object() thus testing the object creation and the object
 * encoding. All APIs expect IPs to be in network byte order.
 */

static struct pcep_versioning *versioning = NULL;
static uint8_t object_buf[2000];

void reset_objects_buffer(void);

int pcep_objects_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_objects_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

void reset_objects_buffer(void)
{
	memset(object_buf, 0, 2000);
}

void pcep_objects_test_setup(void)
{
	versioning = create_default_pcep_versioning();
	reset_objects_buffer();
}

void pcep_objects_test_teardown(void)
{
	destroy_pcep_versioning(versioning);
}

/* Internal util verification function */
static void verify_pcep_obj_header2(uint8_t obj_class, uint8_t obj_type,
				    uint16_t obj_length, const uint8_t *obj_buf)
{
	/* Object Header
	 *
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *  | Object-Class  |   OT  |Res|P|I|   Object Length (bytes)       |
	 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */

	/* Not using CU_ASSERT_EQUAL here, so that in case of failure,
	 * we can provide more info in the error message. */
	if (obj_buf[0] != obj_class) {
		fprintf(stderr,
			"Test failure obj_class expected [%d] found [%d]\n",
			obj_class, obj_buf[0]);
		CU_FAIL("Object Header Class");
	}

	uint8_t found8 = (obj_buf[1] >> 4) & 0x0f;
	if (obj_type != found8) {
		fprintf(stderr,
			"Test failure obj_class [%d] obj_type expected [%d] found [%d]\n",
			obj_class, obj_type, found8);
		CU_FAIL("Object Header Type");
	}

	uint8_t exp8 = 0;
	found8 = obj_buf[1] & 0x0f;
	if (exp8 != found8) {
		fprintf(stderr,
			"Test failure obj_class [%d] flags expected [%d] found [%d]\n",
			obj_class, exp8, found8);
		CU_FAIL("Object Header Flags");
	}

	uint16_t found16 = ntohs(*((uint16_t *)(obj_buf + 2)));
	if (obj_length != found16) {
		fprintf(stderr,
			"Test failure obj_class [%d] obj_length expected [%d] found [%d]\n",
			obj_class, obj_length, found16);
		CU_FAIL("Object Header Length");
	}
}

/* Internal util verification function */
static void verify_pcep_obj_header(uint8_t obj_class, uint8_t obj_type,
				   struct pcep_object_header *obj_hdr)
{
	assert(obj_hdr != NULL);
	verify_pcep_obj_header2(obj_class, obj_type,
				pcep_object_get_length_by_hdr(obj_hdr),
				obj_hdr->encoded_object);
}

void test_pcep_obj_create_open(void)
{
	uint8_t deadtimer = 60;
	uint8_t keepalive = 30;
	uint8_t sid = 1;

	struct pcep_object_open *open =
		pcep_obj_create_open(keepalive, deadtimer, sid, NULL);

	CU_ASSERT_PTR_NOT_NULL(open);
	pcep_encode_object(&open->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN,
			       &open->header);

	CU_ASSERT_EQUAL(open->header.encoded_object[4],
			(PCEP_OBJECT_OPEN_VERSION << 5) & 0xe0);
	CU_ASSERT_EQUAL(open->header.encoded_object[4] & 0x1f, 0);
	CU_ASSERT_EQUAL(open->header.encoded_object[5], keepalive);
	CU_ASSERT_EQUAL(open->header.encoded_object[6], deadtimer);
	CU_ASSERT_EQUAL(open->header.encoded_object[7], sid);

	pcep_obj_free_object((struct pcep_object_header *)open);
}

void test_pcep_obj_create_open_with_tlvs(void)
{
	uint8_t deadtimer = 60;
	uint8_t keepalive = 30;
	uint8_t sid = 1;
	double_linked_list *tlv_list = dll_initialize();

	struct pcep_object_tlv_stateful_pce_capability *tlv =
		pcep_tlv_create_stateful_pce_capability(true, true, true, true,
							true, true);
	dll_append(tlv_list, tlv);
	struct pcep_object_open *open =
		pcep_obj_create_open(keepalive, deadtimer, sid, tlv_list);

	CU_ASSERT_PTR_NOT_NULL(open);
	assert(open != NULL);
	pcep_encode_object(&open->header, versioning, object_buf);
	verify_pcep_obj_header2(PCEP_OBJ_CLASS_OPEN, PCEP_OBJ_TYPE_OPEN,
				pcep_object_get_length_by_hdr(&open->header)
					+ sizeof(uint32_t) * 2,
				open->header.encoded_object);
	CU_ASSERT_PTR_NOT_NULL(open->header.tlv_list);
	assert(open->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(open->header.tlv_list->num_entries, 1);

	CU_ASSERT_EQUAL(open->header.encoded_object[4],
			(PCEP_OBJECT_OPEN_VERSION << 5) & 0xe0);
	CU_ASSERT_EQUAL(open->header.encoded_object[4] & 0x1f, 0);
	CU_ASSERT_EQUAL(open->header.encoded_object[5], keepalive);
	CU_ASSERT_EQUAL(open->header.encoded_object[6], deadtimer);
	CU_ASSERT_EQUAL(open->header.encoded_object[7], sid);

	pcep_obj_free_object((struct pcep_object_header *)open);
}

void test_pcep_obj_create_rp(void)
{
	uint32_t reqid = 15;
	uint8_t invalid_priority = 100;
	uint8_t priority = 7;

	struct pcep_object_rp *rp = pcep_obj_create_rp(
		invalid_priority, true, false, false, true, reqid, NULL);
	CU_ASSERT_PTR_NULL(rp);

	rp = pcep_obj_create_rp(priority, true, false, false, true, reqid,
				NULL);
	CU_ASSERT_PTR_NOT_NULL(rp);
	pcep_encode_object(&rp->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_RP, PCEP_OBJ_TYPE_RP,
			       &rp->header);

	CU_ASSERT_EQUAL(rp->header.encoded_object[4], 0);
	CU_ASSERT_EQUAL(rp->header.encoded_object[5], 0);
	CU_ASSERT_EQUAL(rp->header.encoded_object[6], 0);
	CU_ASSERT_EQUAL((rp->header.encoded_object[7] & 0x07), priority);
	CU_ASSERT_TRUE(rp->header.encoded_object[7] & OBJECT_RP_FLAG_R);
	CU_ASSERT_TRUE(rp->header.encoded_object[7] & OBJECT_RP_FLAG_OF);
	CU_ASSERT_TRUE(rp->header.encoded_object[7] & ~OBJECT_RP_FLAG_B);
	CU_ASSERT_TRUE(rp->header.encoded_object[7] & ~OBJECT_RP_FLAG_O);
	CU_ASSERT_EQUAL(*((uint32_t *)(rp->header.encoded_object + 8)),
			htonl(reqid));

	pcep_obj_free_object((struct pcep_object_header *)rp);
}

void test_pcep_obj_create_nopath(void)
{
	uint8_t ni = 8;
	uint32_t errorcode = 42;

	struct pcep_object_nopath *nopath =
		pcep_obj_create_nopath(ni, true, errorcode);

	CU_ASSERT_PTR_NOT_NULL(nopath);
	pcep_encode_object(&nopath->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_NOPATH, PCEP_OBJ_TYPE_NOPATH,
			       &nopath->header);

	CU_ASSERT_EQUAL(nopath->header.encoded_object[4], ni);
	CU_ASSERT_TRUE(nopath->header.encoded_object[5] & OBJECT_NOPATH_FLAG_C);
	CU_ASSERT_EQUAL(nopath->header.encoded_object[6], 0);
	CU_ASSERT_EQUAL(nopath->header.encoded_object[7], 0);

	/* Verify the TLV */
	assert(nopath != NULL);
	assert(nopath->header.tlv_list != NULL);
	CU_ASSERT_PTR_NOT_NULL(nopath->header.tlv_list);
	struct pcep_object_tlv_nopath_vector *tlv =
		(struct pcep_object_tlv_nopath_vector *)
			nopath->header.tlv_list->head->data;
	CU_ASSERT_EQUAL(tlv->header.encoded_tlv_length, 4);
	CU_ASSERT_EQUAL(tlv->header.type, 1);
	CU_ASSERT_EQUAL(tlv->error_code, errorcode);

	CU_ASSERT_EQUAL(*((uint16_t *)(nopath->header.encoded_object + 8)),
			htons(PCEP_OBJ_TLV_TYPE_NO_PATH_VECTOR));
	CU_ASSERT_EQUAL(*((uint16_t *)(nopath->header.encoded_object + 10)),
			htons(4));
	CU_ASSERT_EQUAL(*((uint32_t *)(nopath->header.encoded_object + 12)),
			htonl(errorcode));

	pcep_obj_free_object((struct pcep_object_header *)nopath);
}

void test_pcep_obj_create_association_ipv4(void)
{

	uint16_t all_assoc_groups = 0xffff;
	struct in_addr src;
	inet_pton(AF_INET, "192.168.1.2", &src);

	struct pcep_object_association_ipv4 *assoc =
		pcep_obj_create_association_ipv4(
			false, PCEP_ASSOCIATION_TYPE_SR_POLICY_ASSOCIATION_TYPE,
			all_assoc_groups, src);
	CU_ASSERT_PTR_NOT_NULL(assoc);
	assert(assoc != NULL);
	CU_ASSERT_EQUAL(assoc->association_type,
			PCEP_ASSOCIATION_TYPE_SR_POLICY_ASSOCIATION_TYPE);
	CU_ASSERT_EQUAL(assoc->association_id, all_assoc_groups);
	CU_ASSERT_EQUAL(assoc->header.object_class, PCEP_OBJ_CLASS_ASSOCIATION);
	CU_ASSERT_EQUAL(assoc->header.object_type,
			PCEP_OBJ_TYPE_ASSOCIATION_IPV4);
	CU_ASSERT_EQUAL(assoc->src.s_addr, src.s_addr);

	pcep_obj_free_object((struct pcep_object_header *)assoc);
}

void test_pcep_obj_create_association_ipv6(void)
{
	uint32_t all_assoc_groups = 0xffff;
	struct in6_addr src;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &src);

	struct pcep_object_association_ipv6 *assoc =
		pcep_obj_create_association_ipv6(
			false, PCEP_ASSOCIATION_TYPE_SR_POLICY_ASSOCIATION_TYPE,
			all_assoc_groups, src);
	CU_ASSERT_PTR_NOT_NULL(assoc);
	assert(assoc != NULL);
	CU_ASSERT_EQUAL(assoc->association_type,
			PCEP_ASSOCIATION_TYPE_SR_POLICY_ASSOCIATION_TYPE);
	CU_ASSERT_EQUAL(assoc->association_id, all_assoc_groups);
	CU_ASSERT_EQUAL(assoc->header.object_class, PCEP_OBJ_CLASS_ASSOCIATION);
	CU_ASSERT_EQUAL(assoc->header.object_type,
			PCEP_OBJ_TYPE_ASSOCIATION_IPV6);
	CU_ASSERT_EQUAL(assoc->src.__in6_u.__u6_addr32[0],
			(src.__in6_u.__u6_addr32[0]));
	CU_ASSERT_EQUAL(assoc->src.__in6_u.__u6_addr32[1],
			(src.__in6_u.__u6_addr32[1]));
	CU_ASSERT_EQUAL(assoc->src.__in6_u.__u6_addr32[2],
			(src.__in6_u.__u6_addr32[2]));
	CU_ASSERT_EQUAL(assoc->src.__in6_u.__u6_addr32[3],
			(src.__in6_u.__u6_addr32[3]));

	pcep_obj_free_object((struct pcep_object_header *)assoc);
}

void test_pcep_obj_create_endpoint_ipv4(void)
{
	struct in_addr src_ipv4, dst_ipv4;
	inet_pton(AF_INET, "192.168.1.2", &src_ipv4);
	inet_pton(AF_INET, "172.168.1.2", &dst_ipv4);

	struct pcep_object_endpoints_ipv4 *ipv4 =
		pcep_obj_create_endpoint_ipv4(NULL, NULL);
	CU_ASSERT_PTR_NULL(ipv4);

	ipv4 = pcep_obj_create_endpoint_ipv4(&src_ipv4, NULL);
	CU_ASSERT_PTR_NULL(ipv4);

	ipv4 = pcep_obj_create_endpoint_ipv4(NULL, &dst_ipv4);
	CU_ASSERT_PTR_NULL(ipv4);

	ipv4 = pcep_obj_create_endpoint_ipv4(&src_ipv4, &dst_ipv4);
	CU_ASSERT_PTR_NOT_NULL(ipv4);
	pcep_encode_object(&ipv4->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_ENDPOINTS,
			       PCEP_OBJ_TYPE_ENDPOINT_IPV4, &ipv4->header);
	CU_ASSERT_EQUAL(*((uint32_t *)(ipv4->header.encoded_object + 4)),
			src_ipv4.s_addr);
	CU_ASSERT_EQUAL(*((uint32_t *)(ipv4->header.encoded_object + 8)),
			dst_ipv4.s_addr);

	pcep_obj_free_object((struct pcep_object_header *)ipv4);
}

void test_pcep_obj_create_endpoint_ipv6(void)
{
	struct in6_addr src_ipv6, dst_ipv6;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &src_ipv6);
	inet_pton(AF_INET6, "2001:db8::8a2e:370:8446", &dst_ipv6);

	struct pcep_object_endpoints_ipv6 *ipv6 =
		pcep_obj_create_endpoint_ipv6(NULL, NULL);
	CU_ASSERT_PTR_NULL(ipv6);

	ipv6 = pcep_obj_create_endpoint_ipv6(&src_ipv6, NULL);
	CU_ASSERT_PTR_NULL(ipv6);

	ipv6 = pcep_obj_create_endpoint_ipv6(NULL, &dst_ipv6);
	CU_ASSERT_PTR_NULL(ipv6);

	ipv6 = pcep_obj_create_endpoint_ipv6(&src_ipv6, &dst_ipv6);
	CU_ASSERT_PTR_NOT_NULL(ipv6);
	pcep_encode_object(&ipv6->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_ENDPOINTS,
			       PCEP_OBJ_TYPE_ENDPOINT_IPV6, &ipv6->header);
	uint32_t *uint32_ptr = (uint32_t *)(ipv6->header.encoded_object + 4);
	CU_ASSERT_EQUAL(uint32_ptr[0], src_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[1], src_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[2], src_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[3], src_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(uint32_ptr[4], dst_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[5], dst_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[6], dst_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[7], dst_ipv6.__in6_u.__u6_addr32[3]);

	pcep_obj_free_object((struct pcep_object_header *)ipv6);
}

void test_pcep_obj_create_bandwidth(void)
{
	/* 1.8 => binary 1.11001101
	 * exponent = 127 => 0111 1111
	 * fraction = 1100 1101 0000 0000 0000 000 */
	float bandwidth = 1.8;

	struct pcep_object_bandwidth *bw = pcep_obj_create_bandwidth(bandwidth);

	CU_ASSERT_PTR_NOT_NULL(bw);
	pcep_encode_object(&bw->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_BANDWIDTH,
			       PCEP_OBJ_TYPE_BANDWIDTH_REQ, &bw->header);
	CU_ASSERT_EQUAL(bw->header.encoded_object[4], 0x3f);
	CU_ASSERT_EQUAL(bw->header.encoded_object[5], 0xe6);
	CU_ASSERT_EQUAL(bw->header.encoded_object[6], 0x66);
	CU_ASSERT_EQUAL(bw->header.encoded_object[7], 0x66);

	pcep_obj_free_object((struct pcep_object_header *)bw);
}

void test_pcep_obj_create_metric(void)
{
	uint8_t type = PCEP_METRIC_BORDER_NODE_COUNT;
	/* https://en.wikipedia.org/wiki/IEEE_754-1985
	 * 0.15625 = 1/8 + 1/32 = binary 0.00101 = 1.01 x 10^-3
	 * Exponent bias = 127, so exponent = (127-3) = 124 = 0111 1100
	 *            Sign  Exponent   Fraction
	 *                  (8 bits)   (23 bits)
	 * 0.15625 =>  0    0111 1100  010 0000 ... 0000 */
	float value = 0.15625;

	struct pcep_object_metric *metric =
		pcep_obj_create_metric(type, true, true, value);

	CU_ASSERT_PTR_NOT_NULL(metric);
	pcep_encode_object(&metric->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_METRIC, PCEP_OBJ_TYPE_METRIC,
			       &metric->header);
	CU_ASSERT_EQUAL(metric->header.encoded_object[4], 0);
	CU_ASSERT_EQUAL(metric->header.encoded_object[5], 0);
	CU_ASSERT_TRUE(metric->header.encoded_object[6] & OBJECT_METRIC_FLAC_B);
	CU_ASSERT_TRUE(metric->header.encoded_object[6] & OBJECT_METRIC_FLAC_C);
	CU_ASSERT_EQUAL(metric->header.encoded_object[7], type);
	/* See comments above for explanation of these values */
	CU_ASSERT_EQUAL(metric->header.encoded_object[8], 0x3e);
	CU_ASSERT_EQUAL(metric->header.encoded_object[9], 0x20);
	CU_ASSERT_EQUAL(metric->header.encoded_object[10], 0x00);
	CU_ASSERT_EQUAL(metric->header.encoded_object[11], 0x00);

	pcep_obj_free_object((struct pcep_object_header *)metric);
}

void test_pcep_obj_create_lspa(void)
{
	uint32_t exclude_any = 10;
	uint32_t include_any = 20;
	uint32_t include_all = 30;
	uint8_t prio = 0;
	uint8_t hold_prio = 10;

	struct pcep_object_lspa *lspa = pcep_obj_create_lspa(
		exclude_any, include_any, include_all, prio, hold_prio, true);

	CU_ASSERT_PTR_NOT_NULL(lspa);
	pcep_encode_object(&lspa->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_LSPA, PCEP_OBJ_TYPE_LSPA,
			       &lspa->header);
	uint32_t *uint32_ptr = (uint32_t *)(lspa->header.encoded_object + 4);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(exclude_any));
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(include_any));
	CU_ASSERT_EQUAL(uint32_ptr[2], htonl(include_all));
	CU_ASSERT_EQUAL(lspa->header.encoded_object[16], prio);
	CU_ASSERT_EQUAL(lspa->header.encoded_object[17], hold_prio);
	CU_ASSERT_TRUE(lspa->header.encoded_object[18] & OBJECT_LSPA_FLAG_L);
	CU_ASSERT_EQUAL(lspa->header.encoded_object[19], 0);

	pcep_obj_free_object((struct pcep_object_header *)lspa);
}

void test_pcep_obj_create_svec(void)
{
	struct pcep_object_svec *svec =
		pcep_obj_create_svec(true, true, true, NULL);
	CU_ASSERT_PTR_NULL(svec);

	double_linked_list *id_list = dll_initialize();
	uint32_t *uint32_ptr =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(uint32_t));
	*uint32_ptr = 10;
	dll_append(id_list, uint32_ptr);

	svec = pcep_obj_create_svec(true, true, true, id_list);
	CU_ASSERT_PTR_NOT_NULL(svec);
	assert(svec != NULL);
	pcep_encode_object(&svec->header, versioning, object_buf);
	verify_pcep_obj_header2(PCEP_OBJ_CLASS_SVEC, PCEP_OBJ_TYPE_SVEC,
				(OBJECT_HEADER_LENGTH + sizeof(uint32_t) * 2),
				svec->header.encoded_object);
	CU_ASSERT_EQUAL(svec->header.encoded_object[4], 0);
	CU_ASSERT_EQUAL(svec->header.encoded_object[5], 0);
	CU_ASSERT_EQUAL(svec->header.encoded_object[6], 0);
	CU_ASSERT_TRUE(svec->header.encoded_object[7] & OBJECT_SVEC_FLAG_S);
	CU_ASSERT_TRUE(svec->header.encoded_object[7] & OBJECT_SVEC_FLAG_N);
	CU_ASSERT_TRUE(svec->header.encoded_object[7] & OBJECT_SVEC_FLAG_L);
	CU_ASSERT_EQUAL(*((uint32_t *)(svec->header.encoded_object + 8)),
			htonl(*uint32_ptr));

	pcep_obj_free_object((struct pcep_object_header *)svec);
}

void test_pcep_obj_create_error(void)
{
	uint8_t error_type = PCEP_ERRT_SESSION_FAILURE;
	uint8_t error_value = PCEP_ERRV_RECVD_INVALID_OPEN_MSG;

	struct pcep_object_error *error =
		pcep_obj_create_error(error_type, error_value);

	CU_ASSERT_PTR_NOT_NULL(error);
	pcep_encode_object(&error->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_ERROR, PCEP_OBJ_TYPE_ERROR,
			       &error->header);
	CU_ASSERT_EQUAL(error->header.encoded_object[4], 0);
	CU_ASSERT_EQUAL(error->header.encoded_object[5], 0);
	CU_ASSERT_EQUAL(error->header.encoded_object[6], error_type);
	CU_ASSERT_EQUAL(error->header.encoded_object[7], error_value);

	pcep_obj_free_object((struct pcep_object_header *)error);
}

void test_pcep_obj_create_close(void)
{
	uint8_t reason = PCEP_CLOSE_REASON_DEADTIMER;

	struct pcep_object_close *close = pcep_obj_create_close(reason);

	CU_ASSERT_PTR_NOT_NULL(close);
	pcep_encode_object(&close->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_CLOSE, PCEP_OBJ_TYPE_CLOSE,
			       &close->header);
	CU_ASSERT_EQUAL(close->header.encoded_object[4], 0);
	CU_ASSERT_EQUAL(close->header.encoded_object[5], 0);
	CU_ASSERT_EQUAL(close->header.encoded_object[6], 0);
	CU_ASSERT_EQUAL(close->header.encoded_object[7], reason);

	pcep_obj_free_object((struct pcep_object_header *)close);
}

void test_pcep_obj_create_srp(void)
{
	bool lsp_remove = true;
	uint32_t srp_id_number = 0x89674523;
	struct pcep_object_srp *srp =
		pcep_obj_create_srp(lsp_remove, srp_id_number, NULL);

	CU_ASSERT_PTR_NOT_NULL(srp);
	pcep_encode_object(&srp->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_SRP, PCEP_OBJ_TYPE_SRP,
			       &srp->header);
	CU_ASSERT_EQUAL(srp->header.encoded_object[4], 0);
	CU_ASSERT_EQUAL(srp->header.encoded_object[5], 0);
	CU_ASSERT_EQUAL(srp->header.encoded_object[6], 0);
	CU_ASSERT_TRUE(srp->header.encoded_object[7] & OBJECT_SRP_FLAG_R);
	CU_ASSERT_EQUAL(*((uint32_t *)(srp->header.encoded_object + 8)),
			htonl(srp_id_number));

	pcep_obj_free_object((struct pcep_object_header *)srp);
}

void test_pcep_obj_create_lsp(void)
{
	uint32_t plsp_id = 0x000fffff;
	enum pcep_lsp_operational_status status = PCEP_LSP_OPERATIONAL_ACTIVE;
	bool c_flag = true;
	bool a_flag = true;
	bool r_flag = true;
	bool s_flag = true;
	bool d_flag = true;

	/* Should return for invalid plsp_id */
	struct pcep_object_lsp *lsp =
		pcep_obj_create_lsp(0x001fffff, status, c_flag, a_flag, r_flag,
				    s_flag, d_flag, NULL);
	CU_ASSERT_PTR_NULL(lsp);

	/* Should return for invalid status */
	lsp = pcep_obj_create_lsp(plsp_id, 8, c_flag, a_flag, r_flag, s_flag,
				  d_flag, NULL);
	CU_ASSERT_PTR_NULL(lsp);

	lsp = pcep_obj_create_lsp(plsp_id, status, c_flag, a_flag, r_flag,
				  s_flag, d_flag, NULL);

	CU_ASSERT_PTR_NOT_NULL(lsp);
	pcep_encode_object(&lsp->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_LSP, PCEP_OBJ_TYPE_LSP,
			       &lsp->header);
	CU_ASSERT_EQUAL((ntohl(*((uint32_t *)(lsp->header.encoded_object + 4)))
			 >> 12) & 0x000fffff,
			plsp_id);
	CU_ASSERT_EQUAL((lsp->header.encoded_object[7] >> 4) & 0x07, status);
	CU_ASSERT_TRUE(lsp->header.encoded_object[7] & OBJECT_LSP_FLAG_A);
	CU_ASSERT_TRUE(lsp->header.encoded_object[7] & OBJECT_LSP_FLAG_C);
	CU_ASSERT_TRUE(lsp->header.encoded_object[7] & OBJECT_LSP_FLAG_D);
	CU_ASSERT_TRUE(lsp->header.encoded_object[7] & OBJECT_LSP_FLAG_R);
	CU_ASSERT_TRUE(lsp->header.encoded_object[7] & OBJECT_LSP_FLAG_S);

	pcep_obj_free_object((struct pcep_object_header *)lsp);
}

void test_pcep_obj_create_vendor_info(void)
{
	uint32_t enterprise_number = 0x01020304;
	uint32_t enterprise_specific_info = 0x05060708;

	struct pcep_object_vendor_info *obj = pcep_obj_create_vendor_info(
		enterprise_number, enterprise_specific_info);

	CU_ASSERT_PTR_NOT_NULL(obj);
	pcep_encode_object(&obj->header, versioning, object_buf);
	verify_pcep_obj_header(PCEP_OBJ_CLASS_VENDOR_INFO,
			       PCEP_OBJ_TYPE_VENDOR_INFO, &obj->header);
	uint32_t *uint32_ptr = (uint32_t *)(obj->header.encoded_object + 4);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(enterprise_number));
	CU_ASSERT_EQUAL(uint32_ptr[1], htonl(enterprise_specific_info));

	pcep_obj_free_object((struct pcep_object_header *)obj);
}

/* Internal test function. The only difference between pcep_obj_create_ero(),
 * pcep_obj_create_iro(), and pcep_obj_create_rro() is the object_class
 * and the object_type.
 */
typedef struct pcep_object_ro *(*ro_func)(double_linked_list *);
static void test_pcep_obj_create_object_common(ro_func func_to_test,
					       uint8_t object_class,
					       uint8_t object_type)
{
	double_linked_list *ero_list = dll_initialize();

	struct pcep_object_ro *ero = func_to_test(NULL);
	CU_ASSERT_PTR_NOT_NULL(ero);
	assert(ero != NULL);
	pcep_encode_object(&ero->header, versioning, object_buf);
	verify_pcep_obj_header2(object_class, object_type, OBJECT_HEADER_LENGTH,
				ero->header.encoded_object);
	pcep_obj_free_object((struct pcep_object_header *)ero);

	reset_objects_buffer();
	ero = func_to_test(ero_list);
	CU_ASSERT_PTR_NOT_NULL(ero);
	assert(ero != NULL);
	pcep_encode_object(&ero->header, versioning, object_buf);
	verify_pcep_obj_header2(object_class, object_type, OBJECT_HEADER_LENGTH,
				ero->header.encoded_object);
	pcep_obj_free_object((struct pcep_object_header *)ero);

	reset_objects_buffer();
	struct pcep_ro_subobj_32label *ro_subobj =
		pcep_obj_create_ro_subobj_32label(false, 0, 101);
	ero_list = dll_initialize();
	dll_append(ero_list, ro_subobj);
	ero = func_to_test(ero_list);
	CU_ASSERT_PTR_NOT_NULL(ero);
	assert(ero != NULL);
	pcep_encode_object(&ero->header, versioning, object_buf);
	/* 4 bytes for obj header +
	 * 2 bytes for ro_subobj header +
	 * 2 bytes for lable c-type and flags +
	 * 4 bytes for label */
	verify_pcep_obj_header2(object_class, object_type,
				OBJECT_HEADER_LENGTH + sizeof(uint32_t) * 2,
				ero->header.encoded_object);
	pcep_obj_free_object((struct pcep_object_header *)ero);
}

void test_pcep_obj_create_ero(void)
{
	test_pcep_obj_create_object_common(
		pcep_obj_create_ero, PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO);
}

void test_pcep_obj_create_rro(void)
{
	test_pcep_obj_create_object_common(
		pcep_obj_create_rro, PCEP_OBJ_CLASS_RRO, PCEP_OBJ_TYPE_RRO);
}

void test_pcep_obj_create_iro(void)
{
	test_pcep_obj_create_object_common(
		pcep_obj_create_iro, PCEP_OBJ_CLASS_IRO, PCEP_OBJ_TYPE_IRO);
}

/* Internal util function to wrap an RO Subobj in a RO and encode it */
static struct pcep_object_ro *encode_ro_subobj(struct pcep_object_ro_subobj *sr)
{
	double_linked_list *sr_subobj_list = dll_initialize();
	dll_append(sr_subobj_list, sr);
	struct pcep_object_ro *ro = pcep_obj_create_ero(sr_subobj_list);
	pcep_encode_object(&ro->header, versioning, object_buf);

	return ro;
}

static void verify_pcep_obj_ro_header(struct pcep_object_ro *ro,
				      struct pcep_object_ro_subobj *ro_subobj,
				      uint8_t ro_subobj_type, bool loose_hop,
				      uint16_t length)
{
	(void)ro_subobj;

	verify_pcep_obj_header2(PCEP_OBJ_CLASS_ERO, PCEP_OBJ_TYPE_ERO, length,
				ro->header.encoded_object);

	/* TODO consider printing the stack trace:
	 * https://stackoverflow.com/questions/105659/how-can-one-grab-a-stack-trace-in-c
	 */

	/* Not using CU_ASSERT_EQUAL here, so that in case of failure,
	 * we can provide more info in the error message. */
	uint8_t found_type = (ro->header.encoded_object[4]
			      & 0x7f); /* remove the Loose hop bit */
	if (found_type != ro_subobj_type) {
		fprintf(stderr,
			"Test failure ro_sub_obj_type expected [%d] found [%d]\n",
			ro_subobj_type, found_type);
		CU_FAIL("Sub Object Header Type");
	}

	bool loose_hop_found = (ro->header.encoded_object[4] & 0x80);
	if (loose_hop != loose_hop_found) {
		fprintf(stderr,
			"Test failure ro_sub_obj Loose Hop bit expected [%d] found [%d]\n",
			loose_hop, loose_hop_found);
		CU_FAIL("Sub Object Header Loose Hop bit");
	}

	if (length - 4 != ro->header.encoded_object[5]) {
		fprintf(stderr,
			"Test failure ro_sub_obj length expected [%d] found [%d]\n",
			length - 4, ro->header.encoded_object[5]);
		CU_FAIL("Sub Object Length");
	}
}

static void
verify_pcep_obj_ro_sr_header(struct pcep_object_ro *ro,
			     struct pcep_object_ro_subobj *ro_subobj,
			     uint8_t nai_type, bool loose_hop, uint16_t length)
{
	verify_pcep_obj_ro_header(ro, ro_subobj, RO_SUBOBJ_TYPE_SR, loose_hop,
				  length);
	uint8_t found_nai_type = ((ro->header.encoded_object[6] >> 4) & 0x0f);
	if (nai_type != found_nai_type) {
		fprintf(stderr,
			"Test failure ro_sr_sub_obj nai_type expected [%d] found [%d]\n",
			nai_type, found_nai_type);
		CU_FAIL("Sub Object SR NAI Type");
	}
}

void test_pcep_obj_create_ro_subobj_ipv4(void)
{
	struct in_addr ro_ipv4;
	inet_pton(AF_INET, "192.168.1.2", &ro_ipv4);
	uint8_t prefix_len = 8;

	struct pcep_ro_subobj_ipv4 *ipv4 =
		pcep_obj_create_ro_subobj_ipv4(true, NULL, prefix_len, false);
	CU_ASSERT_PTR_NULL(ipv4);

	ipv4 = pcep_obj_create_ro_subobj_ipv4(false, &ro_ipv4, prefix_len,
					      true);
	CU_ASSERT_PTR_NOT_NULL(ipv4);
	struct pcep_object_ro *ro = encode_ro_subobj(&ipv4->ro_subobj);
	verify_pcep_obj_ro_header(ro, &ipv4->ro_subobj, RO_SUBOBJ_TYPE_IPV4,
				  false, sizeof(uint32_t) * 3);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 6)),
			ro_ipv4.s_addr);
	CU_ASSERT_EQUAL(ro->header.encoded_object[10], prefix_len);
	CU_ASSERT_TRUE(ro->header.encoded_object[11]
		       & OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	reset_objects_buffer();
	ipv4 = pcep_obj_create_ro_subobj_ipv4(true, &ro_ipv4, prefix_len,
					      false);
	CU_ASSERT_PTR_NOT_NULL(ipv4);
	ro = encode_ro_subobj(&ipv4->ro_subobj);
	verify_pcep_obj_ro_header(ro, &ipv4->ro_subobj, RO_SUBOBJ_TYPE_IPV4,
				  true, sizeof(uint32_t) * 3);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 6)),
			ro_ipv4.s_addr);
	CU_ASSERT_EQUAL(ro->header.encoded_object[10], prefix_len);
	CU_ASSERT_EQUAL(ro->header.encoded_object[11], 0);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_ipv6(void)
{
	struct in6_addr ro_ipv6;
	uint8_t prefix_len = 16;

	struct pcep_ro_subobj_ipv6 *ipv6 =
		pcep_obj_create_ro_subobj_ipv6(true, NULL, prefix_len, true);
	CU_ASSERT_PTR_NULL(ipv6);

	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &ro_ipv6);
	ipv6 = pcep_obj_create_ro_subobj_ipv6(false, &ro_ipv6, prefix_len,
					      true);
	CU_ASSERT_PTR_NOT_NULL(ipv6);
	struct pcep_object_ro *ro = encode_ro_subobj(&ipv6->ro_subobj);
	verify_pcep_obj_ro_header(ro, &ipv6->ro_subobj, RO_SUBOBJ_TYPE_IPV6,
				  false, sizeof(uint32_t) * 6);
	uint32_t *uint32_ptr = (uint32_t *)(ro->header.encoded_object + 6);
	CU_ASSERT_EQUAL(uint32_ptr[0], ro_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[1], ro_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[2], ro_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[3], ro_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(ro->header.encoded_object[22], prefix_len);
	CU_ASSERT_TRUE(ro->header.encoded_object[23]
		       & OBJECT_SUBOBJ_IP_FLAG_LOCAL_PROT);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	reset_objects_buffer();
	ipv6 = pcep_obj_create_ro_subobj_ipv6(true, &ro_ipv6, prefix_len,
					      false);
	CU_ASSERT_PTR_NOT_NULL(ipv6);
	ro = encode_ro_subobj(&ipv6->ro_subobj);
	verify_pcep_obj_ro_header(ro, &ipv6->ro_subobj, RO_SUBOBJ_TYPE_IPV6,
				  true, sizeof(uint32_t) * 6);
	uint32_ptr = (uint32_t *)(ro->header.encoded_object + 6);
	CU_ASSERT_EQUAL(uint32_ptr[0], ro_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[1], ro_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[2], ro_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[3], ro_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(ro->header.encoded_object[22], prefix_len);
	CU_ASSERT_EQUAL(ro->header.encoded_object[23], 0);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_unnum(void)
{
	struct in_addr router_id;
	uint32_t if_id = 123;

	struct pcep_ro_subobj_unnum *unnum =
		pcep_obj_create_ro_subobj_unnum(NULL, if_id);
	CU_ASSERT_PTR_NULL(unnum);

	inet_pton(AF_INET, "192.168.1.2", &router_id);
	unnum = pcep_obj_create_ro_subobj_unnum(&router_id, if_id);
	CU_ASSERT_PTR_NOT_NULL(unnum);
	struct pcep_object_ro *ro = encode_ro_subobj(&unnum->ro_subobj);
	verify_pcep_obj_ro_header(ro, &unnum->ro_subobj, RO_SUBOBJ_TYPE_UNNUM,
				  false, sizeof(uint32_t) * 4);
	CU_ASSERT_EQUAL(ro->header.encoded_object[6], 0);
	CU_ASSERT_EQUAL(ro->header.encoded_object[7], 0);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 8)),
			router_id.s_addr);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 12)),
			htonl(if_id));

	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_32label(void)
{
	uint8_t class_type = 1;
	uint32_t label = 0xeeffaabb;

	struct pcep_ro_subobj_32label *label32 =
		pcep_obj_create_ro_subobj_32label(true, class_type, label);
	CU_ASSERT_PTR_NOT_NULL(label32);
	struct pcep_object_ro *ro = encode_ro_subobj(&label32->ro_subobj);
	verify_pcep_obj_ro_header(ro, &label32->ro_subobj, RO_SUBOBJ_TYPE_LABEL,
				  false, sizeof(uint32_t) * 3);
	CU_ASSERT_TRUE(ro->header.encoded_object[6]
		       & OBJECT_SUBOBJ_LABEL_FLAG_GLOGAL);
	CU_ASSERT_EQUAL(ro->header.encoded_object[7], class_type);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 8)),
			htonl(label));

	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_asn(void)
{
	uint16_t asn = 0x0102;

	struct pcep_ro_subobj_asn *asn_obj = pcep_obj_create_ro_subobj_asn(asn);
	CU_ASSERT_PTR_NOT_NULL(asn_obj);
	struct pcep_object_ro *ro = encode_ro_subobj(&asn_obj->ro_subobj);
	verify_pcep_obj_ro_header(ro, &asn_obj->ro_subobj, RO_SUBOBJ_TYPE_ASN,
				  false, sizeof(uint32_t) * 2);
	CU_ASSERT_EQUAL(*((uint16_t *)(ro->header.encoded_object + 6)),
			htons(asn));

	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_sr_nonai(void)
{
	uint32_t sid = 0x01020304;

	struct pcep_ro_subobj_sr *sr =
		pcep_obj_create_ro_subobj_sr_nonai(false, sid, false, false);
	CU_ASSERT_PTR_NOT_NULL(sr);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_ABSENT, false,
				     sizeof(uint32_t) * 3);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	reset_objects_buffer();
	sr = pcep_obj_create_ro_subobj_sr_nonai(true, sid, true, true);
	CU_ASSERT_PTR_NOT_NULL(sr);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_ABSENT, true,
				     sizeof(uint32_t) * 3);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_M);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv4_node(void)
{
	uint32_t sid = 0x01020304;
	struct in_addr ipv4_node_id;
	inet_pton(AF_INET, "192.168.1.2", &ipv4_node_id);

	/* (loose_hop, sid_absent, c_flag, m_flag, sid, ipv4_node_id) */
	struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_ipv4_node(
		true, false, true, true, sid, NULL);
	CU_ASSERT_PTR_NULL(sr);

	/* Test the sid is absent */
	sr = pcep_obj_create_ro_subobj_sr_ipv4_node(true, true, false, false,
						    sid, &ipv4_node_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	assert(sr != NULL);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV4_NODE, true,
				     sizeof(uint32_t) * 3);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_EQUAL(sr->sid, 0);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 8)),
			ipv4_node_id.s_addr);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* Test the sid is present */
	reset_objects_buffer();
	inet_pton(AF_INET, "192.168.1.2", &ipv4_node_id);
	sr = pcep_obj_create_ro_subobj_sr_ipv4_node(false, false, true, true,
						    sid, &ipv4_node_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	assert(sr != NULL);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV4_NODE, false,
				     sizeof(uint32_t) * 4);
	assert(ro != NULL);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 8)),
			htonl(sid));
	CU_ASSERT_EQUAL(*((uint32_t *)(ro->header.encoded_object + 12)),
			ipv4_node_id.s_addr);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv6_node(void)
{
	uint32_t sid = 0x01020304;
	struct in6_addr ipv6_node_id;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &ipv6_node_id);

	/* (loose_hop, sid_absent, c_flag, m_flag, sid, ipv6_node_id) */
	struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_ipv6_node(
		false, true, true, true, sid, NULL);
	CU_ASSERT_PTR_NULL(sr);

	/* Test the sid is absent */
	sr = pcep_obj_create_ro_subobj_sr_ipv6_node(true, true, true, true, sid,
						    &ipv6_node_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV6_NODE, true,
				     sizeof(uint32_t) * 6);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	uint32_t *uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], ipv6_node_id.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[1], ipv6_node_id.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[2], ipv6_node_id.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[3], ipv6_node_id.__in6_u.__u6_addr32[3]);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* Test the sid is present */
	reset_objects_buffer();
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &ipv6_node_id);
	sr = pcep_obj_create_ro_subobj_sr_ipv6_node(false, false, true, true,
						    sid, &ipv6_node_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV6_NODE, false,
				     sizeof(uint32_t) * 7);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(sid));
	CU_ASSERT_EQUAL(uint32_ptr[1], ipv6_node_id.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[2], ipv6_node_id.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[3], ipv6_node_id.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[4], ipv6_node_id.__in6_u.__u6_addr32[3]);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv4_adj(void)
{
	struct in_addr local_ipv4;
	struct in_addr remote_ipv4;
	inet_pton(AF_INET, "192.168.1.2", &local_ipv4);
	inet_pton(AF_INET, "172.168.1.2", &remote_ipv4);

	uint32_t sid = ENCODE_SR_ERO_SID(3, 7, 0, 188);
	CU_ASSERT_EQUAL(sid, 16060);

	/* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv4, remote_ipv4)
	 */
	struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(
		false, true, true, true, sid, NULL, NULL);
	CU_ASSERT_PTR_NULL(sr);

	sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid,
						   &local_ipv4, NULL);
	CU_ASSERT_PTR_NULL(sr);

	sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(false, true, true, true, sid,
						   NULL, &remote_ipv4);
	CU_ASSERT_PTR_NULL(sr);

	/* Test the sid is absent */
	sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(true, true, true, true, sid,
						   &local_ipv4, &remote_ipv4);
	CU_ASSERT_PTR_NOT_NULL(sr);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY, true,
				     sizeof(uint32_t) * 4);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	assert(sr != NULL);
	CU_ASSERT_EQUAL(sr->sid, 0);
	uint32_t *uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], local_ipv4.s_addr);
	CU_ASSERT_EQUAL(uint32_ptr[1], remote_ipv4.s_addr);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* Test the sid is present */
	inet_pton(AF_INET, "192.168.1.2", &local_ipv4);
	inet_pton(AF_INET, "172.168.1.2", &remote_ipv4);
	reset_objects_buffer();
	sr = pcep_obj_create_ro_subobj_sr_ipv4_adj(
		false, false, true, true, sid, &local_ipv4, &remote_ipv4);
	CU_ASSERT_PTR_NOT_NULL(sr);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV4_ADJACENCY, false,
				     sizeof(uint32_t) * 5);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(sid));
	CU_ASSERT_EQUAL(uint32_ptr[1], local_ipv4.s_addr);
	CU_ASSERT_EQUAL(uint32_ptr[2], remote_ipv4.s_addr);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_sr_ipv6_adj(void)
{
	uint32_t sid = 0x01020304;
	struct in6_addr local_ipv6;
	struct in6_addr remote_ipv6;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);

	/* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv6, remote_ipv6)
	 */
	struct pcep_ro_subobj_sr *sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(
		false, true, true, true, sid, NULL, NULL);
	CU_ASSERT_PTR_NULL(sr);

	sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid,
						   &local_ipv6, NULL);
	CU_ASSERT_PTR_NULL(sr);

	sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(false, true, true, true, sid,
						   NULL, &remote_ipv6);
	CU_ASSERT_PTR_NULL(sr);

	/* Test the sid is absent */
	sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(true, true, true, true, sid,
						   &local_ipv6, &remote_ipv6);
	CU_ASSERT_PTR_NOT_NULL(sr);
	assert(sr != NULL);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY, true,
				     sizeof(uint32_t) * 10);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_EQUAL(sr->sid, 0);
	uint32_t *uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], local_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[1], local_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[2], local_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[3], local_ipv6.__in6_u.__u6_addr32[3]);

	CU_ASSERT_EQUAL(uint32_ptr[4], remote_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[5], remote_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[6], remote_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[7], remote_ipv6.__in6_u.__u6_addr32[3]);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* Test the sid is present */
	reset_objects_buffer();
	inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);
	sr = pcep_obj_create_ro_subobj_sr_ipv6_adj(
		false, false, true, false, sid, &local_ipv6, &remote_ipv6);
	CU_ASSERT_PTR_NOT_NULL(sr);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(ro, &sr->ro_subobj,
				     PCEP_SR_SUBOBJ_NAI_IPV6_ADJACENCY, false,
				     sizeof(uint32_t) * 11);
	/* All flags are false */
	CU_ASSERT_EQUAL(ro->header.encoded_object[7], 0);
	uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(sid));
	CU_ASSERT_EQUAL(uint32_ptr[1], local_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[2], local_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[3], local_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[4], local_ipv6.__in6_u.__u6_addr32[3]);

	CU_ASSERT_EQUAL(uint32_ptr[5], remote_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[6], remote_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[7], remote_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[8], remote_ipv6.__in6_u.__u6_addr32[3]);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}

void test_pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(void)
{
	uint32_t sid = 0x01020304;
	uint32_t local_node_id = 0x11223344;
	uint32_t local_if_id = 0x55667788;
	uint32_t remote_node_id = 0x99aabbcc;
	uint32_t remote_if_id = 0xddeeff11;

	/* (loose_hop, sid_absent, c_flag, m_flag,
	    sid, local_node_id, local_if_id, remote_node_id, remote_if_id) */

	/* Test the sid is absent */
	struct pcep_ro_subobj_sr *sr =
		pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
			true, true, true, true, sid, local_node_id, local_if_id,
			remote_node_id, remote_if_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(
		ro, &sr->ro_subobj,
		PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY, true,
		sizeof(uint32_t) * 6);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	assert(sr != NULL);
	CU_ASSERT_EQUAL(sr->sid, 0);
	uint32_t *uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], local_node_id);
	CU_ASSERT_EQUAL(uint32_ptr[1], local_if_id);
	CU_ASSERT_EQUAL(uint32_ptr[2], remote_node_id);
	CU_ASSERT_EQUAL(uint32_ptr[3], remote_if_id);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* Test the sid is present */
	reset_objects_buffer();
	sr = pcep_obj_create_ro_subobj_sr_unnumbered_ipv4_adj(
		false, false, true, true, sid, local_node_id, local_if_id,
		remote_node_id, remote_if_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(
		ro, &sr->ro_subobj,
		PCEP_SR_SUBOBJ_NAI_UNNUMBERED_IPV4_ADJACENCY, false,
		sizeof(uint32_t) * 7);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(sid));
	CU_ASSERT_EQUAL(uint32_ptr[1], local_node_id);
	CU_ASSERT_EQUAL(uint32_ptr[2], local_if_id);
	CU_ASSERT_EQUAL(uint32_ptr[3], remote_node_id);
	CU_ASSERT_EQUAL(uint32_ptr[4], remote_if_id);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* TODO Test draft07 types  */
}

void test_pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(void)
{
	uint32_t sid = 0x01020304;
	uint32_t local_if_id = 0x11002200;
	uint32_t remote_if_id = 0x00110022;
	struct in6_addr local_ipv6;
	struct in6_addr remote_ipv6;
	inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);

	/* (loose_hop, sid_absent, c_flag, m_flag, sid, local_ipv6, local_if_id,
	 * remote_ipv6, remote_if_id */
	struct pcep_ro_subobj_sr *sr =
		pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
			false, true, true, true, sid, NULL, local_if_id, NULL,
			remote_if_id);
	CU_ASSERT_PTR_NULL(sr);

	sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
		false, true, true, true, sid, &local_ipv6, local_if_id, NULL,
		remote_if_id);
	CU_ASSERT_PTR_NULL(sr);

	sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
		false, true, true, true, sid, NULL, local_if_id, &remote_ipv6,
		remote_if_id);
	CU_ASSERT_PTR_NULL(sr);

	/* Test the sid is absent */
	sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
		true, true, true, true, sid, &local_ipv6, local_if_id,
		&remote_ipv6, remote_if_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	struct pcep_object_ro *ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(
		ro, &sr->ro_subobj,
		PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY, true,
		sizeof(uint32_t) * 12);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_M);
	assert(sr != NULL);
	CU_ASSERT_EQUAL(sr->sid, 0);
	uint32_t *uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], local_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[1], local_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[2], local_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[3], local_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(uint32_ptr[4], local_if_id);

	CU_ASSERT_EQUAL(uint32_ptr[5], remote_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[6], remote_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[7], remote_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[8], remote_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(uint32_ptr[9], remote_if_id);
	pcep_obj_free_object((struct pcep_object_header *)ro);

	/* Test the sid is present */
	inet_pton(AF_INET6, "2001:db8::8a2e:370:8221", &local_ipv6);
	inet_pton(AF_INET6, "2001:db8::8a2e:370:7334", &remote_ipv6);
	reset_objects_buffer();
	sr = pcep_obj_create_ro_subobj_sr_linklocal_ipv6_adj(
		false, false, true, true, sid, &local_ipv6, local_if_id,
		&remote_ipv6, remote_if_id);
	CU_ASSERT_PTR_NOT_NULL(sr);
	ro = encode_ro_subobj(&sr->ro_subobj);
	verify_pcep_obj_ro_sr_header(
		ro, &sr->ro_subobj,
		PCEP_SR_SUBOBJ_NAI_LINK_LOCAL_IPV6_ADJACENCY, false,
		sizeof(uint32_t) * 13);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_C);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & OBJECT_SUBOBJ_SR_FLAG_M);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_S);
	CU_ASSERT_TRUE(ro->header.encoded_object[7] & ~OBJECT_SUBOBJ_SR_FLAG_F);
	uint32_ptr = (uint32_t *)(ro->header.encoded_object + 8);
	CU_ASSERT_EQUAL(uint32_ptr[0], htonl(sid));
	CU_ASSERT_EQUAL(uint32_ptr[1], local_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[2], local_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[3], local_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[4], local_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(uint32_ptr[5], local_if_id);

	CU_ASSERT_EQUAL(uint32_ptr[6], remote_ipv6.__in6_u.__u6_addr32[0]);
	CU_ASSERT_EQUAL(uint32_ptr[7], remote_ipv6.__in6_u.__u6_addr32[1]);
	CU_ASSERT_EQUAL(uint32_ptr[8], remote_ipv6.__in6_u.__u6_addr32[2]);
	CU_ASSERT_EQUAL(uint32_ptr[9], remote_ipv6.__in6_u.__u6_addr32[3]);
	CU_ASSERT_EQUAL(uint32_ptr[10], remote_if_id);
	pcep_obj_free_object((struct pcep_object_header *)ro);
}
