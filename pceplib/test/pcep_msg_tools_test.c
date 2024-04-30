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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>


#include <CUnit/CUnit.h>

#include <zebra.h>

#include "pcep_msg_encoding.h"
#include "pcep_msg_messages.h"
#include "pcep_msg_tools.h"
#include "pcep_msg_tools_test.h"
#include "pcep_utils_double_linked_list.h"
#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

const uint8_t any_obj_class = 255;

uint16_t pcep_open_hexbyte_strs_length = 28;
const char *pcep_open_odl_hexbyte_strs[] = {
	"20", "01", "00", "1c", "01", "10", "00", "18", "20", "1e",
	"78", "55", "00", "10", "00", "04", "00", "00", "00", "3f",
	"00", "1a", "00", "04", "00", "00", "00", "00"};

/* PCEP INITIATE str received from ODL with 4 objects: [SRP, LSP, Endpoints,
 * ERO] The LSP has a SYMBOLIC_PATH_NAME TLV. The ERO has 2 IPV4 Endpoints. */
uint16_t pcep_initiate_hexbyte_strs_length = 68;
const char *pcep_initiate_hexbyte_strs[] = {
	"20", "0c", "00", "44", "21", "12", "00", "0c", "00", "00", "00", "00",
	"00", "00", "00", "01", "20", "10", "00", "14", "00", "00", "00", "09",
	"00", "11", "00", "08", "66", "61", "39", "33", "33", "39", "32", "39",
	"04", "10", "00", "0c", "7f", "00", "00", "01", "28", "28", "28", "28",
	"07", "10", "00", "14", "01", "08", "0a", "00", "01", "01", "18", "00",
	"01", "08", "0a", "00", "07", "04", "18", "00"};

uint16_t pcep_initiate2_hexbyte_strs_length = 72;
const char *pcep_initiate2_hexbyte_strs[] = {
	"20", "0c", "00", "48", "21", "12", "00", "14", "00", "00", "00", "00",
	"00", "00", "00", "01", "00", "1c", "00", "04", "00", "00", "00", "01",
	"20", "10", "00", "14", "00", "00", "00", "09", "00", "11", "00", "08",
	"36", "65", "31", "31", "38", "39", "32", "31", "04", "10", "00", "0c",
	"c0", "a8", "14", "05", "01", "01", "01", "01", "07", "10", "00", "10",
	"05", "0c", "10", "01", "03", "e8", "a0", "00", "01", "01", "01", "01"};

uint16_t pcep_update_hexbyte_strs_length = 48;
const char *pcep_update_hexbyte_strs[] = {
	"20", "0b", "00", "30", "21", "12", "00", "14", "00", "00", "00", "00",
	"00", "00", "00", "01", "00", "1c", "00", "04", "00", "00", "00", "01",
	"20", "10", "00", "08", "00", "02", "a0", "09", "07", "10", "00", "10",
	"05", "0c", "10", "01", "03", "e8", "a0", "00", "01", "01", "01", "01"};

/* Test that pcep_msg_read() can read multiple messages in 1 call */
uint16_t pcep_open_initiate_hexbyte_strs_length = 100;
const char *pcep_open_initiate_odl_hexbyte_strs[] = {
	"20", "01", "00", "1c", "01", "10", "00", "18", "20", "1e", "78", "55",
	"00", "10", "00", "04", "00", "00", "00", "3f", "00", "1a", "00", "04",
	"00", "00", "00", "00", "20", "0c", "00", "48", "21", "12", "00", "14",
	"00", "00", "00", "00", "00", "00", "00", "01", "00", "1c", "00", "04",
	"00", "00", "00", "01", "20", "10", "00", "14", "00", "00", "00", "09",
	"00", "11", "00", "08", "36", "65", "31", "31", "38", "39", "32", "31",
	"04", "10", "00", "0c", "c0", "a8", "14", "05", "01", "01", "01", "01",
	"07", "10", "00", "10", "05", "0c", "10", "01", "03", "e8", "a0", "00",
	"01", "01", "01", "01"};

uint16_t pcep_open_cisco_pce_hexbyte_strs_length = 28;
const char *pcep_open_cisco_pce_hexbyte_strs[] = {
	"20", "01", "00", "1c", "01", "10", "00", "18", "20", "3c",
	"78", "00", "00", "10", "00", "04", "00", "00", "00", "05",
	"00", "1a", "00", "04", "00", "00", "00", "0a"};

uint16_t pcep_update_cisco_pce_hexbyte_strs_length = 100;
const char *pcep_update_cisco_pce_hexbyte_strs[] = {
	"20", "0b", "00", "64", "21", "10", "00", "14", "00", "00", "00", "00",
	"00", "00", "00", "01", "00", "1c", "00", "04", "00", "00", "00", "01",
	"20", "10", "00", "18", "80", "00", "f0", "89", "00", "07", "00", "0c",
	"00", "00", "00", "09", "00", "03", "00", "04", "00", "00", "00", "01",
	"07", "10", "00", "28", "24", "0c", "10", "01", "04", "65", "50", "00",
	"0a", "0a", "0a", "05", "24", "0c", "10", "01", "04", "65", "20", "00",
	"0a", "0a", "0a", "02", "24", "0c", "10", "01", "04", "65", "10", "00",
	"0a", "0a", "0a", "01", "06", "10", "00", "0c", "00", "00", "00", "02",
	"41", "f0", "00", "00"};

uint16_t pcep_report_cisco_pcc_hexbyte_strs_length = 148;
const char *pcep_report_cisco_pcc_hexbyte_strs[] = {
	"20", "0a", "00", "94", "21", "10", "00", "14", "00", "00", "00", "00",
	"00", "00", "00", "00", "00", "1c", "00", "04", "00", "00", "00", "01",
	"20", "10", "00", "3c", "80", "00", "f0", "09", "00", "12", "00", "10",
	"0a", "0a", "0a", "06", "00", "02", "00", "0f", "0a", "0a", "0a", "06",
	"0a", "0a", "0a", "01", "00", "11", "00", "0d", "63", "66", "67", "5f",
	"52", "36", "2d", "74", "6f", "2d", "52", "31", "00", "00", "00", "00",
	"ff", "e1", "00", "06", "00", "00", "05", "dd", "70", "00", "00", "00",
	"07", "10", "00", "04", "09", "10", "00", "14", "00", "00", "00", "00",
	"00", "00", "00", "00", "00", "00", "00", "00", "07", "07", "01", "00",
	"05", "12", "00", "08", "00", "00", "00", "00", "05", "52", "00", "08",
	"00", "00", "00", "00", "06", "10", "00", "0c", "00", "00", "00", "02",
	"00", "00", "00", "00", "06", "10", "00", "0c", "00", "00", "01", "04",
	"41", "80", "00", "00"};

/* Cisco PcInitiate with the following objects:
 *   SRP, LSP, Endpoint, Inter-layer, Switch-layer, ERO
 */
uint16_t pcep_initiate_cisco_pcc_hexbyte_strs_length = 104;
const char *pcep_initiate_cisco_pcc_hexbyte_strs[] = {
	"20", "0c", "00", "68", "21", "10", "00", "14", "00", "00", "00", "00",
	"00", "00", "00", "01", "00", "1c", "00", "04", "00", "00", "00", "01",
	"20", "10", "00", "30", "00", "00", "00", "89", "00", "11", "00", "13",
	"50", "4f", "4c", "31", "5f", "50", "43", "49", "4e", "49", "54", "41",
	"54", "45", "5f", "54", "45", "53", "54", "00", "00", "07", "00", "0c",
	"00", "00", "00", "09", "00", "03", "00", "04", "00", "00", "00", "01",
	"04", "10", "00", "0c", "0a", "0a", "0a", "0a", "0a", "0a", "0a", "04",
	"24", "10", "00", "08", "00", "00", "01", "4d", "25", "10", "00", "08",
	"00", "00", "00", "64", "07", "10", "00", "04"};

struct pcep_message *create_message(uint8_t msg_type, uint8_t obj1_class,
				    uint8_t obj2_class, uint8_t obj3_class,
				    uint8_t obj4_class);
int convert_hexstrs_to_binary(char *filename, const char *hexbyte_strs[],
			      uint16_t hexbyte_strs_length);

int pcep_tools_test_suite_setup(void)
{
	pceplib_memory_reset();
	return 0;
}

int pcep_tools_test_suite_teardown(void)
{
	printf("\n");
	pceplib_memory_dump();
	return 0;
}

void pcep_tools_test_setup(void)
{
}

void pcep_tools_test_teardown(void)
{
}

static const char BASE_TMPFILE[] = "/tmp/pceplib_XXXXXX";
static int BASE_TMPFILE_SIZE = sizeof(BASE_TMPFILE);

/* Reads an array of hexbyte strs, and writes them to a temporary file.
 * The caller should close the returned file. */
int convert_hexstrs_to_binary(char *filename, const char *hexbyte_strs[],
			      uint16_t hexbyte_strs_length)
{
	mode_t oldumask;
	oldumask = umask(S_IXUSR | S_IXGRP | S_IWOTH | S_IROTH | S_IXOTH);
	/* Set umask before anything for security */
	umask(0027);

	strlcpy(filename, BASE_TMPFILE, BASE_TMPFILE_SIZE);
	int fd = mkstemp(filename);
	umask(oldumask);

	if (fd == -1)
		return -1;

	int i = 0;
	for (; i < hexbyte_strs_length; i++) {
		uint8_t byte = (uint8_t)strtol(hexbyte_strs[i], 0, 16);
		if (write(fd, (char *)&byte, 1) < 0) {
			return -1;
		}
	}

	/* Go back to the beginning of the file */
	lseek(fd, 0, SEEK_SET);
	return fd;
}

static bool pcep_obj_has_tlv(struct pcep_object_header *obj_hdr)
{
	if (obj_hdr->tlv_list == NULL) {
		return false;
	}

	return (obj_hdr->tlv_list->num_entries > 0);
}

void test_pcep_msg_read_pcep_initiate(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(filename, pcep_initiate_hexbyte_strs,
					   pcep_initiate_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_INITIATE);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_initiate_hexbyte_strs_length);

	/* Verify each of the object types */

	/* SRP object */
	double_linked_list_node *node = msg->obj_list->head;
	struct pcep_object_header *obj_hdr =
		(struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_SRP);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_SRP);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length,
			pcep_object_get_length_by_hdr(obj_hdr));
	CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

	/* LSP object and its TLV*/
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_LSP);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_LSP);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 20);
	CU_ASSERT_EQUAL(((struct pcep_object_lsp *)obj_hdr)->plsp_id, 0);
	CU_ASSERT_TRUE(((struct pcep_object_lsp *)obj_hdr)->flag_d);
	CU_ASSERT_TRUE(((struct pcep_object_lsp *)obj_hdr)->flag_a);
	CU_ASSERT_FALSE(((struct pcep_object_lsp *)obj_hdr)->flag_s);
	CU_ASSERT_FALSE(((struct pcep_object_lsp *)obj_hdr)->flag_r);
	CU_ASSERT_FALSE(((struct pcep_object_lsp *)obj_hdr)->flag_c);

	/* LSP TLV */
	CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));
	CU_ASSERT_EQUAL(obj_hdr->tlv_list->num_entries, 1);
	struct pcep_object_tlv_header *tlv =
		(struct pcep_object_tlv_header *)obj_hdr->tlv_list->head->data;
	CU_ASSERT_EQUAL(tlv->type, PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
	CU_ASSERT_EQUAL(tlv->encoded_tlv_length, 8);

	/* Endpoints object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ENDPOINTS);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV4);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length,
			pcep_object_get_length_by_hdr(obj_hdr));
	CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

	/* ERO object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ERO);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ERO);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 20);

	/* ERO Subobjects */
	double_linked_list *ero_subobj_list =
		((struct pcep_object_ro *)obj_hdr)->sub_objects;
	CU_ASSERT_PTR_NOT_NULL(ero_subobj_list);
	assert(ero_subobj_list != NULL);
	CU_ASSERT_EQUAL(ero_subobj_list->num_entries, 2);
	double_linked_list_node *subobj_node = ero_subobj_list->head;
	struct pcep_object_ro_subobj *subobj_hdr =
		(struct pcep_object_ro_subobj *)subobj_node->data;
	CU_ASSERT_EQUAL(subobj_hdr->ro_subobj_type, RO_SUBOBJ_TYPE_IPV4);
	struct in_addr ero_subobj_ip;
	inet_pton(AF_INET, "10.0.1.1", &ero_subobj_ip);
	CU_ASSERT_EQUAL(
		((struct pcep_ro_subobj_ipv4 *)subobj_hdr)->ip_addr.s_addr,
		ero_subobj_ip.s_addr);
	CU_ASSERT_EQUAL(
		((struct pcep_ro_subobj_ipv4 *)subobj_hdr)->prefix_length, 24);

	subobj_hdr =
		(struct pcep_object_ro_subobj *)subobj_node->next_node->data;
	CU_ASSERT_EQUAL(subobj_hdr->ro_subobj_type, RO_SUBOBJ_TYPE_IPV4);
	inet_pton(AF_INET, "10.0.7.4", &ero_subobj_ip);
	CU_ASSERT_EQUAL(
		((struct pcep_ro_subobj_ipv4 *)subobj_hdr)->ip_addr.s_addr,
		ero_subobj_ip.s_addr);
	CU_ASSERT_EQUAL(
		((struct pcep_ro_subobj_ipv4 *)subobj_hdr)->prefix_length, 24);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}


void test_pcep_msg_read_pcep_initiate2(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd =
		convert_hexstrs_to_binary(filename, pcep_initiate2_hexbyte_strs,
					  pcep_initiate2_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_INITIATE);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_initiate2_hexbyte_strs_length);

	/* Verify each of the object types */

	/* SRP object */
	double_linked_list_node *node = msg->obj_list->head;
	struct pcep_object_header *obj_hdr =
		(struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_SRP);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_SRP);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 20);
	CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));
	/* TODO test the TLVs */

	/* LSP object and its TLV*/
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_LSP);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_LSP);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 20);

	/* LSP TLV */
	CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));
	CU_ASSERT_EQUAL(obj_hdr->tlv_list->num_entries, 1);
	struct pcep_object_tlv_header *tlv =
		(struct pcep_object_tlv_header *)obj_hdr->tlv_list->head->data;
	CU_ASSERT_EQUAL(tlv->type, PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
	CU_ASSERT_EQUAL(tlv->encoded_tlv_length, 8);

	/* Endpoints object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ENDPOINTS);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ENDPOINT_IPV4);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length,
			pcep_object_get_length_by_hdr(obj_hdr));
	CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

	/* ERO object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ERO);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ERO);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 16);

	/* ERO Subobjects */
	double_linked_list *ero_subobj_list =
		((struct pcep_object_ro *)obj_hdr)->sub_objects;
	CU_ASSERT_PTR_NOT_NULL(ero_subobj_list);
	assert(ero_subobj_list != NULL);
	CU_ASSERT_EQUAL(ero_subobj_list->num_entries, 0);
	double_linked_list_node *subobj_node = ero_subobj_list->head;
	CU_ASSERT_PTR_NULL(subobj_node);
	/* We no longer support draft07 SR sub-object type=5, and only support
	type=36 struct pcep_object_ro_subobj *subobj_hdr = (struct
	pcep_object_ro_subobj *) subobj_node->data;
	CU_ASSERT_EQUAL(subobj_hdr->ro_subobj_type, RO_SUBOBJ_TYPE_SR);
	struct pcep_ro_subobj_sr *subobj_sr = (struct pcep_ro_subobj_sr *)
	subobj_hdr; CU_ASSERT_EQUAL(subobj_sr->nai_type,
	PCEP_SR_SUBOBJ_NAI_IPV4_NODE); CU_ASSERT_TRUE(subobj_sr->flag_m);
	CU_ASSERT_FALSE(subobj_sr->flag_c);
	CU_ASSERT_FALSE(subobj_sr->flag_s);
	CU_ASSERT_FALSE(subobj_sr->flag_f);
	CU_ASSERT_EQUAL(subobj_sr->sid, 65576960);
	CU_ASSERT_EQUAL(*((uint32_t *) subobj_sr->nai_list->head->data),
	0x01010101);
	*/

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_open(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(filename, pcep_open_odl_hexbyte_strs,
					   pcep_open_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_OPEN);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_open_hexbyte_strs_length);

	/* Verify the Open message */
	struct pcep_object_header *obj_hdr =
		(struct pcep_object_header *)msg->obj_list->head->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_OPEN);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 24);
	CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));

	/* Open TLV: Stateful PCE Capability */
	CU_ASSERT_EQUAL(obj_hdr->tlv_list->num_entries, 2);
	double_linked_list_node *tlv_node = obj_hdr->tlv_list->head;
	struct pcep_object_tlv_header *tlv =
		(struct pcep_object_tlv_header *)tlv_node->data;
	CU_ASSERT_EQUAL(tlv->type, PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(tlv->encoded_tlv_length, 4);

	/* Open TLV: SR PCE Capability */
	tlv_node = tlv_node->next_node;
	tlv = (struct pcep_object_tlv_header *)tlv_node->data;
	CU_ASSERT_EQUAL(tlv->type, PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(tlv->encoded_tlv_length, 4);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_update(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(filename, pcep_update_hexbyte_strs,
					   pcep_update_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 3);

	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_UPDATE);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_update_hexbyte_strs_length);

	/* Verify each of the object types */

	double_linked_list_node *node = msg->obj_list->head;

	/* SRP object */
	struct pcep_object_header *obj_hdr =
		(struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_SRP);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_SRP);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 20);
	CU_ASSERT_TRUE(pcep_obj_has_tlv(obj_hdr));

	/* SRP TLV */
	CU_ASSERT_EQUAL(obj_hdr->tlv_list->num_entries, 1);
	struct pcep_object_tlv_header *tlv =
		(struct pcep_object_tlv_header *)obj_hdr->tlv_list->head->data;
	CU_ASSERT_EQUAL(tlv->type, PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE);
	CU_ASSERT_EQUAL(tlv->encoded_tlv_length, 4);
	/* TODO verify the path setup type */

	/* LSP object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_LSP);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_LSP);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length,
			pcep_object_get_length_by_hdr(obj_hdr));
	CU_ASSERT_FALSE(pcep_obj_has_tlv(obj_hdr));

	/* ERO object */
	node = node->next_node;
	obj_hdr = (struct pcep_object_header *)node->data;
	CU_ASSERT_EQUAL(obj_hdr->object_class, PCEP_OBJ_CLASS_ERO);
	CU_ASSERT_EQUAL(obj_hdr->object_type, PCEP_OBJ_TYPE_ERO);
	CU_ASSERT_EQUAL(obj_hdr->encoded_object_length, 16);

	/* ERO Subobjects */
	double_linked_list *ero_subobj_list =
		((struct pcep_object_ro *)obj_hdr)->sub_objects;
	CU_ASSERT_PTR_NOT_NULL(ero_subobj_list);
	assert(ero_subobj_list != NULL);
	CU_ASSERT_EQUAL(ero_subobj_list->num_entries, 0);
	double_linked_list_node *subobj_node = ero_subobj_list->head;
	CU_ASSERT_PTR_NULL(subobj_node);
	/* We no longer support draft07 SR sub-object type=5, and only support
	type=36 struct pcep_object_ro_subobj *subobj_hdr = (struct
	pcep_object_ro_subobj *) subobj_node->data;
	CU_ASSERT_EQUAL(subobj_hdr->ro_subobj_type, RO_SUBOBJ_TYPE_SR);
	struct pcep_ro_subobj_sr *subobj_sr = (struct pcep_ro_subobj_sr *)
	subobj_hdr; CU_ASSERT_EQUAL(subobj_sr->nai_type,
	PCEP_SR_SUBOBJ_NAI_IPV4_NODE); CU_ASSERT_TRUE(subobj_sr->flag_m);
	CU_ASSERT_FALSE(subobj_sr->flag_c);
	CU_ASSERT_FALSE(subobj_sr->flag_s);
	CU_ASSERT_FALSE(subobj_sr->flag_f);
	CU_ASSERT_EQUAL(subobj_sr->sid, 65576960);
	CU_ASSERT_EQUAL(*((uint32_t *) subobj_sr->nai_list->head->data),
	0x01010101);
	*/

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_open_initiate(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(
		filename, pcep_open_initiate_odl_hexbyte_strs,
		pcep_open_initiate_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 2);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 1);
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_OPEN);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_open_hexbyte_strs_length);

	msg = (struct pcep_message *)msg_list->head->next_node->data;
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_INITIATE);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_initiate2_hexbyte_strs_length);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_open_cisco_pce(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(
		filename, pcep_open_cisco_pce_hexbyte_strs,
		pcep_open_cisco_pce_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_OPEN);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_open_hexbyte_strs_length);
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 1);

	/* Open object */
	struct pcep_object_open *open =
		(struct pcep_object_open *)msg->obj_list->head->data;
	CU_ASSERT_EQUAL(open->header.object_class, PCEP_OBJ_CLASS_OPEN);
	CU_ASSERT_EQUAL(open->header.object_type, PCEP_OBJ_TYPE_OPEN);
	CU_ASSERT_EQUAL(open->header.encoded_object_length, 24);
	CU_ASSERT_EQUAL(open->open_deadtimer, 120);
	CU_ASSERT_EQUAL(open->open_keepalive, 60);
	CU_ASSERT_EQUAL(open->open_sid, 0);
	CU_ASSERT_EQUAL(open->open_version, 1);
	CU_ASSERT_PTR_NOT_NULL(open->header.tlv_list);
	assert(open->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(open->header.tlv_list->num_entries, 2);

	/* Stateful PCE Capability TLV */
	double_linked_list_node *tlv_node = open->header.tlv_list->head;
	struct pcep_object_tlv_stateful_pce_capability *pce_cap_tlv =
		(struct pcep_object_tlv_stateful_pce_capability *)
			tlv_node->data;
	CU_ASSERT_EQUAL(pce_cap_tlv->header.type,
			PCEP_OBJ_TLV_TYPE_STATEFUL_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(pce_cap_tlv->header.encoded_tlv_length, 4);
	CU_ASSERT_TRUE(pce_cap_tlv->flag_u_lsp_update_capability);
	CU_ASSERT_TRUE(pce_cap_tlv->flag_i_lsp_instantiation_capability);
	CU_ASSERT_FALSE(pce_cap_tlv->flag_s_include_db_version);
	CU_ASSERT_FALSE(pce_cap_tlv->flag_t_triggered_resync);
	CU_ASSERT_FALSE(pce_cap_tlv->flag_d_delta_lsp_sync);
	CU_ASSERT_FALSE(pce_cap_tlv->flag_f_triggered_initial_sync);

	/* SR PCE Capability TLV */
	tlv_node = tlv_node->next_node;
	struct pcep_object_tlv_sr_pce_capability *sr_pce_cap_tlv =
		(struct pcep_object_tlv_sr_pce_capability *)tlv_node->data;
	CU_ASSERT_EQUAL(sr_pce_cap_tlv->header.type,
			PCEP_OBJ_TLV_TYPE_SR_PCE_CAPABILITY);
	CU_ASSERT_EQUAL(sr_pce_cap_tlv->header.encoded_tlv_length, 4);
	CU_ASSERT_FALSE(sr_pce_cap_tlv->flag_n);
	CU_ASSERT_FALSE(sr_pce_cap_tlv->flag_x);
	CU_ASSERT_EQUAL(sr_pce_cap_tlv->max_sid_depth, 10);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_update_cisco_pce(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(
		filename, pcep_update_cisco_pce_hexbyte_strs,
		pcep_update_cisco_pce_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_UPDATE);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_update_cisco_pce_hexbyte_strs_length);
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 4);

	/* SRP object */
	double_linked_list_node *obj_node = msg->obj_list->head;
	struct pcep_object_srp *srp = (struct pcep_object_srp *)obj_node->data;
	CU_ASSERT_EQUAL(srp->header.object_class, PCEP_OBJ_CLASS_SRP);
	CU_ASSERT_EQUAL(srp->header.object_type, PCEP_OBJ_TYPE_SRP);
	CU_ASSERT_EQUAL(srp->header.encoded_object_length, 20);
	CU_ASSERT_PTR_NOT_NULL(srp->header.tlv_list);
	assert(srp->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(srp->header.tlv_list->num_entries, 1);
	CU_ASSERT_EQUAL(srp->srp_id_number, 1);
	CU_ASSERT_FALSE(srp->flag_lsp_remove);

	/* SRP Path Setup Type TLV */
	double_linked_list_node *tlv_node = srp->header.tlv_list->head;
	struct pcep_object_tlv_path_setup_type *pst_tlv =
		(struct pcep_object_tlv_path_setup_type *)tlv_node->data;
	CU_ASSERT_EQUAL(pst_tlv->header.type,
			PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE);
	CU_ASSERT_EQUAL(pst_tlv->header.encoded_tlv_length, 4);
	CU_ASSERT_EQUAL(pst_tlv->path_setup_type, 1);

	/* LSP object */
	obj_node = obj_node->next_node;
	struct pcep_object_lsp *lsp = (struct pcep_object_lsp *)obj_node->data;
	CU_ASSERT_EQUAL(lsp->header.object_class, PCEP_OBJ_CLASS_LSP);
	CU_ASSERT_EQUAL(lsp->header.object_type, PCEP_OBJ_TYPE_LSP);
	CU_ASSERT_EQUAL(lsp->header.encoded_object_length, 24);
	CU_ASSERT_PTR_NOT_NULL(lsp->header.tlv_list);
	assert(lsp->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(lsp->header.tlv_list->num_entries, 1);
	CU_ASSERT_EQUAL(lsp->plsp_id, 524303);
	CU_ASSERT_EQUAL(lsp->operational_status, PCEP_LSP_OPERATIONAL_DOWN);
	CU_ASSERT_TRUE(lsp->flag_a);
	CU_ASSERT_TRUE(lsp->flag_c);
	CU_ASSERT_TRUE(lsp->flag_d);
	CU_ASSERT_FALSE(lsp->flag_r);
	CU_ASSERT_FALSE(lsp->flag_s);

	/* LSP Vendor Info TLV */
	tlv_node = lsp->header.tlv_list->head;
	struct pcep_object_tlv_vendor_info *vendor_tlv =
		(struct pcep_object_tlv_vendor_info *)tlv_node->data;
	CU_ASSERT_EQUAL(vendor_tlv->header.type, PCEP_OBJ_TLV_TYPE_VENDOR_INFO);
	CU_ASSERT_EQUAL(vendor_tlv->header.encoded_tlv_length, 12);
	CU_ASSERT_EQUAL(vendor_tlv->enterprise_number, 9);
	CU_ASSERT_EQUAL(vendor_tlv->enterprise_specific_info, 0x00030004);

	/* ERO object */
	obj_node = obj_node->next_node;
	struct pcep_object_ro *ero = (struct pcep_object_ro *)obj_node->data;
	CU_ASSERT_EQUAL(ero->header.object_class, PCEP_OBJ_CLASS_ERO);
	CU_ASSERT_EQUAL(ero->header.object_type, PCEP_OBJ_TYPE_ERO);
	CU_ASSERT_EQUAL(ero->header.encoded_object_length, 40);
	CU_ASSERT_PTR_NULL(ero->header.tlv_list);
	CU_ASSERT_PTR_NOT_NULL(ero->sub_objects);
	assert(ero->sub_objects != NULL);
	CU_ASSERT_EQUAL(ero->sub_objects->num_entries, 3);

	/* ERO Subobjects */
	double_linked_list_node *ero_subobj_node = ero->sub_objects->head;
	struct pcep_ro_subobj_sr *sr_subobj_ipv4_node =
		(struct pcep_ro_subobj_sr *)ero_subobj_node->data;
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->ro_subobj.ro_subobj_type,
			RO_SUBOBJ_TYPE_SR);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->ro_subobj.flag_subobj_loose_hop);
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->nai_type,
			PCEP_SR_SUBOBJ_NAI_IPV4_NODE);
	CU_ASSERT_TRUE(sr_subobj_ipv4_node->flag_m);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_c);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_f);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_s);
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->sid, 73748480);
	CU_ASSERT_EQUAL(
		*((uint32_t *)sr_subobj_ipv4_node->nai_list->head->data),
		htonl(0x0a0a0a05));

	ero_subobj_node = ero_subobj_node->next_node;
	sr_subobj_ipv4_node = (struct pcep_ro_subobj_sr *)ero_subobj_node->data;
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->ro_subobj.ro_subobj_type,
			RO_SUBOBJ_TYPE_SR);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->ro_subobj.flag_subobj_loose_hop);
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->nai_type,
			PCEP_SR_SUBOBJ_NAI_IPV4_NODE);
	CU_ASSERT_TRUE(sr_subobj_ipv4_node->flag_m);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_c);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_f);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_s);
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->sid, 73736192);
	CU_ASSERT_EQUAL(
		*((uint32_t *)sr_subobj_ipv4_node->nai_list->head->data),
		htonl(0x0a0a0a02));

	ero_subobj_node = ero_subobj_node->next_node;
	sr_subobj_ipv4_node = (struct pcep_ro_subobj_sr *)ero_subobj_node->data;
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->ro_subobj.ro_subobj_type,
			RO_SUBOBJ_TYPE_SR);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->ro_subobj.flag_subobj_loose_hop);
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->nai_type,
			PCEP_SR_SUBOBJ_NAI_IPV4_NODE);
	CU_ASSERT_TRUE(sr_subobj_ipv4_node->flag_m);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_c);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_f);
	CU_ASSERT_FALSE(sr_subobj_ipv4_node->flag_s);
	CU_ASSERT_EQUAL(sr_subobj_ipv4_node->sid, 73732096);
	CU_ASSERT_EQUAL(
		*((uint32_t *)sr_subobj_ipv4_node->nai_list->head->data),
		htonl(0x0a0a0a01));

	/* Metric object */
	obj_node = obj_node->next_node;
	struct pcep_object_metric *metric =
		(struct pcep_object_metric *)obj_node->data;
	CU_ASSERT_EQUAL(metric->header.object_class, PCEP_OBJ_CLASS_METRIC);
	CU_ASSERT_EQUAL(metric->header.object_type, PCEP_OBJ_TYPE_METRIC);
	CU_ASSERT_EQUAL(metric->header.encoded_object_length, 12);
	CU_ASSERT_PTR_NULL(metric->header.tlv_list);
	CU_ASSERT_FALSE(metric->flag_b);
	CU_ASSERT_FALSE(metric->flag_c);
	CU_ASSERT_EQUAL(metric->type, PCEP_METRIC_TE);
	CU_ASSERT_EQUAL(metric->value, 30.0);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_report_cisco_pcc(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(
		filename, pcep_report_cisco_pcc_hexbyte_strs,
		pcep_report_cisco_pcc_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_REPORT);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_report_cisco_pcc_hexbyte_strs_length);
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 8);

	/* SRP object */
	double_linked_list_node *obj_node = msg->obj_list->head;
	struct pcep_object_srp *srp = (struct pcep_object_srp *)obj_node->data;
	CU_ASSERT_EQUAL(srp->header.object_class, PCEP_OBJ_CLASS_SRP);
	CU_ASSERT_EQUAL(srp->header.object_type, PCEP_OBJ_TYPE_SRP);
	CU_ASSERT_EQUAL(srp->header.encoded_object_length, 20);
	CU_ASSERT_PTR_NOT_NULL(srp->header.tlv_list);
	assert(srp->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(srp->header.tlv_list->num_entries, 1);
	CU_ASSERT_EQUAL(srp->srp_id_number, 0);
	CU_ASSERT_FALSE(srp->flag_lsp_remove);

	/* SRP Path Setup Type TLV */
	double_linked_list_node *tlv_node = srp->header.tlv_list->head;
	struct pcep_object_tlv_path_setup_type *pst_tlv =
		(struct pcep_object_tlv_path_setup_type *)tlv_node->data;
	CU_ASSERT_EQUAL(pst_tlv->header.type,
			PCEP_OBJ_TLV_TYPE_PATH_SETUP_TYPE);
	CU_ASSERT_EQUAL(pst_tlv->header.encoded_tlv_length, 4);
	CU_ASSERT_EQUAL(pst_tlv->path_setup_type, 1);

	/* LSP object */
	obj_node = obj_node->next_node;
	struct pcep_object_lsp *lsp = (struct pcep_object_lsp *)obj_node->data;
	CU_ASSERT_EQUAL(lsp->header.object_class, PCEP_OBJ_CLASS_LSP);
	CU_ASSERT_EQUAL(lsp->header.object_type, PCEP_OBJ_TYPE_LSP);
	CU_ASSERT_EQUAL(lsp->header.encoded_object_length, 60);
	CU_ASSERT_PTR_NOT_NULL(lsp->header.tlv_list);
	/* The TLV with ID 65505 is now recognized, and its in the list */
	CU_ASSERT_EQUAL(lsp->header.tlv_list->num_entries, 3);
	CU_ASSERT_EQUAL(lsp->plsp_id, 524303);
	CU_ASSERT_EQUAL(lsp->operational_status, PCEP_LSP_OPERATIONAL_DOWN);
	CU_ASSERT_TRUE(lsp->flag_a);
	CU_ASSERT_TRUE(lsp->flag_d);
	CU_ASSERT_FALSE(lsp->flag_c);
	CU_ASSERT_FALSE(lsp->flag_r);
	CU_ASSERT_FALSE(lsp->flag_s);

	/* LSP IPv4 LSP Identifier TLV */
	tlv_node = lsp->header.tlv_list->head;
	struct pcep_object_tlv_ipv4_lsp_identifier *ipv4_lsp_id =
		(struct pcep_object_tlv_ipv4_lsp_identifier *)tlv_node->data;
	CU_ASSERT_EQUAL(ipv4_lsp_id->header.type,
			PCEP_OBJ_TLV_TYPE_IPV4_LSP_IDENTIFIERS);
	CU_ASSERT_EQUAL(ipv4_lsp_id->header.encoded_tlv_length, 16);
	CU_ASSERT_EQUAL(ipv4_lsp_id->ipv4_tunnel_sender.s_addr,
			htonl(0x0a0a0a06));
	CU_ASSERT_EQUAL(ipv4_lsp_id->ipv4_tunnel_endpoint.s_addr,
			htonl(0x0a0a0a01));
	CU_ASSERT_EQUAL(ipv4_lsp_id->extended_tunnel_id.s_addr,
			htonl(0x0a0a0a06));
	CU_ASSERT_EQUAL(ipv4_lsp_id->tunnel_id, 15);
	CU_ASSERT_EQUAL(ipv4_lsp_id->lsp_id, 2);

	/* LSP Symbolic Path Name TLV */
	tlv_node = tlv_node->next_node;
	struct pcep_object_tlv_symbolic_path_name *sym_path_name =
		(struct pcep_object_tlv_symbolic_path_name *)tlv_node->data;
	CU_ASSERT_EQUAL(sym_path_name->header.type,
			PCEP_OBJ_TLV_TYPE_SYMBOLIC_PATH_NAME);
	CU_ASSERT_EQUAL(sym_path_name->header.encoded_tlv_length, 13);
	CU_ASSERT_EQUAL(sym_path_name->symbolic_path_name_length, 13);
	CU_ASSERT_EQUAL(
		strncmp(sym_path_name->symbolic_path_name, "cfg_R6-to-R1", 13),
		0);

	/* ERO object */
	obj_node = obj_node->next_node;
	struct pcep_object_ro *ero = (struct pcep_object_ro *)obj_node->data;
	CU_ASSERT_EQUAL(ero->header.object_class, PCEP_OBJ_CLASS_ERO);
	CU_ASSERT_EQUAL(ero->header.object_type, PCEP_OBJ_TYPE_ERO);
	CU_ASSERT_EQUAL(ero->header.encoded_object_length, 4);
	CU_ASSERT_PTR_NULL(ero->header.tlv_list);
	CU_ASSERT_PTR_NOT_NULL(ero->sub_objects);
	assert(ero->sub_objects != NULL);
	CU_ASSERT_EQUAL(ero->sub_objects->num_entries, 0);

	/* LSPA object */
	obj_node = obj_node->next_node;
	struct pcep_object_lspa *lspa =
		(struct pcep_object_lspa *)obj_node->data;
	CU_ASSERT_EQUAL(lspa->header.object_class, PCEP_OBJ_CLASS_LSPA);
	CU_ASSERT_EQUAL(lspa->header.object_type, PCEP_OBJ_TYPE_LSPA);
	CU_ASSERT_EQUAL(lspa->header.encoded_object_length, 20);
	CU_ASSERT_PTR_NULL(lspa->header.tlv_list);
	CU_ASSERT_TRUE(lspa->flag_local_protection);
	CU_ASSERT_EQUAL(lspa->holding_priority, 7);
	CU_ASSERT_EQUAL(lspa->setup_priority, 7);
	CU_ASSERT_EQUAL(lspa->lspa_include_all, 0);
	CU_ASSERT_EQUAL(lspa->lspa_include_any, 0);
	CU_ASSERT_EQUAL(lspa->lspa_exclude_any, 0);

	/* Bandwidth object 1 */
	obj_node = obj_node->next_node;
	struct pcep_object_bandwidth *bandwidth =
		(struct pcep_object_bandwidth *)obj_node->data;
	CU_ASSERT_EQUAL(bandwidth->header.object_class,
			PCEP_OBJ_CLASS_BANDWIDTH);
	CU_ASSERT_EQUAL(bandwidth->header.object_type,
			PCEP_OBJ_TYPE_BANDWIDTH_REQ);
	CU_ASSERT_EQUAL(bandwidth->header.encoded_object_length, 8);
	CU_ASSERT_EQUAL(bandwidth->bandwidth, 0);

	/* Bandwidth object 2 */
	obj_node = obj_node->next_node;
	bandwidth = (struct pcep_object_bandwidth *)obj_node->data;
	CU_ASSERT_EQUAL(bandwidth->header.object_class,
			PCEP_OBJ_CLASS_BANDWIDTH);
	CU_ASSERT_EQUAL(bandwidth->header.object_type,
			PCEP_OBJ_TYPE_BANDWIDTH_CISCO);
	CU_ASSERT_EQUAL(bandwidth->header.encoded_object_length, 8);
	CU_ASSERT_EQUAL(bandwidth->bandwidth, 0);

	/* Metric object 1 */
	obj_node = obj_node->next_node;
	struct pcep_object_metric *metric =
		(struct pcep_object_metric *)obj_node->data;
	CU_ASSERT_EQUAL(metric->header.object_class, PCEP_OBJ_CLASS_METRIC);
	CU_ASSERT_EQUAL(metric->header.object_type, PCEP_OBJ_TYPE_METRIC);
	CU_ASSERT_EQUAL(metric->header.encoded_object_length, 12);
	CU_ASSERT_PTR_NULL(metric->header.tlv_list);
	CU_ASSERT_FALSE(metric->flag_b);
	CU_ASSERT_FALSE(metric->flag_c);
	CU_ASSERT_EQUAL(metric->type, PCEP_METRIC_TE);
	CU_ASSERT_EQUAL(metric->value, 0);

	/* Metric object 2 */
	obj_node = obj_node->next_node;
	metric = (struct pcep_object_metric *)obj_node->data;
	CU_ASSERT_EQUAL(metric->header.object_class, PCEP_OBJ_CLASS_METRIC);
	CU_ASSERT_EQUAL(metric->header.object_type, PCEP_OBJ_TYPE_METRIC);
	CU_ASSERT_EQUAL(metric->header.encoded_object_length, 12);
	CU_ASSERT_PTR_NULL(metric->header.tlv_list);
	CU_ASSERT_TRUE(metric->flag_b);
	CU_ASSERT_FALSE(metric->flag_c);
	CU_ASSERT_EQUAL(metric->type, PCEP_METRIC_AGGREGATE_BW);
	CU_ASSERT_EQUAL(metric->value, 16.0);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_pcep_msg_read_pcep_initiate_cisco_pcc(void)
{
	char filename[BASE_TMPFILE_SIZE];

	int fd = convert_hexstrs_to_binary(
		filename, pcep_initiate_cisco_pcc_hexbyte_strs,
		pcep_initiate_cisco_pcc_hexbyte_strs_length);
	if (fd == -1) {
		CU_ASSERT_TRUE(fd >= 0);
		return;
	}
	double_linked_list *msg_list = pcep_msg_read(fd);
	CU_ASSERT_PTR_NOT_NULL(msg_list);
	assert(msg_list != NULL);
	CU_ASSERT_EQUAL(msg_list->num_entries, 1);

	struct pcep_message *msg = (struct pcep_message *)msg_list->head->data;
	CU_ASSERT_EQUAL(msg->msg_header->type, PCEP_TYPE_INITIATE);
	CU_ASSERT_EQUAL(msg->encoded_message_length,
			pcep_initiate_cisco_pcc_hexbyte_strs_length);
	CU_ASSERT_EQUAL(msg->obj_list->num_entries, 6);

	/* SRP object */
	double_linked_list_node *obj_node = msg->obj_list->head;
	struct pcep_object_srp *srp = (struct pcep_object_srp *)obj_node->data;
	CU_ASSERT_EQUAL(srp->header.object_class, PCEP_OBJ_CLASS_SRP);
	CU_ASSERT_EQUAL(srp->header.object_type, PCEP_OBJ_TYPE_SRP);
	CU_ASSERT_EQUAL(srp->header.encoded_object_length, 20);
	CU_ASSERT_PTR_NOT_NULL(srp->header.tlv_list);
	assert(srp->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(srp->header.tlv_list->num_entries, 1);
	CU_ASSERT_EQUAL(srp->srp_id_number, 1);
	CU_ASSERT_FALSE(srp->flag_lsp_remove);

	/* LSP object */
	obj_node = obj_node->next_node;
	struct pcep_object_lsp *lsp = (struct pcep_object_lsp *)obj_node->data;
	CU_ASSERT_EQUAL(lsp->header.object_class, PCEP_OBJ_CLASS_LSP);
	CU_ASSERT_EQUAL(lsp->header.object_type, PCEP_OBJ_TYPE_LSP);
	CU_ASSERT_EQUAL(lsp->header.encoded_object_length, 48);
	CU_ASSERT_PTR_NOT_NULL(lsp->header.tlv_list);
	assert(lsp->header.tlv_list != NULL);
	CU_ASSERT_EQUAL(lsp->header.tlv_list->num_entries, 2);
	CU_ASSERT_EQUAL(lsp->plsp_id, 0);
	CU_ASSERT_EQUAL(lsp->operational_status, PCEP_LSP_OPERATIONAL_DOWN);
	CU_ASSERT_TRUE(lsp->flag_a);
	CU_ASSERT_TRUE(lsp->flag_d);
	CU_ASSERT_TRUE(lsp->flag_c);
	CU_ASSERT_FALSE(lsp->flag_r);
	CU_ASSERT_FALSE(lsp->flag_s);

	/* Endpoint object */
	obj_node = obj_node->next_node;
	struct pcep_object_endpoints_ipv4 *endpoint =
		(struct pcep_object_endpoints_ipv4 *)obj_node->data;
	CU_ASSERT_EQUAL(endpoint->header.object_class,
			PCEP_OBJ_CLASS_ENDPOINTS);
	CU_ASSERT_EQUAL(endpoint->header.object_type,
			PCEP_OBJ_TYPE_ENDPOINT_IPV4);
	CU_ASSERT_EQUAL(endpoint->header.encoded_object_length, 12);
	CU_ASSERT_PTR_NULL(endpoint->header.tlv_list);
	CU_ASSERT_EQUAL(endpoint->src_ipv4.s_addr, htonl(0x0a0a0a0a));
	CU_ASSERT_EQUAL(endpoint->dst_ipv4.s_addr, htonl(0x0a0a0a04));

	/* Inter-Layer object */
	obj_node = obj_node->next_node;
	struct pcep_object_inter_layer *inter_layer =
		(struct pcep_object_inter_layer *)obj_node->data;
	CU_ASSERT_EQUAL(inter_layer->header.object_class,
			PCEP_OBJ_CLASS_INTER_LAYER);
	CU_ASSERT_EQUAL(inter_layer->header.object_type,
			PCEP_OBJ_TYPE_INTER_LAYER);
	CU_ASSERT_EQUAL(inter_layer->header.encoded_object_length, 8);
	CU_ASSERT_PTR_NULL(inter_layer->header.tlv_list);
	CU_ASSERT_TRUE(inter_layer->flag_i);
	CU_ASSERT_FALSE(inter_layer->flag_m);
	CU_ASSERT_TRUE(inter_layer->flag_t);

	/* Switch-Layer object */
	obj_node = obj_node->next_node;
	struct pcep_object_switch_layer *switch_layer =
		(struct pcep_object_switch_layer *)obj_node->data;
	CU_ASSERT_EQUAL(switch_layer->header.object_class,
			PCEP_OBJ_CLASS_SWITCH_LAYER);
	CU_ASSERT_EQUAL(switch_layer->header.object_type,
			PCEP_OBJ_TYPE_SWITCH_LAYER);
	CU_ASSERT_EQUAL(switch_layer->header.encoded_object_length, 8);
	CU_ASSERT_PTR_NULL(switch_layer->header.tlv_list);
	assert(switch_layer->header.tlv_list == NULL);
	CU_ASSERT_PTR_NOT_NULL(switch_layer->switch_layer_rows);
	assert(switch_layer->switch_layer_rows != NULL);
	CU_ASSERT_EQUAL(switch_layer->switch_layer_rows->num_entries, 1);
	struct pcep_object_switch_layer_row *switch_layer_row =
		(struct pcep_object_switch_layer_row *)
			switch_layer->switch_layer_rows->head->data;
	CU_ASSERT_EQUAL(switch_layer_row->lsp_encoding_type, 0);
	CU_ASSERT_EQUAL(switch_layer_row->switching_type, 0);
	CU_ASSERT_FALSE(switch_layer_row->flag_i);

	/* ERO object */
	obj_node = obj_node->next_node;
	struct pcep_object_ro *ero = (struct pcep_object_ro *)obj_node->data;
	CU_ASSERT_EQUAL(ero->header.object_class, PCEP_OBJ_CLASS_ERO);
	CU_ASSERT_EQUAL(ero->header.object_type, PCEP_OBJ_TYPE_ERO);
	CU_ASSERT_EQUAL(ero->header.encoded_object_length, 4);
	CU_ASSERT_PTR_NULL(ero->header.tlv_list);

	pcep_msg_free_message_list(msg_list);
	close(fd);
	unlink(filename);
}

void test_validate_message_header(void)
{
	uint8_t pcep_message_invalid_version[] = {0x40, 0x01, 0x04, 0x00};
	uint8_t pcep_message_invalid_flags[] = {0x22, 0x01, 0x04, 0x00};
	uint8_t pcep_message_invalid_length[] = {0x20, 0x01, 0x00, 0x00};
	uint8_t pcep_message_invalid_type[] = {0x20, 0xff, 0x04, 0x00};
	uint8_t pcep_message_valid[] = {0x20, 0x01, 0x00, 0x04};

	/* Verify invalid message header version */
	CU_ASSERT_TRUE(
		pcep_decode_validate_msg_header(pcep_message_invalid_version)
		< 0);

	/* Verify invalid message header flags */
	CU_ASSERT_TRUE(
		pcep_decode_validate_msg_header(pcep_message_invalid_flags)
		< 0);

	/* Verify invalid message header lengths */
	CU_ASSERT_TRUE(
		pcep_decode_validate_msg_header(pcep_message_invalid_length)
		< 0);
	pcep_message_invalid_length[3] = 0x05;
	CU_ASSERT_TRUE(
		pcep_decode_validate_msg_header(pcep_message_invalid_length)
		< 0);

	/* Verify invalid message header types */
	CU_ASSERT_TRUE(
		pcep_decode_validate_msg_header(pcep_message_invalid_type) < 0);
	pcep_message_invalid_type[1] = 0x00;
	CU_ASSERT_TRUE(
		pcep_decode_validate_msg_header(pcep_message_invalid_type) < 0);

	/* Verify a valid message header */
	CU_ASSERT_EQUAL(pcep_decode_validate_msg_header(pcep_message_valid), 4);
}

/* Internal util function */
struct pcep_message *create_message(uint8_t msg_type, uint8_t obj1_class,
				    uint8_t obj2_class, uint8_t obj3_class,
				    uint8_t obj4_class)
{
	struct pcep_message *msg =
		pceplib_malloc(PCEPLIB_MESSAGES, sizeof(struct pcep_message));
	msg->obj_list = dll_initialize();
	msg->msg_header = pceplib_malloc(PCEPLIB_MESSAGES,
					 sizeof(struct pcep_message_header));
	msg->msg_header->type = msg_type;
	msg->encoded_message = NULL;

	if (obj1_class > 0) {
		struct pcep_object_header *obj_hdr = pceplib_malloc(
			PCEPLIB_MESSAGES, sizeof(struct pcep_object_header));
		obj_hdr->object_class = obj1_class;
		obj_hdr->tlv_list = NULL;
		dll_append(msg->obj_list, obj_hdr);
	}

	if (obj2_class > 0) {
		struct pcep_object_header *obj_hdr = pceplib_malloc(
			PCEPLIB_MESSAGES, sizeof(struct pcep_object_header));
		obj_hdr->object_class = obj2_class;
		obj_hdr->tlv_list = NULL;
		dll_append(msg->obj_list, obj_hdr);
	}

	if (obj3_class > 0) {
		struct pcep_object_header *obj_hdr = pceplib_malloc(
			PCEPLIB_MESSAGES, sizeof(struct pcep_object_header));
		obj_hdr->object_class = obj3_class;
		obj_hdr->tlv_list = NULL;
		dll_append(msg->obj_list, obj_hdr);
	}

	if (obj4_class > 0) {
		struct pcep_object_header *obj_hdr = pceplib_malloc(
			PCEPLIB_MESSAGES, sizeof(struct pcep_object_header));
		obj_hdr->object_class = obj4_class;
		obj_hdr->tlv_list = NULL;
		dll_append(msg->obj_list, obj_hdr);
	}

	return msg;
}

void test_validate_message_objects(void)
{
	/* Valid Open message */
	struct pcep_message *msg =
		create_message(PCEP_TYPE_OPEN, PCEP_OBJ_CLASS_OPEN, 0, 0, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid KeepAlive message */
	msg = create_message(PCEP_TYPE_KEEPALIVE, 0, 0, 0, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid PcReq message */
	/* Using object_class=255 to verify it can take any object */
	msg = create_message(PCEP_TYPE_PCREQ, PCEP_OBJ_CLASS_RP,
			     PCEP_OBJ_CLASS_ENDPOINTS, any_obj_class, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid PcRep message */
	msg = create_message(PCEP_TYPE_PCREP, PCEP_OBJ_CLASS_RP, any_obj_class,
			     0, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid Notify message */
	msg = create_message(PCEP_TYPE_PCNOTF, PCEP_OBJ_CLASS_NOTF,
			     any_obj_class, 0, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid Error message */
	msg = create_message(PCEP_TYPE_ERROR, PCEP_OBJ_CLASS_ERROR,
			     any_obj_class, 0, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid Close message */
	msg = create_message(PCEP_TYPE_CLOSE, PCEP_OBJ_CLASS_CLOSE, 0, 0, 0);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid Report message */
	msg = create_message(PCEP_TYPE_REPORT, PCEP_OBJ_CLASS_SRP,
			     PCEP_OBJ_CLASS_LSP, any_obj_class, any_obj_class);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid Update message */
	msg = create_message(PCEP_TYPE_UPDATE, PCEP_OBJ_CLASS_SRP,
			     PCEP_OBJ_CLASS_LSP, any_obj_class, any_obj_class);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Valid Initiate message */
	msg = create_message(PCEP_TYPE_INITIATE, PCEP_OBJ_CLASS_SRP,
			     PCEP_OBJ_CLASS_LSP, any_obj_class, any_obj_class);
	CU_ASSERT_TRUE(validate_message_objects(msg));
	pcep_msg_free_message(msg);
}

void test_validate_message_objects_invalid(void)
{
	/* unsupported message ID = 0
	 * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
	struct pcep_message *msg = create_message(0, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Open message
	 * {PCEP_OBJ_CLASS_OPEN, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
	msg = create_message(PCEP_TYPE_OPEN, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_OPEN, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_OPEN, PCEP_OBJ_CLASS_OPEN, any_obj_class,
			     0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* KeepAlive message
	 * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
	msg = create_message(PCEP_TYPE_KEEPALIVE, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* PcReq message
	 * {PCEP_OBJ_CLASS_RP, PCEP_OBJ_CLASS_ENDPOINTS, ANY_OBJECT, ANY_OBJECT}
	 */
	msg = create_message(PCEP_TYPE_PCREQ, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_PCREQ, PCEP_OBJ_CLASS_RP, any_obj_class,
			     0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* PcRep message
	 * {PCEP_OBJ_CLASS_RP, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT} */
	msg = create_message(PCEP_TYPE_PCREP, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_PCREP, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Notify message
	 * {PCEP_OBJ_CLASS_NOTF, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT} */
	msg = create_message(PCEP_TYPE_PCNOTF, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_PCNOTF, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Error message
	 * {PCEP_OBJ_CLASS_ERROR, ANY_OBJECT, ANY_OBJECT, ANY_OBJECT} */
	msg = create_message(PCEP_TYPE_ERROR, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_ERROR, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Close message
	 * {PCEP_OBJ_CLASS_CLOSE, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
	msg = create_message(PCEP_TYPE_CLOSE, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_CLOSE, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* unsupported message ID = 8
	 * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
	msg = create_message(8, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* unsupported message ID = 9
	 * {NO_OBJECT, NO_OBJECT, NO_OBJECT, NO_OBJECT} */
	msg = create_message(9, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Report message
	 * {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT} */
	msg = create_message(PCEP_TYPE_REPORT, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_REPORT, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_REPORT, PCEP_OBJ_CLASS_SRP, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_REPORT, PCEP_OBJ_CLASS_SRP,
			     any_obj_class, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Update message
	 * {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT} */
	msg = create_message(PCEP_TYPE_UPDATE, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_UPDATE, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_UPDATE, PCEP_OBJ_CLASS_SRP, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_UPDATE, PCEP_OBJ_CLASS_SRP,
			     any_obj_class, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	/* Initiate message
	 * {PCEP_OBJ_CLASS_SRP, PCEP_OBJ_CLASS_LSP, ANY_OBJECT, ANY_OBJECT} */
	msg = create_message(PCEP_TYPE_INITIATE, 0, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_INITIATE, any_obj_class, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_INITIATE, PCEP_OBJ_CLASS_SRP, 0, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);

	msg = create_message(PCEP_TYPE_INITIATE, PCEP_OBJ_CLASS_SRP,
			     any_obj_class, 0, 0);
	CU_ASSERT_FALSE(validate_message_objects(msg));
	pcep_msg_free_message(msg);
}
