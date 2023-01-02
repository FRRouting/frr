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
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdint.h>

#include <CUnit/CUnit.h>

#include "pcep_utils_memory.h"
#include "pcep_utils_memory_test.h"

void *test_pceplib_malloc(void *mem_type, size_t size);
void *test_pceplib_calloc(void *mem_type, size_t size);
void *test_pceplib_realloc(void *mem_type, void *ptr, size_t size);
void *test_pceplib_strdup(void *mem_type, const char *str);
void test_pceplib_free(void *mem_type, void *ptr);
void verify_memory_type(struct pceplib_memory_type *mt, uint32_t num_alloc,
			uint32_t alloc_bytes, uint32_t num_free,
			uint32_t free_bytes);
void verify_ext_memory_type(void *mt, int num_malloc_calls,
			    int num_calloc_calls, int num_realloc_calls,
			    int num_strdup_calls, int num_free_calls);

struct test_memory_type {
	int num_malloc_calls;
	int num_calloc_calls;
	int num_realloc_calls;
	int num_strdup_calls;
	int num_free_calls;
};

void *test_pceplib_malloc(void *mem_type, size_t size)
{
	((struct test_memory_type *)mem_type)->num_malloc_calls++;
	return malloc(size);
}

void *test_pceplib_calloc(void *mem_type, size_t size)
{
	((struct test_memory_type *)mem_type)->num_calloc_calls++;
	return calloc(1, size);
}

void *test_pceplib_realloc(void *mem_type, void *ptr, size_t size)
{
	((struct test_memory_type *)mem_type)->num_realloc_calls++;
	return realloc(ptr, size);
}

void *test_pceplib_strdup(void *mem_type, const char *str)
{
	((struct test_memory_type *)mem_type)->num_strdup_calls++;
	return strdup(str);
}

void test_pceplib_free(void *mem_type, void *ptr)
{
	((struct test_memory_type *)mem_type)->num_free_calls++;
	free(ptr);
}

void verify_memory_type(struct pceplib_memory_type *mt, uint32_t num_alloc,
			uint32_t alloc_bytes, uint32_t num_free,
			uint32_t free_bytes)
{
	CU_ASSERT_EQUAL(num_alloc, mt->num_allocates);
	CU_ASSERT_EQUAL(alloc_bytes, mt->total_bytes_allocated);
	CU_ASSERT_EQUAL(num_free, mt->num_frees);
	CU_ASSERT_EQUAL(free_bytes, mt->total_bytes_freed);
}

void verify_ext_memory_type(void *mt, int num_malloc_calls,
			    int num_calloc_calls, int num_realloc_calls,
			    int num_strdup_calls, int num_free_calls)
{
	struct test_memory_type *mt_ptr = (struct test_memory_type *)mt;
	CU_ASSERT_EQUAL(num_malloc_calls, mt_ptr->num_malloc_calls);
	CU_ASSERT_EQUAL(num_calloc_calls, mt_ptr->num_calloc_calls);
	CU_ASSERT_EQUAL(num_realloc_calls, mt_ptr->num_realloc_calls);
	CU_ASSERT_EQUAL(num_strdup_calls, mt_ptr->num_strdup_calls);
	CU_ASSERT_EQUAL(num_free_calls, mt_ptr->num_free_calls);
}

void test_memory_internal_impl()
{
	int alloc_size = 100;
	struct pceplib_memory_type *pceplib_infra_ptr =
		(struct pceplib_memory_type *)PCEPLIB_INFRA;
	struct pceplib_memory_type *pceplib_messages_ptr =
		(struct pceplib_memory_type *)PCEPLIB_MESSAGES;
	int alloc_counter = 1;
	int free_counter = 1;

	/* reset the memory type counters for easier testing */
	pceplib_infra_ptr->num_allocates =
		pceplib_infra_ptr->total_bytes_allocated =
			pceplib_infra_ptr->num_frees =
				pceplib_infra_ptr->total_bytes_freed = 0;
	pceplib_messages_ptr->num_allocates =
		pceplib_messages_ptr->total_bytes_allocated =
			pceplib_messages_ptr->num_frees =
				pceplib_messages_ptr->total_bytes_freed = 0;

	/* Make sure nothing crashes when all these are set NULL, since the
	 * internal default values should still be used. */
	pceplib_memory_initialize(NULL, NULL, NULL, NULL, NULL, NULL, NULL);

	/* Test malloc() */
	void *ptr = pceplib_malloc(PCEPLIB_INFRA, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_INFRA, ptr);
	verify_memory_type(pceplib_infra_ptr, alloc_counter, alloc_size,
			   free_counter++, 0);

	/* Test calloc() */
	ptr = pceplib_calloc(PCEPLIB_INFRA, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_INFRA, ptr);
	alloc_counter++;
	verify_memory_type(pceplib_infra_ptr, alloc_counter,
			   alloc_size * alloc_counter, free_counter++, 0);

	/* Test realloc() */
	ptr = pceplib_malloc(PCEPLIB_INFRA, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	ptr = pceplib_realloc(PCEPLIB_INFRA, ptr, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_INFRA, ptr);
	alloc_counter += 2;
	verify_memory_type(pceplib_infra_ptr, alloc_counter,
			   alloc_size * alloc_counter, free_counter++, 0);

	/* Test strdup() */
	ptr = pceplib_malloc(PCEPLIB_INFRA, alloc_size);
	/* Make strdup duplicate (alloc_size - 1) bytes */
	memset(ptr, 'a', alloc_size);
	((char *)ptr)[alloc_size - 1] = '\0';
	char *str = pceplib_strdup(PCEPLIB_INFRA, (char *)ptr);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_INFRA, ptr);
	pceplib_free(PCEPLIB_INFRA, str);
	alloc_counter += 2;
	free_counter++;
	verify_memory_type(pceplib_infra_ptr, alloc_counter,
			   (alloc_size * alloc_counter) - 1, free_counter, 0);

	/* Make sure only the pceplib_infra_ptr memory counters are incremented
	 */
	verify_memory_type(pceplib_messages_ptr, 0, 0, 0, 0);
}

void test_memory_external_impl()
{
	int alloc_size = 100;
	struct pceplib_memory_type *pceplib_infra_ptr =
		(struct pceplib_memory_type *)PCEPLIB_INFRA;
	struct pceplib_memory_type *pceplib_messages_ptr =
		(struct pceplib_memory_type *)PCEPLIB_MESSAGES;

	/* reset the internal memory type counters to later verify they are NOT
	 * incremented since an external impl was provided */
	pceplib_infra_ptr->num_allocates =
		pceplib_infra_ptr->total_bytes_allocated =
			pceplib_infra_ptr->num_frees =
				pceplib_infra_ptr->total_bytes_freed = 0;
	pceplib_messages_ptr->num_allocates =
		pceplib_messages_ptr->total_bytes_allocated =
			pceplib_messages_ptr->num_frees =
				pceplib_messages_ptr->total_bytes_freed = 0;

	/* Setup the external memory type */
	struct test_memory_type infra_mt, messages_mt;
	void *infra_ptr = &infra_mt;
	void *messages_ptr = &messages_mt;
	memset(infra_ptr, 0, sizeof(struct test_memory_type));
	memset(messages_ptr, 0, sizeof(struct test_memory_type));
	int free_counter = 1;

	/* Initialize the PCEPlib memory system with an external implementation
	 */
	pceplib_memory_initialize(infra_ptr, messages_ptr, test_pceplib_malloc,
				  test_pceplib_calloc, test_pceplib_realloc,
				  test_pceplib_strdup, test_pceplib_free);

	/* Test malloc() */
	void *ptr = pceplib_malloc(PCEPLIB_MESSAGES, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_MESSAGES, ptr);
	verify_ext_memory_type(messages_ptr, 1, 0, 0, 0, free_counter++);

	/* Test calloc() */
	ptr = pceplib_calloc(PCEPLIB_MESSAGES, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_MESSAGES, ptr);
	verify_ext_memory_type(messages_ptr, 1, 1, 0, 0, free_counter++);

	/* Test realloc() */
	ptr = pceplib_malloc(PCEPLIB_MESSAGES, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	ptr = pceplib_realloc(PCEPLIB_MESSAGES, ptr, alloc_size);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_MESSAGES, ptr);
	verify_ext_memory_type(messages_ptr, 2, 1, 1, 0, free_counter++);

	/* Test strdup() */
	ptr = pceplib_malloc(PCEPLIB_MESSAGES, alloc_size);
	/* Make strdup duplicate (alloc_size - 1) bytes */
	memset(ptr, 'a', alloc_size);
	((char *)ptr)[alloc_size - 1] = '\0';
	char *str = pceplib_strdup(PCEPLIB_MESSAGES, (char *)ptr);
	CU_ASSERT_PTR_NOT_NULL(ptr);
	pceplib_free(PCEPLIB_MESSAGES, ptr);
	pceplib_free(PCEPLIB_MESSAGES, str);
	verify_ext_memory_type(messages_ptr, 3, 1, 1, 1, free_counter + 1);

	/* Make sure the internal memory counters are NOT incremented */
	verify_memory_type(pceplib_infra_ptr, 0, 0, 0, 0);
	verify_memory_type(pceplib_messages_ptr, 0, 0, 0, 0);

	verify_ext_memory_type(infra_ptr, 0, 0, 0, 0, 0);
}
