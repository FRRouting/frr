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
#include <string.h>

#include "pcep_utils_logging.h"
#include "pcep_utils_memory.h"

/* Set default values for memory function pointers */
static pceplib_malloc_func mfunc = NULL;
static pceplib_calloc_func cfunc = NULL;
static pceplib_realloc_func rfunc = NULL;
static pceplib_strdup_func sfunc = NULL;
static pceplib_free_func ffunc = NULL;

/* Internal memory types */
struct pceplib_memory_type pceplib_infra_mt = {
	.memory_type_name = "PCEPlib Infrastructure memory",
	.total_bytes_allocated = 0,
	.num_allocates = 0,
	.total_bytes_freed = 0,
	.num_frees = 0};
struct pceplib_memory_type pceplib_messages_mt = {
	.memory_type_name = "PCEPlib Messages memory",
	.total_bytes_allocated = 0,
	.num_allocates = 0,
	.total_bytes_freed = 0,
	.num_frees = 0};

/* The memory type pointers default to the internal memory types */
void *PCEPLIB_INFRA = &pceplib_infra_mt;
void *PCEPLIB_MESSAGES = &pceplib_messages_mt;

/* Initialize memory function pointers and memory type pointers */
bool pceplib_memory_initialize(void *pceplib_infra_mt,
			       void *pceplib_messages_mt,
			       pceplib_malloc_func mf, pceplib_calloc_func cf,
			       pceplib_realloc_func rf, pceplib_strdup_func sf,
			       pceplib_free_func ff)
{
	PCEPLIB_INFRA = (pceplib_infra_mt ? pceplib_infra_mt : PCEPLIB_INFRA);
	PCEPLIB_MESSAGES =
		(pceplib_messages_mt ? pceplib_messages_mt : PCEPLIB_MESSAGES);

	mfunc = (mf ? mf : mfunc);
	cfunc = (cf ? cf : cfunc);
	rfunc = (rf ? rf : rfunc);
	sfunc = (sf ? sf : sfunc);
	ffunc = (ff ? ff : ffunc);

	return true;
}

void pceplib_memory_reset(void)
{
	pceplib_infra_mt.total_bytes_allocated = 0;
	pceplib_infra_mt.num_allocates = 0;
	pceplib_infra_mt.total_bytes_freed = 0;
	pceplib_infra_mt.num_frees = 0;

	pceplib_messages_mt.total_bytes_allocated = 0;
	pceplib_messages_mt.num_allocates = 0;
	pceplib_messages_mt.total_bytes_freed = 0;
	pceplib_messages_mt.num_frees = 0;
}

void pceplib_memory_dump(void)
{
	if (PCEPLIB_INFRA) {
		pcep_log(
			LOG_INFO,
			"%s: Memory Type [%s] Total [allocs, alloc bytes, frees] [%d, %d, %d]",
			__func__,
			((struct pceplib_memory_type *)PCEPLIB_INFRA)
				->memory_type_name,
			((struct pceplib_memory_type *)PCEPLIB_INFRA)
				->num_allocates,
			((struct pceplib_memory_type *)PCEPLIB_INFRA)
				->total_bytes_allocated,
			((struct pceplib_memory_type *)PCEPLIB_INFRA)
				->num_frees);
	}

	if (PCEPLIB_MESSAGES) {
		pcep_log(
			LOG_INFO,
			"%s: Memory Type [%s] Total [allocs, alloc bytes, frees] [%d, %d, %d]",
			__func__,
			((struct pceplib_memory_type *)PCEPLIB_MESSAGES)
				->memory_type_name,
			((struct pceplib_memory_type *)PCEPLIB_MESSAGES)
				->num_allocates,
			((struct pceplib_memory_type *)PCEPLIB_MESSAGES)
				->total_bytes_allocated,
			((struct pceplib_memory_type *)PCEPLIB_MESSAGES)
				->num_frees);
	}
}

/* PCEPlib memory functions:
 * They either call the supplied function pointers, or use the internal
 * implementations, which just increment simple counters and call the
 * C stdlib memory implementations. */

void *pceplib_malloc(void *mem_type, size_t size)
{
	if (mfunc == NULL) {
		if (mem_type != NULL) {
			((struct pceplib_memory_type *)mem_type)
				->total_bytes_allocated += size;
			((struct pceplib_memory_type *)mem_type)
				->num_allocates++;
		}

		return malloc(size);
	} else {
		return mfunc(mem_type, size);
	}
}

void *pceplib_calloc(void *mem_type, size_t size)
{
	if (cfunc == NULL) {
		if (mem_type != NULL) {
			((struct pceplib_memory_type *)mem_type)
				->total_bytes_allocated += size;
			((struct pceplib_memory_type *)mem_type)
				->num_allocates++;
		}

		return calloc(1, size);
	} else {
		return cfunc(mem_type, size);
	}
}

void *pceplib_realloc(void *mem_type, void *ptr, size_t size)
{
	if (rfunc == NULL) {
		if (mem_type != NULL) {
			/* TODO should add previous allocated bytes to
			 * total_bytes_freed */
			((struct pceplib_memory_type *)mem_type)
				->total_bytes_allocated += size;
			((struct pceplib_memory_type *)mem_type)
				->num_allocates++;
		}

		return realloc(ptr, size);
	} else {
		return rfunc(mem_type, ptr, size);
	}
}

void *pceplib_strdup(void *mem_type, const char *str)
{
	if (sfunc == NULL) {
		if (mem_type != NULL) {
			((struct pceplib_memory_type *)mem_type)
				->total_bytes_allocated += strlen(str);
			((struct pceplib_memory_type *)mem_type)
				->num_allocates++;
		}

		return strdup(str);
	} else {
		return sfunc(mem_type, str);
	}
}

void pceplib_free(void *mem_type, void *ptr)
{
	if (ffunc == NULL) {
		if (mem_type != NULL) {
			/* TODO in order to increment total_bytes_freed, we need
			 * to keep track of the bytes allocated per pointer.
			 * Currently not implemented. */
			((struct pceplib_memory_type *)mem_type)->num_frees++;
			if (((struct pceplib_memory_type *)mem_type)
				    ->num_allocates
			    < ((struct pceplib_memory_type *)mem_type)
				      ->num_frees) {
				pcep_log(
					LOG_ERR,
					"%s: pceplib_free MT N_Alloc < N_Free: MemType [%s] NumAllocates [%d] NumFrees [%d]",
					__func__,
					((struct pceplib_memory_type *)mem_type)
						->memory_type_name,
					((struct pceplib_memory_type *)mem_type)
						->num_allocates,
					((struct pceplib_memory_type *)mem_type)
						->num_frees);
			}
		}

		return free(ptr);
	} else {
		return ffunc(mem_type, ptr);
	}
}
