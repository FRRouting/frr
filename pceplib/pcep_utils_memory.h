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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 *
 * Author : Brady Johnson <brady@voltanet.io>
 *
 */

#ifndef PCEP_UTILS_INCLUDE_PCEP_UTILS_MEMORY_H_
#define PCEP_UTILS_INCLUDE_PCEP_UTILS_MEMORY_H_

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* This module is intended to be used primarily with FRR's memory module,
 * which has memory groups and memory types, although any memory infrastructure
 * can be used that has memory types or the memory types in this module can be
 * set to NULL. The PCEPlib can be used stand-alone, in which case the simple
 * internal memory type system will be used.
 */

/* These memory function pointers are modeled after the memory functions
 * in frr/lib/memory.h */
typedef void *(*pceplib_malloc_func)(void *mem_type, size_t size);
typedef void *(*pceplib_calloc_func)(void *mem_type, size_t size);
typedef void *(*pceplib_realloc_func)(void *mem_type, void *ptr, size_t size);
typedef void *(*pceplib_strdup_func)(void *mem_type, const char *str);
typedef void (*pceplib_free_func)(void *mem_type, void *ptr);

/* Either an internal pceplib_memory_type pointer
 * or could be an FRR memory type pointer */
extern void *PCEPLIB_INFRA;
extern void *PCEPLIB_MESSAGES;

/* Internal PCEPlib memory type */
struct pceplib_memory_type {
	char memory_type_name[64];
	uint32_t total_bytes_allocated;
	uint32_t num_allocates;
	uint32_t total_bytes_freed; /* currently not used */
	uint32_t num_frees;
};

/* Initialize this module by passing in the 2 memory types used in the PCEPlib
 * and by passing in the different memory allocation/free function pointers.
 * Any of these parameters can be NULL, in which case an internal implementation
 * will be used.
 */
bool pceplib_memory_initialize(void *pceplib_infra_mt,
			       void *pceplib_messages_mt,
			       pceplib_malloc_func mfunc,
			       pceplib_calloc_func cfunc,
			       pceplib_realloc_func rfunc,
			       pceplib_strdup_func sfunc,
			       pceplib_free_func ffunc);

/* Reset the internal allocation/free counters. Used mainly for internal
 * testing. */
void pceplib_memory_reset(void);
void pceplib_memory_dump(void);

/* Memory functions to be used throughout the PCEPlib. Internally, these
 * functions will either used the function pointers passed in via
 * pceplib_memory_initialize() or a simple internal implementation. The
 * internal implementations just increment the internal memory type
 * counters and call the C stdlib memory functions.
 */
void *pceplib_malloc(void *mem_type, size_t size);
void *pceplib_calloc(void *mem_type, size_t size);
void *pceplib_realloc(void *mem_type, void *ptr, size_t size);
void *pceplib_strdup(void *mem_type, const char *str);
void pceplib_free(void *mem_type, void *ptr);

#endif /* PCEP_UTILS_INCLUDE_PCEP_UTILS_MEMORY_H_ */
