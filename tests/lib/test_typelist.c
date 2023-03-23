// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2016-2018  David Lamparter, for NetDEF, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <arpa/inet.h>

#define WNO_ATOMLIST_UNSAFE_FIND

#include "typesafe.h"
#include "atomlist.h"
#include "memory.h"
#include "monotime.h"
#include "jhash.h"
#include "sha256.h"
#include "printfrr.h"

#include "tests/helpers/c/prng.h"

/* note: these macros are layered 2-deep because that makes the C
 * preprocessor expand the "type" argument.  Otherwise, you get
 * "PREDECL_type" instead of "PREDECL_LIST"
 */
#define _concat(a, b)		a ## b
#define concat(a, b)		_concat(a, b)
#define _str(x)			#x
#define str(x)			_str(x)

#define _PREDECL(type, ...)	PREDECL_##type(__VA_ARGS__)
#define PREDECL(type, ...)	_PREDECL(type, __VA_ARGS__)
#define _DECLARE(type, ...)	DECLARE_##type(__VA_ARGS__)
#define DECLARE(type, ...)	_DECLARE(type, __VA_ARGS__)

#define T_SORTED		(1 << 0)
#define T_UNIQ			(1 << 1)
#define T_HASH			(1 << 2)
#define T_HEAP			(1 << 3)
#define T_ATOMIC		(1 << 4)
#define T_REVERSE		(1 << 5)

#define _T_LIST			(0)
#define _T_DLIST		(0                 | T_REVERSE)
#define _T_ATOMLIST		(0                 | T_ATOMIC)
#define _T_HEAP			(T_SORTED          | T_HEAP)
#define _T_SORTLIST_UNIQ	(T_SORTED | T_UNIQ)
#define _T_SORTLIST_NONUNIQ	(T_SORTED)
#define _T_HASH			(T_SORTED | T_UNIQ | T_HASH)
#define _T_SKIPLIST_UNIQ	(T_SORTED | T_UNIQ)
#define _T_SKIPLIST_NONUNIQ	(T_SORTED)
#define _T_RBTREE_UNIQ		(T_SORTED | T_UNIQ | T_REVERSE)
#define _T_RBTREE_NONUNIQ	(T_SORTED          | T_REVERSE)
#define _T_ATOMSORT_UNIQ	(T_SORTED | T_UNIQ | T_ATOMIC)
#define _T_ATOMSORT_NONUNIQ	(T_SORTED          | T_ATOMIC)

#define _T_TYPE(type)		_T_##type
#define IS_SORTED(type)		(_T_TYPE(type) & T_SORTED)
#define IS_UNIQ(type)		(_T_TYPE(type) & T_UNIQ)
#define IS_HASH(type)		(_T_TYPE(type) & T_HASH)
#define IS_HEAP(type)		(_T_TYPE(type) & T_HEAP)
#define IS_ATOMIC(type)		(_T_TYPE(type) & T_ATOMIC)
#define IS_REVERSE(type)	(_T_TYPE(type) & T_REVERSE)

static struct timeval ref, ref0;

static void ts_start(void)
{
	monotime(&ref0);
	monotime(&ref);
}
static void ts_ref(const char *text)
{
	int64_t us;
	us = monotime_since(&ref, NULL);
	printfrr("%7"PRId64"us  %s\n", us, text);
	monotime(&ref);
}
static void ts_end(void)
{
	int64_t us;
	us = monotime_since(&ref0, NULL);
	printfrr("%7"PRId64"us  total\n", us);
}

#define TYPE LIST
#include "test_typelist.h"

#define TYPE DLIST
#include "test_typelist.h"

#define TYPE ATOMLIST
#include "test_typelist.h"

#define TYPE HEAP
#include "test_typelist.h"

#define TYPE SORTLIST_UNIQ
#include "test_typelist.h"

#define TYPE SORTLIST_NONUNIQ
#include "test_typelist.h"

#define TYPE HASH
#include "test_typelist.h"

#define TYPE HASH_collisions
#define REALTYPE HASH
#define SHITTY_HASH
#include "test_typelist.h"
#undef SHITTY_HASH

#define TYPE SKIPLIST_UNIQ
#include "test_typelist.h"

#define TYPE SKIPLIST_NONUNIQ
#include "test_typelist.h"

#define TYPE RBTREE_UNIQ
#include "test_typelist.h"

#define TYPE RBTREE_NONUNIQ
#include "test_typelist.h"

#define TYPE ATOMSORT_UNIQ
#include "test_typelist.h"

#define TYPE ATOMSORT_NONUNIQ
#include "test_typelist.h"

int main(int argc, char **argv)
{
	srandom(1);

	test_LIST();
	test_DLIST();
	test_ATOMLIST();
	test_HEAP();
	test_SORTLIST_UNIQ();
	test_SORTLIST_NONUNIQ();
	test_HASH();
	test_HASH_collisions();
	test_SKIPLIST_UNIQ();
	test_SKIPLIST_NONUNIQ();
	test_RBTREE_UNIQ();
	test_RBTREE_NONUNIQ();
	test_ATOMSORT_UNIQ();
	test_ATOMSORT_NONUNIQ();

	log_memstats_stderr("test: ");
	return 0;
}
