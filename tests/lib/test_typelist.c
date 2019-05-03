/*
 * Copyright (c) 2016-2018  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
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

#define WNO_ATOMLIST_UNSAFE_FIND

#include "typesafe.h"
#include "atomlist.h"
#include "memory.h"
#include "monotime.h"

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

#define _U_SORTLIST_UNIQ	1
#define _U_SORTLIST_NONUNIQ	0
#define _U_HASH			1
#define _U_SKIPLIST_UNIQ	1
#define _U_SKIPLIST_NONUNIQ	0
#define _U_RBTREE_UNIQ		1
#define _U_RBTREE_NONUNIQ	0
#define _U_ATOMSORT_UNIQ	1
#define _U_ATOMSORT_NONUNIQ	0

#define _IS_UNIQ(type)		_U_##type
#define IS_UNIQ(type)		_IS_UNIQ(type)

#define _H_SORTLIST_UNIQ	0
#define _H_SORTLIST_NONUNIQ	0
#define _H_HASH			1
#define _H_SKIPLIST_UNIQ	0
#define _H_SKIPLIST_NONUNIQ	0
#define _H_RBTREE_UNIQ		0
#define _H_RBTREE_NONUNIQ	0
#define _H_ATOMSORT_UNIQ	0
#define _H_ATOMSORT_NONUNIQ	0

#define _IS_HASH(type)		_H_##type
#define IS_HASH(type)		_IS_HASH(type)

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
	printf("%7"PRId64"us  %s\n", us, text);
	monotime(&ref);
}
static void ts_end(void)
{
	int64_t us;
	us = monotime_since(&ref0, NULL);
	printf("%7"PRId64"us  total\n", us);
}

#define TYPE SORTLIST_UNIQ
#include "test_typelist.h"

#define TYPE SORTLIST_NONUNIQ
#include "test_typelist.h"

#define TYPE HASH
#include "test_typelist.h"

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

	test_SORTLIST_UNIQ();
	test_SORTLIST_NONUNIQ();
	test_HASH();
	test_SKIPLIST_UNIQ();
	test_SKIPLIST_NONUNIQ();
	test_RBTREE_UNIQ();
	test_RBTREE_NONUNIQ();
	test_ATOMSORT_UNIQ();
	test_ATOMSORT_NONUNIQ();

	log_memstats_stderr("test: ");
	return 0;
}
