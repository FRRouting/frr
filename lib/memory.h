/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

#ifndef _QUAGGA_MEMORY_H
#define _QUAGGA_MEMORY_H

#include <stdlib.h>

#define array_size(ar) (sizeof(ar) / sizeof(ar[0]))

#define SIZE_VAR ~0UL
struct memtype
{
  struct memtype *next;
  const char *name;
  size_t n_alloc;
  size_t size;
};

struct memgroup
{
  struct memgroup *next;
  struct memtype *types, **insert;
  const char *name;
};

#if defined(__clang__)
# if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 5)
#  define _RET_NONNULL  , returns_nonnull
# endif
# define _CONSTRUCTOR(x) constructor(x)
#elif defined(__GNUC__)
# if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
#  define _RET_NONNULL  , returns_nonnull
# endif
# if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#  define _CONSTRUCTOR(x) constructor(x)
#  define _ALLOC_SIZE(x)  alloc_size(x)
# endif
#endif

#ifdef __sun
/* Solaris doesn't do constructor priorities due to linker restrictions */
# undef _CONSTRUCTOR
#endif

#ifndef _RET_NONNULL
# define _RET_NONNULL
#endif
#ifndef _CONSTRUCTOR
# define _CONSTRUCTOR(x) constructor
#endif
#ifndef _ALLOC_SIZE
# define _ALLOC_SIZE(x)
#endif

/* macro usage:
 *
 *  mydaemon.h
 *    DECLARE_MGROUP(MYDAEMON)
 *    DECLARE_MTYPE(MYDAEMON_COMMON)
 *
 *  mydaemon.c
 *    DEFINE_MGROUP(MYDAEMON, "my daemon memory")
 *    DEFINE_MTYPE(MYDAEMON, MYDAEMON_COMMON,
 *                   "this mtype is used in multiple files in mydaemon")
 *    foo = qmalloc (MTYPE_MYDAEMON_COMMON, sizeof (*foo))
 *
 *  mydaemon_io.c
 *    bar = qmalloc (MTYPE_MYDAEMON_COMMON, sizeof (*bar))
 *
 *    DEFINE_MTYPE_STATIC(MYDAEMON, MYDAEMON_IO,
 *                          "this mtype is used only in this file")
 *    baz = qmalloc (MTYPE_MYDAEMON_IO, sizeof (*baz))
 *
 *  Note:  Naming conventions (MGROUP_ and MTYPE_ prefixes are enforced
 *         by not having these as part of the macro arguments)
 *  Note:  MTYPE_* are symbols to the compiler (of type struct memtype *),
 *         but MGROUP_* aren't.
 */

#define DECLARE_MGROUP(name) \
	extern struct memgroup _mg_##name;
#define DEFINE_MGROUP(mname, desc) \
	struct memgroup _mg_##mname \
	__attribute__ ((section (".data.mgroups"))) = { \
		.name = desc, \
		.types = NULL, .next = NULL, .insert = NULL, \
	}; \
	static void _mginit_##mname (void) \
	  __attribute__ ((_CONSTRUCTOR (1000))); \
	static void _mginit_##mname (void) \
	{	extern struct memgroup **mg_insert; \
		*mg_insert = &_mg_##mname; \
		mg_insert =  &_mg_##mname.next; }


#define DECLARE_MTYPE(name) \
	extern struct memtype _mt_##name; \
	static struct memtype * const MTYPE_ ## name = &_mt_##name;

#define DEFINE_MTYPE_ATTR(group, mname, attr, desc) \
	attr struct memtype _mt_##mname \
	__attribute__ ((section (".data.mtypes"))) = { \
		.name = desc, \
		.next = NULL, .n_alloc = 0, .size = 0, \
	}; \
	static void _mtinit_##mname (void) \
	  __attribute__ ((_CONSTRUCTOR (1001))); \
	static void _mtinit_##mname (void) \
	{	if (_mg_##group.insert == NULL) \
			_mg_##group.insert = &_mg_##group.types; \
		*_mg_##group.insert = &_mt_##mname; \
		_mg_##group.insert =  &_mt_##mname.next; }

#define DEFINE_MTYPE(group, name, desc) \
	DEFINE_MTYPE_ATTR(group, name, , desc)
#define DEFINE_MTYPE_STATIC(group, name, desc) \
	DEFINE_MTYPE_ATTR(group, name, static, desc) \
	static struct memtype * const MTYPE_ ## name = &_mt_##name;

DECLARE_MGROUP(LIB)
DECLARE_MTYPE(TMP)


extern void *qmalloc (struct memtype *mt, size_t size)
	__attribute__ ((malloc, _ALLOC_SIZE(2), nonnull (1) _RET_NONNULL));
extern void *qcalloc (struct memtype *mt, size_t size)
	__attribute__ ((malloc, _ALLOC_SIZE(2), nonnull (1) _RET_NONNULL));
extern void *qrealloc (struct memtype *mt, void *ptr, size_t size)
	__attribute__ ((_ALLOC_SIZE(3), nonnull (1) _RET_NONNULL));
extern void *qstrdup (struct memtype *mt, const char *str)
	__attribute__ ((malloc, nonnull (1) _RET_NONNULL));
extern void qfree (struct memtype *mt, void *ptr)
	__attribute__ ((nonnull (1)));

#define XMALLOC(mtype, size)		qmalloc(mtype, size)
#define XCALLOC(mtype, size)		qcalloc(mtype, size)
#define XREALLOC(mtype, ptr, size)	qrealloc(mtype, ptr, size)
#define XSTRDUP(mtype, str)		qstrdup(mtype, str)
#define XFREE(mtype, ptr)		do { qfree(mtype, ptr); ptr = NULL; } \
					while (0)

static inline size_t mtype_stats_alloc(struct memtype *mt)
{
	return mt->n_alloc;
}

/* NB: calls are ordered by memgroup; and there is a call with mt == NULL for
 * each memgroup (so that a header can be printed, and empty memgroups show)
 *
 * return value: 0: continue, !0: abort walk.  qmem_walk will return the
 * last value from qmem_walk_fn. */
typedef int qmem_walk_fn (void *arg, struct memgroup *mg, struct memtype *mt);
extern int qmem_walk (qmem_walk_fn *func, void *arg);
extern void log_memstats_stderr (const char *);

extern void memory_oom (size_t size, const char *name);

#endif /* _QUAGGA_MEMORY_H */
