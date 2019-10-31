/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
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

#ifndef _QUAGGA_MEMORY_H
#define _QUAGGA_MEMORY_H

#include <stdlib.h>
#include <stdio.h>
#include <frratomic.h>
#include "compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(HAVE_MALLOC_SIZE) && !defined(HAVE_MALLOC_USABLE_SIZE)
#define malloc_usable_size(x) malloc_size(x)
#define HAVE_MALLOC_USABLE_SIZE
#endif

#define SIZE_VAR ~0UL
struct memtype {
	struct memtype *next, **ref;
	const char *name;
	atomic_size_t n_alloc;
	atomic_size_t n_max;
	atomic_size_t size;
#ifdef HAVE_MALLOC_USABLE_SIZE
	atomic_size_t total;
	atomic_size_t max_size;
#endif
};

struct memgroup {
	struct memgroup *next, **ref;
	struct memtype *types, **insert;
	const char *name;
};

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
 *    foo = qmalloc(MTYPE_MYDAEMON_COMMON, sizeof(*foo))
 *
 *  mydaemon_io.c
 *    bar = qmalloc(MTYPE_MYDAEMON_COMMON, sizeof(*bar))
 *
 *    DEFINE_MTYPE_STATIC(MYDAEMON, MYDAEMON_IO,
 *                          "this mtype is used only in this file")
 *    baz = qmalloc(MTYPE_MYDAEMON_IO, sizeof(*baz))
 *
 *  Note:  Naming conventions (MGROUP_ and MTYPE_ prefixes are enforced
 *         by not having these as part of the macro arguments)
 *  Note:  MTYPE_* are symbols to the compiler (of type struct memtype *),
 *         but MGROUP_* aren't.
 */

#define DECLARE_MGROUP(name) extern struct memgroup _mg_##name;
#define DEFINE_MGROUP(mname, desc)                                             \
	struct memgroup _mg_##mname                                            \
		__attribute__((section(".data.mgroups"))) = {                  \
			.name = desc,                                          \
			.types = NULL,                                         \
			.next = NULL,                                          \
			.insert = NULL,                                        \
			.ref = NULL,                                           \
	};                                                                     \
	static void _mginit_##mname(void) __attribute__((_CONSTRUCTOR(1000))); \
	static void _mginit_##mname(void)                                      \
	{                                                                      \
		extern struct memgroup **mg_insert;                            \
		_mg_##mname.ref = mg_insert;                                   \
		*mg_insert = &_mg_##mname;                                     \
		mg_insert = &_mg_##mname.next;                                 \
	}                                                                      \
	static void _mgfini_##mname(void) __attribute__((_DESTRUCTOR(1000)));  \
	static void _mgfini_##mname(void)                                      \
	{                                                                      \
		if (_mg_##mname.next)                                          \
			_mg_##mname.next->ref = _mg_##mname.ref;               \
		*_mg_##mname.ref = _mg_##mname.next;                           \
	}

#define DECLARE_MTYPE(name)                                                    \
	extern struct memtype _mt_##name;                                      \
	extern struct memtype *const MTYPE_##name;                             \
	/* end */

#define DEFINE_MTYPE_ATTR(group, mname, attr, desc)                            \
	attr struct memtype _mt_##mname                                        \
		__attribute__((section(".data.mtypes"))) = {                   \
			.name = desc,                                          \
			.next = NULL,                                          \
			.n_alloc = 0,                                          \
			.size = 0,                                             \
			.ref = NULL,                                           \
	};                                                                     \
	static void _mtinit_##mname(void) __attribute__((_CONSTRUCTOR(1001))); \
	static void _mtinit_##mname(void)                                      \
	{                                                                      \
		if (_mg_##group.insert == NULL)                                \
			_mg_##group.insert = &_mg_##group.types;               \
		_mt_##mname.ref = _mg_##group.insert;                          \
		*_mg_##group.insert = &_mt_##mname;                            \
		_mg_##group.insert = &_mt_##mname.next;                        \
	}                                                                      \
	static void _mtfini_##mname(void) __attribute__((_DESTRUCTOR(1001)));  \
	static void _mtfini_##mname(void)                                      \
	{                                                                      \
		if (_mt_##mname.next)                                          \
			_mt_##mname.next->ref = _mt_##mname.ref;               \
		*_mt_##mname.ref = _mt_##mname.next;                           \
	}                                                                      \
	/* end */

#define DEFINE_MTYPE(group, name, desc)                                        \
	DEFINE_MTYPE_ATTR(group, name, , desc)                                 \
	struct memtype *const MTYPE_##name = &_mt_##name;                      \
	/* end */

#define DEFINE_MTYPE_STATIC(group, name, desc)                                 \
	DEFINE_MTYPE_ATTR(group, name, static, desc)                           \
	static struct memtype *const MTYPE_##name = &_mt_##name;               \
	/* end */

DECLARE_MGROUP(LIB)
DECLARE_MTYPE(TMP)


extern void *qmalloc(struct memtype *mt, size_t size)
	__attribute__((malloc, _ALLOC_SIZE(2), nonnull(1) _RET_NONNULL));
extern void *qcalloc(struct memtype *mt, size_t size)
	__attribute__((malloc, _ALLOC_SIZE(2), nonnull(1) _RET_NONNULL));
extern void *qrealloc(struct memtype *mt, void *ptr, size_t size)
	__attribute__((_ALLOC_SIZE(3), nonnull(1) _RET_NONNULL));
extern void *qstrdup(struct memtype *mt, const char *str)
	__attribute__((malloc, nonnull(1) _RET_NONNULL));
extern void qfree(struct memtype *mt, void *ptr) __attribute__((nonnull(1)));

#define XMALLOC(mtype, size)		qmalloc(mtype, size)
#define XCALLOC(mtype, size)		qcalloc(mtype, size)
#define XREALLOC(mtype, ptr, size)	qrealloc(mtype, ptr, size)
#define XSTRDUP(mtype, str)		qstrdup(mtype, str)
#define XFREE(mtype, ptr)                                                      \
	do {                                                                   \
		qfree(mtype, ptr);                                             \
		ptr = NULL;                                                    \
	} while (0)

static inline size_t mtype_stats_alloc(struct memtype *mt)
{
	return mt->n_alloc;
}

/* NB: calls are ordered by memgroup; and there is a call with mt == NULL for
 * each memgroup (so that a header can be printed, and empty memgroups show)
 *
 * return value: 0: continue, !0: abort walk.  qmem_walk will return the
 * last value from qmem_walk_fn. */
typedef int qmem_walk_fn(void *arg, struct memgroup *mg, struct memtype *mt);
extern int qmem_walk(qmem_walk_fn *func, void *arg);
extern int log_memstats(FILE *fp, const char *);
#define log_memstats_stderr(prefix) log_memstats(stderr, prefix)

extern void memory_oom(size_t size, const char *name);

#ifdef __cplusplus
}
#endif

#endif /* _QUAGGA_MEMORY_H */
