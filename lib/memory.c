// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 */

#include <zebra.h>

#include <stdlib.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
#ifdef HAVE_MALLOC_NP_H
#include <malloc_np.h>
#endif
#ifdef HAVE_MALLOC_MALLOC_H
#include <malloc/malloc.h>
#endif

#include "memory.h"
#include "log.h"
#include "libfrr_trace.h"

static struct memgroup *mg_first = NULL;
struct memgroup **mg_insert = &mg_first;

DEFINE_MGROUP(LIB, "libfrr");
DEFINE_MTYPE(LIB, TMP, "Temporary memory");
DEFINE_MTYPE(LIB, TMP_TTABLE, "Temporary memory for TTABLE");
DEFINE_MTYPE(LIB, BITFIELD, "Bitfield memory");

static inline void mt_count_alloc(struct memtype *mt, size_t size, void *ptr)
{
	size_t current;
	size_t oldsize;

	current = 1 + atomic_fetch_add_explicit(&mt->n_alloc, 1,
						memory_order_relaxed);

	oldsize = atomic_load_explicit(&mt->n_max, memory_order_relaxed);
	if (current > oldsize)
		/* note that this may fail, but approximation is sufficient */
		atomic_compare_exchange_weak_explicit(&mt->n_max, &oldsize,
						      current,
						      memory_order_relaxed,
						      memory_order_relaxed);

	oldsize = atomic_load_explicit(&mt->size, memory_order_relaxed);
	if (oldsize == 0)
		oldsize = atomic_exchange_explicit(&mt->size, size,
						   memory_order_relaxed);
	if (oldsize != 0 && oldsize != size && oldsize != SIZE_VAR)
		atomic_store_explicit(&mt->size, SIZE_VAR,
				      memory_order_relaxed);

#ifdef HAVE_MALLOC_USABLE_SIZE
	size_t mallocsz = malloc_usable_size(ptr);

	current = mallocsz + atomic_fetch_add_explicit(&mt->total, mallocsz,
						       memory_order_relaxed);
	oldsize = atomic_load_explicit(&mt->max_size, memory_order_relaxed);
	if (current > oldsize)
		/* note that this may fail, but approximation is sufficient */
		atomic_compare_exchange_weak_explicit(&mt->max_size, &oldsize,
						      current,
						      memory_order_relaxed,
						      memory_order_relaxed);
#endif
}

static inline void mt_count_free(struct memtype *mt, void *ptr)
{
	frrtrace(2, frr_libfrr, memfree, mt, ptr);

	assert(mt->n_alloc);
	atomic_fetch_sub_explicit(&mt->n_alloc, 1, memory_order_relaxed);

#ifdef HAVE_MALLOC_USABLE_SIZE
	size_t mallocsz = malloc_usable_size(ptr);

	atomic_fetch_sub_explicit(&mt->total, mallocsz, memory_order_relaxed);
#endif
}

static inline void *mt_checkalloc(struct memtype *mt, void *ptr, size_t size)
{
	frrtrace(3, frr_libfrr, memalloc, mt, ptr, size);

	if (__builtin_expect(ptr == NULL, 0)) {
		if (size) {
			/* malloc(0) is allowed to return NULL */
			memory_oom(size, mt->name);
		}
		return NULL;
	}
	mt_count_alloc(mt, size, ptr);
	return ptr;
}

void *qmalloc(struct memtype *mt, size_t size)
{
	return mt_checkalloc(mt, malloc(size), size);
}

void *qcalloc(struct memtype *mt, size_t size)
{
	return mt_checkalloc(mt, calloc(size, 1), size);
}

void *qrealloc(struct memtype *mt, void *ptr, size_t size)
{
	if (ptr)
		mt_count_free(mt, ptr);
	return mt_checkalloc(mt, ptr ? realloc(ptr, size) : malloc(size), size);
}

void *qstrdup(struct memtype *mt, const char *str)
{
	return str ? mt_checkalloc(mt, strdup(str), strlen(str) + 1) : NULL;
}

void qcountfree(struct memtype *mt, void *ptr)
{
	if (ptr)
		mt_count_free(mt, ptr);
}

void qfree(struct memtype *mt, void *ptr)
{
	if (ptr)
		mt_count_free(mt, ptr);
	free(ptr);
}

int qmem_walk(qmem_walk_fn *func, void *arg)
{
	struct memgroup *mg;
	struct memtype *mt;
	int rv;

	for (mg = mg_first; mg; mg = mg->next) {
		if ((rv = func(arg, mg, NULL)))
			return rv;
		for (mt = mg->types; mt; mt = mt->next)
			if ((rv = func(arg, mg, mt)))
				return rv;
	}
	return 0;
}

struct exit_dump_args {
	const char *daemon_name;
	bool do_log;
	bool do_file;
	bool do_stderr;
	int error;
	FILE *fp;
	struct memgroup *last_mg;
};

static void qmem_exit_fopen(struct exit_dump_args *eda)
{
	char filename[128];

	if (eda->fp || !eda->do_file || !eda->daemon_name)
		return;

	snprintf(filename, sizeof(filename), "/tmp/frr-memstats-%s-%llu-%llu", eda->daemon_name,
		 (unsigned long long)getpid(), (unsigned long long)time(NULL));
	eda->fp = fopen(filename, "w");

	if (!eda->fp) {
		zlog_err("failed to open memstats dump file %pSQq: %m", filename);
		/* don't try opening file over and over again */
		eda->do_file = false;
	}
}

static int qmem_exit_walker(void *arg, struct memgroup *mg, struct memtype *mt)
{
	struct exit_dump_args *eda = arg;
	const char *prefix = eda->daemon_name ?: "NONE";
	char size[32];

	if (!mt)
		/* iterator calls mg=X, mt=NULL first */
		return 0;

	if (!mt->n_alloc)
		return 0;

	if (mt->size != SIZE_VAR)
		snprintf(size, sizeof(size), "%10zu", mt->size);
	else
		snprintf(size, sizeof(size), "(variably sized)");

	if (mg->active_at_exit) {
		/* not an error - this memgroup has allocations remain active
		 * at exit.  Only printed to zlog_debug.
		 */
		if (!eda->do_log)
			return 0;

		if (eda->last_mg != mg) {
			zlog_debug("showing active allocations in memory group %s (not an error)",
				   mg->name);
			eda->last_mg = mg;
		}
		zlog_debug("memstats:  %-30s: %6zu * %s", mt->name, mt->n_alloc, size);
		return 0;
	}

	eda->error++;
	if (eda->do_file)
		qmem_exit_fopen(eda);

	if (eda->last_mg != mg) {
		if (eda->do_log)
			zlog_warn("showing active allocations in memory group %s", mg->name);
		if (eda->do_stderr)
			fprintf(stderr, "%s: showing active allocations in memory group %s\n",
				prefix, mg->name);
		if (eda->fp)
			fprintf(eda->fp, "%s: showing active allocations in memory group %s\n",
				prefix, mg->name);
		eda->last_mg = mg;
	}

	if (eda->do_log)
		zlog_warn("memstats:  %-30s: %6zu * %s", mt->name, mt->n_alloc, size);
	if (eda->do_stderr)
		fprintf(stderr, "%s: memstats:  %-30s: %6zu * %s\n", prefix, mt->name, mt->n_alloc,
			size);
	if (eda->fp)
		fprintf(eda->fp, "%s: memstats:  %-30s: %6zu * %s\n", prefix, mt->name, mt->n_alloc,
			size);
	return 0;
}

int log_memstats(const char *daemon_name, bool enabled)
{
	struct exit_dump_args eda = {
		.daemon_name = daemon_name,
		.do_log = enabled,
		.do_file = enabled,
		.do_stderr = enabled || !isatty(STDERR_FILENO),
		.error = 0,
	};

	qmem_walk(qmem_exit_walker, &eda);
	if (eda.fp)
		fclose(eda.fp);
	if (eda.error && eda.do_log)
		zlog_warn("exiting with %d leaked MTYPEs", eda.error);
	return eda.error;
}
