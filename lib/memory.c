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

#include <zebra.h>

#include <stdlib.h>

#include "memory.h"

static struct memgroup *mg_first = NULL;
struct memgroup **mg_insert = &mg_first;

DEFINE_MGROUP(LIB, "libzebra")
DEFINE_MTYPE(LIB, TMP, "Temporary memory")

static inline void
mt_count_alloc (struct memtype *mt, size_t size)
{
  mt->n_alloc++;

  if (mt->size == 0)
    mt->size = size;
  else if (mt->size != size)
    mt->size = SIZE_VAR;
}

static inline void
mt_count_free (struct memtype *mt)
{
  mt->n_alloc--;
}

static inline void *
mt_checkalloc (struct memtype *mt, void *ptr, size_t size)
{
  if (__builtin_expect(ptr == NULL, 0))
    {
      memory_oom (size, mt->name);
      return NULL;
    }
  mt_count_alloc (mt, size);
  return ptr;
}

void *
qmalloc (struct memtype *mt, size_t size)
{
  return mt_checkalloc (mt, malloc (size), size);
}

void *
qcalloc (struct memtype *mt, size_t size)
{
  return mt_checkalloc (mt, calloc (size, 1), size);
}

void *
qrealloc (struct memtype *mt, void *ptr, size_t size)
{
  if (ptr)
    mt_count_free (mt);
  return mt_checkalloc (mt, ptr ? realloc (ptr, size) : malloc (size), size);
}

void *
qstrdup (struct memtype *mt, const char *str)
{
  return mt_checkalloc (mt, strdup (str), strlen (str) + 1);
}

void
qfree (struct memtype *mt, void *ptr)
{
  if (ptr)
    mt_count_free (mt);
  free (ptr);
}

int
qmem_walk (qmem_walk_fn *func, void *arg)
{
  struct memgroup *mg;
  struct memtype *mt;
  int rv;

  for (mg = mg_first; mg; mg = mg->next)
    {
      if ((rv = func (arg, mg, NULL)))
        return rv;
      for (mt = mg->types; mt; mt = mt->next)
        if ((rv = func (arg, mg, mt)))
          return rv;
    }
  return 0;
}

struct exit_dump_args
{
  const char *prefix;
  int error;
};

static int
qmem_exit_walker (void *arg, struct memgroup *mg, struct memtype *mt)
{
  struct exit_dump_args *eda = arg;

  if (!mt)
    {
      fprintf (stderr, "%s: showing active allocations in memory group %s\n",
               eda->prefix, mg->name);
    }
  else if (mt->n_alloc)
    {
      char size[32];
      eda->error++;
      snprintf (size, sizeof (size), "%10zu", mt->size);
      fprintf (stderr, "%s: memstats:  %-30s: %6zu * %s\n",
               eda->prefix, mt->name, mt->n_alloc,
               mt->size == SIZE_VAR ? "(variably sized)" : size);
    }
  return 0;
}

void
log_memstats_stderr (const char *prefix)
{
  struct exit_dump_args eda = { .prefix = prefix, .error = 0 };
  qmem_walk (qmem_exit_walker, &eda);
}
