/*
 * Memory management routine
 * Copyright (C) 1998 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.  
 */

#include <zebra.h>
/* malloc.h is generally obsolete, however GNU Libc mallinfo wants it. */
#if !defined(HAVE_STDLIB_H) || (defined(GNU_LINUX) && defined(HAVE_MALLINFO))
#include <malloc.h>
#endif /* !HAVE_STDLIB_H || HAVE_MALLINFO */

#include "log.h"
#include "memory.h"
#include "memory_vty.h"

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

void
log_memstats_stderr (const char *prefix)
{
#if 0
  struct mlist *ml;
  struct memory_list *m;
  int i;
  int j = 0;

  for (ml = mlists; ml->list; ml++)
    {
      i = 0;

      for (m = ml->list; m->index >= 0; m++)
        if (m->index && mstat[m->index].alloc)
          {
            if (!i)
              fprintf (stderr,
                       "%s: memstats: Current memory utilization in module %s:\n",
                       prefix,
                       ml->name);
            fprintf (stderr,
                     "%s: memstats:  %-30s: %10ld%s\n",
                     prefix,
                     m->format,
                     mstat[m->index].alloc,
                     mstat[m->index].alloc < 0 ? " (REPORT THIS BUG!)" : "");
            i = j = 1;
          }
    }

  if (j)
    fprintf (stderr,
             "%s: memstats: NOTE: If configuration exists, utilization may be "
             "expected.\n",
             prefix);
  else
    fprintf (stderr,
             "%s: memstats: No remaining tracked memory utilization.\n",
             prefix);
#endif
}

#if 0
static void
show_separator(struct vty *vty)
{
  vty_out (vty, "-----------------------------\r\n");
}

static int
show_memory_vty (struct vty *vty, struct memory_list *list)
{
  struct memory_list *m;
  int needsep = 0;

  for (m = list; m->index >= 0; m++)
    if (m->index == 0)
      {
	if (needsep)
	  {
	    show_separator (vty);
	    needsep = 0;
	  }
      }
    else if (mstat[m->index].alloc)
      {
	vty_out (vty, "%-30s: %10ld\r\n", m->format, mstat[m->index].alloc);
	needsep = 1;
      }
  return needsep;
}
#endif

#ifdef HAVE_MALLINFO
static int
show_memory_mallinfo (struct vty *vty)
{
  struct mallinfo minfo = mallinfo();
  char buf[MTYPE_MEMSTR_LEN];
  
  vty_out (vty, "System allocator statistics:%s", VTY_NEWLINE);
  vty_out (vty, "  Total heap allocated:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.arena),
           VTY_NEWLINE);
  vty_out (vty, "  Holding block headers: %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.hblkhd),
           VTY_NEWLINE);
  vty_out (vty, "  Used small blocks:     %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.usmblks),
           VTY_NEWLINE);
  vty_out (vty, "  Used ordinary blocks:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.uordblks),
           VTY_NEWLINE);
  vty_out (vty, "  Free small blocks:     %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.fsmblks),
           VTY_NEWLINE);
  vty_out (vty, "  Free ordinary blocks:  %s%s",
           mtype_memstr (buf, MTYPE_MEMSTR_LEN, minfo.fordblks),
           VTY_NEWLINE);
  vty_out (vty, "  Ordinary blocks:       %ld%s",
           (unsigned long)minfo.ordblks,
           VTY_NEWLINE);
  vty_out (vty, "  Small blocks:          %ld%s",
           (unsigned long)minfo.smblks,
           VTY_NEWLINE);
  vty_out (vty, "  Holding blocks:        %ld%s",
           (unsigned long)minfo.hblks,
           VTY_NEWLINE);
  vty_out (vty, "(see system documentation for 'mallinfo' for meaning)%s",
           VTY_NEWLINE);
  return 1;
}
#endif /* HAVE_MALLINFO */

static int qmem_walker(void *arg, struct memgroup *mg, struct memtype *mt)
{
	struct vty *vty = arg;
	if (!mt)
		vty_out (vty, "--- qmem %s ---%s", mg->name, VTY_NEWLINE);
	else {
		char size[32];
		snprintf(size, sizeof(size), "%6zu", mt->size);
		vty_out (vty, "%-30s: %10zu  %s%s",
			mt->name, mt->n_alloc,
			mt->size == 0 ? "" :
			mt->size == SIZE_VAR ? "(variably sized)" :
			size, VTY_NEWLINE);
	}
	return 0;
}


DEFUN (show_memory,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")
{
  int needsep = 0;
  
#ifdef HAVE_MALLINFO
  needsep = show_memory_mallinfo (vty);
#endif /* HAVE_MALLINFO */

  (void) needsep;
#if 0
  struct mlist *ml;
  for (ml = mlists; ml->list; ml++)
    {
      if (needsep)
	show_separator (vty);
      needsep = show_memory_vty (vty, ml->list);
    }
#endif

  qmem_walk(qmem_walker, vty);
  return CMD_SUCCESS;
}

void
memory_init (void)
{
  install_element (RESTRICTED_NODE, &show_memory_cmd);

  install_element (VIEW_NODE, &show_memory_cmd);

  install_element (ENABLE_NODE, &show_memory_cmd);
}

/* Stats querying from users */
/* Return a pointer to a human friendly string describing
 * the byte count passed in. E.g:
 * "0 bytes", "2048 bytes", "110kB", "500MiB", "11GiB", etc.
 * Up to 4 significant figures will be given.
 * The pointer returned may be NULL (indicating an error)
 * or point to the given buffer, or point to static storage.
 */
const char *
mtype_memstr (char *buf, size_t len, unsigned long bytes)
{
  unsigned int m, k;

  /* easy cases */
  if (!bytes)
    return "0 bytes";
  if (bytes == 1)
    return "1 byte";

  /*
   * When we pass the 2gb barrier mallinfo() can no longer report
   * correct data so it just does something odd...
   * Reporting like Terrabytes of data.  Which makes users...
   * edgy.. yes edgy that's the term for it.
   * So let's just give up gracefully
   */
  if (bytes > 0x7fffffff)
    return "> 2GB";

  m = bytes >> 20;
  k = bytes >> 10;

 if (m > 10)
    {
      if (bytes & (1 << 19))
        m++;
      snprintf (buf, len, "%d MiB", m);
    }
  else if (k > 10)
    {
      if (bytes & (1 << 9))
        k++;
      snprintf (buf, len, "%d KiB", k);
    }
  else
    snprintf (buf, len, "%ld bytes", bytes);
  
  return buf;
}
