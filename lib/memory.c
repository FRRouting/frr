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

#include "log.h"
#include "memory.h"

static void alloc_inc (int);
static void alloc_dec (int);
static void log_memstats(int log_priority);

static struct message mstr [] =
{
  { MTYPE_THREAD, "thread" },
  { MTYPE_THREAD_MASTER, "thread_master" },
  { MTYPE_VECTOR, "vector" },
  { MTYPE_VECTOR_INDEX, "vector_index" },
  { MTYPE_IF, "interface" },
  { 0, NULL },
};

/* Fatal memory allocation error occured. */
static void
zerror (const char *fname, int type, size_t size)
{
  zlog_err ("%s : can't allocate memory for `%s' size %d: %s\n", 
	    fname, lookup (mstr, type), (int) size, safe_strerror(errno));
  log_memstats(LOG_WARNING);
  /* N.B. It might be preferable to call zlog_backtrace_sigsafe here, since
     that function should definitely be safe in an OOM condition.  But
     unfortunately zlog_backtrace_sigsafe does not support syslog logging at
     this time... */
  zlog_backtrace(LOG_WARNING);
  abort();
}

/* Memory allocation. */
void *
zmalloc (int type, size_t size)
{
  void *memory;

  memory = malloc (size);

  if (memory == NULL)
    zerror ("malloc", type, size);

  alloc_inc (type);

  return memory;
}

/* Memory allocation with num * size with cleared. */
void *
zcalloc (int type, size_t size)
{
  void *memory;

  memory = calloc (1, size);

  if (memory == NULL)
    zerror ("calloc", type, size);

  alloc_inc (type);

  return memory;
}

/* Memory reallocation. */
void *
zrealloc (int type, void *ptr, size_t size)
{
  void *memory;

  memory = realloc (ptr, size);
  if (memory == NULL)
    zerror ("realloc", type, size);
  return memory;
}

/* Memory free. */
void
zfree (int type, void *ptr)
{
  alloc_dec (type);
  free (ptr);
}

/* String duplication. */
char *
zstrdup (int type, const char *str)
{
  void *dup;

  dup = strdup (str);
  if (dup == NULL)
    zerror ("strdup", type, strlen (str));
  alloc_inc (type);
  return dup;
}

#ifdef MEMORY_LOG
static struct 
{
  const char *name;
  unsigned long alloc;
  unsigned long t_malloc;
  unsigned long c_malloc;
  unsigned long t_calloc;
  unsigned long c_calloc;
  unsigned long t_realloc;
  unsigned long t_free;
  unsigned long c_strdup;
} mstat [MTYPE_MAX];

static void
mtype_log (char *func, void *memory, const char *file, int line, int type)
{
  zlog_debug ("%s: %s %p %s %d", func, lookup (mstr, type), memory, file, line);
}

void *
mtype_zmalloc (const char *file, int line, int type, size_t size)
{
  void *memory;

  mstat[type].c_malloc++;
  mstat[type].t_malloc++;

  memory = zmalloc (type, size);
  mtype_log ("zmalloc", memory, file, line, type);

  return memory;
}

void *
mtype_zcalloc (const char *file, int line, int type, size_t size)
{
  void *memory;

  mstat[type].c_calloc++;
  mstat[type].t_calloc++;

  memory = zcalloc (type, size);
  mtype_log ("xcalloc", memory, file, line, type);

  return memory;
}

void *
mtype_zrealloc (const char *file, int line, int type, void *ptr, size_t size)
{
  void *memory;

  /* Realloc need before allocated pointer. */
  mstat[type].t_realloc++;

  memory = zrealloc (type, ptr, size);

  mtype_log ("xrealloc", memory, file, line, type);

  return memory;
}

/* Important function. */
void 
mtype_zfree (const char *file, int line, int type, void *ptr)
{
  mstat[type].t_free++;

  mtype_log ("xfree", ptr, file, line, type);

  zfree (type, ptr);
}

char *
mtype_zstrdup (const char *file, int line, int type, const char *str)
{
  char *memory;

  mstat[type].c_strdup++;

  memory = zstrdup (type, str);
  
  mtype_log ("xstrdup", memory, file, line, type);

  return memory;
}
#else
static struct 
{
  char *name;
  unsigned long alloc;
} mstat [MTYPE_MAX];
#endif /* MTPYE_LOG */

/* Increment allocation counter. */
static void
alloc_inc (int type)
{
  mstat[type].alloc++;
}

/* Decrement allocation counter. */
static void
alloc_dec (int type)
{
  mstat[type].alloc--;
}

/* Looking up memory status from vty interface. */
#include "vector.h"
#include "vty.h"
#include "command.h"

static void
log_memstats(int pri)
{
  struct mlist *ml;

  for (ml = mlists; ml->list; ml++)
    {
      struct memory_list *m;

      zlog (NULL, pri, "Memory utilization in module %s:", ml->name);
      for (m = ml->list; m->index >= 0; m++)
	if (m->index && mstat[m->index].alloc)
	  zlog (NULL, pri, "  %-30s: %10ld", m->format, mstat[m->index].alloc);
    }
}

static struct memory_list memory_list_separator[] =
{
  { 0, NULL},
  {-1, NULL}
};

static void
show_memory_vty (struct vty *vty, struct memory_list *list)
{
  struct memory_list *m;

  for (m = list; m->index >= 0; m++)
    if (m->index == 0)
      vty_out (vty, "-----------------------------\r\n");
    else
      vty_out (vty, "%-30s: %10ld\r\n", m->format, mstat[m->index].alloc);
}

DEFUN (show_memory_all,
       show_memory_all_cmd,
       "show memory all",
       "Show running system information\n"
       "Memory statistics\n"
       "All memory statistics\n")
{
  struct mlist *ml;

  for (ml = mlists; ml->list; ml++)
    {
      if (ml != mlists)
        show_memory_vty (vty, memory_list_separator);
      show_memory_vty (vty, ml->list);
    }

  return CMD_SUCCESS;
}

ALIAS (show_memory_all,
       show_memory_cmd,
       "show memory",
       "Show running system information\n"
       "Memory statistics\n")

DEFUN (show_memory_lib,
       show_memory_lib_cmd,
       "show memory lib",
       SHOW_STR
       "Memory statistics\n"
       "Library memory\n")
{
  show_memory_vty (vty, memory_list_lib);
  return CMD_SUCCESS;
}

DEFUN (show_memory_zebra,
       show_memory_zebra_cmd,
       "show memory zebra",
       SHOW_STR
       "Memory statistics\n"
       "Zebra memory\n")
{
  show_memory_vty (vty, memory_list_zebra);
  return CMD_SUCCESS;
}

DEFUN (show_memory_rip,
       show_memory_rip_cmd,
       "show memory rip",
       SHOW_STR
       "Memory statistics\n"
       "RIP memory\n")
{
  show_memory_vty (vty, memory_list_rip);
  return CMD_SUCCESS;
}

DEFUN (show_memory_ripng,
       show_memory_ripng_cmd,
       "show memory ripng",
       SHOW_STR
       "Memory statistics\n"
       "RIPng memory\n")
{
  show_memory_vty (vty, memory_list_ripng);
  return CMD_SUCCESS;
}

DEFUN (show_memory_bgp,
       show_memory_bgp_cmd,
       "show memory bgp",
       SHOW_STR
       "Memory statistics\n"
       "BGP memory\n")
{
  show_memory_vty (vty, memory_list_bgp);
  return CMD_SUCCESS;
}

DEFUN (show_memory_ospf,
       show_memory_ospf_cmd,
       "show memory ospf",
       SHOW_STR
       "Memory statistics\n"
       "OSPF memory\n")
{
  show_memory_vty (vty, memory_list_ospf);
  return CMD_SUCCESS;
}

DEFUN (show_memory_ospf6,
       show_memory_ospf6_cmd,
       "show memory ospf6",
       SHOW_STR
       "Memory statistics\n"
       "OSPF6 memory\n")
{
  show_memory_vty (vty, memory_list_ospf6);
  return CMD_SUCCESS;
}

DEFUN (show_memory_isis,
       show_memory_isis_cmd,
       "show memory isis",
       SHOW_STR
       "Memory statistics\n"
       "ISIS memory\n")
{
  show_memory_vty (vty, memory_list_isis);
  return CMD_SUCCESS;
}

void
memory_init (void)
{
  install_element (VIEW_NODE, &show_memory_cmd);
  install_element (VIEW_NODE, &show_memory_all_cmd);
  install_element (VIEW_NODE, &show_memory_lib_cmd);
  install_element (VIEW_NODE, &show_memory_rip_cmd);
  install_element (VIEW_NODE, &show_memory_ripng_cmd);
  install_element (VIEW_NODE, &show_memory_bgp_cmd);
  install_element (VIEW_NODE, &show_memory_ospf_cmd);
  install_element (VIEW_NODE, &show_memory_ospf6_cmd);
  install_element (VIEW_NODE, &show_memory_isis_cmd);

  install_element (ENABLE_NODE, &show_memory_cmd);
  install_element (ENABLE_NODE, &show_memory_all_cmd);
  install_element (ENABLE_NODE, &show_memory_lib_cmd);
  install_element (ENABLE_NODE, &show_memory_zebra_cmd);
  install_element (ENABLE_NODE, &show_memory_rip_cmd);
  install_element (ENABLE_NODE, &show_memory_ripng_cmd);
  install_element (ENABLE_NODE, &show_memory_bgp_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf6_cmd);
  install_element (ENABLE_NODE, &show_memory_isis_cmd);
}
