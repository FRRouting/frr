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

/* For pretty printng of memory allocate information. */
struct memory_list
{
  int index;
  const char *format;
};

static struct memory_list memory_list_lib[] =
{
  { MTYPE_TMP,                "Temporary memory" },
  { MTYPE_ROUTE_TABLE,        "Route table     " },
  { MTYPE_ROUTE_NODE,         "Route node      " },
  { MTYPE_RIB,                "RIB             " },
  { MTYPE_DISTRIBUTE,         "Distribute list " },
  { MTYPE_DISTRIBUTE_IFNAME,  "Dist-list ifname" },
  { MTYPE_NEXTHOP,            "Nexthop         " },
  { MTYPE_LINK_LIST,          "Link List       " },
  { MTYPE_LINK_NODE,          "Link Node       " },
  { MTYPE_HASH,               "Hash            " },
  { MTYPE_HASH_BACKET,        "Hash Bucket     " },
  { MTYPE_ACCESS_LIST,        "Access List     " },
  { MTYPE_ACCESS_LIST_STR,    "Access List Str " },
  { MTYPE_ACCESS_FILTER,      "Access Filter   " },
  { MTYPE_PREFIX_LIST,        "Prefix List     " },
  { MTYPE_PREFIX_LIST_STR,    "Prefix List Str " },
  { MTYPE_PREFIX_LIST_ENTRY,  "Prefix List Entry "},
  { MTYPE_ROUTE_MAP,          "Route map       " },
  { MTYPE_ROUTE_MAP_NAME,     "Route map name  " },
  { MTYPE_ROUTE_MAP_INDEX,    "Route map index " },
  { MTYPE_ROUTE_MAP_RULE,     "Route map rule  " },
  { MTYPE_ROUTE_MAP_RULE_STR, "Route map rule str" },
  { MTYPE_ROUTE_MAP_COMPILED, "Route map compiled" },
  { MTYPE_DESC,               "Command desc    " },
  { MTYPE_BUFFER,             "Buffer          " },
  { MTYPE_BUFFER_DATA,        "Buffer data     " },
  { MTYPE_STREAM,             "Stream          " },
  { MTYPE_KEYCHAIN,           "Key chain       " },
  { MTYPE_KEY,                "Key             " },
  { MTYPE_VTY,                "VTY             " },
  { -1, NULL }
};

static struct memory_list memory_list_bgp[] =
{
  { MTYPE_BGP_PEER,               "BGP peer" },
  { MTYPE_ATTR,                   "BGP attribute" },
  { MTYPE_AS_PATH,                "BGP aspath" },
  { MTYPE_AS_SEG,                 "BGP aspath seg" },
  { MTYPE_AS_STR,                 "BGP aspath str" },
  { 0, NULL },
  { MTYPE_BGP_TABLE,              "BGP table" },
  { MTYPE_BGP_NODE,               "BGP node" },
  { MTYPE_BGP_ADVERTISE_ATTR,     "BGP adv attr" },
  { MTYPE_BGP_ADVERTISE,          "BGP adv" },
  { MTYPE_BGP_ADJ_IN,             "BGP adj in" },
  { MTYPE_BGP_ADJ_OUT,            "BGP adj out" },
  { 0, NULL },
  { MTYPE_AS_LIST,                "BGP AS list" },
  { MTYPE_AS_FILTER,              "BGP AS filter" },
  { MTYPE_AS_FILTER_STR,          "BGP AS filter str" },
  { 0, NULL },
  { MTYPE_COMMUNITY,              "community" },
  { MTYPE_COMMUNITY_VAL,          "community val" },
  { MTYPE_COMMUNITY_STR,          "community str" },
  { 0, NULL },
  { MTYPE_ECOMMUNITY,             "extcommunity" },
  { MTYPE_ECOMMUNITY_VAL,         "extcommunity val" },
  { MTYPE_ECOMMUNITY_STR,         "extcommunity str" },
  { 0, NULL },
  { MTYPE_COMMUNITY_LIST,         "community-list" },
  { MTYPE_COMMUNITY_LIST_NAME,    "community-list name" },
  { MTYPE_COMMUNITY_LIST_ENTRY,   "community-list entry" },
  { MTYPE_COMMUNITY_LIST_CONFIG,  "community-list config" },
  { 0, NULL },
  { MTYPE_CLUSTER,                "Cluster list" },
  { MTYPE_CLUSTER_VAL,            "Cluster list val" },
  { 0, NULL },
  { MTYPE_TRANSIT,                "BGP transit attr" },
  { MTYPE_TRANSIT_VAL,            "BGP transit val" },
  { 0, NULL },
  { MTYPE_BGP_DISTANCE,           "BGP distance" },
  { MTYPE_BGP_NEXTHOP_CACHE,      "BGP nexthop" },
  { MTYPE_BGP_CONFED_LIST,        "BGP confed list" },
  { MTYPE_PEER_UPDATE_SOURCE,     "peer update if" },
  { MTYPE_BGP_DAMP_INFO,          "Dampening info" },
  { MTYPE_BGP_REGEXP,             "BGP regexp" },
  { -1, NULL }
};

static struct memory_list memory_list_rip[] =
{
  { MTYPE_RIP,                "RIP structure   " },
  { MTYPE_RIP_INFO,           "RIP route info  " },
  { MTYPE_RIP_INTERFACE,      "RIP interface   " },
  { MTYPE_RIP_PEER,           "RIP peer        " },
  { MTYPE_RIP_OFFSET_LIST,    "RIP offset list " },
  { MTYPE_RIP_DISTANCE,       "RIP distance    " },
  { -1, NULL }
};

static struct memory_list memory_list_ripng[] =
{
  { MTYPE_RIPNG,              "RIPng structure " },
  { MTYPE_RIPNG_ROUTE,        "RIPng route info" },
  { MTYPE_RIPNG_AGGREGATE,    "RIPng aggregate " },
  { MTYPE_RIPNG_PEER,         "RIPng peer      " },
  { MTYPE_RIPNG_OFFSET_LIST,  "RIPng offset lst" },
  { MTYPE_RIPNG_RTE_DATA,     "RIPng rte data  " },
  { -1, NULL }
};

static struct memory_list memory_list_ospf[] =
{
  { MTYPE_OSPF_TOP,           "OSPF top        " },
  { MTYPE_OSPF_AREA,          "OSPF area       " },
  { MTYPE_OSPF_AREA_RANGE,    "OSPF area range " },
  { MTYPE_OSPF_NETWORK,       "OSPF network    " },
#ifdef NBMA_ENABLE
  { MTYPE_OSPF_NEIGHBOR_STATIC,"OSPF static nbr " },
#endif  /* NBMA_ENABLE */
  { MTYPE_OSPF_IF,            "OSPF interface  " },
  { MTYPE_OSPF_NEIGHBOR,      "OSPF neighbor   " },
  { MTYPE_OSPF_ROUTE,         "OSPF route      " },
  { MTYPE_OSPF_TMP,           "OSPF tmp mem    " },
  { MTYPE_OSPF_LSA,           "OSPF LSA        " },
  { MTYPE_OSPF_LSA_DATA,      "OSPF LSA data   " },
  { MTYPE_OSPF_LSDB,          "OSPF LSDB       " },
  { MTYPE_OSPF_PACKET,        "OSPF packet     " },
  { MTYPE_OSPF_FIFO,          "OSPF FIFO queue " },
  { MTYPE_OSPF_VERTEX,        "OSPF vertex     " },
  { MTYPE_OSPF_NEXTHOP,       "OSPF nexthop    " },
  { MTYPE_OSPF_PATH,	      "OSPF path       " },
  { MTYPE_OSPF_VL_DATA,       "OSPF VL data    " },
  { MTYPE_OSPF_CRYPT_KEY,     "OSPF crypt key  " },
  { MTYPE_OSPF_EXTERNAL_INFO, "OSPF ext. info  " },
  { MTYPE_OSPF_DISTANCE,      "OSPF distance   " },
  { MTYPE_OSPF_IF_INFO,       "OSPF if info    " },
  { MTYPE_OSPF_IF_PARAMS,     "OSPF if params  " },
  { -1, NULL },
};

static struct memory_list memory_list_ospf6[] =
{
  { MTYPE_OSPF6_TOP,          "OSPF6 top         " },
  { MTYPE_OSPF6_AREA,         "OSPF6 area        " },
  { MTYPE_OSPF6_IF,           "OSPF6 interface   " },
  { MTYPE_OSPF6_NEIGHBOR,     "OSPF6 neighbor    " },
  { MTYPE_OSPF6_ROUTE,        "OSPF6 route       " },
  { MTYPE_OSPF6_PREFIX,       "OSPF6 prefix      " },
  { MTYPE_OSPF6_MESSAGE,      "OSPF6 message     " },
  { MTYPE_OSPF6_LSA,          "OSPF6 LSA         " },
  { MTYPE_OSPF6_LSA_SUMMARY,  "OSPF6 LSA summary " },
  { MTYPE_OSPF6_LSDB,         "OSPF6 LSA database" },
  { MTYPE_OSPF6_VERTEX,       "OSPF6 vertex      " },
  { MTYPE_OSPF6_SPFTREE,      "OSPF6 SPF tree    " },
  { MTYPE_OSPF6_NEXTHOP,      "OSPF6 nexthop     " },
  { MTYPE_OSPF6_EXTERNAL_INFO,"OSPF6 ext. info   " },
  { MTYPE_OSPF6_OTHER,        "OSPF6 other       " },
  { -1, NULL },
};

static struct memory_list memory_list_isis[] =
{
  { MTYPE_ISIS,               "ISIS              " },
  { MTYPE_ISIS_TMP,           "ISIS TMP          " },
  { MTYPE_ISIS_CIRCUIT,       "ISIS circuit      " },
  { MTYPE_ISIS_LSP,           "ISIS LSP          " },
  { MTYPE_ISIS_ADJACENCY,     "ISIS adjacency    " },
  { MTYPE_ISIS_AREA,          "ISIS area         " },
  { MTYPE_ISIS_AREA_ADDR,     "ISIS area address " },
  { MTYPE_ISIS_TLV,           "ISIS TLV          " },
  { MTYPE_ISIS_DYNHN,         "ISIS dyn hostname " },
  { MTYPE_ISIS_SPFTREE,       "ISIS SPFtree      " },
  { MTYPE_ISIS_VERTEX,        "ISIS vertex       " },
  { MTYPE_ISIS_ROUTE_INFO,    "ISIS route info   " },
  { MTYPE_ISIS_NEXTHOP,       "ISIS nexthop      " },
  { MTYPE_ISIS_NEXTHOP6,      "ISIS nexthop6     " },
  { -1, NULL },
};

static struct mlist {
  struct memory_list *list;
  const char *name;
} mlists[] = {
  { memory_list_lib,   "LIB"},
  { memory_list_rip,   "RIP"},
  { memory_list_ripng, "RIPNG"},
  { memory_list_ospf,  "OSPF"},
  { memory_list_ospf6, "OSPF6"},
  { memory_list_isis,  "ISIS"},
  { memory_list_bgp,   "BGP"},
  { NULL, NULL},
};

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
	  zlog (NULL, pri, "  %-22s: %5ld", m->format, mstat[m->index].alloc);
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
      vty_out (vty, "%-22s: %5ld\r\n", m->format, mstat[m->index].alloc);
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
  install_element (ENABLE_NODE, &show_memory_rip_cmd);
  install_element (ENABLE_NODE, &show_memory_ripng_cmd);
  install_element (ENABLE_NODE, &show_memory_bgp_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf_cmd);
  install_element (ENABLE_NODE, &show_memory_ospf6_cmd);
  install_element (ENABLE_NODE, &show_memory_isis_cmd);
}
