/* Prefix list functions.
 * Copyright (C) 1999 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */

#include <zebra.h>
#include "lib/json.h"

#include "prefix.h"
#include "command.h"
#include "memory.h"
#include "plist.h"
#include "sockunion.h"
#include "buffer.h"
#include "stream.h"
#include "log.h"
#include "routemap.h"

#include "plist_int.h"

/* not currently changeable, code assumes bytes further down */
#define PLC_BITS	8
#define PLC_LEN		(1 << PLC_BITS)
#define PLC_MAXLEVELV4	2	/* /24 for IPv4 */
#define PLC_MAXLEVELV6	4	/* /48 for IPv6 */
#define PLC_MAXLEVEL	4	/* max(v4,v6) */

struct pltrie_entry {
	union {
		struct pltrie_table *next_table;
		struct prefix_list_entry *final_chain;
	};

	struct prefix_list_entry *up_chain;
};

struct pltrie_table {
	struct pltrie_entry entries[PLC_LEN];
};

/* List of struct prefix_list. */
struct prefix_list_list
{
  struct prefix_list *head;
  struct prefix_list *tail;
};

/* Master structure of prefix_list. */
struct prefix_master
{
  /* List of prefix_list which name is number. */
  struct prefix_list_list num;

  /* List of prefix_list which name is string. */
  struct prefix_list_list str;

  /* Whether sequential number is used. */
  int seqnum;

  /* The latest update. */
  struct prefix_list *recent;

  /* Hook function which is executed when new prefix_list is added. */
  void (*add_hook) (struct prefix_list *);

  /* Hook function which is executed when prefix_list is deleted. */
  void (*delete_hook) (struct prefix_list *);

  /* number of bytes that have a trie level */
  size_t trie_depth;
};

/* Static structure of IPv4 prefix_list's master. */
static struct prefix_master prefix_master_ipv4 = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  1,
  NULL,
  NULL,
  NULL,
  PLC_MAXLEVELV4,
};

#ifdef HAVE_IPV6
/* Static structure of IPv6 prefix-list's master. */
static struct prefix_master prefix_master_ipv6 = 
{ 
  {NULL, NULL},
  {NULL, NULL},
  1,
  NULL,
  NULL,
  NULL,
  PLC_MAXLEVELV6,
};
#endif /* HAVE_IPV6*/

/* Static structure of BGP ORF prefix_list's master. */
static struct prefix_master prefix_master_orf_v4 =
{
  {NULL, NULL},
  {NULL, NULL},
  1,
  NULL,
  NULL,
  NULL,
  PLC_MAXLEVELV4,
};

/* Static structure of BGP ORF prefix_list's master. */
static struct prefix_master prefix_master_orf_v6 =
{
  {NULL, NULL},
  {NULL, NULL},
  1,
  NULL,
  NULL,
  NULL,
  PLC_MAXLEVELV6,
};

static struct prefix_master *
prefix_master_get (afi_t afi, int orf)
{
  if (afi == AFI_IP)
    return orf ? &prefix_master_orf_v4 : &prefix_master_ipv4;
  if (afi == AFI_IP6)
    return orf ? &prefix_master_orf_v6 : &prefix_master_ipv6;
  return NULL;
}

const char *prefix_list_name (struct prefix_list *plist)
{
  return plist->name;
}

/* Lookup prefix_list from list of prefix_list by name. */
static struct prefix_list *
prefix_list_lookup_do (afi_t afi, int orf, const char *name)
{
  struct prefix_list *plist;
  struct prefix_master *master;

  if (name == NULL)
    return NULL;

  master = prefix_master_get (afi, orf);
  if (master == NULL)
    return NULL;

  for (plist = master->num.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  for (plist = master->str.head; plist; plist = plist->next)
    if (strcmp (plist->name, name) == 0)
      return plist;

  return NULL;
}

struct prefix_list *
prefix_list_lookup (afi_t afi, const char *name)
{
  return prefix_list_lookup_do (afi, 0, name);
}

struct prefix_list *
prefix_bgp_orf_lookup (afi_t afi, const char *name)
{
  return prefix_list_lookup_do (afi, 1, name);
}

static struct prefix_list *
prefix_list_new (void)
{
  struct prefix_list *new;

  new = XCALLOC (MTYPE_PREFIX_LIST, sizeof (struct prefix_list));
  return new;
}

static void
prefix_list_free (struct prefix_list *plist)
{
  XFREE (MTYPE_PREFIX_LIST, plist);
}

static struct prefix_list_entry *
prefix_list_entry_new (void)
{
  struct prefix_list_entry *new;

  new = XCALLOC (MTYPE_PREFIX_LIST_ENTRY, sizeof (struct prefix_list_entry));
  return new;
}

static void
prefix_list_entry_free (struct prefix_list_entry *pentry)
{
  XFREE (MTYPE_PREFIX_LIST_ENTRY, pentry);
}

/* Insert new prefix list to list of prefix_list.  Each prefix_list
   is sorted by the name. */
static struct prefix_list *
prefix_list_insert (afi_t afi, int orf, const char *name)
{
  unsigned int i;
  long number;
  struct prefix_list *plist;
  struct prefix_list *point;
  struct prefix_list_list *list;
  struct prefix_master *master;

  master = prefix_master_get (afi, orf);
  if (master == NULL)
    return NULL;

  /* Allocate new prefix_list and copy given name. */
  plist = prefix_list_new ();
  plist->name = XSTRDUP (MTYPE_PREFIX_LIST_STR, name);
  plist->master = master;
  plist->trie = XCALLOC (MTYPE_PREFIX_LIST_TRIE, sizeof (struct pltrie_table));

  /* If name is made by all digit character.  We treat it as
     number. */
  for (number = 0, i = 0; i < strlen (name); i++)
    {
      if (isdigit ((int) name[i]))
	number = (number * 10) + (name[i] - '0');
      else
	break;
    }

  /* In case of name is all digit character */
  if (i == strlen (name))
    {
      plist->type = PREFIX_TYPE_NUMBER;

      /* Set prefix_list to number list. */
      list = &master->num;

      for (point = list->head; point; point = point->next)
	if (atol (point->name) >= number)
	  break;
    }
  else
    {
      plist->type = PREFIX_TYPE_STRING;

      /* Set prefix_list to string list. */
      list = &master->str;
  
      /* Set point to insertion point. */
      for (point = list->head; point; point = point->next)
	if (strcmp (point->name, name) >= 0)
	  break;
    }

  /* In case of this is the first element of master. */
  if (list->head == NULL)
    {
      list->head = list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the tail of access_list. */
  if (point == NULL)
    {
      plist->prev = list->tail;
      list->tail->next = plist;
      list->tail = plist;
      return plist;
    }

  /* In case of insertion is made at the head of access_list. */
  if (point == list->head)
    {
      plist->next = list->head;
      list->head->prev = plist;
      list->head = plist;
      return plist;
    }

  /* Insertion is made at middle of the access_list. */
  plist->next = point;
  plist->prev = point->prev;

  if (point->prev)
    point->prev->next = plist;
  point->prev = plist;

  return plist;
}

static struct prefix_list *
prefix_list_get (afi_t afi, int orf, const char *name)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup_do (afi, orf, name);

  if (plist == NULL)
    plist = prefix_list_insert (afi, orf, name);
  return plist;
}

/* Delete prefix-list from prefix_list_master and free it. */
static void
prefix_list_delete (struct prefix_list *plist)
{
  struct prefix_list_list *list;
  struct prefix_master *master;
  struct prefix_list_entry *pentry;
  struct prefix_list_entry *next;

  /* If prefix-list contain prefix_list_entry free all of it. */
  for (pentry = plist->head; pentry; pentry = next)
    {
      next = pentry->next;
      prefix_list_entry_free (pentry);
      plist->count--;
    }

  master = plist->master;

  if (plist->type == PREFIX_TYPE_NUMBER)
    list = &master->num;
  else
    list = &master->str;

  if (plist->next)
    plist->next->prev = plist->prev;
  else
    list->tail = plist->prev;

  if (plist->prev)
    plist->prev->next = plist->next;
  else
    list->head = plist->next;

  if (plist->desc)
    XFREE (MTYPE_TMP, plist->desc);

  /* Make sure master's recent changed prefix-list information is
     cleared. */
  master->recent = NULL;

  route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_DELETED);

  if (master->delete_hook)
    (*master->delete_hook) (plist);

  if (plist->name)
    XFREE (MTYPE_PREFIX_LIST_STR, plist->name);

  XFREE (MTYPE_PREFIX_LIST_TRIE, plist->trie);

  prefix_list_free (plist);

}

static struct prefix_list_entry *
prefix_list_entry_make (struct prefix *prefix, enum prefix_list_type type,
			int seq, int le, int ge, int any)
{
  struct prefix_list_entry *pentry;

  pentry = prefix_list_entry_new ();

  if (any)
    pentry->any = 1;

  prefix_copy (&pentry->prefix, prefix);
  pentry->type = type;
  pentry->seq = seq;
  pentry->le = le;
  pentry->ge = ge;

  return pentry;
}

/* Add hook function. */
void
prefix_list_add_hook (void (*func) (struct prefix_list *plist))
{
  prefix_master_ipv4.add_hook = func;
#ifdef HAVE_IPV6
  prefix_master_ipv6.add_hook = func;
#endif /* HAVE_IPV6 */
}

/* Delete hook function. */
void
prefix_list_delete_hook (void (*func) (struct prefix_list *plist))
{
  prefix_master_ipv4.delete_hook = func;
#ifdef HAVE_IPV6
  prefix_master_ipv6.delete_hook = func;
#endif /* HAVE_IPVt6 */
}

/* Calculate new sequential number. */
static int
prefix_new_seq_get (struct prefix_list *plist)
{
  int maxseq;
  int newseq;
  struct prefix_list_entry *pentry;

  maxseq = newseq = 0;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (maxseq < pentry->seq)
	maxseq = pentry->seq;
    }

  newseq = ((maxseq / 5) * 5) + 5;
  
  return newseq;
}

/* Return prefix list entry which has same seq number. */
static struct prefix_list_entry *
prefix_seq_check (struct prefix_list *plist, int seq)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (pentry->seq == seq)
      return pentry;
  return NULL;
}

static struct prefix_list_entry *
prefix_list_entry_lookup (struct prefix_list *plist, struct prefix *prefix,
			  enum prefix_list_type type, int seq, int le, int ge)
{
  struct prefix_list_entry *pentry;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    if (prefix_same (&pentry->prefix, prefix) && pentry->type == type)
      {
	if (seq >= 0 && pentry->seq != seq)
	  continue;

	if (pentry->le != le)
	  continue;
	if (pentry->ge != ge)
	  continue;

	return pentry;
      }

  return NULL;
}

static void
trie_walk_affected (size_t validbits, struct pltrie_table *table, uint8_t byte,
                    struct prefix_list_entry *object,
                    void (*fn)(struct prefix_list_entry *object,
                               struct prefix_list_entry **updptr))
{
  uint8_t mask;
  uint16_t bwalk;

  if (validbits > PLC_BITS)
    {
      fn (object, &table->entries[byte].final_chain);
      return;
    }

  mask = (1 << (8 - validbits)) - 1;
  for (bwalk = byte & ~mask; bwalk <= byte + mask; bwalk++)
    {
      fn (object, &table->entries[bwalk].up_chain);
    }
}

static void trie_uninstall_fn (struct prefix_list_entry *object,
                               struct prefix_list_entry **updptr)
{
  for (; *updptr; updptr = &(*updptr)->next_best)
    if (*updptr == object)
      {
        *updptr = object->next_best;
        break;
      }
}

static int
trie_table_empty (struct pltrie_table *table)
{
  size_t i;
  for (i = 0; i < PLC_LEN; i++)
    if (table->entries[i].next_table || table->entries[i].final_chain)
      return 0;
  return 1;
}

static void
prefix_list_trie_del (struct prefix_list *plist,
		      struct prefix_list_entry *pentry)
{
  size_t depth, maxdepth = plist->master->trie_depth;
  uint8_t *bytes = &pentry->prefix.u.prefix;
  size_t validbits = pentry->prefix.prefixlen;
  struct pltrie_table *table, **tables[PLC_MAXLEVEL];

  table = plist->trie;
  for (depth = 0; validbits > PLC_BITS && depth < maxdepth - 1; depth++)
    {
      uint8_t byte = bytes[depth];
      assert (table->entries[byte].next_table);

      tables[depth + 1] = &table->entries[byte].next_table;
      table = table->entries[byte].next_table;

      validbits -= PLC_BITS;
    }

  trie_walk_affected (validbits, table, bytes[depth], pentry, trie_uninstall_fn);

  for (; depth > 0; depth--)
    if (trie_table_empty (*tables[depth]))
      {
        XFREE (MTYPE_PREFIX_LIST_TRIE, *tables[depth]);
        *tables[depth] = NULL;
      }
}


static void
prefix_list_entry_delete (struct prefix_list *plist, 
			  struct prefix_list_entry *pentry,
			  int update_list)
{
  prefix_list_trie_del (plist, pentry);

  if (plist == NULL || pentry == NULL)
    return;
  if (pentry->prev)
    pentry->prev->next = pentry->next;
  else
    plist->head = pentry->next;
  if (pentry->next)
    pentry->next->prev = pentry->prev;
  else
    plist->tail = pentry->prev;

  prefix_list_entry_free (pentry);

  plist->count--;

  if (update_list)
    {
      route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_DELETED);
      if (plist->master->delete_hook)
	(*plist->master->delete_hook) (plist);

      if (plist->head == NULL && plist->tail == NULL && plist->desc == NULL)
	prefix_list_delete (plist);
      else
	plist->master->recent = plist;
    }
}

static void trie_install_fn (struct prefix_list_entry *object,
                             struct prefix_list_entry **updptr)
{
  while (*updptr)
    {
      if (*updptr == object)
        return;
      if ((*updptr)->prefix.prefixlen < object->prefix.prefixlen)
        break;
      if ((*updptr)->seq > object->seq)
        break;
      updptr = &(*updptr)->next_best;
    }

  if (!object->next_best)
    object->next_best = *updptr;
  else
    assert (object->next_best == *updptr || !*updptr);

  *updptr = object;
}

static void
prefix_list_trie_add (struct prefix_list *plist,
		      struct prefix_list_entry *pentry)
{
  size_t depth = plist->master->trie_depth;
  uint8_t *bytes = &pentry->prefix.u.prefix;
  size_t validbits = pentry->prefix.prefixlen;
  struct pltrie_table *table;

  table = plist->trie;
  while (validbits > PLC_BITS && depth > 1)
    {
      if (!table->entries[*bytes].next_table)
        table->entries[*bytes].next_table = XCALLOC (MTYPE_PREFIX_LIST_TRIE,
                sizeof(struct pltrie_table));
      table = table->entries[*bytes].next_table;
      bytes++;
      depth--;
      validbits -= PLC_BITS;
    }

  trie_walk_affected (validbits, table, *bytes, pentry, trie_install_fn);
}

static void
prefix_list_entry_add (struct prefix_list *plist,
		       struct prefix_list_entry *pentry)
{
  struct prefix_list_entry *replace;
  struct prefix_list_entry *point;

  /* Automatic asignment of seq no. */
  if (pentry->seq == -1)
    pentry->seq = prefix_new_seq_get (plist);

  if (plist->tail && pentry->seq > plist->tail->seq)
    point = NULL;
  else
    {
      /* Is there any same seq prefix list entry? */
      replace = prefix_seq_check (plist, pentry->seq);
      if (replace)
        prefix_list_entry_delete (plist, replace, 0);

      /* Check insert point. */
      for (point = plist->head; point; point = point->next)
        if (point->seq >= pentry->seq)
          break;
    }

  /* In case of this is the first element of the list. */
  pentry->next = point;

  if (point)
    {
      if (point->prev)
	point->prev->next = pentry;
      else
	plist->head = pentry;

      pentry->prev = point->prev;
      point->prev = pentry;
    }
  else
    {
      if (plist->tail)
	plist->tail->next = pentry;
      else
	plist->head = pentry;

      pentry->prev = plist->tail;
      plist->tail = pentry;
    }

  prefix_list_trie_add (plist, pentry);

  /* Increment count. */
  plist->count++;

  /* Run hook function. */
  if (plist->master->add_hook)
    (*plist->master->add_hook) (plist);

  route_map_notify_dependencies(plist->name, RMAP_EVENT_PLIST_ADDED);
  plist->master->recent = plist;
}

/* Return string of prefix_list_type. */
static const char *
prefix_list_type_str (struct prefix_list_entry *pentry)
{
  switch (pentry->type)
    {
    case PREFIX_PERMIT:
      return "permit";
    case PREFIX_DENY:
      return "deny";
    default:
      return "";
    }
}

static int
prefix_list_entry_match (struct prefix_list_entry *pentry, struct prefix *p)
{
  int ret;

  ret = prefix_match (&pentry->prefix, p);
  if (! ret)
    return 0;
  
  /* In case of le nor ge is specified, exact match is performed. */
  if (! pentry->le && ! pentry->ge)
    {
      if (pentry->prefix.prefixlen != p->prefixlen)
	return 0;
    }
  else
    {  
      if (pentry->le)
	if (p->prefixlen > pentry->le)
	  return 0;

      if (pentry->ge)
	if (p->prefixlen < pentry->ge)
	  return 0;
    }
  return 1;
}

enum prefix_list_type
prefix_list_apply (struct prefix_list *plist, void *object)
{
  struct prefix_list_entry *pentry, *pbest = NULL;

  struct prefix *p = (struct prefix *) object;
  uint8_t *byte = &p->u.prefix;
  size_t depth = plist->master->trie_depth;
  size_t validbits = p->prefixlen;
  struct pltrie_table *table;

  if (plist == NULL)
    return PREFIX_DENY;

  if (plist->count == 0)
    return PREFIX_PERMIT;

  table = plist->trie;
  while (1)
    {
      for (pentry = table->entries[*byte].up_chain; pentry; pentry = pentry->next_best)
        {
          if (pbest && pbest->seq < pentry->seq)
            continue;
          if (prefix_list_entry_match (pentry, p))
            pbest = pentry;
        }

      if (validbits <= PLC_BITS)
        break;
      validbits -= PLC_BITS;

      if (--depth)
        {
          if (!table->entries[*byte].next_table)
            break;

          table = table->entries[*byte].next_table;
          byte++;
          continue;
        }

      for (pentry = table->entries[*byte].final_chain; pentry; pentry = pentry->next_best)
        {
          if (pbest && pbest->seq < pentry->seq)
            continue;
          if (prefix_list_entry_match (pentry, p))
            pbest = pentry;
        }
      break;
    }

  if (pbest == NULL)
    return PREFIX_DENY;

  return pbest->type;
}

static void __attribute__ ((unused))
prefix_list_print (struct prefix_list *plist)
{
  struct prefix_list_entry *pentry;

  if (plist == NULL)
    return;

  printf ("ip prefix-list %s: %d entries\n", plist->name, plist->count);

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      if (pentry->any)
	printf ("any %s\n", prefix_list_type_str (pentry));
      else
	{
	  struct prefix *p;
	  char buf[BUFSIZ];
	  
	  p = &pentry->prefix;
	  
	  printf ("  seq %d %s %s/%d", 
		  pentry->seq,
		  prefix_list_type_str (pentry),
		  inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		  p->prefixlen);
	  if (pentry->ge)
	    printf (" ge %d", pentry->ge);
	  if (pentry->le)
	    printf (" le %d", pentry->le);
	  printf ("\n");
	}
    }
}

/* Retrun 1 when plist already include pentry policy. */
static struct prefix_list_entry *
prefix_entry_dup_check (struct prefix_list *plist,
			struct prefix_list_entry *new)
{
  size_t depth, maxdepth = plist->master->trie_depth;
  uint8_t byte, *bytes = &new->prefix.u.prefix;
  size_t validbits = new->prefix.prefixlen;
  struct pltrie_table *table;
  struct prefix_list_entry *pentry;
  int seq = 0;

  if (new->seq == -1)
    seq = prefix_new_seq_get (plist);
  else
    seq = new->seq;

  table = plist->trie;
  for (depth = 0; validbits > PLC_BITS && depth < maxdepth - 1; depth++)
    {
      byte = bytes[depth];
      if (!table->entries[byte].next_table)
        return NULL;

      table = table->entries[byte].next_table;
      validbits -= PLC_BITS;
    }

  byte = bytes[depth];
  if (validbits > PLC_BITS)
    pentry = table->entries[byte].final_chain;
  else
    pentry = table->entries[byte].up_chain;

  for (; pentry; pentry = pentry->next_best)
    {
      if (prefix_same (&pentry->prefix, &new->prefix)
	  && pentry->type == new->type
	  && pentry->le == new->le
	  && pentry->ge == new->ge
	  && pentry->seq != seq)
	return pentry;
    }
  return NULL;
}

static int
vty_invalid_prefix_range (struct vty *vty, const char *prefix)
{
  vty_out (vty, "%% Invalid prefix range for %s, make sure: len < ge-value <= le-value%s",
           prefix, VTY_NEWLINE);
  return CMD_WARNING;
}

static int
vty_prefix_list_install (struct vty *vty, afi_t afi, const char *name, 
                         const char *seq, const char *typestr,
			 const char *prefix, const char *ge, const char *le)
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_list_entry *dup;
  struct prefix p;
  int any = 0;
  int seqnum = -1;
  int lenum = 0;
  int genum = 0;

  /* Sequential number. */
  if (seq)
    seqnum = atoi (seq);

  /* ge and le number */
  if (ge)
    genum = atoi (ge);
  if (le)
    lenum = atoi (le);

  /* Check filter type. */
  if (strncmp ("permit", typestr, 1) == 0)
    type = PREFIX_PERMIT;
  else if (strncmp ("deny", typestr, 1) == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "%% prefix type must be permit or deny%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* "any" is special token for matching any IPv4 addresses.  */
  if (afi == AFI_IP)
    {
      if (strncmp ("any", prefix, strlen (prefix)) == 0)
	{
	  ret = str2prefix_ipv4 ("0.0.0.0/0", (struct prefix_ipv4 *) &p);
	  genum = 0;
	  lenum = IPV4_MAX_BITLEN;
	  any = 1;
	}
      else
	ret = str2prefix_ipv4 (prefix, (struct prefix_ipv4 *) &p);

      if (ret <= 0)
	{
	  vty_out (vty, "%% Malformed IPv4 prefix%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    {
      if (strncmp ("any", prefix, strlen (prefix)) == 0)
	{
	  ret = str2prefix_ipv6 ("::/0", (struct prefix_ipv6 *) &p);
	  genum = 0;
	  lenum = IPV6_MAX_BITLEN;
	  any = 1;
	}
      else
	ret = str2prefix_ipv6 (prefix, (struct prefix_ipv6 *) &p);

      if (ret <= 0)
	{
	  vty_out (vty, "%% Malformed IPv6 prefix%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
#endif /* HAVE_IPV6 */

  /* ge and le check. */
  if (genum && genum <= p.prefixlen)
    return vty_invalid_prefix_range (vty, prefix);

  if (lenum && lenum <= p.prefixlen)
    return vty_invalid_prefix_range (vty, prefix);

  if (lenum && genum > lenum)
    return vty_invalid_prefix_range (vty, prefix);

  if (genum && lenum == (afi == AFI_IP ? 32 : 128))
    lenum = 0;

  /* Get prefix_list with name. */
  plist = prefix_list_get (afi, 0, name);

  /* Make prefix entry. */
  pentry = prefix_list_entry_make (&p, type, seqnum, lenum, genum, any);
    
  /* Check same policy. */
  dup = prefix_entry_dup_check (plist, pentry);

  if (dup)
    {
      prefix_list_entry_free (pentry);
      vty_out (vty, "%% Insertion failed - prefix-list entry exists:%s",
	       VTY_NEWLINE);
      vty_out (vty, "   seq %d %s %s", dup->seq, typestr, prefix);
      if (! any && genum)
	vty_out (vty, " ge %d", genum);
      if (! any && lenum)
	vty_out (vty, " le %d", lenum);
      vty_out (vty, "%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_add (plist, pentry);

  return CMD_SUCCESS;
}

static int
vty_prefix_list_uninstall (struct vty *vty, afi_t afi, const char *name, 
                           const char *seq, const char *typestr,
			   const char *prefix, const char *ge, const char *le)
{
  int ret;
  enum prefix_list_type type;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int seqnum = -1;
  int lenum = 0;
  int genum = 0;

  /* Check prefix list name. */
  plist = prefix_list_lookup (afi, name);
  if (! plist)
    {
      vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Only prefix-list name specified, delete the entire prefix-list. */
  if (seq == NULL && typestr == NULL && prefix == NULL && 
      ge == NULL && le == NULL)
    {
      prefix_list_delete (plist);
      return CMD_SUCCESS;
    }

  /* We must have, at a minimum, both the type and prefix here */
  if ((typestr == NULL) || (prefix == NULL))
    {
      vty_out (vty, "%% Both prefix and type required%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Check sequence number. */
  if (seq)
    seqnum = atoi (seq);

  /* ge and le number */
  if (ge)
    genum = atoi (ge);
  if (le)
    lenum = atoi (le);

  /* Check of filter type. */
  if (strncmp ("permit", typestr, 1) == 0)
    type = PREFIX_PERMIT;
  else if (strncmp ("deny", typestr, 1) == 0)
    type = PREFIX_DENY;
  else
    {
      vty_out (vty, "%% prefix type must be permit or deny%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* "any" is special token for matching any IPv4 addresses.  */
  if (afi == AFI_IP)
    {
      if (strncmp ("any", prefix, strlen (prefix)) == 0)
	{
	  ret = str2prefix_ipv4 ("0.0.0.0/0", (struct prefix_ipv4 *) &p);
	  genum = 0;
	  lenum = IPV4_MAX_BITLEN;
	}
      else
	ret = str2prefix_ipv4 (prefix, (struct prefix_ipv4 *) &p);

      if (ret <= 0)
	{
	  vty_out (vty, "%% Malformed IPv4 prefix%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
#ifdef HAVE_IPV6
  else if (afi == AFI_IP6)
    {
      if (strncmp ("any", prefix, strlen (prefix)) == 0)
	{
	  ret = str2prefix_ipv6 ("::/0", (struct prefix_ipv6 *) &p);
	  genum = 0;
	  lenum = IPV6_MAX_BITLEN;
	}
      else
	ret = str2prefix_ipv6 (prefix, (struct prefix_ipv6 *) &p);

      if (ret <= 0)
	{
	  vty_out (vty, "%% Malformed IPv6 prefix%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
    }
#endif /* HAVE_IPV6 */

  /* Lookup prefix entry. */
  pentry = prefix_list_entry_lookup(plist, &p, type, seqnum, lenum, genum);

  if (pentry == NULL)
    {
      vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  /* Install new filter to the access_list. */
  prefix_list_entry_delete (plist, pentry, 1);

  return CMD_SUCCESS;
}

static int
vty_prefix_list_desc_unset (struct vty *vty, afi_t afi, const char *name)
{
  struct prefix_list *plist;

  plist = prefix_list_lookup (afi, name);
  if (! plist)
    {
      vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  if (plist->desc)
    {
      XFREE (MTYPE_TMP, plist->desc);
      plist->desc = NULL;
    }

  if (plist->head == NULL && plist->tail == NULL && plist->desc == NULL)
    prefix_list_delete (plist);

  return CMD_SUCCESS;
}

enum display_type
{
  normal_display,
  summary_display,
  detail_display,
  sequential_display,
  longer_display,
  first_match_display
};

static void
vty_show_prefix_entry (struct vty *vty, afi_t afi, struct prefix_list *plist,
		       struct prefix_master *master, enum display_type dtype,
		       int seqnum)
{
  struct prefix_list_entry *pentry;

  /* Print the name of the protocol */
  if (zlog_default)
      vty_out (vty, "%s: ", zlog_proto_names[zlog_default->protocol]);
                                                                           
  if (dtype == normal_display)
    {
      vty_out (vty, "ip%s prefix-list %s: %d entries%s",
	       afi == AFI_IP ? "" : "v6",
	       plist->name, plist->count, VTY_NEWLINE);
      if (plist->desc)
	vty_out (vty, "   Description: %s%s", plist->desc, VTY_NEWLINE);
    }
  else if (dtype == summary_display || dtype == detail_display)
    {
      vty_out (vty, "ip%s prefix-list %s:%s",
	       afi == AFI_IP ? "" : "v6", plist->name, VTY_NEWLINE);

      if (plist->desc)
	vty_out (vty, "   Description: %s%s", plist->desc, VTY_NEWLINE);

      vty_out (vty, "   count: %d, range entries: %d, sequences: %d - %d%s",
	       plist->count, plist->rangecount, 
	       plist->head ? plist->head->seq : 0, 
	       plist->tail ? plist->tail->seq : 0,
	       VTY_NEWLINE);
    }

  if (dtype != summary_display)
    {
      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  if (dtype == sequential_display && pentry->seq != seqnum)
	    continue;
	    
	  vty_out (vty, "   ");

	  if (master->seqnum)
	    vty_out (vty, "seq %d ", pentry->seq);

	  vty_out (vty, "%s ", prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, "any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];

	      vty_out (vty, "%s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);

	      if (pentry->ge)
		vty_out (vty, " ge %d", pentry->ge);
	      if (pentry->le)
		vty_out (vty, " le %d", pentry->le);
	    }

	  if (dtype == detail_display || dtype == sequential_display)
	    vty_out (vty, " (hit count: %ld, refcount: %ld)", 
		     pentry->hitcnt, pentry->refcnt);
	  
	  vty_out (vty, "%s", VTY_NEWLINE);
	}
    }
}

static int
vty_show_prefix_list (struct vty *vty, afi_t afi, const char *name,
		      const char *seq, enum display_type dtype)
{
  struct prefix_list *plist;
  struct prefix_master *master;
  int seqnum = 0;

  master = prefix_master_get (afi, 0);
  if (master == NULL)
    return CMD_WARNING;

  if (seq)
    seqnum = atoi (seq);

  if (name)
    {
      plist = prefix_list_lookup (afi, name);
      if (! plist)
	{
	  vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}
      vty_show_prefix_entry (vty, afi, plist, master, dtype, seqnum);
    }
  else
    {
      if (dtype == detail_display || dtype == summary_display)
	{
	  if (master->recent)
	    vty_out (vty, "Prefix-list with the last deletion/insertion: %s%s",
		     master->recent->name, VTY_NEWLINE);
	}

      for (plist = master->num.head; plist; plist = plist->next)
	vty_show_prefix_entry (vty, afi, plist, master, dtype, seqnum);

      for (plist = master->str.head; plist; plist = plist->next)
	vty_show_prefix_entry (vty, afi, plist, master, dtype, seqnum);
    }

  return CMD_SUCCESS;
}

static int
vty_show_prefix_list_prefix (struct vty *vty, afi_t afi, const char *name, 
			     const char *prefix, enum display_type type)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix p;
  int ret;
  int match;

  plist = prefix_list_lookup (afi, name);
  if (! plist)
    {
      vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  ret = str2prefix (prefix, &p);
  if (ret <= 0)
    {
      vty_out (vty, "%% prefix is malformed%s", VTY_NEWLINE);
      return CMD_WARNING;
    }

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      match = 0;

      if (type == normal_display || type == first_match_display)
	if (prefix_same (&p, &pentry->prefix))
	  match = 1;

      if (type == longer_display)
	if (prefix_match (&p, &pentry->prefix))
	  match = 1;

      if (match)
	{
	  vty_out (vty, "   seq %d %s ", 
		   pentry->seq,
		   prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, "any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];
	      
	      vty_out (vty, "%s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);

	      if (pentry->ge)
		vty_out (vty, " ge %d", pentry->ge);
	      if (pentry->le)
		vty_out (vty, " le %d", pentry->le);
	    }
	  
	  if (type == normal_display || type == first_match_display)
	    vty_out (vty, " (hit count: %ld, refcount: %ld)", 
		     pentry->hitcnt, pentry->refcnt);

	  vty_out (vty, "%s", VTY_NEWLINE);

	  if (type == first_match_display)
	    return CMD_SUCCESS;
	}
    }
  return CMD_SUCCESS;
}

static int
vty_clear_prefix_list (struct vty *vty, afi_t afi, const char *name, 
                       const char *prefix)
{
  struct prefix_master *master;
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  int ret;
  struct prefix p;

  master = prefix_master_get (afi, 0);
  if (master == NULL)
    return CMD_WARNING;

  if (name == NULL && prefix == NULL)
    {
      for (plist = master->num.head; plist; plist = plist->next)
	for (pentry = plist->head; pentry; pentry = pentry->next)
	  pentry->hitcnt = 0;

      for (plist = master->str.head; plist; plist = plist->next)
	for (pentry = plist->head; pentry; pentry = pentry->next)
	  pentry->hitcnt = 0;
    }
  else
    {
      plist = prefix_list_lookup (afi, name);
      if (! plist)
	{
	  vty_out (vty, "%% Can't find specified prefix-list%s", VTY_NEWLINE);
	  return CMD_WARNING;
	}

      if (prefix)
	{
	  ret = str2prefix (prefix, &p);
	  if (ret <= 0)
	    {
	      vty_out (vty, "%% prefix is malformed%s", VTY_NEWLINE);
	      return CMD_WARNING;
	    }
	}

      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  if (prefix)
	    {
	      if (prefix_match (&pentry->prefix, &p))
		pentry->hitcnt = 0;
	    }
	  else
	    pentry->hitcnt = 0;
	}
    }
  return CMD_SUCCESS;
}

DEFUN (ip_prefix_list,
       ip_prefix_list_cmd,
       "ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], NULL, 
				  argv[1], argv[2], NULL, NULL);
}

DEFUN (ip_prefix_list_ge,
       ip_prefix_list_ge_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], NULL, argv[1], 
				 argv[2], argv[3], NULL);
}

DEFUN (ip_prefix_list_ge_le,
       ip_prefix_list_ge_le_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], NULL, argv[1], 
				  argv[2], argv[3], argv[4]);
}

DEFUN (ip_prefix_list_le,
       ip_prefix_list_le_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], NULL, argv[1],
				  argv[2], NULL, argv[3]);
}

DEFUN (ip_prefix_list_le_ge,
       ip_prefix_list_le_ge_cmd,
       "ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], NULL, argv[1],
				  argv[2], argv[4], argv[3]);
}

DEFUN (ip_prefix_list_seq,
       ip_prefix_list_seq_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match. Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], argv[1], argv[2],
				  argv[3], NULL, NULL);
}

DEFUN (ip_prefix_list_seq_ge,
       ip_prefix_list_seq_ge_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], argv[1], argv[2],
				  argv[3], argv[4], NULL);
}

DEFUN (ip_prefix_list_seq_ge_le,
       ip_prefix_list_seq_ge_le_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], argv[1], argv[2],
				  argv[3], argv[4], argv[5]);
}

DEFUN (ip_prefix_list_seq_le,
       ip_prefix_list_seq_le_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], argv[1], argv[2],
				  argv[3], NULL, argv[4]);
}

DEFUN (ip_prefix_list_seq_le_ge,
       ip_prefix_list_seq_le_ge_cmd,
       "ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP, argv[0], argv[1], argv[2],
				  argv[3], argv[5], argv[4]);
}

DEFUN (no_ip_prefix_list,
       no_ip_prefix_list_cmd,
       "no ip prefix-list WORD",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], NULL, NULL,
				    NULL, NULL, NULL);
}

DEFUN (no_ip_prefix_list_prefix,
       no_ip_prefix_list_prefix_cmd,
       "no ip prefix-list WORD (deny|permit) (A.B.C.D/M|any)",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], NULL, argv[1],
				    argv[2], NULL, NULL);
}

DEFUN (no_ip_prefix_list_ge,
       no_ip_prefix_list_ge_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], NULL, argv[1],
				    argv[2], argv[3], NULL);
}

DEFUN (no_ip_prefix_list_ge_le,
       no_ip_prefix_list_ge_le_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], NULL, argv[1],
				    argv[2], argv[3], argv[4]);
}

DEFUN (no_ip_prefix_list_le,
       no_ip_prefix_list_le_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], NULL, argv[1],
				    argv[2], NULL, argv[3]);
}

DEFUN (no_ip_prefix_list_le_ge,
       no_ip_prefix_list_le_ge_cmd,
       "no ip prefix-list WORD (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], NULL, argv[1],
				    argv[2], argv[4], argv[3]);
}

DEFUN (no_ip_prefix_list_seq,
       no_ip_prefix_list_seq_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) (A.B.C.D/M|any)",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Any prefix match.  Same as \"0.0.0.0/0 le 32\"\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], argv[1], argv[2],
				    argv[3], NULL, NULL);
}

DEFUN (no_ip_prefix_list_seq_ge,
       no_ip_prefix_list_seq_ge_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], argv[1], argv[2],
				    argv[3], argv[4], NULL);
}

DEFUN (no_ip_prefix_list_seq_ge_le,
       no_ip_prefix_list_seq_ge_le_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M ge <0-32> le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], argv[1], argv[2],
				    argv[3], argv[4], argv[5]);
}

DEFUN (no_ip_prefix_list_seq_le,
       no_ip_prefix_list_seq_le_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], argv[1], argv[2],
				    argv[3], NULL, argv[4]);
}

DEFUN (no_ip_prefix_list_seq_le_ge,
       no_ip_prefix_list_seq_le_ge_cmd,
       "no ip prefix-list WORD seq <1-4294967295> (deny|permit) A.B.C.D/M le <0-32> ge <0-32>",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP, argv[0], argv[1], argv[2],
				    argv[3], argv[5], argv[4]);
}

DEFUN (ip_prefix_list_sequence_number,
       ip_prefix_list_sequence_number_cmd,
       "ip prefix-list sequence-number",
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv4.seqnum = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ip_prefix_list_sequence_number,
       no_ip_prefix_list_sequence_number_cmd,
       "no ip prefix-list sequence-number",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv4.seqnum = 0;
  return CMD_SUCCESS;
}

DEFUN (ip_prefix_list_description,
       ip_prefix_list_description_cmd,
       "ip prefix-list WORD description .LINE",
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
  struct prefix_list *plist;

  plist = prefix_list_get (AFI_IP, 0, argv[0]);
  
  if (plist->desc)
    {
      XFREE (MTYPE_TMP, plist->desc);
      plist->desc = NULL;
    }
  plist->desc = argv_concat(argv, argc, 1);

  return CMD_SUCCESS;
}       

DEFUN (no_ip_prefix_list_description,
       no_ip_prefix_list_description_cmd,
       "no ip prefix-list WORD description",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
  return vty_prefix_list_desc_unset (vty, AFI_IP, argv[0]);
}

ALIAS (no_ip_prefix_list_description,
       no_ip_prefix_list_description_arg_cmd,
       "no ip prefix-list WORD description .LINE",
       NO_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFUN (show_ip_prefix_list,
       show_ip_prefix_list_cmd,
       "show ip prefix-list",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR)
{
  return vty_show_prefix_list (vty, AFI_IP, NULL, NULL, normal_display);
}

DEFUN (show_ip_prefix_list_name,
       show_ip_prefix_list_name_cmd,
       "show ip prefix-list WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AFI_IP, argv[0], NULL, normal_display);
}

DEFUN (show_ip_prefix_list_name_seq,
       show_ip_prefix_list_name_seq_cmd,
       "show ip prefix-list WORD seq <1-4294967295>",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
  return vty_show_prefix_list (vty, AFI_IP, argv[0], argv[1], sequential_display);
}

DEFUN (show_ip_prefix_list_prefix,
       show_ip_prefix_list_prefix_cmd,
       "show ip prefix-list WORD A.B.C.D/M",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP, argv[0], argv[1], normal_display);
}

DEFUN (show_ip_prefix_list_prefix_longer,
       show_ip_prefix_list_prefix_longer_cmd,
       "show ip prefix-list WORD A.B.C.D/M longer",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "Lookup longer prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP, argv[0], argv[1], longer_display);
}

DEFUN (show_ip_prefix_list_prefix_first_match,
       show_ip_prefix_list_prefix_first_match_cmd,
       "show ip prefix-list WORD A.B.C.D/M first-match",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n"
       "First matched prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP, argv[0], argv[1], first_match_display);
}

DEFUN (show_ip_prefix_list_summary,
       show_ip_prefix_list_summary_cmd,
       "show ip prefix-list summary",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")
{
  return vty_show_prefix_list (vty, AFI_IP, NULL, NULL, summary_display);
}

DEFUN (show_ip_prefix_list_summary_name,
       show_ip_prefix_list_summary_name_cmd,
       "show ip prefix-list summary WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AFI_IP, argv[0], NULL, summary_display);
}


DEFUN (show_ip_prefix_list_detail,
       show_ip_prefix_list_detail_cmd,
       "show ip prefix-list detail",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")
{
  return vty_show_prefix_list (vty, AFI_IP, NULL, NULL, detail_display);
}

DEFUN (show_ip_prefix_list_detail_name,
       show_ip_prefix_list_detail_name_cmd,
       "show ip prefix-list detail WORD",
       SHOW_STR
       IP_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AFI_IP, argv[0], NULL, detail_display);
}

DEFUN (clear_ip_prefix_list,
       clear_ip_prefix_list_cmd,
       "clear ip prefix-list",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (vty, AFI_IP, NULL, NULL);
}

DEFUN (clear_ip_prefix_list_name,
       clear_ip_prefix_list_name_cmd,
       "clear ip prefix-list WORD",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_clear_prefix_list (vty, AFI_IP, argv[0], NULL);
}

DEFUN (clear_ip_prefix_list_name_prefix,
       clear_ip_prefix_list_name_prefix_cmd,
       "clear ip prefix-list WORD A.B.C.D/M",
       CLEAR_STR
       IP_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IP prefix <network>/<length>, e.g., 35.0.0.0/8\n")
{
  return vty_clear_prefix_list (vty, AFI_IP, argv[0], argv[1]);
}

#ifdef HAVE_IPV6
DEFUN (ipv6_prefix_list,
       ipv6_prefix_list_cmd,
       "ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], NULL, 
				  argv[1], argv[2], NULL, NULL);
}

DEFUN (ipv6_prefix_list_ge,
       ipv6_prefix_list_ge_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], NULL, argv[1], 
				 argv[2], argv[3], NULL);
}

DEFUN (ipv6_prefix_list_ge_le,
       ipv6_prefix_list_ge_le_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")

{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], NULL, argv[1], 
				  argv[2], argv[3], argv[4]);
}

DEFUN (ipv6_prefix_list_le,
       ipv6_prefix_list_le_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], NULL, argv[1],
				  argv[2], NULL, argv[3]);
}

DEFUN (ipv6_prefix_list_le_ge,
       ipv6_prefix_list_le_ge_cmd,
       "ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], NULL, argv[1],
				  argv[2], argv[4], argv[3]);
}

DEFUN (ipv6_prefix_list_seq,
       ipv6_prefix_list_seq_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], argv[1], argv[2],
				  argv[3], NULL, NULL);
}

DEFUN (ipv6_prefix_list_seq_ge,
       ipv6_prefix_list_seq_ge_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], argv[1], argv[2],
				  argv[3], argv[4], NULL);
}

DEFUN (ipv6_prefix_list_seq_ge_le,
       ipv6_prefix_list_seq_ge_le_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], argv[1], argv[2],
				  argv[3], argv[4], argv[5]);
}

DEFUN (ipv6_prefix_list_seq_le,
       ipv6_prefix_list_seq_le_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], argv[1], argv[2],
				  argv[3], NULL, argv[4]);
}

DEFUN (ipv6_prefix_list_seq_le_ge,
       ipv6_prefix_list_seq_le_ge_cmd,
       "ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_install (vty, AFI_IP6, argv[0], argv[1], argv[2],
				  argv[3], argv[5], argv[4]);
}

DEFUN (no_ipv6_prefix_list,
       no_ipv6_prefix_list_cmd,
       "no ipv6 prefix-list WORD",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], NULL, NULL,
				    NULL, NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_prefix,
       no_ipv6_prefix_list_prefix_cmd,
       "no ipv6 prefix-list WORD (deny|permit) (X:X::X:X/M|any)",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], NULL, argv[1],
				    argv[2], NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_ge,
       no_ipv6_prefix_list_ge_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], NULL, argv[1],
				    argv[2], argv[3], NULL);
}

DEFUN (no_ipv6_prefix_list_ge_le,
       no_ipv6_prefix_list_ge_le_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], NULL, argv[1],
				    argv[2], argv[3], argv[4]);
}

DEFUN (no_ipv6_prefix_list_le,
       no_ipv6_prefix_list_le_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], NULL, argv[1],
				    argv[2], NULL, argv[3]);
}

DEFUN (no_ipv6_prefix_list_le_ge,
       no_ipv6_prefix_list_le_ge_cmd,
       "no ipv6 prefix-list WORD (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], NULL, argv[1],
				    argv[2], argv[4], argv[3]);
}

DEFUN (no_ipv6_prefix_list_seq,
       no_ipv6_prefix_list_seq_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) (X:X::X:X/M|any)",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Any prefix match.  Same as \"::0/0 le 128\"\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], argv[1], argv[2],
				    argv[3], NULL, NULL);
}

DEFUN (no_ipv6_prefix_list_seq_ge,
       no_ipv6_prefix_list_seq_ge_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], argv[1], argv[2],
				    argv[3], argv[4], NULL);
}

DEFUN (no_ipv6_prefix_list_seq_ge_le,
       no_ipv6_prefix_list_seq_ge_le_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M ge <0-128> le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], argv[1], argv[2],
				    argv[3], argv[4], argv[5]);
}

DEFUN (no_ipv6_prefix_list_seq_le,
       no_ipv6_prefix_list_seq_le_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], argv[1], argv[2],
				    argv[3], NULL, argv[4]);
}

DEFUN (no_ipv6_prefix_list_seq_le_ge,
       no_ipv6_prefix_list_seq_le_ge_cmd,
       "no ipv6 prefix-list WORD seq <1-4294967295> (deny|permit) X:X::X:X/M le <0-128> ge <0-128>",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n"
       "Specify packets to reject\n"
       "Specify packets to forward\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Maximum prefix length to be matched\n"
       "Maximum prefix length\n"
       "Minimum prefix length to be matched\n"
       "Minimum prefix length\n")
{
  return vty_prefix_list_uninstall (vty, AFI_IP6, argv[0], argv[1], argv[2],
				    argv[3], argv[5], argv[4]);
}

DEFUN (ipv6_prefix_list_sequence_number,
       ipv6_prefix_list_sequence_number_cmd,
       "ipv6 prefix-list sequence-number",
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv6.seqnum = 1;
  return CMD_SUCCESS;
}

DEFUN (no_ipv6_prefix_list_sequence_number,
       no_ipv6_prefix_list_sequence_number_cmd,
       "no ipv6 prefix-list sequence-number",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Include/exclude sequence numbers in NVGEN\n")
{
  prefix_master_ipv6.seqnum = 0;
  return CMD_SUCCESS;
}

DEFUN (ipv6_prefix_list_description,
       ipv6_prefix_list_description_cmd,
       "ipv6 prefix-list WORD description .LINE",
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")
{
  struct prefix_list *plist;

  plist = prefix_list_get (AFI_IP6, 0, argv[0]);
  
  if (plist->desc)
    {
      XFREE (MTYPE_TMP, plist->desc);
      plist->desc = NULL;
    }
  plist->desc = argv_concat(argv, argc, 1);

  return CMD_SUCCESS;
}       

DEFUN (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_cmd,
       "no ipv6 prefix-list WORD description",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n")
{
  return vty_prefix_list_desc_unset (vty, AFI_IP6, argv[0]);
}

ALIAS (no_ipv6_prefix_list_description,
       no_ipv6_prefix_list_description_arg_cmd,
       "no ipv6 prefix-list WORD description .LINE",
       NO_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "Prefix-list specific description\n"
       "Up to 80 characters describing this prefix-list\n")

DEFUN (show_ipv6_prefix_list,
       show_ipv6_prefix_list_cmd,
       "show ipv6 prefix-list",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR)
{
  return vty_show_prefix_list (vty, AFI_IP6, NULL, NULL, normal_display);
}

DEFUN (show_ipv6_prefix_list_name,
       show_ipv6_prefix_list_name_cmd,
       "show ipv6 prefix-list WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AFI_IP6, argv[0], NULL, normal_display);
}

DEFUN (show_ipv6_prefix_list_name_seq,
       show_ipv6_prefix_list_name_seq_cmd,
       "show ipv6 prefix-list WORD seq <1-4294967295>",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "sequence number of an entry\n"
       "Sequence number\n")
{
  return vty_show_prefix_list (vty, AFI_IP6, argv[0], argv[1], sequential_display);
}

DEFUN (show_ipv6_prefix_list_prefix,
       show_ipv6_prefix_list_prefix_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP6, argv[0], argv[1], normal_display);
}

DEFUN (show_ipv6_prefix_list_prefix_longer,
       show_ipv6_prefix_list_prefix_longer_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M longer",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "Lookup longer prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP6, argv[0], argv[1], longer_display);
}

DEFUN (show_ipv6_prefix_list_prefix_first_match,
       show_ipv6_prefix_list_prefix_first_match_cmd,
       "show ipv6 prefix-list WORD X:X::X:X/M first-match",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n"
       "First matched prefix\n")
{
  return vty_show_prefix_list_prefix (vty, AFI_IP6, argv[0], argv[1], first_match_display);
}

DEFUN (show_ipv6_prefix_list_summary,
       show_ipv6_prefix_list_summary_cmd,
       "show ipv6 prefix-list summary",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n")
{
  return vty_show_prefix_list (vty, AFI_IP6, NULL, NULL, summary_display);
}

DEFUN (show_ipv6_prefix_list_summary_name,
       show_ipv6_prefix_list_summary_name_cmd,
       "show ipv6 prefix-list summary WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Summary of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AFI_IP6, argv[0], NULL, summary_display);
}

DEFUN (show_ipv6_prefix_list_detail,
       show_ipv6_prefix_list_detail_cmd,
       "show ipv6 prefix-list detail",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n")
{
  return vty_show_prefix_list (vty, AFI_IP6, NULL, NULL, detail_display);
}

DEFUN (show_ipv6_prefix_list_detail_name,
       show_ipv6_prefix_list_detail_name_cmd,
       "show ipv6 prefix-list detail WORD",
       SHOW_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Detail of prefix lists\n"
       "Name of a prefix list\n")
{
  return vty_show_prefix_list (vty, AFI_IP6, argv[0], NULL, detail_display);
}

DEFUN (clear_ipv6_prefix_list,
       clear_ipv6_prefix_list_cmd,
       "clear ipv6 prefix-list",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR)
{
  return vty_clear_prefix_list (vty, AFI_IP6, NULL, NULL);
}

DEFUN (clear_ipv6_prefix_list_name,
       clear_ipv6_prefix_list_name_cmd,
       "clear ipv6 prefix-list WORD",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n")
{
  return vty_clear_prefix_list (vty, AFI_IP6, argv[0], NULL);
}

DEFUN (clear_ipv6_prefix_list_name_prefix,
       clear_ipv6_prefix_list_name_prefix_cmd,
       "clear ipv6 prefix-list WORD X:X::X:X/M",
       CLEAR_STR
       IPV6_STR
       PREFIX_LIST_STR
       "Name of a prefix list\n"
       "IPv6 prefix <network>/<length>, e.g., 3ffe::/16\n")
{
  return vty_clear_prefix_list (vty, AFI_IP6, argv[0], argv[1]);
}
#endif /* HAVE_IPV6 */

/* Configuration write function. */
static int
config_write_prefix_afi (afi_t afi, struct vty *vty)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  struct prefix_master *master;
  int write = 0;

  master = prefix_master_get (afi, 0);
  if (master == NULL)
    return 0;

  if (! master->seqnum)
    {
      vty_out (vty, "no ip%s prefix-list sequence-number%s", 
	       afi == AFI_IP ? "" : "v6", VTY_NEWLINE);
      vty_out (vty, "!%s", VTY_NEWLINE);
    }

  for (plist = master->num.head; plist; plist = plist->next)
    {
      if (plist->desc)
	{
	  vty_out (vty, "ip%s prefix-list %s description %s%s",
		   afi == AFI_IP ? "" : "v6",
		   plist->name, plist->desc, VTY_NEWLINE);
	  write++;
	}

      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  vty_out (vty, "ip%s prefix-list %s ",
		   afi == AFI_IP ? "" : "v6",
		   plist->name);

	  if (master->seqnum)
	    vty_out (vty, "seq %d ", pentry->seq);
	
	  vty_out (vty, "%s ", prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, "any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];

	      vty_out (vty, "%s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);

	      if (pentry->ge)
		vty_out (vty, " ge %d", pentry->ge);
	      if (pentry->le)
		vty_out (vty, " le %d", pentry->le);
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	  write++;
	}
      /* vty_out (vty, "!%s", VTY_NEWLINE); */
    }

  for (plist = master->str.head; plist; plist = plist->next)
    {
      if (plist->desc)
	{
	  vty_out (vty, "ip%s prefix-list %s description %s%s",
		   afi == AFI_IP ? "" : "v6",
		   plist->name, plist->desc, VTY_NEWLINE);
	  write++;
	}

      for (pentry = plist->head; pentry; pentry = pentry->next)
	{
	  vty_out (vty, "ip%s prefix-list %s ",
		   afi == AFI_IP ? "" : "v6",
		   plist->name);

	  if (master->seqnum)
	    vty_out (vty, "seq %d ", pentry->seq);

	  vty_out (vty, "%s", prefix_list_type_str (pentry));

	  if (pentry->any)
	    vty_out (vty, " any");
	  else
	    {
	      struct prefix *p = &pentry->prefix;
	      char buf[BUFSIZ];

	      vty_out (vty, " %s/%d",
		       inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
		       p->prefixlen);

	      if (pentry->ge)
		vty_out (vty, " ge %d", pentry->ge);
	      if (pentry->le)
		vty_out (vty, " le %d", pentry->le);
	    }
	  vty_out (vty, "%s", VTY_NEWLINE);
	  write++;
	}
    }
  
  return write;
}

struct stream *
prefix_bgp_orf_entry (struct stream *s, struct prefix_list *plist,
		      u_char init_flag, u_char permit_flag, u_char deny_flag)
{
  struct prefix_list_entry *pentry;

  if (! plist)
    return s;

  for (pentry = plist->head; pentry; pentry = pentry->next)
    {
      u_char flag = init_flag;
      struct prefix *p = &pentry->prefix;

      flag |= (pentry->type == PREFIX_PERMIT ?
               permit_flag : deny_flag);
      stream_putc (s, flag);
      stream_putl (s, (u_int32_t)pentry->seq);
      stream_putc (s, (u_char)pentry->ge);
      stream_putc (s, (u_char)pentry->le);
      stream_put_prefix (s, p);
    }

  return s;
}

int
prefix_bgp_orf_set (char *name, afi_t afi, struct orf_prefix *orfp,
		    int permit, int set)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;

  /* ge and le value check */ 
  if (orfp->ge && orfp->ge <= orfp->p.prefixlen)
    return CMD_WARNING;
  if (orfp->le && orfp->le <= orfp->p.prefixlen)
    return CMD_WARNING;
  if (orfp->le && orfp->ge > orfp->le)
    return CMD_WARNING;

  if (orfp->ge && orfp->le == (afi == AFI_IP ? 32 : 128))
    orfp->le = 0;

  plist = prefix_list_get (afi, 1, name);
  if (! plist)
    return CMD_WARNING;

  if (set)
    {
      pentry = prefix_list_entry_make (&orfp->p,
				       (permit ? PREFIX_PERMIT : PREFIX_DENY),
				       orfp->seq, orfp->le, orfp->ge, 0);

      if (prefix_entry_dup_check (plist, pentry))
	{
	  prefix_list_entry_free (pentry);
	  return CMD_WARNING;
	}

      prefix_list_entry_add (plist, pentry);
    }
  else
    {
      pentry = prefix_list_entry_lookup (plist, &orfp->p,
					 (permit ? PREFIX_PERMIT : PREFIX_DENY),
					 orfp->seq, orfp->le, orfp->ge);

      if (! pentry)
	return CMD_WARNING;

      prefix_list_entry_delete (plist, pentry, 1);
    }

  return CMD_SUCCESS;
}

void
prefix_bgp_orf_remove_all (afi_t afi, char *name)
{
  struct prefix_list *plist;

  plist = prefix_bgp_orf_lookup (afi, name);
  if (plist)
    prefix_list_delete (plist);
}

/* return prefix count */
int
prefix_bgp_show_prefix_list (struct vty *vty, afi_t afi, char *name, u_char use_json)
{
  struct prefix_list *plist;
  struct prefix_list_entry *pentry;
  json_object *json = NULL;
  json_object *json_prefix = NULL;
  json_object *json_list = NULL;

  plist = prefix_bgp_orf_lookup (afi, name);
  if (! plist)
    return 0;

  if (! vty)
    return plist->count;

  if(use_json)
    {
      json = json_object_new_object();
      json_prefix = json_object_new_object();
      json_list = json_object_new_object();

      json_object_int_add(json_prefix, "prefixListCounter", plist->count);
      json_object_string_add(json_prefix, "prefixListName", plist->name);

      for (pentry = plist->head; pentry; pentry = pentry->next)
        {
          struct prefix *p = &pentry->prefix;
          char buf_a[BUFSIZ];
          char buf_b[BUFSIZ];

          sprintf(buf_a, "%s/%d", inet_ntop (p->family, &p->u.prefix, buf_b, BUFSIZ),
                            p->prefixlen);

          json_object_int_add(json_list, "seq", pentry->seq);
          json_object_string_add(json_list, "seqPrefixListType", prefix_list_type_str (pentry));

          if (pentry->ge)
            json_object_int_add(json_list, "ge", pentry->ge);
          if (pentry->le)
            json_object_int_add(json_list, "le", pentry->le);

          json_object_object_add(json_prefix, buf_a, json_list);
        }
      if (afi == AFI_IP)
        json_object_object_add(json, "ipPrefixList", json_prefix);
      else
        json_object_object_add(json, "ipv6PrefixList", json_prefix);

      vty_out (vty, "%s%s", json_object_to_json_string(json), VTY_NEWLINE);
      json_object_free(json);
    }
  else
    {
      vty_out (vty, "ip%s prefix-list %s: %d entries%s",
               afi == AFI_IP ? "" : "v6",
               plist->name, plist->count, VTY_NEWLINE);

      for (pentry = plist->head; pentry; pentry = pentry->next)
        {
          struct prefix *p = &pentry->prefix;
          char buf[BUFSIZ];

          vty_out (vty, "   seq %d %s %s/%d", pentry->seq,
                   prefix_list_type_str (pentry),
                   inet_ntop (p->family, &p->u.prefix, buf, BUFSIZ),
                   p->prefixlen);

          if (pentry->ge)
            vty_out (vty, " ge %d", pentry->ge);
          if (pentry->le)
            vty_out (vty, " le %d", pentry->le);

          vty_out (vty, "%s", VTY_NEWLINE);
        }
    }
  return plist->count;
}

static void
prefix_list_reset_afi (afi_t afi, int orf)
{
  struct prefix_list *plist;
  struct prefix_list *next;
  struct prefix_master *master;

  master = prefix_master_get (afi, orf);
  if (master == NULL)
    return;

  for (plist = master->num.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }
  for (plist = master->str.head; plist; plist = next)
    {
      next = plist->next;
      prefix_list_delete (plist);
    }

  assert (master->num.head == NULL);
  assert (master->num.tail == NULL);

  assert (master->str.head == NULL);
  assert (master->str.tail == NULL);

  master->seqnum = 1;
  master->recent = NULL;
}


/* Prefix-list node. */
static struct cmd_node prefix_node =
{
  PREFIX_NODE,
  "",				/* Prefix list has no interface. */
  1
};

static int
config_write_prefix_ipv4 (struct vty *vty)
{
  return config_write_prefix_afi (AFI_IP, vty);
}

static void
prefix_list_init_ipv4 (void)
{
  install_node (&prefix_node, config_write_prefix_ipv4);

  install_element (CONFIG_NODE, &ip_prefix_list_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &ip_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &no_ip_prefix_list_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_prefix_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &ip_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_description_arg_cmd);

  install_element (CONFIG_NODE, &ip_prefix_list_sequence_number_cmd);
  install_element (CONFIG_NODE, &no_ip_prefix_list_sequence_number_cmd);

  install_element (VIEW_NODE, &show_ip_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_name_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_name_seq_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_prefix_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_prefix_first_match_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_summary_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_summary_name_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_detail_cmd);
  install_element (VIEW_NODE, &show_ip_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &show_ip_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_name_seq_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_prefix_first_match_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_summary_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_summary_name_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_detail_cmd);
  install_element (ENABLE_NODE, &show_ip_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &clear_ip_prefix_list_cmd);
  install_element (ENABLE_NODE, &clear_ip_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &clear_ip_prefix_list_name_prefix_cmd);
}

#ifdef HAVE_IPV6
/* Prefix-list node. */
static struct cmd_node prefix_ipv6_node =
{
  PREFIX_IPV6_NODE,
  "",				/* Prefix list has no interface. */
  1
};

static int
config_write_prefix_ipv6 (struct vty *vty)
{
  return config_write_prefix_afi (AFI_IP6, vty);
}

static void
prefix_list_init_ipv6 (void)
{
  install_node (&prefix_ipv6_node, config_write_prefix_ipv6);

  install_element (CONFIG_NODE, &ipv6_prefix_list_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &ipv6_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &no_ipv6_prefix_list_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_prefix_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_ge_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_le_ge_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_ge_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_ge_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_le_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_seq_le_ge_cmd);

  install_element (CONFIG_NODE, &ipv6_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_description_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_description_arg_cmd);

  install_element (CONFIG_NODE, &ipv6_prefix_list_sequence_number_cmd);
  install_element (CONFIG_NODE, &no_ipv6_prefix_list_sequence_number_cmd);

  install_element (VIEW_NODE, &show_ipv6_prefix_list_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_name_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_name_seq_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_longer_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_prefix_first_match_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_summary_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_summary_name_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_detail_cmd);
  install_element (VIEW_NODE, &show_ipv6_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &show_ipv6_prefix_list_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_name_seq_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_longer_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_prefix_first_match_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_summary_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_summary_name_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_detail_cmd);
  install_element (ENABLE_NODE, &show_ipv6_prefix_list_detail_name_cmd);

  install_element (ENABLE_NODE, &clear_ipv6_prefix_list_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_prefix_list_name_cmd);
  install_element (ENABLE_NODE, &clear_ipv6_prefix_list_name_prefix_cmd);
}
#endif /* HAVE_IPV6 */

void
prefix_list_init ()
{
  prefix_list_init_ipv4 ();
#ifdef HAVE_IPV6
  prefix_list_init_ipv6 ();
#endif /* HAVE_IPV6 */
}

void
prefix_list_reset ()
{
  prefix_list_reset_afi (AFI_IP,  0);
  prefix_list_reset_afi (AFI_IP6, 0);
  prefix_list_reset_afi (AFI_IP,  1);
  prefix_list_reset_afi (AFI_IP6, 1);
}
