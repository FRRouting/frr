/*
 * Copyright (C) 1999 Yasuhiro Ohara
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
 * along with GNU Zebra; see the file COPYING.  If not, write to the 
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330, 
 * Boston, MA 02111-1307, USA.  
 */

#if 0

#include <zebra.h>

#include "log.h"
#include "prefix.h"
#include "memory.h"
#include "linklist.h"

#include "ospf6_prefix.h"

#else /*0*/

#include "ospf6d.h"

#endif /*0*/

struct ospf6_prefix *
ospf6_prefix_create (u_int8_t options, u_int16_t metric, struct prefix_ipv6 *p)
{
  struct prefix_ipv6 prefix;
  struct ospf6_prefix *o6p;
  size_t size;

  /* copy prefix and apply mask */
  prefix_copy ((struct prefix *) &prefix, (struct prefix *) p);
  apply_mask_ipv6 (&prefix);

  size = OSPF6_PREFIX_SPACE (prefix.prefixlen) + sizeof (struct ospf6_prefix);
  o6p = (struct ospf6_prefix *) XMALLOC (MTYPE_OSPF6_PREFIX, size);
  if (! o6p)
    zlog_warn ("Can't allocate memory for ospf6 prefix: size: %d", size);
  else
    memset (o6p, 0, size);

  o6p->prefix_length = prefix.prefixlen;
  o6p->prefix_options = options;
  o6p->prefix_metric = htons (metric);
  memcpy (o6p + 1, &prefix.prefix, OSPF6_PREFIX_SPACE (prefix.prefixlen));

  return o6p;
}

void
ospf6_prefix_delete (struct ospf6_prefix *p)
{
  XFREE (MTYPE_OSPF6_PREFIX, p);
}

int
ospf6_prefix_issame (struct ospf6_prefix *p1, struct ospf6_prefix *p2)
{
  if (p1->prefix_length != p2->prefix_length)
    return 0;
  if (memcmp (&p1->u, &p2->u, sizeof (p1->u)))
    return 0;
  if (memcmp (p1 + 1, p2 + 1, OSPF6_PREFIX_SPACE (p1->prefix_length)))
    return 0;
  return 1;
}

struct ospf6_prefix *
ospf6_prefix_lookup (list l, struct ospf6_prefix *p1)
{
  listnode node;
  struct ospf6_prefix *p2;
  for (node = listhead (l); node; nextnode (node))
    {
      p2 = (struct ospf6_prefix *) getdata (node);
      if (ospf6_prefix_issame (p1, p2))
        return p2;
    }
  return NULL;
}

/* add a copy of given prefix to the list */
void
ospf6_prefix_add (list l, struct ospf6_prefix *p)
{
  struct ospf6_prefix *add;
  add = (struct ospf6_prefix *) XMALLOC (MTYPE_OSPF6_PREFIX,
                                         OSPF6_PREFIX_SIZE (p));
  if (add == NULL)
    {
      zlog_warn ("Can't allocate memory for ospf6 prefix");
      return;
    }
  else
    memcpy (add, p, OSPF6_PREFIX_SIZE (p));

  if (ospf6_prefix_lookup (l, add))
    {
      ospf6_prefix_delete (add);
      return;
    }
  listnode_add (l, add);
}

void
ospf6_prefix_remove (list l, struct ospf6_prefix *p)
{
  struct ospf6_prefix *rem;
  rem = ospf6_prefix_lookup (l, p);
  if (rem)
    {
      listnode_delete (l, rem);
      ospf6_prefix_delete (rem);
    }
}

void
ospf6_prefix_in6_addr (struct ospf6_prefix *o6p, struct in6_addr *in6)
{
  memset (in6, 0, sizeof (struct in6_addr));
  memcpy (in6, o6p + 1, OSPF6_PREFIX_SPACE (o6p->prefix_length));
  return;
}

char *
ospf6_prefix_options_str (u_int8_t opt, char *buf, size_t bufsize)
{
  char *p, *mc, *la, *nu;

  p = (CHECK_FLAG (opt, OSPF6_PREFIX_OPTION_P) ? "P" : "-");
  mc = (CHECK_FLAG (opt, OSPF6_PREFIX_OPTION_MC) ? "MC" : "--");
  la = (CHECK_FLAG (opt, OSPF6_PREFIX_OPTION_LA) ? "LA" : "--");
  nu = (CHECK_FLAG (opt, OSPF6_PREFIX_OPTION_NU) ? "NU" : "--");

  snprintf (buf, bufsize, "%s|%s|%s|%s", p, mc, la, nu);
  return buf;
}

char *
ospf6_prefix_string (struct ospf6_prefix *prefix, char *buf, size_t size)
{
  struct in6_addr in6;
  char s[64];

  memset (&in6, 0, sizeof (in6));
  memcpy (&in6, prefix + 1, OSPF6_PREFIX_SPACE (prefix->prefix_length));
  inet_ntop (AF_INET6, &in6, s, sizeof (s));

  snprintf (buf, size, "%s/%d", s, prefix->prefix_length);
  return buf;
}

void
ospf6_prefix_copy (struct ospf6_prefix *dst, struct ospf6_prefix *src,
                   size_t dstsize)
{
  size_t srcsize;

  memset (dst, 0, dstsize);

  srcsize = OSPF6_PREFIX_SIZE (src);
  if (dstsize < srcsize)
    memcpy (dst, src, dstsize);
  else
    memcpy (dst, src, srcsize);

  return;
}

void
ospf6_prefix_apply_mask (struct ospf6_prefix *o6p)
{
  u_char *pnt, mask;
  int index, offset;

  char buf[128];
  struct in6_addr in6;
  ospf6_prefix_in6_addr (o6p, &in6);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));

  pnt = (u_char *)(o6p + 1);
  index = o6p->prefix_length / 8;
  offset = o6p->prefix_length % 8;
  mask = 0xff << (8 - offset);

  if (index >= 16)
    return;

  pnt[index] &= mask;
  index ++;

  while (index < OSPF6_PREFIX_SPACE (o6p->prefix_length))
    pnt[index++] = 0;

  ospf6_prefix_in6_addr (o6p, &in6);
  inet_ntop (AF_INET6, &in6, buf, sizeof (buf));
}

