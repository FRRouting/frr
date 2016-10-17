/*
 * Copyright (c) 2015-16  David Lamparter, for NetDEF, Inc.
 *
 * This file is part of Quagga
 *
 * Quagga is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * Quagga is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Quagga; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include <zebra.h>

#include "thread.h"
#include "memory.h"
#include "hash.h"
#include "log.h"
#include "qobj.h"

static struct hash *nodes = NULL;

static unsigned int qobj_key (void *data)
{
  struct qobj_node *node = data;
  return (unsigned int)node->nid;
}

static int qobj_cmp (const void *a, const void *b)
{
  const struct qobj_node *na = a, *nb = b;
  return na->nid == nb->nid;
}

void qobj_reg(struct qobj_node *node, struct qobj_nodetype *type)
{
  node->type = type;
  do
    {
      node->nid  = (uint64_t)random();
      node->nid ^= (uint64_t)random() << 32;
    }
  while (hash_get (nodes, node, hash_alloc_intern) != node);
}

void qobj_unreg(struct qobj_node *node)
{
  hash_release (nodes, node);
}

struct qobj_node *qobj_get(uint64_t id)
{
  struct qobj_node dummy = { .nid = id };
  return hash_lookup (nodes, &dummy);
}

void *qobj_get_typed(uint64_t id, struct qobj_nodetype *type)
{
  struct qobj_node *node = qobj_get(id);
  if (!node || node->type != type)
    return NULL;
  return (char *)node - node->type->node_member_offset;
}

void qobj_init (void)
{
  nodes = hash_create (qobj_key, qobj_cmp);
}

void qobj_finish (void)
{
  hash_free (nodes);
  nodes = NULL;
}
