/*
 * Graph data structure and companion routines for CLI backend.
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
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
#include "command_graph.h"
#include "memory.h"

struct graph_node *
graphnode_add_child (struct graph_node *parent, struct graph_node *child)
{
  vector_set (parent->children, child);
  child->refs++;
  return child;
}

struct graph_node *
graphnode_new (enum graph_node_type type)
{
  struct graph_node *node =
     XCALLOC(MTYPE_CMD_TOKENS, sizeof(struct graph_node));

  node->type = type;
  node->children = vector_init(VECTOR_MIN_SIZE);

  return node;
}

void
graphnode_delete (struct graph_node *node)
{
  if (!node) return;
  if (node->children) vector_free (node->children);
  if (node->element) free_cmd_element (node->element);
  free (node->text);
  free (node->arg);
  free (node);
}

void
graphnode_delete_graph (struct graph_node *start)
{
  if (start && start->children && vector_active (start->children) > 0)
    {
      for (unsigned int i = 0; i < vector_active (start->children); i++)
        {
          graphnode_delete (vector_slot(start->children, i));
          vector_unset (start->children, i);
        }
    }

  if (--(start->refs) == 0)
    graphnode_delete (start);
}
