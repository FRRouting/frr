/*
 * Graph data structure.
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
#include "graph.h"
#include "memory.h"

struct graph *
graph_new ()
{
  struct graph *graph = XCALLOC (MTYPE_GRAPH, sizeof(struct graph));
  graph->nodes = vector_init (VECTOR_MIN_SIZE);

  return graph;
}

struct graph_node *
graph_new_node (struct graph *graph, void *data, void (*del) (void*))
{
  struct graph_node *node =
     XCALLOC(MTYPE_GRAPH_NODE, sizeof(struct graph_node));

  node->from = vector_init (VECTOR_MIN_SIZE);
  node->to   = vector_init (VECTOR_MIN_SIZE);
  node->data = data;
  node->del  = del;

  vector_set (graph->nodes, node);

  return node;
}

void
graph_delete_node (struct graph *graph, struct graph_node *node)
{
  if (!node) return;

  // an adjacent node
  struct graph_node *adj;

  // for all nodes that have an edge to us, remove us from their ->to
  for (unsigned int i = 0; i < vector_active (node->from); i++)
    {
      adj = vector_slot (node->from, i);
      for (unsigned int j = 0; j < vector_active (adj->to); j++)
        if (vector_slot (adj->to, j) == node)
          vector_unset (adj->to, j);
    }

  // for all nodes that we have an edge to, remove us from their ->from
  for (unsigned int i = 0; i < vector_active (node->to); i++)
    {
      adj = vector_slot (node->to, i);
      for (unsigned int j = 0; j < vector_active (adj->from); j++)
        if (vector_slot (adj->from, j) == node)
          vector_unset (adj->from, j);
    }

  // if there is a deletion callback, call it
  if (node->del && node->data)
    (*node->del) (node->data);

  // free adjacency lists
  vector_free (node->to);
  vector_free (node->from);

  // remove node from graph->nodes
  for (unsigned int i = 0; i < vector_active (graph->nodes); i++)
    if (vector_slot (graph->nodes, i) == node)
      vector_unset (graph->nodes, i);

  // free the node itself
  XFREE (MTYPE_GRAPH_NODE, node);
}

struct graph_node *
graph_add_edge (struct graph_node *from, struct graph_node *to)
{
  vector_set (from->to, to);
  vector_set (to->from, from);
  return to;
}

void
graph_delete_graph (struct graph *graph)
{
  // delete each node in the graph
  for (unsigned int i = 0; i < vector_active (graph->nodes); i++)
    graph_delete_node (graph, vector_slot (graph->nodes, i));

  vector_free (graph->nodes);
  XFREE (MTYPE_GRAPH, graph);
}
