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

#ifndef _ZEBRA_COMMAND_GRAPH_H
#define _ZEBRA_COMMAND_GRAPH_H

#include "vector.h"

struct graph
{
  vector nodes;
};

struct graph_node
{
  vector from;                  // nodes which have edges to this node
  vector to;                    // nodes which this node has edges to

  void *data;                   // node data
  void (*del) (void *data);     // deletion callback
};

struct graph *
graph_new (void);

/**
 * Creates a new node.
 *
 * @struct graph the graph this node exists in
 * @param[in] data this node's data
 * @param[in] del data deletion callback
 * @return the new node
 */
struct graph_node *
graph_new_node (struct graph *graph, void *data, void (*del) (void*));

/**
 * Deletes a node.
 *
 * Before deletion, this function removes all edges to and from this node from
 * any neighbor nodes.
 *
 * If *data and *del are non-null, the following call is made:
 *   (*node->del) (node->data);
 *
 * @param[in] graph the graph this node belongs to
 * @param[out] node pointer to node to delete
 */
void
graph_delete_node (struct graph *graph, struct graph_node *node);

/**
 * Makes a directed edge between two nodes.
 *
 * @param[in] from
 * @param[in] to
 * @return to
 */
struct graph_node *
graph_add_edge (struct graph_node *from, struct graph_node *to);

/**
 * Removes a directed edge between two nodes.
 *
 * @param[in] from
 * @param[in] to
 */
void
graph_remove_edge (struct graph_node *from, struct graph_node *to);

/**
 * Deletes a graph.
 * Calls graph_delete_node on each node before freeing the graph struct itself.
 *
 * @param graph the graph to delete
 */
void
graph_delete_graph (struct graph *graph);

#endif /* _ZEBRA_COMMAND_GRAPH_H */
