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

#ifndef _ZEBRA_COMMAND_GRAPH_H
#define _ZEBRA_COMMAND_GRAPH_H

#include "command.h"

/**
 * Types for graph nodes.
 *
 * The node type determines what kind of data the node can match (in the
 * matching use case) or hold (in the argv use case).
 */
enum graph_node_type
{
  IPV4_GN,          // IPV4 addresses
  IPV4_PREFIX_GN,   // IPV4 network prefixes
  IPV6_GN,          // IPV6 prefixes
  IPV6_PREFIX_GN,   // IPV6 network prefixes
  WORD_GN,          // words
  RANGE_GN,         // integer ranges
  NUMBER_GN,        // numbers
  VARIABLE_GN,      // almost anything
  /* plumbing types */
  SELECTOR_GN,      // marks beginning of selector subgraph
  OPTION_GN,        // marks beginning of option subgraph
  NUL_GN,           // transparent node with various uses
  START_GN,         // first node in the graph (has no parents)
  END_GN            // leaf node in the graph, has pointer to cmd_element
};

/**
 * Command graph node.
 * Used for matching and passing arguments to vtysh commands.
 */
struct graph_node
{
  enum graph_node_type type;    // data type this node matches or holds
  vector children;              // this node's children

  char *text;                   // original format text
  char *doc;                    // docstring for this node
  long long value;              // for NUMBER_GN
  long long min, max;           // for RANGE_GN

  /* cmd_element struct pointer, only valid for END_GN */
  struct cmd_element *element;

  /* used for passing arguments to command functions */
  char *arg;

  /* refcount for node parents */
  unsigned int refs;
};

/**
 * Adds a node as a child of another node.
 *
 * @param[in] parent node
 * @param[in] child node
 * @return child node
 */
struct graph_node *
add_node (struct graph_node *parent, struct graph_node *child);

/**
 * Creates a new node, initializes all fields to default values and sets the
 * node type.
 *
 * @param[in] type node type
 * @return pointer to the created node
 */
struct graph_node *
new_node (enum graph_node_type type);

/**
 * Deletes a graph node without deleting its children.
 *
 * @param[out] node pointer to node to delete
 */
void
delete_node (struct graph_node *node);

/**
 * Deletes a graph node and recursively deletes all its direct and indirect
 * children.
 *
 * @param[out] node start node of graph to free
 */
void
delete_graph (struct graph_node *node);

#endif /* _ZEBRA_COMMAND_GRAPH_H */
