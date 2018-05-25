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
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>
#include "graph.h"
#include "memory.h"
#include "buffer.h"

DEFINE_MTYPE_STATIC(LIB, GRAPH, "Graph")
DEFINE_MTYPE_STATIC(LIB, GRAPH_NODE, "Graph Node")
struct graph *graph_new()
{
	struct graph *graph = XCALLOC(MTYPE_GRAPH, sizeof(struct graph));
	graph->nodes = vector_init(VECTOR_MIN_SIZE);

	return graph;
}

void graph_delete_graph(struct graph *graph)
{
	for (unsigned int i = vector_active(graph->nodes); i--; /**/)
		graph_delete_node(graph, vector_slot(graph->nodes, i));

	vector_free(graph->nodes);
	XFREE(MTYPE_GRAPH, graph);
}

struct graph_node *graph_new_node(struct graph *graph, void *data,
				  void (*del)(void *))
{
	struct graph_node *node =
		XCALLOC(MTYPE_GRAPH_NODE, sizeof(struct graph_node));

	node->from = vector_init(VECTOR_MIN_SIZE);
	node->to = vector_init(VECTOR_MIN_SIZE);
	node->data = data;
	node->del = del;

	vector_set(graph->nodes, node);

	return node;
}

static void graph_vector_remove(vector v, unsigned int ix)
{
	if (ix >= v->active)
		return;

	/* v->active is guaranteed >= 1 because ix can't be lower than 0
	 * and v->active is > ix. */
	v->active--;
	/* if ix == v->active--, we set the item to itself, then to NULL...
	 * still correct, no check neccessary. */
	v->index[ix] = v->index[v->active];
	v->index[v->active] = NULL;
}

void graph_delete_node(struct graph *graph, struct graph_node *node)
{
	if (!node)
		return;

	// an adjacent node
	struct graph_node *adj;

	// remove all edges from other nodes to us
	for (unsigned int i = vector_active(node->from); i--; /**/) {
		adj = vector_slot(node->from, i);
		graph_remove_edge(adj, node);
	}

	// remove all edges from us to other nodes
	for (unsigned int i = vector_active(node->to); i--; /**/) {
		adj = vector_slot(node->to, i);
		graph_remove_edge(node, adj);
	}

	// if there is a deletion callback, call it
	if (node->del && node->data)
		(*node->del)(node->data);

	// free adjacency lists
	vector_free(node->to);
	vector_free(node->from);

	// remove node from graph->nodes
	for (unsigned int i = vector_active(graph->nodes); i--; /**/)
		if (vector_slot(graph->nodes, i) == node) {
			graph_vector_remove(graph->nodes, i);
			break;
		}

	// free the node itself
	XFREE(MTYPE_GRAPH_NODE, node);
}

struct graph_node *graph_add_edge(struct graph_node *from,
				  struct graph_node *to)
{
	vector_set(from->to, to);
	vector_set(to->from, from);
	return to;
}

void graph_remove_edge(struct graph_node *from, struct graph_node *to)
{
	// remove from from to->from
	for (unsigned int i = vector_active(to->from); i--; /**/)
		if (vector_slot(to->from, i) == from) {
			graph_vector_remove(to->from, i);
			break;
		}
	// remove to from from->to
	for (unsigned int i = vector_active(from->to); i--; /**/)
		if (vector_slot(from->to, i) == to) {
			graph_vector_remove(from->to, i);
			break;
		}
}

struct graph_node *graph_find_node(struct graph *graph, void *data)
{
	struct graph_node *g;

	for (unsigned int i = vector_active(graph->nodes); i--; /**/) {
		g = vector_slot(graph->nodes, i);
		if (g->data == data)
			return g;
	}

	return NULL;
}

bool graph_has_edge(struct graph_node *from, struct graph_node *to)
{
	for (unsigned int i = vector_active(from->to); i--; /**/)
		if (vector_slot(from->to, i) == to)
			return true;

	return false;
}

static void _graph_dfs(struct graph *graph, struct graph_node *start,
		       vector visited,
		       void (*dfs_cb)(struct graph_node *, void *), void *arg)
{
	/* check that we have not visited this node */
	for (unsigned int i = 0; i < vector_active(visited); i++) {
		if (start == vector_slot(visited, i))
			return;
	}

	/* put this node in visited stack */
	vector_ensure(visited, vector_active(visited));
	vector_set_index(visited, vector_active(visited), start);

	/* callback */
	dfs_cb(start, arg);

	/* recurse into children */
	for (unsigned int i = vector_active(start->to); i--; /**/) {
		struct graph_node *c = vector_slot(start->to, i);

		_graph_dfs(graph, c, visited, dfs_cb, arg);
	}
}

void graph_dfs(struct graph *graph, struct graph_node *start,
	       void (*dfs_cb)(struct graph_node *, void *), void *arg)
{
	vector visited = vector_init(VECTOR_MIN_SIZE);

	_graph_dfs(graph, start, visited, dfs_cb, arg);
	vector_free(visited);
}

#ifndef BUILDING_CLIPPY

void graph_dump_dot_default_print_cb(struct graph_node *gn, struct buffer *buf)
{
	char nbuf[64];

	for (unsigned int i = 0; i < vector_active(gn->to); i++) {
		struct graph_node *adj = vector_slot(gn->to, i);

		snprintf(nbuf, sizeof(nbuf), "    n%p -> n%p;\n", gn, adj);
		buffer_putstr(buf, nbuf);
	}
}

char *graph_dump_dot(struct graph *graph, struct graph_node *start,
		     void (*pcb)(struct graph_node *, struct buffer *))
{
	struct buffer *buf = buffer_new(0);
	char *ret;

	pcb = (pcb) ? pcb : graph_dump_dot_default_print_cb;
	buffer_putstr(buf, "digraph {\n");

	graph_dfs(graph, start, (void (*)(struct graph_node *, void *))pcb,
		  buf);

	buffer_putstr(buf, "}\n");

	ret = buffer_getstr(buf);
	buffer_free(buf);

	return ret;
}

#endif /* BUILDING_CLIPPY */
