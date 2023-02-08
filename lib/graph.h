// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Graph data structure.
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */

#ifndef _ZEBRA_COMMAND_GRAPH_H
#define _ZEBRA_COMMAND_GRAPH_H

#include <stdbool.h>
#include "vector.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

struct graph {
	vector nodes;
};

struct graph_node {
	vector from; // nodes which have edges to this node
	vector to;   // nodes which this node has edges to

	void *data;		 // node data
	void (*del)(void *data); // deletion callback
};

struct graph *graph_new(void);

/**
 * Creates a new node.
 *
 * @struct graph the graph this node exists in
 * @param[in] data this node's data
 * @param[in] del data deletion callback
 * @return the new node
 */
struct graph_node *graph_new_node(struct graph *graph, void *data,
				  void (*del)(void *));

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
void graph_delete_node(struct graph *graph, struct graph_node *node);

/**
 * Makes a directed edge between two nodes.
 *
 * @param[in] from
 * @param[in] to
 * @return to
 */
struct graph_node *graph_add_edge(struct graph_node *from,
				  struct graph_node *to);

/**
 * Removes a directed edge between two nodes.
 *
 * @param[in] from
 * @param[in] to
 */
void graph_remove_edge(struct graph_node *from, struct graph_node *to);

/**
 * Deletes a graph.
 * Calls graph_delete_node on each node before freeing the graph struct itself.
 *
 * @param graph the graph to delete
 */
void graph_delete_graph(struct graph *graph);

/*
 * Finds a node in the graph.
 *
 * @param[in] graph the graph to search in
 * @param[in] data the data to key off
 * @return the first graph node whose data pointer matches `data`
 */
struct graph_node *graph_find_node(struct graph *graph, void *data);


/*
 * Determines whether two nodes have a directed edge between them.
 *
 * @param from
 * @param to
 * @return whether there is a directed edge from `from` to `to`.
 */
bool graph_has_edge(struct graph_node *from, struct graph_node *to);

/*
 * Depth-first search.
 *
 * Performs a depth-first traversal of the given graph, visiting each node
 * exactly once and calling the user-provided callback for each visit.
 *
 * @param graph the graph to operate on
 * @param start the node to take as the root
 * @param dfs_cb callback called for each node visited in the traversal
 * @param arg argument to provide to dfs_cb
 */
void graph_dfs(struct graph *graph, struct graph_node *start,
	       void (*dfs_cb)(struct graph_node *, void *), void *arg);

#ifndef BUILDING_CLIPPY
/*
 * Clippy relies on a small subset of sources in lib/, but it cannot link
 * libfrr since clippy itself is required to build libfrr. Instead it directly
 * includes the sources it needs. One of these is the command graph
 * implementation, which wraps this graph implementation. Since we need to use
 * the buffer.[ch] sources here, which indirectly rely on most of libfrr, we
 * have to ignore them when compiling clippy to avoid build dependency issues.
 *
 * TODO: Fix clippy build.
 */

/*
 * Default node printer for use with graph_dump_dot.
 *
 * @param gn the node to print
 * @param buf the buffer to print into
 */
void graph_dump_dot_default_print_cb(struct graph_node *gn, struct buffer *buf);

/*
 * Prints a graph in the DOT language.
 *
 * The generated output is produced from a depth-first traversal of the graph.
 *
 * @param graph the graph to print
 * @param start the node to take as the root
 * @param pcb callback called for each node in the traversal that should
 *        print the node in the DOT language. Passing NULL for this argument
 *        will use the default printer. See graph_dump_dot_default_print_cb for
 *        an example.
 * @return representation of graph in DOT language, allocated with MTYPE_TMP.
 *         Caller is responsible for freeing this string.
 */
char *graph_dump_dot(struct graph *graph, struct graph_node *start,
		     void (*pcb)(struct graph_node *, struct buffer *buf));

#endif /* BUILDING_CLIPPY */

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_COMMAND_GRAPH_H */
