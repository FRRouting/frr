// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Test graph data structure.
 * Copyright (C) 2018  Cumulus Networks, Inc.
 *                     Quentin Young
 */
#include <zebra.h>
#include <graph.h>
#include <memory.h>
#include <buffer.h>

#define NUMNODES 32

static void graph_custom_print_cb(struct graph_node *gn, struct buffer *buf)
{
	char nbuf[64];
	char *gname = gn->data;

	for (unsigned int i = 0; i < vector_active(gn->to); i++) {
		struct graph_node *adj = vector_slot(gn->to, i);
		char *name = adj->data;

		snprintf(nbuf, sizeof(nbuf), "    n%s -> n%s;\n", gname, name);
		buffer_putstr(buf, nbuf);
	}
}

int main(int argc, char **argv)
{
	struct graph *g = graph_new();
	struct graph_node *gn[NUMNODES];
	char names[NUMNODES][16];

	/* create vertices */
	for (unsigned int i = 0; i < NUMNODES; i++) {
		snprintf(names[i], sizeof(names[i]), "%u", i);
		gn[i] = graph_new_node(g, names[i], NULL);
	}

	/* create edges */
	for (unsigned int i = 1; i < NUMNODES - 1; i++) {
		graph_add_edge(gn[0], gn[i]);
		graph_add_edge(gn[i], gn[i + 1]);
	}
	graph_add_edge(gn[0], gn[NUMNODES - 1]);
	graph_add_edge(gn[NUMNODES - 1], gn[1]);

	/* print DOT */
	char *dumped = graph_dump_dot(g, gn[0], graph_custom_print_cb);

	fprintf(stdout, "%s", dumped);
	XFREE(MTYPE_TMP, dumped);

	/* remove some edges */
	for (unsigned int i = NUMNODES - 1; i > NUMNODES / 2; --i)
		for (unsigned int j = 0; j < NUMNODES; j++)
			graph_remove_edge(gn[i], gn[j]);

	/* remove some nodes */
	for (unsigned int i = 0; i < NUMNODES / 2; i++)
		graph_delete_node(g, gn[i]);

	graph_delete_graph(g);
}
