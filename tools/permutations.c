/*
 * Generates all possible matching inputs for a command string.
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

#include "command.h"
#include "graph.h"
#include "vector.h"

#define USAGE "usage: permutations <cmdstr>"

void permute(struct graph_node *);
void pretty_print_graph(struct graph_node *start, int level);

int main(int argc, char *argv[])
{
	if (argc < 2) {
		fprintf(stdout, USAGE "\n");
		exit(EXIT_SUCCESS);
	}
	struct cmd_element *cmd = calloc(1, sizeof(struct cmd_element));
	cmd->string = strdup(argv[1]);

	struct graph *graph = graph_new();
	struct cmd_token *token =
		cmd_token_new(START_TKN, cmd->attr, NULL, NULL);
	graph_new_node(graph, token, NULL);
	cmd_graph_parse(graph, cmd);

	permute(vector_slot(graph->nodes, 0));
}

void permute(struct graph_node *start)
{
	static struct list *position = NULL;
	if (!position)
		position = list_new();

	struct cmd_token *stok = start->data;
	struct graph_node *gnn;
	struct listnode *ln;

	// recursive dfs
	listnode_add(position, start);
	for (unsigned int i = 0; i < vector_active(start->to); i++) {
		struct graph_node *gn = vector_slot(start->to, i);
		struct cmd_token *tok = gn->data;
		if (tok->attr == CMD_ATTR_HIDDEN
		    || tok->attr == CMD_ATTR_DEPRECATED)
			continue;
		else if (tok->type == END_TKN || gn == start) {
			fprintf(stdout, " ");
			for (ALL_LIST_ELEMENTS_RO(position, ln, gnn)) {
				struct cmd_token *tt = gnn->data;
				if (tt->type < SPECIAL_TKN)
					fprintf(stdout, " %s", tt->text);
			}
			if (gn == start)
				fprintf(stdout, "...");
			fprintf(stdout, "\n");
		} else {
			bool skip = false;
			if (stok->type == FORK_TKN && tok->type != FORK_TKN)
				for (ALL_LIST_ELEMENTS_RO(position, ln, gnn))
					if (gnn == gn) {
						skip = true;
						break;
					}
			if (!skip)
				permute(gn);
		}
	}
	list_delete_node(position, listtail(position));
}
