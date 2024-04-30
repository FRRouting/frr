// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Generates all possible matching inputs for a command string.
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

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
	struct cmd_element *cmd = XCALLOC(MTYPE_TMP,
					  sizeof(struct cmd_element));
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
	bool is_neg = false;

	// recursive dfs
	listnode_add(position, start);

	for (ALL_LIST_ELEMENTS_RO(position, ln, gnn)) {
		struct cmd_token *tok = gnn->data;

		if (tok->type == WORD_TKN && !strcmp(tok->text, "no")) {
			is_neg = true;
			break;
		}
		if (tok->type < SPECIAL_TKN)
			break;
	}

	for (unsigned int i = 0; i < vector_active(start->to); i++) {
		struct graph_node *gn = vector_slot(start->to, i);
		struct cmd_token *tok = gn->data;
		if (tok->attr & CMD_ATTR_HIDDEN)
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

			if (tok->type == NEG_ONLY_TKN && !is_neg)
				continue;
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
