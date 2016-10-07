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
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "command.h"
#include "graph.h"
#include "command_parse.h"
#include "vector.h"

#define USAGE "usage: permutations <cmdstr>"

void
permute (struct graph_node *);
void
pretty_print_graph (struct graph_node *start, int level);

int main (int argc, char *argv[])
{
  if (argc < 2)
  {
    fprintf(stdout, USAGE"\n");
    exit(EXIT_SUCCESS);
  }
  struct cmd_element *cmd = calloc (1, sizeof (struct cmd_element));
  cmd->string = strdup(argv[1]);

  struct graph *graph = graph_new();
  struct cmd_token *token = new_cmd_token (START_TKN, NULL, NULL);
  graph_new_node (graph, token, NULL);
  command_parse_format (graph, cmd);

  permute (vector_slot (graph->nodes, 0));
  pretty_print_graph (vector_slot (graph->nodes, 0), 0);
}

void
permute (struct graph_node *start)
{
  static struct list *position = NULL;
  if (!position) position = list_new ();

  // recursive dfs
  listnode_add (position, start);
  for (unsigned int i = 0; i < vector_active (start->to); i++)
  {
    struct graph_node *gn = vector_slot (start->to, i);
    struct cmd_token *tok = gn->data;
    if (tok->type == END_TKN)
    {
      struct graph_node *gnn;
      struct listnode *ln;
      for (ALL_LIST_ELEMENTS_RO (position,ln,gnn))
      {
        struct cmd_token *tt = gnn->data;
        if (tt->type < SELECTOR_TKN)
          fprintf (stdout, "%s ", tt->text);
      }
      fprintf (stdout, "\n");
    }
    else
      permute (gn);
  }
  list_delete_node (position, listtail(position));
}

void
pretty_print_graph (struct graph_node *start, int level)
{
  // print this node
  struct cmd_token *tok = start->data;
  fprintf (stdout, "%s[%d] ", tok->text, tok->type);

  int numto = vector_active (start->to);
  if (numto)
    {
      if (numto > 1)
        fprintf (stdout, "\n");
      for (unsigned int i = 0; i < vector_active (start->to); i++)
        {
          struct graph_node *adj = vector_slot (start->to, i);
          // if we're listing multiple children, indent!
          if (numto > 1)
            for (int j = 0; j < level+1; j++)
              fprintf (stdout, "    ");
          // if this node is a vararg, just print *
          if (adj == start)
            fprintf (stdout, "*");
          else
            pretty_print_graph (adj, numto > 1 ? level+1 : level);
        }
    }
  else
    fprintf(stdout, "\n");
}
