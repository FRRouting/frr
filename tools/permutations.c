#include "command.h"
#include "graph.h"
#include "command_parse.h"
#include "vector.h"

void
pretty_print_graph (struct graph_node *);

int main (int argc, char *argv[])
{
  struct cmd_element *cmd = calloc (1, sizeof (struct cmd_element));
  cmd->string = strdup(argv[1]);

  struct graph *graph = graph_new();
  struct cmd_token *token = new_cmd_token (START_TKN, NULL, NULL);
  graph_new_node (graph, token, NULL);
  command_parse_format (graph, cmd);

  pretty_print_graph (vector_slot (graph->nodes, 0));
}

/**
 * Pretty-prints a graph, assuming it is a tree.
 *
 * @param start the node to take as the root
 * @param level indent level for recursive calls, always pass 0
 */

void
pretty_print_graph (struct graph_node *start)
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
      pretty_print_graph (gn);
  }
  list_delete_node (position, listtail(position));
}
