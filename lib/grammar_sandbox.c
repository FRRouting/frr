#include "command.h"
#include "command_graph.h"
#include "command_parse.h"
#include "command_match.h"
#include "linklist.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

struct graph_node * nodegraph;

DEFUN (grammar_test,
       grammar_test_cmd,
       "grammar parse .COMMAND",
       GRAMMAR_STR
       "command to pass to new parser\n")
{

  const char* command = argv_concat(argv, argc, 0);
  cmd_parse_format(command, "lol", nodegraph);
  walk_graph(nodegraph, 0);

  return CMD_SUCCESS;
}

DEFUN (grammar_test_show,
       grammar_test_show_cmd,
       "grammar tree",
       GRAMMAR_STR
       "print current accumulated DFA\n")
{
  walk_graph(nodegraph, 0);
  return CMD_SUCCESS;
}

DEFUN (grammar_test_match,
       grammar_test_match_cmd,
       "grammar match .COMMAND",
       GRAMMAR_STR
       "attempt to match input on DFA\n"
       "command to match")
{
  const char* command = argv_concat(argv, argc, 0);
  struct list **result = match_command(nodegraph, FILTER_STRICT, command);
  struct list *matched = result[0];
  struct list *next    = result[1];

  if (matched->count == 0) // the last token tried yielded no matches
    fprintf(stderr, "%% Unknown command\n");
  else
  {
    fprintf(stderr, "%% Matched full input, possible completions:\n");
    struct listnode *node;
    struct graph_node *cnode;
    // iterate through currently matched nodes to see if any are leaves
    for (ALL_LIST_ELEMENTS_RO(matched,node,cnode))
      if (cnode->is_leaf)
        fprintf(stderr, "<cr>\n");
    // print possible next hops, if any
    for (ALL_LIST_ELEMENTS_RO(next,node,cnode))
      fprintf(stderr, "%s\n",describe_node(cnode));
  }

  return CMD_SUCCESS;
}


void grammar_sandbox_init(void);
void grammar_sandbox_init() {
  fprintf(stderr, "reinitializing graph\n");
  nodegraph = new_node(NUL_GN);
  install_element (ENABLE_NODE, &grammar_test_cmd);
  install_element (ENABLE_NODE, &grammar_test_show_cmd);
  install_element (ENABLE_NODE, &grammar_test_match_cmd);
}
