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
  struct list *result = match_command(nodegraph, FILTER_STRICT, command);

  if (result->count == 0) // invalid command
    fprintf(stderr, "%% Unknown command\n");
  else
  {
    fprintf(stderr, "%% Matched full input, possible completions:\n");
    char* desc = malloc(50);
    struct listnode *node;
    struct graph_node *cnode;
    // print possible next hops, if any
    for (ALL_LIST_ELEMENTS_RO(result,node,cnode)) {
      if (cnode->type == END_GN)
        fprintf(stderr, "<cr>");
      else
        fprintf(stderr, "%s\n", describe_node(cnode, desc, 50));
    }
    free(desc);
  }
  list_free(result);

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
