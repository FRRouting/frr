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
  char* command = argv_concat(argv, argc, 0);
  struct cmd_element *cmd = malloc(sizeof(struct cmd_element));
  cmd->string = command;
  parse_command_format(nodegraph, cmd);
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

DEFUN (grammar_test_complete,
       grammar_test_complete_cmd,
       "grammar complete .COMMAND",
       GRAMMAR_STR
       "attempt to complete input on DFA\n"
       "command to complete")
{
  const char* command = argv_concat(argv, argc, 0);
  struct list *result = match_command_complete (nodegraph, command, FILTER_STRICT);

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
        fprintf(stderr, "<cr>\n");
      else
        fprintf(stderr, "%s\n", describe_node(cnode, desc, 50));
    }
    free(desc);
  }
  list_free(result);

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
  struct cmd_element *element = match_command (nodegraph, command, FILTER_STRICT);

  if (element)
    fprintf(stderr, "Matched: %s\n", element->string);
  else {
    fprintf(stderr, "Returned NULL\n");
    return CMD_SUCCESS;
  }

  struct list *argvv = match_build_argv (command, element);
  fprintf(stderr, "num args: %d\n", argvv->count);

  struct listnode *ln;
  struct graph_node *gn;
  for (ALL_LIST_ELEMENTS_RO(argvv,ln,gn)) {
    fprintf(stderr, "node text: %s\n", gn->text);
    if (gn->arg)
      fprintf(stderr, "node arg: %s\n", gn->arg);
    else
      fprintf(stderr, "No arg.\n");
  }

  return CMD_SUCCESS;
}


void grammar_sandbox_init(void);
void grammar_sandbox_init() {
  fprintf(stderr, "reinitializing graph\n");
  nodegraph = new_node(START_GN);
  install_element (ENABLE_NODE, &grammar_test_cmd);
  install_element (ENABLE_NODE, &grammar_test_show_cmd);
  install_element (ENABLE_NODE, &grammar_test_match_cmd);
  install_element (ENABLE_NODE, &grammar_test_complete_cmd);
}
