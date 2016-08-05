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
  cmd->doc = NULL;
  cmd->func = NULL;
  cmd->tokens = vector_init(VECTOR_MIN_SIZE);
  parse_command_format(nodegraph, cmd);
  return CMD_SUCCESS;
}

DEFUN (grammar_test_doc,
       grammar_test_doc_cmd,
       "grammar test docstring",
       GRAMMAR_STR
       "Test function for docstring\n"
       "Command end\n")
{
  struct cmd_element *cmd = malloc(sizeof(struct cmd_element));
  cmd->string = "test docstring <example|selector follow> (1-255) end VARIABLE [OPTION|set lol] . VARARG";
  cmd->doc = "Test stuff\n"
             "docstring thing\n"
             "first example\n"
             "second example\n"
             "follow\n"
             "random range\n"
             "end thingy\n"
             "variable\n"
             "optional variable\n"
             "optional set\n"
             "optional lol\n"
             "vararg!\n";
  cmd->func = NULL;
  cmd->tokens = vector_init(VECTOR_MIN_SIZE);
  parse_command_format(nodegraph, cmd);
  return CMD_SUCCESS;
}

DEFUN (grammar_test_show,
       grammar_test_show_cmd,
       "grammar tree",
       GRAMMAR_STR
       "print current accumulated DFA\n")
{
  if (!nodegraph)
    fprintf(stderr, "!nodegraph\n");
  else
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
  struct list *result = match_command_complete (nodegraph, command);

  if (result->count == 0) // invalid command
    fprintf(stderr, "%% Unknown command\n");
  else
  {
    fprintf(stderr, "%% Matched full input, possible completions:\n");
    char* desc = malloc(30);
    struct listnode *node;
    struct graph_node *cnode;
    // print possible next hops, if any
    for (ALL_LIST_ELEMENTS_RO(result,node,cnode)) {
      if (cnode->type == END_GN)
        fprintf(stderr, "<cr> %p\n", cnode->element->func);
      else
        fprintf(stderr, "%-30s%s\n", describe_node(cnode, desc, 30), cnode->doc);
    }
    free(desc);
  }
  list_delete(result);

  return CMD_SUCCESS;
}

DEFUN (grammar_test_match,
       grammar_test_match_cmd,
       "grammar match .COMMAND",
       GRAMMAR_STR
       "attempt to match input on DFA\n"
       "command to match")
{
  const char *line = argv_concat(argv, argc, 0);

  struct list *argvv = NULL;
  struct cmd_element *element = NULL;
  enum matcher_rv result = match_command (nodegraph, line, &argvv, &element);

  if (element) {
    fprintf(stderr, "Matched: %s\n", element->string);
    struct listnode *ln;
    struct graph_node *gn;
    for (ALL_LIST_ELEMENTS_RO(argvv,ln,gn))
      fprintf(stderr, "%s -- %s\n", gn->text, gn->arg);
  }
  else {
     switch (result) {
       case MATCHER_NO_MATCH:
          fprintf(stderr, "%% Unknown command\n");
          break;
       case MATCHER_INCOMPLETE:
          fprintf(stderr, "%% Incomplete command\n");
          break;
       case MATCHER_AMBIGUOUS:
          fprintf(stderr, "%% Ambiguous command\n");
          break;
       default:
          fprintf(stderr, "%% Unknown error\n");
          break;
     }
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
  install_element (ENABLE_NODE, &grammar_test_doc_cmd);
}
