#include "command.h"
#include "command_graph.h"
#include "command_parse.h"
#include "command_match.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

struct graph_node * nodegraph;

/*
char* combine_vararg(char* argv, int argc) {
  size_t linesize = 0;
  for (int i = 0; i < argc; i++)
    linesize += strlen(argv[i]) + 1;

  char* cat = malloc(linesize);
  cat[0] = '\0';
  for (int i = 0; i < argc; i++) {
    strcat(cat, argv[i]);
    if (i != argc)
      strcat(cat, " ");
  }

  return cat;
}
*/

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
  match_command(nodegraph, FILTER_STRICT, command);
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
