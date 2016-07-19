#include "command.h"
#include "command_parse.h"
#include "cmdtree.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

struct graph_node * nodegraph;

DEFUN (grammar_test,
       grammar_test_cmd,
       "grammar parse .COMMAND",
       GRAMMAR_STR
       "command to pass to new parser\n")
{
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

  //struct graph_node *result = new_node(NUL_GN);
  cmd_parse_format_new((const char*) cat, "lol", nodegraph);
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


void grammar_sandbox_init(void);
void grammar_sandbox_init() {
  fprintf(stderr, "reinitializing graph\n");
  nodegraph = new_node(NUL_GN);
  install_element (ENABLE_NODE, &grammar_test_cmd);
  install_element (ENABLE_NODE, &grammar_test_show_cmd);
}
