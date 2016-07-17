#include "command.h"
#include "command_parse.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

DEFUN (grammar_test,
       grammar_test_cmd,
       "grammar .COMMAND",
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

  cmd_parse_format_new((const char*) cat, "lol");

  return CMD_SUCCESS;
}


void grammar_sandbox_init(void);
void grammar_sandbox_init() {
  install_element (ENABLE_NODE, &grammar_test_cmd);
}
