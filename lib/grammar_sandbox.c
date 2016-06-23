#include "command.h"

#define GRAMMAR_STR "CLI grammar sandbox\n"

DEFUN (grammar_midkey_test,
       grammar_midkey_test_cmd,
       "grammar {one|two} test",
       GRAMMAR_STR
       "First option\n"
       "Second option\n"
       "Test parameter to end string\n")
{
   return CMD_SUCCESS;
}

DEFUN (grammar_onemidkey_test,
       grammar_onemidkey_test_cmd,
       "grammar {onekey} test",
       GRAMMAR_STR
       "First option\n"
       "Test parameter to end string\n")
{
   return CMD_SUCCESS;
}

DEFUN (grammar_smashmouth_test,
       grammar_smashmouth_test_cmd,
       "grammar {smash MOUTH} test",
       GRAMMAR_STR
       "It ain't easy bein' cheesy\n"
       "Test parameter to end string\n")
{
   return CMD_SUCCESS;
}

DEFUN (grammar_midopt_test,
       grammar_midopt_test_cmd,
       "grammar [option] test",
       GRAMMAR_STR
       "optional argument\n"
       "Test parameter to end string\n")
{
   return CMD_SUCCESS;
}


void grammar_sandbox_init(void);
void grammar_sandbox_init() {
  install_element (ENABLE_NODE, &grammar_midkey_test_cmd);
  install_element (ENABLE_NODE, &grammar_onemidkey_test_cmd);
  install_element (ENABLE_NODE, &grammar_midopt_test_cmd);
  install_element (ENABLE_NODE, &grammar_smashmouth_test_cmd);
}
