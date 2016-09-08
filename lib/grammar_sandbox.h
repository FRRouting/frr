#ifndef _GRAMMAR_SANDBOX_H
#define _GRAMMAR_SANDBOX_H

/**
 * Houses functionality for testing shim as well as code that should go into
 * command.h and command.c during integration.
 */
#include "memory.h"

#define CMD_CR_TEXT "<cr>"

void
grammar_sandbox_init (void);

/**
 * Types for tokens.
 *
 * The type determines what kind of data the token can match (in the
 * matching use case) or hold (in the argv use case).
 */
enum cmd_token_type_t
{
  WORD_TKN,         // words
  NUMBER_TKN,       // integral numbers
  VARIABLE_TKN,     // almost anything
  RANGE_TKN,        // integer range
  IPV4_TKN,         // IPV4 addresses
  IPV4_PREFIX_TKN,  // IPV4 network prefixes
  IPV6_TKN,         // IPV6 prefixes
  IPV6_PREFIX_TKN,  // IPV6 network prefixes

  /* plumbing types */
  SELECTOR_TKN,     // marks beginning of selector
  OPTION_TKN,       // marks beginning of option
  NUL_TKN,          // dummy token
  START_TKN,        // first token in line
  END_TKN,          // last token in line
};

/**
 * Token struct.
 */
struct cmd_token_t
{
  enum cmd_token_type_t type;   // token type

  char *text;                   // token text
  char *desc;                   // token description

  long long value;              // for numeric types
  long long min, max;           // for ranges

  char *arg;                    // user input that matches this token
};

struct cmd_token_t *
new_cmd_token (enum cmd_token_type_t, char *, char *);

void
del_cmd_token (struct cmd_token_t *);

struct cmd_token_t *
copy_cmd_token (struct cmd_token_t *);

#endif /* _GRAMMAR_SANDBOX_H */
