#include "memory.h"

void
grammar_sandbox_init(void);

/**
 * Types for tokens.
 *
 * The type determines what kind of data the token can match (in the
 * matching use case) or hold (in the argv use case).
 */
enum cmd_token_type_t
{
  _TOKEN_BUG = 0,
  LITERAL_TKN,      // words
  OPTION_TKN,       // integer ranges
  VARIABLE_TKN,     // almost anything
  RANGE_TKN,        // integer range
  IPV4_TKN,         // IPV4 addresses
  IPV4_PREFIX_TKN,  // IPV4 network prefixes
  IPV6_TKN,         // IPV6 prefixes
  IPV6_PREFIX_TKN,  // IPV6 network prefixes

  /* plumbing types */
  SELECTOR,     // marks beginning of selector
  OPTION,       // marks beginning of option
  NUL,          // dummy token
  START,        // first token in line
  END;          // last token in line
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
};

inline struct cmd_token_t *
cmd_new_token (cmd_token_type_t type, char *text, char *desc)
{
  struct cmd_token_t *token = XMALLOC (MTYPE_CMD_TOKENS, sizeof (struct cmd_token_t));
  token->type = type;
  token->text = text;
  token->desc = desc;
}
