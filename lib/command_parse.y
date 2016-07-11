%{
#include "cmdtree.h"

extern int yylex(void);
extern void yyerror(const char *);
extern int cmd_parse_format(const char *, const char *);
extern void set_buffer_string(const char *);

// compile with debugging facilities
#define YYDEBUG 1
%}

%union{
  int integer;
  char *string;
  struct graph_node *node;
}

%{
// last top-level node
struct graph_node *topnode,         // command root node
                  *currnode;        // current node

struct graph_node *optnode_start,   // start node for option set
                  *optnode_end,     // end node for option set
                  *optnode_el;      // start node for an option set element

struct graph_node *selnode_start,   // start node for selector set
                  *selnode_end,     // end node for selector set
                  *selnode_el;      // start node for an selector set element
%}

%token <string>  WORD
%token <string>  IPV4
%token <string>  IPV4_PREFIX
%token <string>  IPV6
%token <string>  IPV6_PREFIX
%token <string>  VARIABLE
%token <string>  RANGE
%token <integer> NUMBER

%type <node> start
%type <node> sentence_root
%type <node> literal_token
%type <node> placeholder_token
%type <node> option_token
%type <node> selector_token
%type <node> option
%type <node> selector
%type <node> selector_token_seq
%type <node> option_token_seq

%defines "command_parse.h"
%output "command_parse.c"

/* grammar proper */
%%

start: sentence_root
       cmd_token_seq;

sentence_root: WORD
  {
    currnode = new_node(WORD_GN);
    currnode->is_root = 1;
    add_node(topnode, currnode);
  };

/* valid top level tokens */
cmd_token:
  placeholder_token
  { currnode = add_node(currnode, $1); }
| literal_token
  { currnode = add_node(currnode, $1); }
| selector
  {
    add_node(currnode, selnode_start);
    currnode = selnode_end;
  }
| option
  {
    add_node(currnode, optnode_start);
    currnode = optnode_end;
  }
;

cmd_token_seq:
  %empty
| cmd_token_seq cmd_token
;

placeholder_token:
  IPV4                                  {$$ = new_node(IPV4_GN);}
| IPV4_PREFIX                           {$$ = new_node(IPV4_PREFIX_GN);}
| IPV6                                  {$$ = new_node(IPV6_GN);}
| IPV6_PREFIX                           {$$ = new_node(IPV6_PREFIX_GN);}
| VARIABLE                              {$$ = new_node(VARIABLE_GN);}
| RANGE                                 {$$ = new_node(RANGE_GN);}
;

literal_token:
  WORD                                  {$$ = new_node(WORD_GN);}
| NUMBER                                {$$ = new_node(NUMBER_GN);}
;

/* <selector|token> productions */
selector:
  '<' selector_part '|'
      selector_element '>'
{
  $$ = new_node(SELECTOR_GN);
  // attach subtree here
};

selector_part:
  selector_part '|' selector_element
| selector_element
;

selector_element:
  WORD selector_token_seq;

selector_token_seq:
  %empty                                {$$ = NULL;}
| selector_token_seq selector_token
{
  currnode = add_node(currnode, $2);
}
;

selector_token:
  literal_token
| placeholder_token
| option
;

/* [option|set] productions */
option: '[' option_part ']'
{
  $$ = new_node(OPTION_GN);
  // attach subtree here
};

option_part:
  option_part '|' option_token_seq
| option_token_seq
;

option_token_seq:
  option_token_seq option_token
| option_token
{
  printf("Matched singular option token in sequence, type: %d\n", $1->type);
}
;

option_token:
  literal_token
{
  // optnode_el points to root of option element
  if (optnode_el == NULL) {
    optnode_el = $1;
    currnode = $1;
  }
  else
    add_node(currnode, $1);
}
| placeholder_token
{
  // optnode_el points to root of option element
  if (optnode_el == NULL) {
    optnode_el = $1;
    currnode = $1;
  }
  else
    add_node(currnode, $1);
}
;

%%

int
main (void)
{
  yydebug = 1;
  const char* input = "show [random conf NAME] thing";
  printf("Parsing:\n\t%s\n", input);
  return cmd_parse_format(input, "description");
}

void yyerror(char const *message) {
  printf("Grammar error: %s\n", message);
  exit(EXIT_FAILURE);
}

int
cmd_parse_format(const char *string, const char *desc)
{
  // make flex read from a string
  set_buffer_string(string);
  // initialize the start node of this command dfa
  topnode = new_node(NUL_GN);
  // parse command into DFA
  yyparse();
  // topnode points to command DFA
  return 0;
}
