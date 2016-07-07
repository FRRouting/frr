%{
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "cmdtree.h"

extern int yylex(void);
void yyerror(const char *);

// turn on debug
#define YYDEBUG 1
%}

%union{
  int integer;
  char *string;
  struct graph_node *node;
}

%{
// last top-level node
struct graph_node *topnode,
// 
                  *optnode,
                  *selnode;
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
%type <node> cmd_token
%type <node> literal_token
%type <node> placeholder_token
%type <node> option_token
%type <node> selector_token
%type <node> option
%type <node> selector
%type <node> selector_token_seq
%type <node> option_token_seq

%output "command.c"
%defines

/* grammar proper */
%%

start: sentence_root
       cmd_token_seq;

sentence_root: WORD                     {
                                          currnode = new_node(WORD_GN);
                                          currnode->is_root = 1;
                                        };

/* valid top level tokens */
cmd_token:
  placeholder_token
| literal_token
| selector
| option
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
      selector_element '>'              {
                                        //$$ = new_node(SELECTOR_GN);
                                        //add_node($$, $4);
                                        };

selector_part:
  selector_part '|' selector_element    
| selector_element
;

selector_element:
  WORD selector_token_seq;

selector_token_seq:
  %empty
| selector_token_seq selector_token     {
                                        //add_node(currnode, $2);
                                        //currnode = $2;
                                        }
;

selector_token:
  literal_token
| placeholder_token
| option
;

/* [option|set] productions */
option: '[' option_part ']';

option_part:
  option_part '|' option_token_seq
| option_token_seq
;

option_token_seq:
  option_token
| option_token_seq option_token
;

option_token:
  literal_token
| placeholder_token
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
  yy_scan_string(string);
  yyparse();
  return 0;
}


