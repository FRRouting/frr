%{
#include "cmdtree.h"

extern int yylex(void);
extern void yyerror(const char *);

// compile with debugging facilities
#define YYDEBUG 1
%}
%code provides {
extern struct graph_node *cmd_parse_format_new(const char *, const char *);
extern void set_buffer_string(const char *);
}

%union{
  int integer;
  char *string;
  struct graph_node *node;
}

%{
// last top-level node
struct graph_node *startnode,       // command root node
                  *currnode,        // current node
                  *tmpnode,         // temp node pointer
                  *seqhead;         // sequence head


struct graph_node *optnode_start = NULL,   // start node for option set
                  *optnode_end = NULL;     // end node for option set

struct graph_node *selnode_start = NULL,   // start node for selector set
                  *selnode_end = NULL;     // end node for selector set
%}

%token <node> WORD
%token <node> IPV4
%token <node> IPV4_PREFIX
%token <node> IPV6
%token <node> IPV6_PREFIX
%token <node> VARIABLE
%token <node> RANGE
%token <node> NUMBER

%type <node> start
%type <node> sentence_root
%type <node> literal_token
%type <node> placeholder_token
%type <node> option
%type <node> option_token
%type <node> option_token_seq
%type <node> selector
%type <node> selector_root
%type <node> selector_token
%type <node> selector_token_seq

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
  add_node(startnode, currnode);
};

/* valid top level tokens */
cmd_token:
  placeholder_token
{ currnode = add_node(currnode, $1); }
| literal_token
{ currnode = add_node(currnode, $1); }
/* selectors and options are subgraphs with start and end nodes */
| selector
{
  add_node(currnode, $1);
  currnode = selnode_end;
  selnode_start = selnode_end = NULL;
}
| option
{
  add_node(currnode, $1);
  currnode = optnode_end;
  optnode_start = optnode_end = NULL;
}
;

cmd_token_seq:
  %empty
| cmd_token_seq cmd_token
;

placeholder_token:
  IPV4
{ $$ = new_node(IPV4_GN); }
| IPV4_PREFIX
{ $$ = new_node(IPV4_PREFIX_GN); }
| IPV6
{ $$ = new_node(IPV6_GN); }
| IPV6_PREFIX
{ $$ = new_node(IPV6_PREFIX_GN); }
| VARIABLE
{ $$ = new_node(VARIABLE_GN); }
| RANGE
{
  $$ = new_node(RANGE_GN);

  // get the numbers out
  strsep(&yylval.string, "(-)");
  $$->start = atoi( strsep(&yylval.string, "(-)") );
  strsep(&yylval.string, "(-)");
  $$->end   = atoi( strsep(&yylval.string, "(-)") );

  // we could do this a variety of ways with either
  // the lexer or the parser, but this is the simplest
  // and involves the least amount of free()
}
;

literal_token:
  WORD
{
  $$ = new_node(WORD_GN);
  $$->text = strdup(yylval.string);
}
| NUMBER
{
  $$ = new_node(NUMBER_GN);
  $$->value = yylval.integer;
}
;

/* <selector|token> productions */
selector:
  '<' selector_part '|' selector_element '>'
{
  // all the graph building is done in selector_element,
  // so just return the selector subgraph head
  $$ = selnode_start;
};

selector_part:
  selector_part '|' selector_element
| selector_element
;

selector_element:
  selector_root selector_token_seq
{
  // if the selector start and end do not exist, create them
  if (!selnode_start || !selnode_end) {     // if one is null
    assert(!selnode_start && !selnode_end); // both should be null
    selnode_start = new_node(SELECTOR_GN);  // diverging node
    selnode_end = new_node(NUL_GN);         // converging node
  }

  // add element head as a child of the selector
  add_node(selnode_start, $1);

  if ($2->type != NUL_GN) {
    add_node($1, seqhead);
    add_node($2, selnode_end);
  }
  else
    add_node($1, selnode_end);

  seqhead = NULL;
}

selector_token_seq:
  %empty { $$ = new_node(NUL_GN); }
| selector_token_seq selector_token
{
  // if the sequence component is NUL_GN, this is a sequence start
  if ($1->type == NUL_GN) {
    assert(!seqhead); // sequence head should always be null here
    seqhead = $2;
  }
  else // chain on new node
    add_node($1, $2);

  $$ = $2;
}
;

selector_root:
  literal_token
| placeholder_token
;

selector_token:
  selector_root
| option
;

/* [option|set] productions */
option: '[' option_part ']'
{ $$ = optnode_start; };

option_part:
  option_part '|' option_element
| option_element
;

option_element:
  option_token_seq
{
  if (!optnode_start || !optnode_end) {
    assert(!optnode_start && !optnode_end);
    optnode_start = new_node(OPTION_GN);
    optnode_end = new_node(NUL_GN);
  }

  add_node(optnode_start, seqhead);
  add_node($1, optnode_end);
}

option_token_seq:
  option_token
{ $$ = seqhead = $1; }
| option_token_seq option_token
{ $$ = add_node($1, $2); }
;

option_token:
  literal_token
| placeholder_token
;

%%
/*
int
main (void)
{
  const char* input = "show [random conf NAME] thing";
  printf("Parsing:\n\t%s\n", input);
  return cmd_parse_format_new(input, "description");
}
*/
void yyerror(char const *message) {
  printf("Grammar error: %s\n", message);
  exit(EXIT_FAILURE);
}

struct graph_node *
cmd_parse_format_new(const char *string, const char *desc)
{
  fprintf(stderr, "parsing: %s\n", string);

  yydebug = 1;
  // make flex read from a string
  set_buffer_string(string);
  // initialize the start node of this command dfa
  startnode = new_node(NUL_GN);
  // parse command into DFA
  yyparse();
  // startnode points to command DFA
  return startnode;
}
