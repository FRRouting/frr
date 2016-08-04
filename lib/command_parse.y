/*
 * Command format string parser.
 *
 * Turns a command definition into a DFA that together with the functions
 * provided in command_match.c may be used to map command line input to a
 * function.
 *
 * @author Quentin Young <qlyoung@cumulusnetworks.com>
 */

%{
extern int yylex(void);
void yyerror(const char *);
struct graph_node *
node_exists(struct graph_node *, struct graph_node *);
struct graph_node *
node_replace(struct graph_node *, struct graph_node *);

#define DECIMAL_STRLEN_MAX 20

// compile with debugging facilities
#define YYDEBUG 1
%}
%code requires {
  #include "command.h"
  #include "command_graph.h"
  #include "memory.h"
}
%code provides {
  extern void
  set_buffer_string(const char *);
  struct graph_node *
  parse_command_format(struct graph_node *, struct cmd_element *);
}


/* valid types for tokens */
%union{
  long long integer;
  char *string;
  struct graph_node *node;
}

/* some helpful state variables */
%{
struct graph_node *startnode,       // command root node
                  *currnode,        // current node
                  *seqhead;         // sequence head


struct graph_node *optnode_start,   // start node for option set
                  *optnode_end;     // end node for option set

struct graph_node *selnode_start,   // start node for selector set
                  *selnode_end;     // end node for selector set

struct cmd_element *command;        // command we're parsing
%}

%token <string> WORD
%token <string> IPV4
%token <string> IPV4_PREFIX
%token <string> IPV6
%token <string> IPV6_PREFIX
%token <string> VARIABLE
%token <string> RANGE
%token <integer> NUMBER

%type <node> start
%type <node> sentence_root
%type <node> literal_token
%type <node> placeholder_token
%type <node> option
%type <node> option_token
%type <node> option_token_seq
%type <node> selector
%type <node> selector_element_root
%type <node> selector_token
%type <node> selector_token_seq

%defines "command_parse.h"
%output "command_parse.c"

/* grammar proper */
%%

start:
  sentence_root cmd_token_seq
{
  // create leaf node
  struct graph_node *end = new_node(END_GN);
  end->element = command;

  // add node
  if (node_exists(currnode, end))
  {
    yyerror("Duplicate command.");
    YYABORT;
  }
  add_node(currnode, end);
  fprintf(stderr, "Parsed full command successfully.\n");
}
| sentence_root cmd_token_seq '.' placeholder_token
{
  if ((currnode = node_replace(currnode, $4)) != $4)
    free_node ($4);

  // since varargs may match any number of the last token,
  // simply add this node as a child of itself and proceed
  // wth normal command termination procedure
  node_replace(currnode, currnode);

  // create leaf node
  struct graph_node *end = new_node(END_GN);
  end->element = command;

  // add node
  if (node_exists(currnode, end))
  {
    yyerror("Duplicate command.");
    YYABORT;
  }
  add_node(currnode, end);
  fprintf(stderr, "Parsed full command successfully.\n");
}

sentence_root: WORD
{
  struct graph_node *root = new_node(WORD_GN);
  root->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);

  if ((currnode = node_replace(startnode, root)) != root)
    free (root);

  free ($1);
  $$ = currnode;
};

/* valid top level tokens */
cmd_token:
  placeholder_token
{
  if ((currnode = node_replace(currnode, $1)) != $1)
    free_node ($1);
}
| literal_token
{
  if ((currnode = node_replace(currnode, $1)) != $1)
    free_node ($1);
}
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
{
  $$ = new_node(IPV4_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);
  free ($1);
}
| IPV4_PREFIX
{
  $$ = new_node(IPV4_PREFIX_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);
  free ($1);
}
| IPV6
{
  $$ = new_node(IPV6_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);
  free ($1);
}
| IPV6_PREFIX
{
  $$ = new_node(IPV6_PREFIX_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);
  free ($1);
}
| VARIABLE
{
  $$ = new_node(VARIABLE_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);
  free ($1);
}
| RANGE
{
  $$ = new_node(RANGE_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);

  // get the numbers out
  yylval.string++;
  $$->min = strtoll( yylval.string, &yylval.string, 10 );
  strsep (&yylval.string, "-");
  $$->max = strtoll( yylval.string, &yylval.string, 10 );

  // validate range
  if ($$->min >= $$->max) yyerror("Invalid range.");

  free ($1);
}
;

literal_token:
  WORD
{
  $$ = new_node(WORD_GN);
  $$->text = XSTRDUP(MTYPE_CMD_TOKENS, $1);
  free ($1);
}
| NUMBER
{
  $$ = new_node(NUMBER_GN);
  $$->value = yylval.integer;
}
;

/* <selector|set> productions */
selector:
  '<' selector_part '>'
{
  // all the graph building is done in selector_element,
  // so just return the selector subgraph head
  $$ = selnode_start;
};

selector_part:
  selector_part '|' selector_element
| selector_element '|' selector_element
;

selector_element:
  selector_element_root selector_token_seq
{
  // if the selector start and end do not exist, create them
  if (!selnode_start || !selnode_end) {     // if one is null
    assert(!selnode_start && !selnode_end); // both should be null
    selnode_start = new_node(SELECTOR_GN);  // diverging node
    selnode_end = new_node(NUL_GN);         // converging node
    selnode_start->end = selnode_end;       // duh
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

selector_element_root:
  literal_token
| placeholder_token
;

selector_token:
  selector_element_root
| option
;

/* [option|set] productions */
option: '[' option_part ']'
{
  // add null path
  add_node(optnode_start, optnode_end);
  $$ = optnode_start;
};

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

void yyerror(char const *message) {
  // fail on bad parse
  fprintf(stderr, "Grammar error: %s\n", message);
  exit(EXIT_FAILURE);
}

struct graph_node *
parse_command_format(struct graph_node *start, struct cmd_element *cmd)
{
  fprintf(stderr, "parsing: %s\n", cmd->string);

  /* clear state pointers */
  startnode = start;
  currnode = seqhead = NULL;
  selnode_start = selnode_end = NULL;
  optnode_start = optnode_end = NULL;

  // trace parser
  yydebug = 0;
  // command string
  command = cmd;
  // make flex read from a string
  set_buffer_string(command->string);
  // parse command into DFA
  yyparse();
  // startnode points to command DFA
  return startnode;
}

struct graph_node *
node_exists(struct graph_node *parent, struct graph_node *child)
{
  struct graph_node *p_child;
  for (unsigned int i = 0; i < vector_active(parent->children); i++)
  {
    p_child = vector_slot(parent->children, i);
    if (cmp_node(child, p_child))
      return p_child;
  }
  return NULL;
}

struct graph_node *
node_replace(struct graph_node *parent, struct graph_node *child)
{
  struct graph_node *existing = node_exists (parent, child);
  if (!existing)
    existing = add_node(parent, child);

  return existing;
}
