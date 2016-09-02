/*
 * Command format string parser for CLI backend.
 *
 * --
 * Copyright (C) 2015 Cumulus Networks, Inc.
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Zebra; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

%{
// compile with debugging facilities
#define YYDEBUG 1
%}

/* names for generated header and parser files */
%defines "command_parse.h"
%output  "command_parse.c"

/* required external units */
%code requires {
  #include "command.h"
  #include "graph.h"
  #include "memory.h"

  extern int
  yylex (void);

  extern void
  set_lexer_string (const char *);

  extern void
  cleanup_lexer (void);
}

/* functionality this unit exports */
%code provides {
  struct graph *
  command_parse_format (struct graph *, struct cmd_element *);

  /* maximum length of a number, lexer will not match anything longer */
  #define DECIMAL_STRLEN_MAX 20
}

/* valid semantic types for tokens and rules */
%union {
  long long number;
  char *string;
  struct graph_node *node;
}

/* union types for lexed tokens */
%token <string> WORD
%token <string> IPV4
%token <string> IPV4_PREFIX
%token <string> IPV6
%token <string> IPV6_PREFIX
%token <string> VARIABLE
%token <string> RANGE
%token <number> NUMBER

/* union types for parsed rules */
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

%code {
  /* bison declarations */
  void
  yyerror (struct cmd_element *el, struct graph_node *sn, char const *msg);

  /* state variables for a single parser run */
  struct graph_node *currnode,        // current position in DFA
                    *seqhead;         // sequence head

  struct graph_node *optnode_start,   // start node for option set
                    *optnode_end;     // end node for option set

  struct graph_node *selnode_start,   // start node for selector set
                    *selnode_end;     // end node for selector set

  char *docstr_start, *docstr;        // pointers to copy of command docstring

  /* helper functions for parser */
  static char *
  doc_next (void);

  static struct graph_node *
  node_exists (struct graph_node *, struct graph_node *);

  static struct graph_node *
  node_replace (struct graph_node *, struct graph_node *);

  static int
  cmp_node (struct graph_node *, struct graph_node *);

  static void
  terminate_graph (struct graph_node *,
                   struct graph_node *,
                   struct cmd_element *);

  static void
  cleanup (void);
}

/* yyparse parameters */
%parse-param { struct cmd_element *element }
%parse-param { struct graph *graph }

/* called automatically before yyparse */
%initial-action {
  /* clear state pointers */
  seqhead = NULL;
  currnode = NULL;
  selnode_start = selnode_end = NULL;
  optnode_start = optnode_end = NULL;

  /* set string to parse */
  set_lexer_string (element->string);

  /* copy docstring and keep a pointer to the copy */
  docstr = element->doc ? XSTRDUP(MTYPE_TMP, element->doc) : NULL;
  docstr_start = docstr;
}

%%

start:
  sentence_root cmd_token_seq
{
  // tack on the command element
  terminate_graph (startnode, currnode, element);
}
| sentence_root cmd_token_seq '.' placeholder_token
{
  if ((currnode = node_replace (currnode, $4)) != $4)
    graph_delete_node ($4);

  // adding a node as a child of itself accepts any number
  // of the same token, which is what we want for varags
  node_replace (currnode, currnode);

  // tack on the command element
  terminate_graph (startnode, currnode, element);
}

sentence_root: WORD
{
  struct graph_node *root =
    new_token_node (WORD_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());

  if ((currnode = node_replace (startnode, root)) != root)
    free (root);

  free ($1);
  $$ = currnode;
};

cmd_token:
  placeholder_token
{
  if ((currnode = node_replace (currnode, $1)) != $1)
    graph_delete_node ($1);
}
| literal_token
{
  if ((currnode = node_replace (currnode, $1)) != $1)
    graph_delete_node ($1);
}
/* selectors and options are subgraphs with start and end nodes */
| selector
{
  graph_add_edge (currnode, $1);
  currnode = selnode_end;
  selnode_start = selnode_end = NULL;
}
| option
{
  graph_add_edge (currnode, $1);
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
  $$ = new_token_node (IPV4_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| IPV4_PREFIX
{
  $$ = new_token_node (IPV4_PREFIX_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| IPV6
{
  $$ = new_token_node (IPV6_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| IPV6_PREFIX
{
  $$ = new_token_node (IPV6_PREFIX_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| VARIABLE
{
  $$ = new_token_node (VARIABLE_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| RANGE
{
  $$ = new_token_node (RANGE_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  cmd_token_t token = (cmd_token_t *) $$->data;

  // get the numbers out
  yylval.string++;
  token->min = strtoll (yylval.string, &yylval.string, 10);
  strsep (&yylval.string, "-");
  token->max = strtoll (yylval.string, &yylval.string, 10);

  // validate range
  if (token->min >= token->max) yyerror (element, startnode, "Invalid range.");

  free ($1);
}
;

literal_token:
  WORD
{
  $$ = new_token_node (WORD_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| NUMBER
{
  $$ = new_token_node (NUMBER_TKN, NULL, doc_next());
  cmd_token_t token = (cmd_token_t *) $$->data;

  token->value = yylval.number;
  token->text = XCALLOC(MTYPE_CMD_TOKENS, DECIMAL_STRLEN_MAX+1);
  snprintf(token->text, DECIMAL_STRLEN_MAX, "%lld", token->value);
}
;

/* <selector|set> productions */
selector: '<' selector_part '>'
{
  // all the graph building is done in selector_element,
  // so just return the selector subgraph head
  $$ = selnode_start;
};

selector_part:
  selector_part '|' selector_element
| selector_element '|' selector_element
;

selector_element: selector_element_root selector_token_seq
{
  // if the selector start and end do not exist, create them
  if (!selnode_start || !selnode_end) {
    assert(!selnode_start && !selnode_end);
    selnode_start = new_token_node (SELECTOR_TKN, NULL, NULL);
    selnode_end = new_token_node (NUL_TKN, NULL, NULL);
  }

  // add element head as a child of the selector
  graph_add_edge (selnode_start, $1);

  if ($2->type != NUL_GN) {
    graph_add_edge ($1, seqhead);
    graph_add_edge ($2, selnode_end);
  }
  else
    graph_add_edge ($1, selnode_end);

  seqhead = NULL;
}

selector_token_seq:
  %empty { $$ = new_token_node (NUL_TKN, NULL, NULL); }
| selector_token_seq selector_token
{
  // if the sequence component is NUL_GN, this is a sequence start
  if ($1->type == NUL_GN) {
    assert(!seqhead); // sequence head should always be null here
    seqhead = $2;
  }
  else // chain on new node
    graph_add_edge ($1, $2);

  $$ = $2;
}
;

selector_element_root:
  literal_token
| placeholder_token
;

selector_token:
  selector_element_root
;

/* [option|set] productions */
option: '[' option_part ']'
{
  // add null path
  graph_add_edge (optnode_start, optnode_end);
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
    optnode_start = new_token_node (OPTION_TKN, NULL, NULL);
    optnode_end = new_token_node (NUL_TKN, NULL, NULL);
  }

  graph_add_edge (optnode_start, seqhead);
  graph_add_edge ($1, optnode_end);
  seqhead = NULL;
}

option_token_seq:
  option_token
{ $$ = seqhead = $1; }
| option_token_seq option_token
{ $$ = graph_add_edge ($1, $2); }
;

option_token:
  literal_token
| placeholder_token
;

%%

struct graph_node *
command_parse_format (struct graph_node *start, struct cmd_element *cmd)
{
  // set to 1 to enable parser traces
  yydebug = 0;

  // parse command into DFA
  yyparse (cmd, start);

  // cleanup
  cleanup ();

  return start;
}

/* parser helper functions */

void
yyerror (struct cmd_element *el, struct graph_node *sn, char const *msg)
{
  zlog_err ("%s: FATAL parse error: %s", __func__, msg);
  zlog_err ("while parsing this command definition: \n\t%s\n", el->string);
  exit(EXIT_FAILURE);
}

static void
cleanup()
{
  /* free resources */
  free (docstr_start);

  /* cleanup lexer */
  cleanup_lexer ();

  /* clear state pointers */
  seqhead = NULL;
  currnode = NULL;
  docstr_start = docstr = NULL;
  selnode_start = selnode_end = NULL;
  optnode_start = optnode_end = NULL;
}

static void
terminate_graph (struct graph_node *startnode,
                 struct graph_node *finalnode,
                 struct cmd_element *element)
{
  struct graph_node *end = graph_new_node (graph, element, &cmd_delete_element);

  if (node_adjacent (finalnode, end))
    yyerror (element, startnode, "Duplicate command.");
  else
    graph_add_edge (finalnode, end);
}

static char *
doc_next()
{
  char *piece = NULL;
  if (!docstr || !(piece = strsep (&docstr, "\n")))
    return NULL;
  return XSTRDUP(MTYPE_CMD_TOKENS, piece);
}

static struct graph_node *
new_token_node (cmd_token_type_t type, char *text, char *doc)
{
  struct cmd_token_t *token =
    XMALLOC(MTYPE_CMD_TOKENS, sizeof (struct cmd_token_t));

  token->type = type;
  token->text = text;
  token->desc = doc;

  return graph_new_node (graph, token, &cmd_delete_token);
}

/**
 * Determines if a node is adjacent to another node
 */
static struct graph_node *
node_adjacent (struct graph_node *node, struct graph_node *neighbor)
{
  struct graph_node *adj;
  for (unsigned int i = 0; i < vector_active (node->to); i++)
    {
      adj = vector_slot (node->to, i);
      if (cmp_node (neighbor, adj))
        return adj;
    }
  return NULL;
}

static struct graph_node *
node_replace (struct graph_node *parent, struct graph_node *child)
{
  struct graph_node *existing = node_adjacent (parent, child);
  return existing ? existing : graph_add_edge (parent, child);
}

static int
cmp_token (struct cmd_token_t *first, struct cmd_token_t *second)
{
  struct cmd_token_t *first = (cmd_token *) firstgn->data;
  struct cmd_token_t *second = (cmd_token *) secondgn->data;

  // compare types
  if (first->type != second->type) return 0;

  switch (first->type) {
    case WORD_GN:
    case VARIABLE_GN:
      if (first->text && second->text)
        {
          if (strcmp (first->text, second->text))
          return 0;
        }
      else if (first->text != second->text) return 0;
      break;
    case RANGE_GN:
      if (first->min != second->min || first->max != second->max)
        return 0;
      break;
    case NUMBER_GN:
      if (first->value != second->value) return 0;
      break;
    /* selectors and options should be equal if their subgraphs are equal,
     * but the graph isomorphism problem is not known to be solvable in
     * polynomial time so we consider selectors and options inequal in all
     * cases; ultimately this forks the graph, but the matcher can handle
     * this regardless
     */
    case SELECTOR_GN:
    case OPTION_GN:
      return 0;
    /* end nodes are always considered equal, since each node may only
     * have one END_GN child at a time
     */
    case START_GN:
    case END_GN:
    case NUL_GN:
    default:
      break;
  }
  return 1;
}
