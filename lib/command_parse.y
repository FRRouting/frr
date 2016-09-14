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
  #include "grammar_sandbox.h"

  extern int
  yylex (void);

  extern void
  set_lexer_string (const char *);

  extern void
  cleanup_lexer (void);
}

/* functionality this unit exports */
%code provides {
  void
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
%type <node> selector_token
%type <node> selector_token_seq

%code {
  /* bison declarations */
  void
  yyerror (struct graph *, struct cmd_element *el, char const *msg);

  /* state variables for a single parser run */
  struct graph_node *startnode;       // start node of DFA

  struct graph_node *currnode;        // current position in DFA

  struct graph_node *optnode_start,   // start node for option set
                    *optnode_seqtail, // sequence tail for option sequence
                    *optnode_end;     // end node for option set

  struct graph_node *selnode_start,   // start node for selector set
                    *selnode_seqtail, // sequence tail for selector sequence
                    *selnode_end;     // end node for selector set

  char *docstr_start, *docstr;        // pointers to copy of command docstring

  /* helper functions for parser */
  static char *
  doc_next (void);

  static struct graph_node *
  node_adjacent (struct graph_node *, struct graph_node *);

  static struct graph_node *
  add_edge_dedup (struct graph_node *, struct graph_node *);

  static int
  cmp_token (struct cmd_token_t *, struct cmd_token_t *);

  static struct graph_node *
  new_token_node (struct graph *,
                  enum cmd_token_type_t type,
                  char *text, char *doc);

  static struct graph_node *
  find_tail (struct graph_node *);

  static void
  terminate_graph (struct graph *,
                   struct graph_node *,
                   struct cmd_element *);

  static void
  cleanup (void);
}

/* yyparse parameters */
%parse-param { struct graph *graph }
%parse-param { struct cmd_element *element }

/* called automatically before yyparse */
%initial-action {
  startnode = vector_slot (graph->nodes, 0);

  /* clear state pointers */
  currnode = NULL;
  selnode_start = selnode_seqtail = selnode_end = NULL;
  optnode_start = optnode_seqtail = optnode_end = NULL;

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
  terminate_graph (graph, currnode, element);
}
| sentence_root cmd_token_seq '.' placeholder_token
{
  if ((currnode = add_edge_dedup (currnode, $4)) != $4)
    graph_delete_node (graph, $4);

  // adding a node as a child of itself accepts any number
  // of the same token, which is what we want for varags
  add_edge_dedup (currnode, currnode);

  // tack on the command element
  terminate_graph (graph, currnode, element);
}

sentence_root: WORD
{
  struct graph_node *root =
    new_token_node (graph, WORD_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());

  if ((currnode = add_edge_dedup (startnode, root)) != root)
    graph_delete_node (graph, root);

  free ($1);
  $$ = currnode;
};

cmd_token:
  placeholder_token
{
  if ((currnode = add_edge_dedup (currnode, $1)) != $1)
    graph_delete_node (graph, $1);
}
| literal_token
{
  if ((currnode = add_edge_dedup (currnode, $1)) != $1)
    graph_delete_node (graph, $1);
}
/* selectors and options are subgraphs with start and end nodes */
| selector
{
  graph_add_edge (currnode, $1);
  currnode = find_tail ($1);
}
| option
{
  graph_add_edge (currnode, $1);
  currnode = find_tail ($1);
}
;

cmd_token_seq:
  %empty
| cmd_token_seq cmd_token
;

placeholder_token:
  IPV4
{
  $$ = new_token_node (graph, IPV4_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| IPV4_PREFIX
{
  $$ = new_token_node (graph, IPV4_PREFIX_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| IPV6
{
  $$ = new_token_node (graph, IPV6_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| IPV6_PREFIX
{
  $$ = new_token_node (graph, IPV6_PREFIX_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| VARIABLE
{
  $$ = new_token_node (graph, VARIABLE_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| RANGE
{
  $$ = new_token_node (graph, RANGE_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  struct cmd_token_t *token = $$->data;

  // get the numbers out
  yylval.string++;
  token->min = strtoll (yylval.string, &yylval.string, 10);
  strsep (&yylval.string, "-");
  token->max = strtoll (yylval.string, &yylval.string, 10);

  // validate range
  if (token->min >= token->max) yyerror (graph, element, "Invalid range.");

  free ($1);
}
;

literal_token:
  WORD
{
  $$ = new_token_node (graph, WORD_TKN, XSTRDUP(MTYPE_CMD_TOKENS, $1), doc_next());
  free ($1);
}
| NUMBER
{
  $$ = new_token_node (graph, NUMBER_TKN, NULL, doc_next());
  struct cmd_token_t *token = $$->data;

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
  selnode_start = selnode_end = NULL;
};

selector_part:
  selector_part '|' selector_element
| selector_element '|' selector_element
;

selector_element: selector_token_seq
{
  // if the selector start and end do not exist, create them
  if (!selnode_start || !selnode_end) {
    assert(!selnode_start && !selnode_end);
    selnode_start = new_token_node (graph, SELECTOR_TKN, NULL, NULL);
    selnode_end = new_token_node (graph, NUL_TKN, NULL, NULL);
  }

  // add element head as a child of the selector
  graph_add_edge (selnode_start, $1);
  graph_add_edge (selnode_seqtail, selnode_end);

  selnode_seqtail = NULL;
}

selector_token_seq:
  selector_token
{
  assert (!selnode_seqtail);
  selnode_seqtail = $1;
}
| selector_token_seq selector_token
{
  graph_add_edge ($1, $2);
  selnode_seqtail = $2;
}
;

selector_token:
  literal_token
| placeholder_token
;

/* [optional] productions */
option: '[' option_element ']'
{
  // add null path
  graph_add_edge (optnode_start, optnode_end);
  $$ = optnode_start;
  optnode_start = optnode_end = NULL;
};

option_element: option_token_seq
{
  if (!optnode_start || !optnode_end) {
    assert (!optnode_start && !optnode_end);
    optnode_start = new_token_node (graph, OPTION_TKN, NULL, NULL);
    optnode_end = new_token_node (graph, NUL_TKN, NULL, NULL);
  }

  graph_add_edge (optnode_start, $1);
  graph_add_edge (optnode_seqtail, optnode_end);
  optnode_seqtail = NULL;
}

option_token_seq:
  option_token
{
  assert (!optnode_seqtail);
  optnode_seqtail = find_tail ($1);
}
| option_token_seq option_token
{
  graph_add_edge (find_tail ($1), $2);
//  exit (EXIT_FAILURE);
  optnode_seqtail = find_tail ($2);
}
;

option_token:
  literal_token
| placeholder_token
| selector
;

%%

void
command_parse_format (struct graph *graph, struct cmd_element *cmd)
{
  // set to 1 to enable parser traces
  yydebug = 0;

  // parse command into DFA
  yyparse (graph, cmd);

  // cleanup
  cleanup ();
}

/* parser helper functions */

void
yyerror (struct graph *graph, struct cmd_element *el, char const *msg)
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
  currnode = NULL;
  docstr_start = docstr = NULL;
  selnode_start = selnode_seqtail = selnode_end = NULL;
  optnode_start = selnode_seqtail = optnode_end = NULL;
}

static void
terminate_graph (struct graph *graph, struct graph_node *finalnode, struct cmd_element *element)
{
  // end of graph should look like this
  // * -> finalnode -> END_TKN -> cmd_element
  struct graph_node *end_token_node =
    new_token_node (graph,
                    END_TKN,
                    XSTRDUP (MTYPE_CMD_TOKENS, CMD_CR_TEXT),
                    XSTRDUP (MTYPE_CMD_TOKENS, ""));
  struct graph_node *end_element_node =
    graph_new_node (graph, element, (void (*)(void *)) &del_cmd_element);

  if (node_adjacent (finalnode, end_token_node))
    yyerror (graph, element, "Duplicate command.");

  graph_add_edge (finalnode, end_token_node);
  graph_add_edge (end_token_node, end_element_node);
}

static char *
doc_next()
{
  char *piece = NULL;
  if (!docstr || !(piece = strsep (&docstr, "\n")))
    return XSTRDUP (MTYPE_CMD_TOKENS, "");
  return XSTRDUP (MTYPE_CMD_TOKENS, piece);
}

static struct graph_node *
new_token_node (struct graph *graph, enum cmd_token_type_t type, char *text, char *doc)
{
  struct cmd_token_t *token = new_cmd_token (type, text, doc);
  return graph_new_node (graph, token, (void (*)(void *)) &del_cmd_token);
}

/**
 * Determines if there is an out edge from the first node to the second
 */
static struct graph_node *
node_adjacent (struct graph_node *first, struct graph_node *second)
{
  struct graph_node *adj;
  for (unsigned int i = 0; i < vector_active (first->to); i++)
    {
      adj = vector_slot (first->to, i);
      struct cmd_token_t *ftok = adj->data,
                         *stok = second->data;
      if (cmp_token (ftok, stok))
        return adj;
    }
  return NULL;
}

/**
 * Walks down the left side of graph, returning the first encountered node with
 * no children.
 */
static struct graph_node *
find_tail (struct graph_node *node)
{
  while (vector_active (node->to) > 0)
    node = vector_slot (node->to, 0);
  return node;
}
/**
 * Creates an edge betwen two nodes, unless there is already an edge to an
 * equivalent node.
 *
 * The first node's out edges are searched to see if any of them point to a
 * node that is equivalent to the second node. If such a node exists, it is
 * returned. Otherwise an edge is created from the first node to the second.
 *
 * @param from start node for edge
 * @param to end node for edge
 * @return the node which the new edge points to
 */
static struct graph_node *
add_edge_dedup (struct graph_node *from, struct graph_node *to)
{
  struct graph_node *existing = node_adjacent (from, to);
  return existing ? existing : graph_add_edge (from, to);
}

/**
 * Compares two cmd_token's for equality,
 *
 * As such, this function is the working definition of token equality
 * for parsing purposes and determines overall graph structure.
 */
static int
cmp_token (struct cmd_token_t *first, struct cmd_token_t *second)
{
  // compare types
  if (first->type != second->type) return 0;

  switch (first->type) {
    case WORD_TKN:
    case VARIABLE_TKN:
      if (first->text && second->text)
        {
          if (strcmp (first->text, second->text))
            return 0;
        }
      else if (first->text != second->text) return 0;
      break;
    case RANGE_TKN:
      if (first->min != second->min || first->max != second->max)
        return 0;
      break;
    case NUMBER_TKN:
      if (first->value != second->value) return 0;
      break;

    /* selectors and options should be equal if their subgraphs are equal,
     * but the graph isomorphism problem is not known to be solvable in
     * polynomial time so we consider selectors and options inequal in all
     * cases; ultimately this forks the graph, but the matcher can handle
     * this regardless
     */
    case SELECTOR_TKN:
    case OPTION_TKN:
      return 0;

    /* end nodes are always considered equal, since each node may only
     * have one END_TKN child at a time
     */
    case START_TKN:
    case END_TKN:
    case NUL_TKN:
    default:
      break;
  }
  return 1;
}
