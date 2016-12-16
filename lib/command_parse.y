/*
 * Command format string parser for CLI backend.
 *
 * --
 * Copyright (C) 2016 Cumulus Networks, Inc.
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

%define api.pure full
/* define api.prefix {cmd_yy} */

/* names for generated header and parser files */
%defines "command_parse.h"
%output  "command_parse.c"

/* note: code blocks are output in order, to both .c and .h:
 *  1. %code requires
 *  2. %union + bison forward decls
 *  3. %code provides
 * command_lex.h needs to be included at 3.; it needs the union and YYSTYPE.
 * struct parser_ctx is needed for the bison forward decls.
 */
%code requires {
  #include "stdlib.h"
  #include "string.h"
  #include "command.h"
  #include "log.h"
  #include "graph.h"

  #define YYSTYPE CMD_YYSTYPE
  struct parser_ctx;
}

%union {
  long long number;
  char *string;
  struct graph_node *node;
  struct subgraph *subgraph;
}

%code provides {
  #ifndef FLEX_SCANNER
  #include "command_lex.h"
  #endif

  extern void set_lexer_string (yyscan_t *scn, const char *string);
  extern void cleanup_lexer (yyscan_t *scn);

  struct parser_ctx {
    yyscan_t scanner;

    struct cmd_element *el;

    struct graph *graph;
    struct graph_node *currnode;

    /* pointers to copy of command docstring */
    char *docstr_start, *docstr;
  };
}

/* union types for lexed tokens */
%token <string> WORD
%token <string> IPV4
%token <string> IPV4_PREFIX
%token <string> IPV6
%token <string> IPV6_PREFIX
%token <string> VARIABLE
%token <string> RANGE

/* union types for parsed rules */
%type <node> start
%type <node> literal_token
%type <node> placeholder_token
%type <node> simple_token
%type <subgraph> option
%type <subgraph> option_token
%type <subgraph> option_token_seq
%type <subgraph> selector
%type <subgraph> selector_token
%type <subgraph> selector_token_seq
%type <subgraph> selector_seq_seq
%type <subgraph> compound_token

%code {

  /* bison declarations */
  void
  cmd_yyerror (struct parser_ctx *ctx, char const *msg);

  /* subgraph semantic value */
  struct subgraph {
    struct graph_node *start, *end;
  };

  /* helper functions for parser */
  static char *
  doc_next (struct parser_ctx *ctx);

  static struct graph_node *
  node_adjacent (struct graph_node *, struct graph_node *);

  static struct graph_node *
  add_edge_dedup (struct graph_node *, struct graph_node *);

  static int
  cmp_token (struct cmd_token *, struct cmd_token *);

  static struct graph_node *
  new_token_node (struct parser_ctx *,
                  enum cmd_token_type type,
                  char *text,
                  char *doc);

  static void
  terminate_graph (struct parser_ctx *ctx,
                   struct graph_node *);

  static void
  cleanup (struct parser_ctx *ctx);

  #define scanner ctx->scanner
}

/* yyparse parameters */
%lex-param {yyscan_t scanner}
%parse-param {struct parser_ctx *ctx}

/* called automatically before yyparse */
%initial-action {
  /* clear state pointers */
  ctx->currnode = vector_slot (ctx->graph->nodes, 0);

  /* copy docstring and keep a pointer to the copy */
  if (ctx->el->doc)
  {
    // allocate a new buffer, making room for a flag
    size_t length = (size_t) strlen (ctx->el->doc) + 2;
    ctx->docstr = malloc (length);
    memcpy (ctx->docstr, ctx->el->doc, strlen (ctx->el->doc));
    // set the flag so doc_next knows when to print a warning
    ctx->docstr[length - 2] = 0x03;
    // null terminate
    ctx->docstr[length - 1] = 0x00;
  }
  ctx->docstr_start = ctx->docstr;
}

%%

start:
  cmd_token_seq
{
  // tack on the command element
  terminate_graph (ctx, ctx->currnode);
}
| cmd_token_seq placeholder_token '.' '.' '.'
{
  if ((ctx->currnode = add_edge_dedup (ctx->currnode, $2)) != $2)
    graph_delete_node (ctx->graph, $2);

  ((struct cmd_token *)ctx->currnode->data)->allowrepeat = 1;

  // adding a node as a child of itself accepts any number
  // of the same token, which is what we want for variadics
  add_edge_dedup (ctx->currnode, ctx->currnode);

  // tack on the command element
  terminate_graph (ctx, ctx->currnode);
}
;

cmd_token_seq:
  /* empty */
| cmd_token_seq cmd_token
;

cmd_token:
  simple_token
{
  if ((ctx->currnode = add_edge_dedup (ctx->currnode, $1)) != $1)
    graph_delete_node (ctx->graph, $1);
}
| compound_token
{
  graph_add_edge (ctx->currnode, $1->start);
  ctx->currnode = $1->end;
  free ($1);
}
;

simple_token:
  literal_token
| placeholder_token
;

compound_token:
  selector
| option
;

literal_token: WORD
{
  $$ = new_token_node (ctx, WORD_TKN, strdup($1), doc_next(ctx));
  free ($1);
}
;

placeholder_token:
  IPV4
{
  $$ = new_token_node (ctx, IPV4_TKN, strdup($1), doc_next(ctx));
  free ($1);
}
| IPV4_PREFIX
{
  $$ = new_token_node (ctx, IPV4_PREFIX_TKN, strdup($1), doc_next(ctx));
  free ($1);
}
| IPV6
{
  $$ = new_token_node (ctx, IPV6_TKN, strdup($1), doc_next(ctx));
  free ($1);
}
| IPV6_PREFIX
{
  $$ = new_token_node (ctx, IPV6_PREFIX_TKN, strdup($1), doc_next(ctx));
  free ($1);
}
| VARIABLE
{
  $$ = new_token_node (ctx, VARIABLE_TKN, strdup($1), doc_next(ctx));
  free ($1);
}
| RANGE
{
  $$ = new_token_node (ctx, RANGE_TKN, strdup($1), doc_next(ctx));
  struct cmd_token *token = $$->data;

  // get the numbers out
  yylval.string++;
  token->min = strtoll (yylval.string, &yylval.string, 10);
  strsep (&yylval.string, "-");
  token->max = strtoll (yylval.string, &yylval.string, 10);

  // validate range
  if (token->min > token->max) cmd_yyerror (ctx, "Invalid range.");

  free ($1);
}

/* <selector|set> productions */
selector: '<' selector_seq_seq '>'
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = new_token_node (ctx, FORK_TKN, NULL, NULL);
  $$->end   = new_token_node (ctx, JOIN_TKN, NULL, NULL);
  for (unsigned int i = 0; i < vector_active ($2->start->to); i++)
  {
    struct graph_node *sn = vector_slot ($2->start->to, i),
                      *en = vector_slot ($2->end->from, i);
    graph_add_edge ($$->start, sn);
    graph_add_edge (en, $$->end);
  }
  graph_delete_node (ctx->graph, $2->start);
  graph_delete_node (ctx->graph, $2->end);
  free ($2);
};

selector_seq_seq:
  selector_seq_seq '|' selector_token_seq
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = graph_new_node (ctx->graph, NULL, NULL);
  $$->end   = graph_new_node (ctx->graph, NULL, NULL);

  // link in last sequence
  graph_add_edge ($$->start, $3->start);
  graph_add_edge ($3->end, $$->end);

  for (unsigned int i = 0; i < vector_active ($1->start->to); i++)
  {
    struct graph_node *sn = vector_slot ($1->start->to, i),
                      *en = vector_slot ($1->end->from, i);
    graph_add_edge ($$->start, sn);
    graph_add_edge (en, $$->end);
  }
  graph_delete_node (ctx->graph, $1->start);
  graph_delete_node (ctx->graph, $1->end);
  free ($1);
  free ($3);
}
| selector_token_seq '|' selector_token_seq
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = graph_new_node (ctx->graph, NULL, NULL);
  $$->end   = graph_new_node (ctx->graph, NULL, NULL);
  graph_add_edge ($$->start, $1->start);
  graph_add_edge ($1->end, $$->end);
  graph_add_edge ($$->start, $3->start);
  graph_add_edge ($3->end, $$->end);
  free ($1);
  free ($3);
}
;

/* {keyword} productions */
selector: '{' selector_seq_seq '}'
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = new_token_node (ctx, FORK_TKN, NULL, NULL);
  $$->end   = new_token_node (ctx, JOIN_TKN, NULL, NULL);
  graph_add_edge ($$->start, $$->end);
  for (unsigned int i = 0; i < vector_active ($2->start->to); i++)
  {
    struct graph_node *sn = vector_slot ($2->start->to, i),
                      *en = vector_slot ($2->end->from, i);
    graph_add_edge ($$->start, sn);
    graph_add_edge (en, $$->start);
  }
  graph_delete_node (ctx->graph, $2->start);
  graph_delete_node (ctx->graph, $2->end);
  free ($2);
};


selector_token_seq:
  simple_token
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = $$->end = $1;
}
| selector_token_seq selector_token
{
  $$ = malloc (sizeof (struct subgraph));
  graph_add_edge ($1->end, $2->start);
  $$->start = $1->start;
  $$->end   = $2->end;
  free ($1);
  free ($2);
}
;

selector_token:
  simple_token
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = $$->end = $1;
}
| option
| selector
;

/* [option] productions */
option: '[' option_token_seq ']'
{
  // make a new option
  $$ = malloc (sizeof (struct subgraph));
  $$->start = new_token_node (ctx, FORK_TKN, NULL, NULL);
  $$->end   = new_token_node (ctx, JOIN_TKN, NULL, NULL);
  // add a path through the sequence to the end
  graph_add_edge ($$->start, $2->start);
  graph_add_edge ($2->end, $$->end);
  // add a path directly from the start to the end
  graph_add_edge ($$->start, $$->end);
  free ($2);
}
;

option_token_seq:
  option_token
| option_token_seq option_token
{
  $$ = malloc (sizeof (struct subgraph));
  graph_add_edge ($1->end, $2->start);
  $$->start = $1->start;
  $$->end   = $2->end;
  free ($1);
  free ($2);
}
;

option_token:
  simple_token
{
  $$ = malloc (sizeof (struct subgraph));
  $$->start = $$->end = $1;
}
| compound_token
;

%%

#undef scanner

void
command_parse_format (struct graph *graph, struct cmd_element *cmd)
{
  struct parser_ctx ctx = { .graph = graph, .el = cmd };

  // set to 1 to enable parser traces
  yydebug = 0;

  set_lexer_string (&ctx.scanner, cmd->string);

  // parse command into DFA
  cmd_yyparse (&ctx);

  /* cleanup lexer */
  cleanup_lexer (&ctx.scanner);

  // cleanup
  cleanup (&ctx);
}

/* parser helper functions */

void
yyerror (struct parser_ctx *ctx, char const *msg)
{
  zlog_err ("%s: FATAL parse error: %s", __func__, msg);
  zlog_err ("while parsing this command definition: \n\t%s\n", ctx->el->string);
  //exit(EXIT_FAILURE);
}

static void
cleanup (struct parser_ctx *ctx)
{
  /* free resources */
  free (ctx->docstr_start);

  /* clear state pointers */
  ctx->currnode = NULL;
  ctx->docstr_start = ctx->docstr = NULL;
}

static void
terminate_graph (struct parser_ctx *ctx, struct graph_node *finalnode)
{
  // end of graph should look like this
  // * -> finalnode -> END_TKN -> cmd_element
  struct cmd_element *element = ctx->el;
  struct graph_node *end_token_node =
    new_token_node (ctx,
                    END_TKN,
                    strdup (CMD_CR_TEXT),
                    strdup (""));
  struct graph_node *end_element_node =
    graph_new_node (ctx->graph, element, NULL);

  if (node_adjacent (finalnode, end_token_node))
    cmd_yyerror (ctx, "Duplicate command.");

  graph_add_edge (finalnode, end_token_node);
  graph_add_edge (end_token_node, end_element_node);
}

static char *
doc_next (struct parser_ctx *ctx)
{
  const char *piece = ctx->docstr ? strsep (&ctx->docstr, "\n") : "";
  if (*piece == 0x03)
  {
    zlog_debug ("Ran out of docstring while parsing '%s'", ctx->el->string);
    piece = "";
  }

  return strdup (piece);
}

static struct graph_node *
new_token_node (struct parser_ctx *ctx, enum cmd_token_type type,
                char *text, char *doc)
{
  struct cmd_token *token = new_cmd_token (type, ctx->el->attr, text, doc);
  return graph_new_node (ctx->graph, token, (void (*)(void *)) &del_cmd_token);
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
      struct cmd_token *ftok = adj->data,
                         *stok = second->data;
      if (cmp_token (ftok, stok))
        return adj;
    }
  return NULL;
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
  if (existing)
  {
    struct cmd_token *ex_tok = existing->data;
    struct cmd_token *to_tok = to->data;
    // NORMAL takes precedence over DEPRECATED takes precedence over HIDDEN
    ex_tok->attr = (ex_tok->attr < to_tok->attr) ? ex_tok->attr : to_tok->attr;
    return existing;
  }
  else
    return graph_add_edge (from, to);
}

/**
 * Compares two cmd_token's for equality,
 *
 * As such, this function is the working definition of token equality
 * for parsing purposes and determines overall graph structure.
 */
static int
cmp_token (struct cmd_token *first, struct cmd_token *second)
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
    /* selectors and options should be equal if their subgraphs are equal,
     * but the graph isomorphism problem is not known to be solvable in
     * polynomial time so we consider selectors and options inequal in all
     * cases; ultimately this forks the graph, but the matcher can handle
     * this regardless
     */
    case FORK_TKN:
      return 0;

    /* end nodes are always considered equal, since each node may only
     * have one END_TKN child at a time
     */
    case START_TKN:
    case END_TKN:
    case JOIN_TKN:
    default:
      break;
  }
  return 1;
}
