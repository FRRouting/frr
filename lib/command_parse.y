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

%locations
/* define parse.error verbose */
%define api.pure full
/* define api.prefix {cmd_yy} */

/* names for generated header and parser files */
%defines "lib/command_parse.h"
%output  "lib/command_parse.c"

/* note: code blocks are output in order, to both .c and .h:
 *  1. %code requires
 *  2. %union + bison forward decls
 *  3. %code provides
 * command_lex.h needs to be included at 3.; it needs the union and YYSTYPE.
 * struct parser_ctx is needed for the bison forward decls.
 */
%code requires {
  #include "config.h"

  #include <stdlib.h>
  #include <string.h>
  #include <ctype.h>

  #include "command_graph.h"
  #include "log.h"

  DECLARE_MTYPE(LEX)

  #define YYSTYPE CMD_YYSTYPE
  #define YYLTYPE CMD_YYLTYPE
  struct parser_ctx;

  /* subgraph semantic value */
  struct subgraph {
    struct graph_node *start, *end;
  };
}

%union {
  long long number;
  char *string;
  struct graph_node *node;
  struct subgraph subgraph;
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
%token <string> MAC
%token <string> MAC_PREFIX

/* union types for parsed rules */
%type <node> start
%type <node> literal_token
%type <node> placeholder_token
%type <node> placeholder_token_real
%type <node> simple_token
%type <subgraph> selector
%type <subgraph> selector_token
%type <subgraph> selector_token_seq
%type <subgraph> selector_seq_seq

%type <string> varname_token

%code {

  /* bison declarations */
  void
  cmd_yyerror (CMD_YYLTYPE *locp, struct parser_ctx *ctx, char const *msg);

  /* helper functions for parser */
  static const char *
  doc_next (struct parser_ctx *ctx);

  static struct graph_node *
  new_token_node (struct parser_ctx *,
                  enum cmd_token_type type,
                  const char *text,
                  const char *doc);

  static void
  terminate_graph (CMD_YYLTYPE *locp, struct parser_ctx *ctx,
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
  terminate_graph (&@1, ctx, ctx->currnode);
}
| cmd_token_seq placeholder_token '.' '.' '.'
{
  if ((ctx->currnode = graph_add_edge (ctx->currnode, $2)) != $2)
    graph_delete_node (ctx->graph, $2);

  ((struct cmd_token *)ctx->currnode->data)->allowrepeat = 1;

  // adding a node as a child of itself accepts any number
  // of the same token, which is what we want for variadics
  graph_add_edge (ctx->currnode, ctx->currnode);

  // tack on the command element
  terminate_graph (&@1, ctx, ctx->currnode);
}
;

varname_token: '$' WORD
{
  $$ = $2;
}
| /* empty */
{
  $$ = NULL;
}
;

cmd_token_seq:
  /* empty */
| cmd_token_seq cmd_token
;

cmd_token:
  simple_token
{
  if ((ctx->currnode = graph_add_edge (ctx->currnode, $1)) != $1)
    graph_delete_node (ctx->graph, $1);
}
| selector
{
  graph_add_edge (ctx->currnode, $1.start);
  ctx->currnode = $1.end;
}
;

simple_token:
  literal_token
| placeholder_token
;

literal_token: WORD varname_token
{
  $$ = new_token_node (ctx, WORD_TKN, $1, doc_next(ctx));
  cmd_token_varname_set ($$->data, $2);
  XFREE (MTYPE_LEX, $2);
  XFREE (MTYPE_LEX, $1);
}
;

placeholder_token_real:
  IPV4
{
  $$ = new_token_node (ctx, IPV4_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}
| IPV4_PREFIX
{
  $$ = new_token_node (ctx, IPV4_PREFIX_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}
| IPV6
{
  $$ = new_token_node (ctx, IPV6_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}
| IPV6_PREFIX
{
  $$ = new_token_node (ctx, IPV6_PREFIX_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}
| VARIABLE
{
  $$ = new_token_node (ctx, VARIABLE_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}
| RANGE
{
  $$ = new_token_node (ctx, RANGE_TKN, $1, doc_next(ctx));
  struct cmd_token *token = $$->data;

  // get the numbers out
  yylval.string++;
  token->min = strtoll (yylval.string, &yylval.string, 10);
  strsep (&yylval.string, "-");
  token->max = strtoll (yylval.string, &yylval.string, 10);

  // validate range
  if (token->min > token->max) cmd_yyerror (&@1, ctx, "Invalid range.");

  XFREE (MTYPE_LEX, $1);
}
| MAC
{
  $$ = new_token_node (ctx, MAC_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}
| MAC_PREFIX
{
  $$ = new_token_node (ctx, MAC_PREFIX_TKN, $1, doc_next(ctx));
  XFREE (MTYPE_LEX, $1);
}

placeholder_token:
  placeholder_token_real varname_token
{
  struct cmd_token *token = $$->data;
  $$ = $1;
  cmd_token_varname_set (token, $2);
  XFREE (MTYPE_LEX, $2);
};


/* <selector|set> productions */
selector: '<' selector_seq_seq '>' varname_token
{
  $$ = $2;
  cmd_token_varname_set ($2.end->data, $4);
  XFREE (MTYPE_LEX, $4);
};

selector_seq_seq:
  selector_seq_seq '|' selector_token_seq
{
  $$ = $1;
  graph_add_edge ($$.start, $3.start);
  graph_add_edge ($3.end, $$.end);
}
| selector_token_seq
{
  $$.start = new_token_node (ctx, FORK_TKN, NULL, NULL);
  $$.end   = new_token_node (ctx, JOIN_TKN, NULL, NULL);
  ((struct cmd_token *)$$.start->data)->forkjoin = $$.end;
  ((struct cmd_token *)$$.end->data)->forkjoin = $$.start;

  graph_add_edge ($$.start, $1.start);
  graph_add_edge ($1.end, $$.end);
}
;

/* {keyword} productions */
selector: '{' selector_seq_seq '}' varname_token
{
  $$ = $2;
  graph_add_edge ($$.end, $$.start);
  /* there is intentionally no start->end link, for two reasons:
   * 1) this allows "at least 1 of" semantics, which are otherwise impossible
   * 2) this would add a start->end->start loop in the graph that the current
   *    loop-avoidal fails to handle
   * just use [{a|b}] if neccessary, that will work perfectly fine, and reason
   * #1 is good enough to keep it this way. */

  cmd_token_varname_set ($2.end->data, $4);
  XFREE (MTYPE_LEX, $4);
};


selector_token:
  simple_token
{
  $$.start = $$.end = $1;
}
| selector
;

selector_token_seq:
  selector_token_seq selector_token
{
  graph_add_edge ($1.end, $2.start);
  $$.start = $1.start;
  $$.end   = $2.end;
}
| selector_token
;

/* [option] productions */
selector: '[' selector_seq_seq ']' varname_token
{
  $$ = $2;
  graph_add_edge ($$.start, $$.end);
  cmd_token_varname_set ($2.end->data, $4);
  XFREE (MTYPE_LEX, $4);
}
;

%%

#undef scanner

DEFINE_MTYPE(LIB, LEX, "Lexer token (temporary)")

void
cmd_graph_parse (struct graph *graph, struct cmd_element *cmd)
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
yyerror (CMD_YYLTYPE *loc, struct parser_ctx *ctx, char const *msg)
{
  char *tmpstr = strdup(ctx->el->string);
  char *line, *eol;
  char spacing[256];
  int lineno = 0;

  zlog_err ("%s: FATAL parse error: %s", __func__, msg);
  zlog_err ("%s: %d:%d-%d of this command definition:", __func__, loc->first_line, loc->first_column, loc->last_column);

  line = tmpstr;
  do {
    lineno++;
    eol = strchr(line, '\n');
    if (eol)
      *eol++ = '\0';

    zlog_err ("%s: | %s", __func__, line);
    if (lineno == loc->first_line && lineno == loc->last_line
        && loc->first_column < (int)sizeof(spacing) - 1
        && loc->last_column < (int)sizeof(spacing) - 1) {

      int len = loc->last_column - loc->first_column;
      if (len == 0)
        len = 1;

      memset(spacing, ' ', loc->first_column - 1);
      memset(spacing + loc->first_column - 1, '^', len);
      spacing[loc->first_column - 1 + len] = '\0';
      zlog_err ("%s: | %s", __func__, spacing);
    }
  } while ((line = eol));
  free(tmpstr);
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
terminate_graph (CMD_YYLTYPE *locp, struct parser_ctx *ctx,
                 struct graph_node *finalnode)
{
  // end of graph should look like this
  // * -> finalnode -> END_TKN -> cmd_element
  struct cmd_element *element = ctx->el;
  struct graph_node *end_token_node =
    new_token_node (ctx, END_TKN, CMD_CR_TEXT, "");
  struct graph_node *end_element_node =
    graph_new_node (ctx->graph, element, NULL);

  if (ctx->docstr && strlen (ctx->docstr) > 1) {
    zlog_debug ("Excessive docstring while parsing '%s'", ctx->el->string);
    zlog_debug ("----------");
    while (ctx->docstr && ctx->docstr[1] != '\0')
      zlog_debug ("%s", strsep(&ctx->docstr, "\n"));
    zlog_debug ("----------\n");
  }

  graph_add_edge (finalnode, end_token_node);
  graph_add_edge (end_token_node, end_element_node);
}

static const char *
doc_next (struct parser_ctx *ctx)
{
  const char *piece = ctx->docstr ? strsep (&ctx->docstr, "\n") : "";
  if (*piece == 0x03)
  {
    zlog_debug ("Ran out of docstring while parsing '%s'", ctx->el->string);
    piece = "";
  }

  return piece;
}

static struct graph_node *
new_token_node (struct parser_ctx *ctx, enum cmd_token_type type,
                const char *text, const char *doc)
{
  struct cmd_token *token = cmd_token_new (type, ctx->el->attr, text, doc);
  return graph_new_node (ctx->graph, token, (void (*)(void *)) &cmd_token_del);
}
