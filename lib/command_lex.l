/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Command format string lexer for CLI backend.
 *
 * --
 * Copyright (C) 2015 Cumulus Networks, Inc.
 */

%top{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
}
%{
/* ignore flex generated code in static analyzer */
#ifndef __clang_analyzer__

/* ignore harmless bugs in old versions of flex */
#pragma GCC diagnostic ignored "-Wsign-compare"
#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#include "lib/command_parse.h"

#define YY_USER_ACTION yylloc->last_column += yyleng;
#define LOC_STEP do { if (yylloc) { \
        yylloc->first_column = yylloc->last_column; \
        yylloc->first_line = yylloc->last_line; \
	} } while(0)
%}

IPV4            A\.B\.C\.D
IPV4_PREFIX     A\.B\.C\.D\/M
IPV6            X:X::X:X
IPV6_PREFIX     X:X::X:X\/M
MAC             X:X:X:X:X:X
MAC_PREFIX      X:X:X:X:X:X\/M
VARIABLE        [A-Z][-_A-Z:0-9]+
WORD            (\-|\+)?[a-zA-Z0-9\*][-+_a-zA-Z0-9\*]*
NUMBER          (\-|\+)?[0-9]{1,20}
RANGE           \({NUMBER}[ ]?\-[ ]?{NUMBER}\)
ASNUM           ASNUM

/* yytext shall be a pointer */
%pointer
%option noyywrap
%option nounput
%option noinput
%option outfile="lib/command_lex.c"
%option header-file="lib/command_lex.h"
%option prefix="cmd_yy"
%option reentrant
%option bison-bridge
%option bison-locations

%%
%{
                LOC_STEP;
%}

[ \t]+          LOC_STEP /* ignore whitespace */;
{ASNUM}         {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return ASNUM;}
{IPV4}          {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return IPV4;}
{IPV4_PREFIX}   {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return IPV4_PREFIX;}
{IPV6}          {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return IPV6;}
{IPV6_PREFIX}   {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return IPV6_PREFIX;}
{MAC}           {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return MAC;}
{MAC_PREFIX}    {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return MAC_PREFIX;}
{VARIABLE}      {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return VARIABLE;}
{WORD}          {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return WORD;}
{RANGE}         {yylval->string = XSTRDUP(MTYPE_LEX, yytext); return RANGE;}
!\[             {yylval->string = NULL; return EXCL_BRACKET;}
.               {return yytext[0];}
%%

static YY_BUFFER_STATE buffer;

void set_lexer_string (yyscan_t *scn, const char *string)
{
  *scn = NULL;
  yylex_init(scn);
  buffer = yy_scan_string (string, *scn);
}

void cleanup_lexer (yyscan_t *scn)
{
  // yy_delete_buffer (buffer, *scn);
  yylex_destroy(*scn);
}

#endif /* __clang_analyzer__ */
