/*
 * Command format string lexer for CLI backend.
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
#include "command_parse.h"

extern void set_lexer_string (const char *);
extern void cleanup_lexer (void);
YY_BUFFER_STATE buffer;
%}

WORD            (\-|\+)?[a-z\*][-+_a-zA-Z0-9\*]*
IPV4            A\.B\.C\.D
IPV4_PREFIX     A\.B\.C\.D\/M
IPV6            X:X::X:X
IPV6_PREFIX     X:X::X:X\/M
VARIABLE        [A-Z][-_a-zA-Z:0-9]+
NUMBER          (\-|\+)?[0-9]{1,20}
RANGE           \({NUMBER}[ ]?\-[ ]?{NUMBER}\)

/* yytext shall be a pointer */
%pointer
%option noyywrap
%option nounput
%option noinput
%option outfile="command_lex.c"

%%
[ /t]           /* ignore whitespace */;
{WORD}          {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return WORD;}
{IPV4}          {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return IPV4;}
{IPV4_PREFIX}   {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return IPV4_PREFIX;}
{IPV6}          {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return IPV6;}
{IPV6_PREFIX}   {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return IPV6_PREFIX;}
{VARIABLE}      {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return VARIABLE;}
{NUMBER}        {
                    char *endptr;
                    yylval.number = strtoimax(yytext, &endptr, 10);
                    return NUMBER;
                }
{RANGE}         {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return RANGE;}
.               {return yytext[0];}
%%

void
set_lexer_string (const char *string)
{
  buffer = yy_scan_string (XSTRDUP(MTYPE_TMP, string));
}

void
cleanup_lexer ()
{
  yy_delete_buffer (buffer);
}
