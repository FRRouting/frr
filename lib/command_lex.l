%{
#include "command_parse.h"

extern void set_buffer_string(const char *);
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
                    yylval.integer = strtoimax(yytext, &endptr, 10);
                    return NUMBER;
                }
{RANGE}         {yylval.string = XSTRDUP(MTYPE_TMP, yytext); return RANGE;}
.               {return yytext[0];}
%%

void
set_buffer_string(const char *string)
{
  yy_scan_string(string);
}
