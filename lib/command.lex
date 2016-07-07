%{
#include <string.h>
#include <stdlib.h>

#include "command.h"
%}

WORD            [a-z][-_a-z0-9]+
IPV4            A\.B\.C\.D
IPV4_PREFIX     A\.B\.C\.D\/M
IPV6            X:X::X:X
IPV6_PREFIX     X:X::X:X\/M
VARIABLE        [A-Z][A-Z_]+
NUMBER          [0-9]{1,20}
RANGE           \({NUMBER}\-{NUMBER}\)

/* yytext shall be a pointer */
%pointer
%option noyywrap

%%
"<"             return '<';
">"             return '>';

[ /t]           /* ignore whitespace */;
{WORD}          {yylval.string = strdup(yytext); return WORD;}
{IPV4}          {yylval.string = strdup(yytext); return IPV4;}
{IPV4_PREFIX}   {yylval.string = strdup(yytext); return IPV4_PREFIX;}
{IPV6}          {yylval.string = strdup(yytext); return IPV6;}
{IPV6_PREFIX}   {yylval.string = strdup(yytext); return IPV6_PREFIX;}
{VARIABLE}      {yylval.string = strdup(yytext); return VARIABLE;}
{NUMBER}        {yylval.integer = atoi(yytext); return NUMBER;}
{RANGE}         {yylval.string = strdup(yytext); return RANGE;}
.               {return yytext[0];}
%%
