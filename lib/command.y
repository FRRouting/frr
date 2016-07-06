%{
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

extern int yylex(void);
extern void yyerror(const char *);
%}

%union{
  int integer;
  char *string;
}

%token <string>     WORD
%token <string>     IPV4
%token <string>     IPV4_PREFIX
%token <string>     IPV6
%token <string>     IPV6_PREFIX
%token <string>     VARIABLE
%token <string>     RANGE
%token <integer>    NUMBER

/* grammar proper */
%%

start: sentence_root                    {printf("Matched sentence root\n");}
       cmd_token_seq                    {printf("Matched sentence\n");};

sentence_root: WORD                     {printf("Sentence root: %s\n", $1);};

/* valid top level tokens */
cmd_token: placeholder_token
         | literal_token
         | selector
         | option
         ;
cmd_token_seq: /* empty */
             | cmd_token_seq cmd_token;

placeholder_token: IPV4                 {printf("Matched placeholder\n");}
                 | IPV4_PREFIX          {printf("Matched placeholder\n");}
                 | IPV6                 {printf("Matched placeholder\n");}
                 | IPV6_PREFIX          {printf("Matched placeholder\n");}
                 | VARIABLE             {printf("Matched placeholder\n");}
                 | RANGE                {printf("Matched placeholder\n");}

literal_token: WORD
             | NUMBER
             ;
/* range: '(' NUMBER '-' NUMBER ')'        {printf("Matched range\n");}; */


/* <selector|token> productions */
selector: '<' selector_part '|'
              selector_element '>'      {printf("Matched selector\n");};
selector_part: selector_part '|'
               selector_element
             | selector_element
                                        {printf("Matched selector part\n");};
selector_element: WORD
                  selector_token_seq
selector_token_seq: /* empty */
                  | selector_token_seq
                    selector_token
                  ;
selector_token: literal_token
              | placeholder_token
              | option
              ;

/* [option|set] productions */
option: '[' option_part ']'             {printf("Matched option\n");};
option_part: option_part '|'
             option_element_seq
           | option_element_seq
           ;
option_element_seq: option_token
                  | option_element_seq
                    option_token
                  ;
option_token: literal_token
            | placeholder_token
            ;
%%

int
main (void)
{
  return yyparse ();
}

void yyerror(char const *message) {
  printf("Grammar error: %s\n", message);
  exit(EXIT_FAILURE);
}
