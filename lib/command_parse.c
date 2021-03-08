/* A Bison parser, made by GNU Bison 3.0.4.  */

/* Bison implementation for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output.  */
#define YYBISON 1

/* Bison version.  */
#define YYBISON_VERSION "3.0.4"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 2

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1

/* Substitute the type names.  */
#define YYSTYPE         CMD_YYSTYPE
#define YYLTYPE         CMD_YYLTYPE
/* Substitute the variable and function names.  */
#define yyparse         cmd_yyparse
#define yylex           cmd_yylex
#define yyerror         cmd_yyerror
#define yydebug         cmd_yydebug
#define yynerrs         cmd_yynerrs


/* Copy the first part of user declarations.  */
#line 25 "lib/command_parse.y" /* yacc.c:339  */

// compile with debugging facilities
#define YYDEBUG 1

#line 79 "lib/command_parse.c" /* yacc.c:339  */

# ifndef YY_NULLPTR
#  if defined __cplusplus && 201103L <= __cplusplus
#   define YY_NULLPTR nullptr
#  else
#   define YY_NULLPTR 0
#  endif
# endif

/* Enabling verbose error messages.  */
#ifdef YYERROR_VERBOSE
# undef YYERROR_VERBOSE
# define YYERROR_VERBOSE 1
#else
# define YYERROR_VERBOSE 1
#endif

/* In a future release of Bison, this section will be replaced
   by #include "command_parse.h".  */
#ifndef YY_CMD_YY_LIB_COMMAND_PARSE_H_INCLUDED
# define YY_CMD_YY_LIB_COMMAND_PARSE_H_INCLUDED
/* Debug traces.  */
#ifndef CMD_YYDEBUG
# if defined YYDEBUG
#if YYDEBUG
#   define CMD_YYDEBUG 1
#  else
#   define CMD_YYDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define CMD_YYDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined CMD_YYDEBUG */
#if CMD_YYDEBUG
extern int cmd_yydebug;
#endif
/* "%code requires" blocks.  */
#line 46 "lib/command_parse.y" /* yacc.c:355  */

  #include "config.h"

  #include <stdbool.h>
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

#line 140 "lib/command_parse.c" /* yacc.c:355  */

/* Token type.  */
#ifndef CMD_YYTOKENTYPE
# define CMD_YYTOKENTYPE
  enum cmd_yytokentype
  {
    WORD = 258,
    IPV4 = 259,
    IPV4_PREFIX = 260,
    IPV6 = 261,
    IPV6_PREFIX = 262,
    VARIABLE = 263,
    RANGE = 264,
    MAC = 265,
    MAC_PREFIX = 266
  };
#endif
/* Tokens.  */
#define WORD 258
#define IPV4 259
#define IPV4_PREFIX 260
#define IPV6 261
#define IPV6_PREFIX 262
#define VARIABLE 263
#define RANGE 264
#define MAC 265
#define MAC_PREFIX 266

/* Value type.  */
#if ! defined CMD_YYSTYPE && ! defined CMD_YYSTYPE_IS_DECLARED

union CMD_YYSTYPE
{
#line 69 "lib/command_parse.y" /* yacc.c:355  */

  long long number;
  char *string;
  struct graph_node *node;
  struct subgraph subgraph;

#line 181 "lib/command_parse.c" /* yacc.c:355  */
};

typedef union CMD_YYSTYPE CMD_YYSTYPE;
# define CMD_YYSTYPE_IS_TRIVIAL 1
# define CMD_YYSTYPE_IS_DECLARED 1
#endif

/* Location type.  */
#if ! defined CMD_YYLTYPE && ! defined CMD_YYLTYPE_IS_DECLARED
typedef struct CMD_YYLTYPE CMD_YYLTYPE;
struct CMD_YYLTYPE
{
  int first_line;
  int first_column;
  int last_line;
  int last_column;
};
# define CMD_YYLTYPE_IS_DECLARED 1
# define CMD_YYLTYPE_IS_TRIVIAL 1
#endif



int cmd_yyparse (struct parser_ctx *ctx);
/* "%code provides" blocks.  */
#line 76 "lib/command_parse.y" /* yacc.c:355  */

  #ifndef FLEX_SCANNER
  #include "command_lex.h"
  #endif

  extern void set_lexer_string (yyscan_t *scn, const char *string);
  extern void cleanup_lexer (yyscan_t *scn);

  struct parser_ctx {
    yyscan_t scanner;

    const struct cmd_element *el;

    struct graph *graph;
    struct graph_node *currnode;

    /* pointers to copy of command docstring */
    char *docstr_start, *docstr;
  };

#line 228 "lib/command_parse.c" /* yacc.c:355  */

#endif /* !YY_CMD_YY_LIB_COMMAND_PARSE_H_INCLUDED  */

/* Copy the second part of user declarations.  */

#line 234 "lib/command_parse.c" /* yacc.c:358  */
/* Unqualified %code blocks.  */
#line 121 "lib/command_parse.y" /* yacc.c:359  */


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

  static void loopcheck(struct parser_ctx *ctx, struct subgraph *sg);

  #define scanner ctx->scanner

#line 264 "lib/command_parse.c" /* yacc.c:359  */

#ifdef short
# undef short
#endif

#ifdef YYTYPE_UINT8
typedef YYTYPE_UINT8 yytype_uint8;
#else
typedef unsigned char yytype_uint8;
#endif

#ifdef YYTYPE_INT8
typedef YYTYPE_INT8 yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef YYTYPE_UINT16
typedef YYTYPE_UINT16 yytype_uint16;
#else
typedef unsigned short int yytype_uint16;
#endif

#ifdef YYTYPE_INT16
typedef YYTYPE_INT16 yytype_int16;
#else
typedef short int yytype_int16;
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif ! defined YYSIZE_T
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned int
# endif
#endif

#define YYSIZE_MAXIMUM ((YYSIZE_T) -1)

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif

#ifndef YY_ATTRIBUTE
# if (defined __GNUC__                                               \
      && (2 < __GNUC__ || (__GNUC__ == 2 && 96 <= __GNUC_MINOR__)))  \
     || defined __SUNPRO_C && 0x5110 <= __SUNPRO_C
#  define YY_ATTRIBUTE(Spec) __attribute__(Spec)
# else
#  define YY_ATTRIBUTE(Spec) /* empty */
# endif
#endif

#ifndef YY_ATTRIBUTE_PURE
# define YY_ATTRIBUTE_PURE   YY_ATTRIBUTE ((__pure__))
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# define YY_ATTRIBUTE_UNUSED YY_ATTRIBUTE ((__unused__))
#endif

#if !defined _Noreturn \
     && (!defined __STDC_VERSION__ || __STDC_VERSION__ < 201112)
# if defined _MSC_VER && 1200 <= _MSC_VER
#  define _Noreturn __declspec (noreturn)
# else
#  define _Noreturn YY_ATTRIBUTE ((__noreturn__))
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YYUSE(E) ((void) (E))
#else
# define YYUSE(E) /* empty */
#endif

#if defined __GNUC__ && 407 <= __GNUC__ * 100 + __GNUC_MINOR__
/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN \
    _Pragma ("GCC diagnostic push") \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")\
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# define YY_IGNORE_MAYBE_UNINITIALIZED_END \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif


#if ! defined yyoverflow || YYERROR_VERBOSE

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* ! defined yyoverflow || YYERROR_VERBOSE */


#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined CMD_YYLTYPE_IS_TRIVIAL && CMD_YYLTYPE_IS_TRIVIAL \
             && defined CMD_YYSTYPE_IS_TRIVIAL && CMD_YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yytype_int16 yyss_alloc;
  YYSTYPE yyvs_alloc;
  YYLTYPE yyls_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (sizeof (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (sizeof (yytype_int16) + sizeof (YYSTYPE) + sizeof (YYLTYPE)) \
      + 2 * YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYSIZE_T yynewbytes;                                            \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * sizeof (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / sizeof (*yyptr);                          \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, (Count) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYSIZE_T yyi;                         \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  3
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   35

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  21
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  13
/* YYNRULES -- Number of rules.  */
#define YYNRULES  30
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  46

/* YYTRANSLATE[YYX] -- Symbol number corresponding to YYX as returned
   by yylex, with out-of-bounds checking.  */
#define YYUNDEFTOK  2
#define YYMAXUTOK   266

#define YYTRANSLATE(YYX)                                                \
  ((unsigned int) (YYX) <= YYMAXUTOK ? yytranslate[YYX] : YYUNDEFTOK)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, without out-of-bounds checking.  */
static const yytype_uint8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,    13,     2,     2,     2,
       2,     2,     2,     2,     2,     2,    12,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      14,     2,    15,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    19,     2,    20,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,    17,    16,    18,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11
};

#if CMD_YYDEBUG
  /* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_uint16 yyrline[] =
{
       0,   176,   176,   181,   197,   202,   207,   209,   213,   218,
     226,   227,   230,   240,   245,   250,   255,   260,   265,   281,
     286,   293,   303,   311,   317,   330,   348,   352,   356,   362,
     366
};
#endif

#if CMD_YYDEBUG || YYERROR_VERBOSE || 1
/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "$end", "error", "$undefined", "WORD", "IPV4", "IPV4_PREFIX", "IPV6",
  "IPV6_PREFIX", "VARIABLE", "RANGE", "MAC", "MAC_PREFIX", "'.'", "'$'",
  "'<'", "'>'", "'|'", "'{'", "'}'", "'['", "']'", "$accept", "start",
  "varname_token", "cmd_token_seq", "cmd_token", "simple_token",
  "literal_token", "placeholder_token_real", "placeholder_token",
  "selector", "selector_seq_seq", "selector_token", "selector_token_seq", YY_NULLPTR
};
#endif

# ifdef YYPRINT
/* YYTOKNUM[NUM] -- (External) token number corresponding to the
   (internal) symbol number NUM (which must be that of a token).  */
static const yytype_uint16 yytoknum[] =
{
       0,   256,   257,   258,   259,   260,   261,   262,   263,   264,
     265,   266,    46,    36,    60,    62,   124,   123,   125,    91,
      93
};
# endif

#define YYPACT_NINF -20

#define yypact_value_is_default(Yystate) \
  (!!((Yystate) == (-20)))

#define YYTABLE_NINF -1

#define yytable_value_is_error(Yytable_value) \
  0

  /* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
     STATE-NUM.  */
static const yytype_int8 yypact[] =
{
     -20,    18,    -2,   -20,     0,   -20,   -20,   -20,   -20,   -20,
     -20,   -20,   -20,    -2,    -2,    -2,   -20,   -20,   -20,     0,
      17,   -20,    19,   -20,   -20,   -20,   -20,    10,   -20,    -2,
       5,    -6,   -20,    20,   -20,     0,    -2,   -20,     0,     0,
      21,   -20,    -2,   -20,   -20,   -20
};

  /* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
     Performed when YYTABLE does not specify something else to do.  Zero
     means the default is an error.  */
static const yytype_uint8 yydefact[] =
{
       6,     0,     2,     1,     5,    13,    14,    15,    16,    17,
      18,    19,    20,     0,     0,     0,     7,     8,    10,     5,
      11,     9,     0,    12,    26,    11,    27,     0,    29,    24,
       0,     0,    21,     0,     4,     5,     0,    28,     5,     5,
       0,    22,    23,    25,    30,     3
};

  /* YYPGOTO[NTERM-NUM].  */
static const yytype_int8 yypgoto[] =
{
     -20,   -20,   -19,   -20,   -20,    28,   -20,   -20,    29,    32,
      13,   -18,    -1
};

  /* YYDEFGOTO[NTERM-NUM].  */
static const yytype_int8 yydefgoto[] =
{
      -1,     1,    23,     2,    16,    24,    18,    19,    25,    26,
      27,    28,    29
};

  /* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
     positive, shift that token.  If negative, reduce the rule whose
     number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_uint8 yytable[] =
{
      32,     4,     5,     6,     7,     8,     9,    10,    11,    12,
      36,    37,    13,    22,    39,    14,    41,    15,     3,    43,
      44,    36,    34,    38,    37,    35,    36,    30,    31,    33,
      17,    20,    40,    45,    21,    42
};

static const yytype_uint8 yycheck[] =
{
      19,     3,     4,     5,     6,     7,     8,     9,    10,    11,
      16,    29,    14,    13,    20,    17,    35,    19,     0,    38,
      39,    16,     3,    18,    42,    15,    16,    14,    15,    12,
       2,     2,    12,    12,     2,    36
};

  /* YYSTOS[STATE-NUM] -- The (internal number of the) accessing
     symbol of state STATE-NUM.  */
static const yytype_uint8 yystos[] =
{
       0,    22,    24,     0,     3,     4,     5,     6,     7,     8,
       9,    10,    11,    14,    17,    19,    25,    26,    27,    28,
      29,    30,    13,    23,    26,    29,    30,    31,    32,    33,
      31,    31,    23,    12,     3,    15,    16,    32,    18,    20,
      12,    23,    33,    23,    23,    12
};

  /* YYR1[YYN] -- Symbol number of symbol that rule YYN derives.  */
static const yytype_uint8 yyr1[] =
{
       0,    21,    22,    22,    23,    23,    24,    24,    25,    25,
      26,    26,    27,    28,    28,    28,    28,    28,    28,    28,
      28,    29,    30,    31,    31,    30,    32,    32,    33,    33,
      30
};

  /* YYR2[YYN] -- Number of symbols on the right hand side of rule YYN.  */
static const yytype_uint8 yyr2[] =
{
       0,     2,     1,     5,     2,     0,     0,     2,     1,     1,
       1,     1,     2,     1,     1,     1,     1,     1,     1,     1,
       1,     2,     4,     3,     1,     4,     1,     1,     2,     1,
       4
};


#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)
#define YYEMPTY         (-2)
#define YYEOF           0

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                  \
do                                                              \
  if (yychar == YYEMPTY)                                        \
    {                                                           \
      yychar = (Token);                                         \
      yylval = (Value);                                         \
      YYPOPSTACK (yylen);                                       \
      yystate = *yyssp;                                         \
      goto yybackup;                                            \
    }                                                           \
  else                                                          \
    {                                                           \
      yyerror (&yylloc, ctx, YY_("syntax error: cannot back up")); \
      YYERROR;                                                  \
    }                                                           \
while (0)

/* Error token number */
#define YYTERROR        1
#define YYERRCODE       256


/* YYLLOC_DEFAULT -- Set CURRENT to span from RHS[1] to RHS[N].
   If N is 0, then set CURRENT to the empty location which ends
   the previous symbol: RHS[0] (always defined).  */

#ifndef YYLLOC_DEFAULT
# define YYLLOC_DEFAULT(Current, Rhs, N)                                \
    do                                                                  \
      if (N)                                                            \
        {                                                               \
          (Current).first_line   = YYRHSLOC (Rhs, 1).first_line;        \
          (Current).first_column = YYRHSLOC (Rhs, 1).first_column;      \
          (Current).last_line    = YYRHSLOC (Rhs, N).last_line;         \
          (Current).last_column  = YYRHSLOC (Rhs, N).last_column;       \
        }                                                               \
      else                                                              \
        {                                                               \
          (Current).first_line   = (Current).last_line   =              \
            YYRHSLOC (Rhs, 0).last_line;                                \
          (Current).first_column = (Current).last_column =              \
            YYRHSLOC (Rhs, 0).last_column;                              \
        }                                                               \
    while (0)
#endif

#define YYRHSLOC(Rhs, K) ((Rhs)[K])


/* Enable debugging if requested.  */
#if CMD_YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)


/* YY_LOCATION_PRINT -- Print the location on the stream.
   This macro was not mandated originally: define only if we know
   we won't break user code: when these are the locations we know.  */

#ifndef YY_LOCATION_PRINT
# if defined CMD_YYLTYPE_IS_TRIVIAL && CMD_YYLTYPE_IS_TRIVIAL

/* Print *YYLOCP on YYO.  Private, do not rely on its existence. */

YY_ATTRIBUTE_UNUSED
static unsigned
yy_location_print_ (FILE *yyo, YYLTYPE const * const yylocp)
{
  unsigned res = 0;
  int end_col = 0 != yylocp->last_column ? yylocp->last_column - 1 : 0;
  if (0 <= yylocp->first_line)
    {
      res += YYFPRINTF (yyo, "%d", yylocp->first_line);
      if (0 <= yylocp->first_column)
        res += YYFPRINTF (yyo, ".%d", yylocp->first_column);
    }
  if (0 <= yylocp->last_line)
    {
      if (yylocp->first_line < yylocp->last_line)
        {
          res += YYFPRINTF (yyo, "-%d", yylocp->last_line);
          if (0 <= end_col)
            res += YYFPRINTF (yyo, ".%d", end_col);
        }
      else if (0 <= end_col && yylocp->first_column < end_col)
        res += YYFPRINTF (yyo, "-%d", end_col);
    }
  return res;
 }

#  define YY_LOCATION_PRINT(File, Loc)          \
  yy_location_print_ (File, &(Loc))

# else
#  define YY_LOCATION_PRINT(File, Loc) ((void) 0)
# endif
#endif


# define YY_SYMBOL_PRINT(Title, Type, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Type, Value, Location, ctx); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*----------------------------------------.
| Print this symbol's value on YYOUTPUT.  |
`----------------------------------------*/

static void
yy_symbol_value_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct parser_ctx *ctx)
{
  FILE *yyo = yyoutput;
  YYUSE (yyo);
  YYUSE (yylocationp);
  YYUSE (ctx);
  if (!yyvaluep)
    return;
# ifdef YYPRINT
  if (yytype < YYNTOKENS)
    YYPRINT (yyoutput, yytoknum[yytype], *yyvaluep);
# endif
  YYUSE (yytype);
}


/*--------------------------------.
| Print this symbol on YYOUTPUT.  |
`--------------------------------*/

static void
yy_symbol_print (FILE *yyoutput, int yytype, YYSTYPE const * const yyvaluep, YYLTYPE const * const yylocationp, struct parser_ctx *ctx)
{
  YYFPRINTF (yyoutput, "%s %s (",
             yytype < YYNTOKENS ? "token" : "nterm", yytname[yytype]);

  YY_LOCATION_PRINT (yyoutput, *yylocationp);
  YYFPRINTF (yyoutput, ": ");
  yy_symbol_value_print (yyoutput, yytype, yyvaluep, yylocationp, ctx);
  YYFPRINTF (yyoutput, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yytype_int16 *yybottom, yytype_int16 *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yytype_int16 *yyssp, YYSTYPE *yyvsp, YYLTYPE *yylsp, int yyrule, struct parser_ctx *ctx)
{
  unsigned long int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %lu):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       yystos[yyssp[yyi + 1 - yynrhs]],
                       &(yyvsp[(yyi + 1) - (yynrhs)])
                       , &(yylsp[(yyi + 1) - (yynrhs)])                       , ctx);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, yylsp, Rule, ctx); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !CMD_YYDEBUG */
# define YYDPRINTF(Args)
# define YY_SYMBOL_PRINT(Title, Type, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !CMD_YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


#if YYERROR_VERBOSE

# ifndef yystrlen
#  if defined __GLIBC__ && defined _STRING_H
#   define yystrlen strlen
#  else
/* Return the length of YYSTR.  */
static YYSIZE_T
yystrlen (const char *yystr)
{
  YYSIZE_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
#  endif
# endif

# ifndef yystpcpy
#  if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#   define yystpcpy stpcpy
#  else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
#  endif
# endif

# ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYSIZE_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYSIZE_T yyn = 0;
      char const *yyp = yystr;

      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            /* Fall through.  */
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (! yyres)
    return yystrlen (yystr);

  return yystpcpy (yyres, yystr) - yyres;
}
# endif

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return 1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return 2 if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYSIZE_T *yymsg_alloc, char **yymsg,
                yytype_int16 *yyssp, int yytoken)
{
  YYSIZE_T yysize0 = yytnamerr (YY_NULLPTR, yytname[yytoken]);
  YYSIZE_T yysize = yysize0;
  enum { YYERROR_VERBOSE_ARGS_MAXIMUM = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat. */
  char const *yyarg[YYERROR_VERBOSE_ARGS_MAXIMUM];
  /* Number of reported tokens (one for the "unexpected", one per
     "expected"). */
  int yycount = 0;

  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yytoken != YYEMPTY)
    {
      int yyn = yypact[*yyssp];
      yyarg[yycount++] = yytname[yytoken];
      if (!yypact_value_is_default (yyn))
        {
          /* Start YYX at -YYN if negative to avoid negative indexes in
             YYCHECK.  In other words, skip the first -YYN actions for
             this state because they are default actions.  */
          int yyxbegin = yyn < 0 ? -yyn : 0;
          /* Stay within bounds of both yycheck and yytname.  */
          int yychecklim = YYLAST - yyn + 1;
          int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
          int yyx;

          for (yyx = yyxbegin; yyx < yyxend; ++yyx)
            if (yycheck[yyx + yyn] == yyx && yyx != YYTERROR
                && !yytable_value_is_error (yytable[yyx + yyn]))
              {
                if (yycount == YYERROR_VERBOSE_ARGS_MAXIMUM)
                  {
                    yycount = 1;
                    yysize = yysize0;
                    break;
                  }
                yyarg[yycount++] = yytname[yyx];
                {
                  YYSIZE_T yysize1 = yysize + yytnamerr (YY_NULLPTR, yytname[yyx]);
                  if (! (yysize <= yysize1
                         && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
                    return 2;
                  yysize = yysize1;
                }
              }
        }
    }

  switch (yycount)
    {
# define YYCASE_(N, S)                      \
      case N:                               \
        yyformat = S;                       \
      break
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
# undef YYCASE_
    }

  {
    YYSIZE_T yysize1 = yysize + yystrlen (yyformat);
    if (! (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM))
      return 2;
    yysize = yysize1;
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return 1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yyarg[yyi++]);
          yyformat += 2;
        }
      else
        {
          yyp++;
          yyformat++;
        }
  }
  return 0;
}
#endif /* YYERROR_VERBOSE */

/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg, int yytype, YYSTYPE *yyvaluep, YYLTYPE *yylocationp, struct parser_ctx *ctx)
{
  YYUSE (yyvaluep);
  YYUSE (yylocationp);
  YYUSE (ctx);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yytype, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YYUSE (yytype);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}




/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct parser_ctx *ctx)
{
/* The lookahead symbol.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

/* Location data for the lookahead symbol.  */
static YYLTYPE yyloc_default
# if defined CMD_YYLTYPE_IS_TRIVIAL && CMD_YYLTYPE_IS_TRIVIAL
  = { 1, 1, 1, 1 }
# endif
;
YYLTYPE yylloc = yyloc_default;

    /* Number of syntax errors so far.  */
    int yynerrs;

    int yystate;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus;

    /* The stacks and their tools:
       'yyss': related to states.
       'yyvs': related to semantic values.
       'yyls': related to locations.

       Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* The state stack.  */
    yytype_int16 yyssa[YYINITDEPTH];
    yytype_int16 *yyss;
    yytype_int16 *yyssp;

    /* The semantic value stack.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs;
    YYSTYPE *yyvsp;

    /* The location stack.  */
    YYLTYPE yylsa[YYINITDEPTH];
    YYLTYPE *yyls;
    YYLTYPE *yylsp;

    /* The locations where the error started and ended.  */
    YYLTYPE yyerror_range[3];

    YYSIZE_T yystacksize;

  int yyn;
  int yyresult;
  /* Lookahead token as an internal (translated) token number.  */
  int yytoken = 0;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;
  YYLTYPE yyloc;

#if YYERROR_VERBOSE
  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYSIZE_T yymsg_alloc = sizeof yymsgbuf;
#endif

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N), yylsp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  yyssp = yyss = yyssa;
  yyvsp = yyvs = yyvsa;
  yylsp = yyls = yylsa;
  yystacksize = YYINITDEPTH;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yystate = 0;
  yyerrstatus = 0;
  yynerrs = 0;
  yychar = YYEMPTY; /* Cause a token to be read.  */

/* User initialization code.  */
#line 154 "lib/command_parse.y" /* yacc.c:1429  */
{
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

#line 1302 "lib/command_parse.c" /* yacc.c:1429  */
  yylsp[0] = yylloc;
  goto yysetstate;

/*------------------------------------------------------------.
| yynewstate -- Push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
 yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;

 yysetstate:
  *yyssp = yystate;

  if (yyss + yystacksize - 1 <= yyssp)
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYSIZE_T yysize = yyssp - yyss + 1;

#ifdef yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        YYSTYPE *yyvs1 = yyvs;
        yytype_int16 *yyss1 = yyss;
        YYLTYPE *yyls1 = yyls;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * sizeof (*yyssp),
                    &yyvs1, yysize * sizeof (*yyvsp),
                    &yyls1, yysize * sizeof (*yylsp),
                    &yystacksize);

        yyls = yyls1;
        yyss = yyss1;
        yyvs = yyvs1;
      }
#else /* no yyoverflow */
# ifndef YYSTACK_RELOCATE
      goto yyexhaustedlab;
# else
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        goto yyexhaustedlab;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yytype_int16 *yyss1 = yyss;
        union yyalloc *yyptr =
          (union yyalloc *) YYSTACK_ALLOC (YYSTACK_BYTES (yystacksize));
        if (! yyptr)
          goto yyexhaustedlab;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
        YYSTACK_RELOCATE (yyls_alloc, yyls);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif
#endif /* no yyoverflow */

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;
      yylsp = yyls + yysize - 1;

      YYDPRINTF ((stderr, "Stack size increased to %lu\n",
                  (unsigned long int) yystacksize));

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }

  YYDPRINTF ((stderr, "Entering state %d\n", yystate));

  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;

/*-----------.
| yybackup.  |
`-----------*/
yybackup:

  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either YYEMPTY or YYEOF or a valid lookahead symbol.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token: "));
      yychar = yylex (&yylval, &yylloc, scanner);
    }

  if (yychar <= YYEOF)
    {
      yychar = yytoken = YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);

  /* Discard the shifted token.  */
  yychar = YYEMPTY;

  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END
  *++yylsp = yylloc;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- Do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];

  /* Default location.  */
  YYLLOC_DEFAULT (yyloc, (yylsp - yylen), yylen);
  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
        case 2:
#line 177 "lib/command_parse.y" /* yacc.c:1646  */
    {
  // tack on the command element
  terminate_graph (&(yylsp[0]), ctx, ctx->currnode);
}
#line 1494 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 3:
#line 182 "lib/command_parse.y" /* yacc.c:1646  */
    {
  if ((ctx->currnode = graph_add_edge (ctx->currnode, (yyvsp[-3].node))) != (yyvsp[-3].node))
    graph_delete_node (ctx->graph, (yyvsp[-3].node));

  ((struct cmd_token *)ctx->currnode->data)->allowrepeat = 1;

  // adding a node as a child of itself accepts any number
  // of the same token, which is what we want for variadics
  graph_add_edge (ctx->currnode, ctx->currnode);

  // tack on the command element
  terminate_graph (&(yylsp[-4]), ctx, ctx->currnode);
}
#line 1512 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 4:
#line 198 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.string) = (yyvsp[0].string);
}
#line 1520 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 5:
#line 202 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.string) = NULL;
}
#line 1528 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 8:
#line 214 "lib/command_parse.y" /* yacc.c:1646  */
    {
  if ((ctx->currnode = graph_add_edge (ctx->currnode, (yyvsp[0].node))) != (yyvsp[0].node))
    graph_delete_node (ctx->graph, (yyvsp[0].node));
}
#line 1537 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 9:
#line 219 "lib/command_parse.y" /* yacc.c:1646  */
    {
  graph_add_edge (ctx->currnode, (yyvsp[0].subgraph).start);
  ctx->currnode = (yyvsp[0].subgraph).end;
}
#line 1546 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 12:
#line 231 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, WORD_TKN, (yyvsp[-1].string), doc_next(ctx));
  cmd_token_varname_set ((yyval.node)->data, (yyvsp[0].string));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
  XFREE (MTYPE_LEX, (yyvsp[-1].string));
}
#line 1557 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 13:
#line 241 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, IPV4_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1566 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 14:
#line 246 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, IPV4_PREFIX_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1575 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 15:
#line 251 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, IPV6_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1584 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 16:
#line 256 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, IPV6_PREFIX_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1593 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 17:
#line 261 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, VARIABLE_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1602 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 18:
#line 266 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, RANGE_TKN, (yyvsp[0].string), doc_next(ctx));
  struct cmd_token *token = (yyval.node)->data;

  // get the numbers out
  yylval.string++;
  token->min = strtoll (yylval.string, &yylval.string, 10);
  strsep (&yylval.string, "-");
  token->max = strtoll (yylval.string, &yylval.string, 10);

  // validate range
  if (token->min > token->max) cmd_yyerror (&(yylsp[0]), ctx, "Invalid range.");

  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1622 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 19:
#line 282 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, MAC_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1631 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 20:
#line 287 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.node) = new_token_node (ctx, MAC_PREFIX_TKN, (yyvsp[0].string), doc_next(ctx));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1640 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 21:
#line 294 "lib/command_parse.y" /* yacc.c:1646  */
    {
  struct cmd_token *token = (yyval.node)->data;
  (yyval.node) = (yyvsp[-1].node);
  cmd_token_varname_set (token, (yyvsp[0].string));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1651 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 22:
#line 304 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.subgraph) = (yyvsp[-2].subgraph);
  cmd_token_varname_set ((yyvsp[-2].subgraph).end->data, (yyvsp[0].string));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1661 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 23:
#line 312 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.subgraph) = (yyvsp[-2].subgraph);
  graph_add_edge ((yyval.subgraph).start, (yyvsp[0].subgraph).start);
  graph_add_edge ((yyvsp[0].subgraph).end, (yyval.subgraph).end);
}
#line 1671 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 24:
#line 318 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.subgraph).start = new_token_node (ctx, FORK_TKN, NULL, NULL);
  (yyval.subgraph).end   = new_token_node (ctx, JOIN_TKN, NULL, NULL);
  ((struct cmd_token *)(yyval.subgraph).start->data)->forkjoin = (yyval.subgraph).end;
  ((struct cmd_token *)(yyval.subgraph).end->data)->forkjoin = (yyval.subgraph).start;

  graph_add_edge ((yyval.subgraph).start, (yyvsp[0].subgraph).start);
  graph_add_edge ((yyvsp[0].subgraph).end, (yyval.subgraph).end);
}
#line 1685 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 25:
#line 331 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.subgraph) = (yyvsp[-2].subgraph);
  graph_add_edge ((yyval.subgraph).end, (yyval.subgraph).start);
  /* there is intentionally no start->end link, for two reasons:
   * 1) this allows "at least 1 of" semantics, which are otherwise impossible
   * 2) this would add a start->end->start loop in the graph that the current
   *    loop-avoidal fails to handle
   * just use [{a|b}] if neccessary, that will work perfectly fine, and reason
   * #1 is good enough to keep it this way. */

  loopcheck(ctx, &(yyval.subgraph));
  cmd_token_varname_set ((yyvsp[-2].subgraph).end->data, (yyvsp[0].string));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1704 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 26:
#line 349 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.subgraph).start = (yyval.subgraph).end = (yyvsp[0].node);
}
#line 1712 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 28:
#line 357 "lib/command_parse.y" /* yacc.c:1646  */
    {
  graph_add_edge ((yyvsp[-1].subgraph).end, (yyvsp[0].subgraph).start);
  (yyval.subgraph).start = (yyvsp[-1].subgraph).start;
  (yyval.subgraph).end   = (yyvsp[0].subgraph).end;
}
#line 1722 "lib/command_parse.c" /* yacc.c:1646  */
    break;

  case 30:
#line 367 "lib/command_parse.y" /* yacc.c:1646  */
    {
  (yyval.subgraph) = (yyvsp[-2].subgraph);
  graph_add_edge ((yyval.subgraph).start, (yyval.subgraph).end);
  cmd_token_varname_set ((yyvsp[-2].subgraph).end->data, (yyvsp[0].string));
  XFREE (MTYPE_LEX, (yyvsp[0].string));
}
#line 1733 "lib/command_parse.c" /* yacc.c:1646  */
    break;


#line 1737 "lib/command_parse.c" /* yacc.c:1646  */
      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", yyr1[yyn], &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);

  *++yyvsp = yyval;
  *++yylsp = yyloc;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */

  yyn = yyr1[yyn];

  yystate = yypgoto[yyn - YYNTOKENS] + *yyssp;
  if (0 <= yystate && yystate <= YYLAST && yycheck[yystate] == *yyssp)
    yystate = yytable[yystate];
  else
    yystate = yydefgoto[yyn - YYNTOKENS];

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYEMPTY : YYTRANSLATE (yychar);

  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
#if ! YYERROR_VERBOSE
      yyerror (&yylloc, ctx, YY_("syntax error"));
#else
# define YYSYNTAX_ERROR yysyntax_error (&yymsg_alloc, &yymsg, \
                                        yyssp, yytoken)
      {
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = YYSYNTAX_ERROR;
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == 1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = (char *) YYSTACK_ALLOC (yymsg_alloc);
            if (!yymsg)
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = 2;
              }
            else
              {
                yysyntax_error_status = YYSYNTAX_ERROR;
                yymsgp = yymsg;
              }
          }
        yyerror (&yylloc, ctx, yymsgp);
        if (yysyntax_error_status == 2)
          goto yyexhaustedlab;
      }
# undef YYSYNTAX_ERROR
#endif
    }

  yyerror_range[1] = yylloc;

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, &yylloc, ctx);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:

  /* Pacify compilers like GCC when the user code never invokes
     YYERROR and the label yyerrorlab therefore never appears in user
     code.  */
  if (/*CONSTCOND*/ 0)
     goto yyerrorlab;

  yyerror_range[1] = yylsp[1-yylen];
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYTERROR;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYTERROR)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;

      yyerror_range[1] = *yylsp;
      yydestruct ("Error: popping",
                  yystos[yystate], yyvsp, yylsp, ctx);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  yyerror_range[2] = yylloc;
  /* Using YYLLOC is tempting, but would change the location of
     the lookahead.  YYLOC is available though.  */
  YYLLOC_DEFAULT (yyloc, yyerror_range, 2);
  *++yylsp = yyloc;

  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", yystos[yyn], yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturn;

/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturn;

#if !defined yyoverflow || YYERROR_VERBOSE
/*-------------------------------------------------.
| yyexhaustedlab -- memory exhaustion comes here.  |
`-------------------------------------------------*/
yyexhaustedlab:
  yyerror (&yylloc, ctx, YY_("memory exhausted"));
  yyresult = 2;
  /* Fall through.  */
#endif

yyreturn:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, &yylloc, ctx);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  yystos[*yyssp], yyvsp, yylsp, ctx);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
#if YYERROR_VERBOSE
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
#endif
  return yyresult;
}
#line 375 "lib/command_parse.y" /* yacc.c:1906  */


#undef scanner

DEFINE_MTYPE(LIB, LEX, "Lexer token (temporary)")

void
cmd_graph_parse (struct graph *graph, const struct cmd_element *cmd)
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

static bool loopcheck_inner(struct graph_node *start, struct graph_node *node,
			    struct graph_node *end, size_t depth)
{
	size_t i;
	bool ret;

	/* safety check */
	if (depth++ == 64)
		return true;

	for (i = 0; i < vector_active(node->to); i++) {
		struct graph_node *next = vector_slot(node->to, i);
		struct cmd_token *tok = next->data;

		if (next == end || next == start)
			return true;
		if (tok->type < SPECIAL_TKN)
			continue;
		ret = loopcheck_inner(start, next, end, depth);
		if (ret)
			return true;
	}
	return false;
}

static void loopcheck(struct parser_ctx *ctx, struct subgraph *sg)
{
	if (loopcheck_inner(sg->start, sg->start, sg->end, 0))
		zlog_err("FATAL: '%s': {} contains an empty path! Use [{...}]",
			 ctx->el->string);
}

void
yyerror (CMD_YYLTYPE *loc, struct parser_ctx *ctx, char const *msg)
{
  char *tmpstr = strdup(ctx->el->string);
  char *line, *eol;
  char spacing[256];
  int lineno = 0;

  zlog_notice ("%s: FATAL parse error: %s", __func__, msg);
  zlog_notice ("%s: %d:%d-%d of this command definition:", __func__, loc->first_line, loc->first_column, loc->last_column);

  line = tmpstr;
  do {
    lineno++;
    eol = strchr(line, '\n');
    if (eol)
      *eol++ = '\0';

    zlog_notice ("%s: | %s", __func__, line);
    if (lineno == loc->first_line && lineno == loc->last_line
        && loc->first_column < (int)sizeof(spacing) - 1
        && loc->last_column < (int)sizeof(spacing) - 1) {

      int len = loc->last_column - loc->first_column;
      if (len == 0)
        len = 1;

      memset(spacing, ' ', loc->first_column - 1);
      memset(spacing + loc->first_column - 1, '^', len);
      spacing[loc->first_column - 1 + len] = '\0';
      zlog_notice ("%s: | %s", __func__, spacing);
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
  const struct cmd_element *element = ctx->el;
  struct graph_node *end_token_node =
    new_token_node (ctx, END_TKN, CMD_CR_TEXT, "");
  struct graph_node *end_element_node =
    graph_new_node (ctx->graph, (void *)element, NULL);

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
