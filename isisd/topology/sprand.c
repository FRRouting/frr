#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <values.h>

#include "random.c"

#define DASH '-'
#define VERY_FAR 100000000

/* generator of random networks for the shortest paths problem;
   extended DIMACS format for output */

main ( argc, argv )

int argc;
char* argv[];

{

char   args[30];

long   n,
       n0,
       source,
       i,
       i0,
       j,
       dij;

long   m,
       m0,
       mc,
       k;

long   *p,
       p_t,
       l,
       lx;

long   seed,
       seed1,
       seed2;

int    ext=0;

FILE   *fout;

/* variables for lengths generating */
/* initialized by default values */
int    l_f = 0, ll_f = 0, lm_f = 0, ln_f = 0, ls_f = 0;
long   ll = 10000,    /* length of the interval */
       lm = 0;        /* minimal bound of the interval */
double ln = 0,        /* l += ln * |i-j| */ 
       ls = 0;        /* l += ls * |i-j|^2 */

/* variables for connecting cycle(s) */
int    c_f = 0, cl_f = 0, ch_f = 0, c_random = 1;
long   cl = 1;        /* length of cycle arc */
long   ch;            /* number of arcs in the cycle 
                         n - by default */

/* variables for artifical source */
int    s_f = 0, sl_f = 0, sm_f = 0;
long   sl   = VERY_FAR, /* upper bound of artifical arc */
       sm,              /* lower bound of artifical arc */
       s;  

/* variables for potentials */
int    p_f = 0, pl_f = 0, pm_f = 0, pn_f = 0, ps_f = 0,
       pa_f = 0, pap_f = 0, pac_f = 0;
long   pl,            /* length of the interval */
       pm;            /* minimal bound of the interval */
double pn = 0,        /* l += ln * |i-j| */ 
       ps = 0,        /* l += ls * |i-j|^2 */
       pap = 0,       /* part of nodes with alternative dustribution */
       pac = -1;      /* multiplier for alternative distribution */

int np;               /* number of parameter parsing now */

#define PRINT_ARC( i, j, length )\
{\
l = length;\
if ( p_f ) l += ( p[i] - p[j] );\
printf ("a %8ld %8ld %12ld\n", i, j, l );\
}

  /* parsing  parameters */

if ( argc < 2 ) goto usage;

np = 0;

strcpy ( args, argv[1] );

  if ( ( args[0] == DASH ) && ( args[1] == 'h')
     )
      goto help;

if ( argc < 4 ) goto usage;

/* first parameter - number of nodes */
np = 1;
if ( ( n = atoi ( argv[1] ) )  <  2  )  goto usage;

/* second parameter - number of arcs */
np = 2;
if ( ( m = atoi ( argv[2] ) )  <  n  )  goto usage;

/* third parameter - seed */
np=3;
if ( ( seed = atoi ( argv[3] ) )  <=  0  )  goto usage;

/* other parameters */

for ( np = 4; np < argc; np ++ )
  {
    strcpy ( args, argv[np] );
    if ( args[0] != DASH ) goto usage;

    switch ( args[1] )
      {

      case 'l' : /* an interval for arc length */
	l_f = 1;
	switch ( args[2] )
	  { 
	  case 'l': /* length of the interval */
	    ll_f = 1;
	    ll  =  (long) atof ( &args[3] );
	    break;
	  case 'm': /* minimal bound */
	    lm_f = 1;
	    lm  = (long ) atof ( &args[3] );
	    break;
	  case 'n': /* additional length: l*|i-j| */
	    ln_f = 1;
	    ln  = atof ( &args[3] );
	    break;
	  case 's': /* additional length: l*|i-j|^2 */
	    ls_f = 1;
	    ls  = atof ( &args[3] );
	    break;
	  default:  /* unknown switch  value */
	    goto usage;
	  }
	break;

      case 'c' : /* connecting cycle(s) */
        c_f = 1;
	switch ( args[2] )
	  { 
	  case 'l':
            c_random = 0;
	    cl_f = 1;
	    cl  =  (long) atof ( &args[3] );
            if ( cl < 0 ) goto usage;
	    break;
	  case 'h':
	    ch_f = 1;
	    ch  =  (long) atof ( &args[3] );
            if ( ch < 2 || ch > n ) goto usage;
	    break;
	  default:  /* unknown switch  value */
	    goto usage;
          }
	break;

      case 's' : /* additional source */
        s_f = 1;
	if ( strlen ( args ) > 2 )
	{  
	switch ( args[2] )
	  { 
	  case 'l': /* upper bound of art. arc */
	    sl_f = 1;
	    sl  =  (long) atof ( &args[3] );
            break;
	  case 'm': /* lower bound of art. arc */
	    sm_f = 1;
	    sm  =  (long) atof ( &args[3] );
            break;
	  default:  /* unknown switch  value */
	    goto usage;
          }
         }
	break;

      case 'p' : /* potentials */
	p_f = 1;
	if ( strlen ( args ) > 2 )
	{  
	switch ( args[2] )
	  { 
	  case 'l': /* length of the interval */
	    pl_f = 1;
	    pl  =  (long) atof ( &args[3] );
	    break;
	  case 'm': /* minimal bound */
	    pm_f = 1;
	    pm  = (long ) atof ( &args[3] );
	    break;
	  case 'n': /* additional length: l*|i-j| */
	    pn_f = 1;
	    pn  = atof ( &args[3] );
	    break;
	  case 's': /* additional length: l*|i-j|^2 */
	    ps_f = 1;
	    ps  = atof ( &args[3] );
	    break;
	  case 'a': /* bipolar distribution */
	    pa_f = 1;
	    switch ( args[3] )
	      {
	      case 'p': /* % of alternative potentials */
                pap_f = 1;
                pap  = atof ( &args[4] );
		if ( pap < 0   ) pap = 0;
		if ( pap > 100 ) pap = 100;
                pap /= 100;
		break;
	      case 'c': /* multiplier */
		pac_f = 1;
		pac = atof ( &args[4] );
		break;
	      default: /* unknown switch value */
		goto usage;
	      }
	    break;
	  default:  /* unknown switch  value */
	    goto usage;
	  }
      }
	break;

      default  : /* unknoun case */
	goto usage;
      }
  }
   

/* ----- ajusting parameters ----- */

n0 = n; m0 = m;

/* length parameters */
if ( ll < lm ) { lx = ll; ll = lm; lm = lx; }

/* potential parameters */
if ( p_f )
  {
   if ( ! pl_f ) pl = ll;
   if ( ! pm_f ) pm = lm;
   if ( pl < pm ) { lx = pl; pl = pm; pm = lx; }
  }

/* path(s) parameters */
if ( ! ch_f ) ch = n;

mc = n + (n-2) / (ch-1);
if ( mc > m ) 
  { fprintf ( stderr,
              "Error: not enough arcs for generating connecting cycle(s)\n" );
    exit (4);
  }

 /* artifical source parameters */
if ( s_f )          
   { m0 += n; n0 ++ ; 
     if ( ! sm_f ) sm = sl;
     if ( sl < sm ) { lx = sl; sl = sm; sm = lx; }
   }

/* printing title */
printf ("c random network for shortest paths problem\n");
printf ("c extended DIMACS format\nc\n" );

/* name of the problem */
printf ("t rd_%ld_%ld_%ld_", n, m, seed );
if ( l_f )
  printf ("%c", 'l');
if ( c_f )
  printf ("%c", 'c');
if ( s_f )
  printf ("%c", 's');
if ( p_f )
  printf ("%c", 'p');
printf ("\nc\n");

/* printing additional information  */
if ( l_f )
  printf ("c length -> min: %ld max: %ld k1: %.2f k2: %.2f\n",
           lm, ll, ln, ls );
if ( c_f )
  {
    if ( c_random )
      printf ("c cycle -> number of arcs: %ld  arc length: random\n", ch);
    else
      printf ("c cycle -> number of arcs: %ld  arc length: %ld\n",
	       ch, cl );
  }
if ( s_f )
  printf ("c length of arcs from artifical source -> min: %ld max: %ld\n",
           sm, sl );
if ( p_f )
  {
  printf ("c potentials -> min: %ld max: %ld k1: %.2f k2: %.2f\n",
	  pm, pl, pn, ps );
  if ( pa_f )
  printf ("c potentials -> part of alternative distribution: %.2f k: %.2f\n",
          pap, pac );
  }
printf ("c\n" );


printf ("p sp %8ld %8ld\nc\n", n0, m0 );

source = ( s_f ) ? n0 : 1;
printf ("n %8ld\nc\n", source );

if ( p_f ) /* generating potentials */
  {
    p = (long*) calloc ( n+2, sizeof (long) );
    seed1 = 2*seed + 1;
    init_rand ( seed1);
    pl = pl - pm + 1;

    for ( i = 0; i <= n; i ++ )
      {
	p_t = pm + nrand ( pl );
	if ( pn_f ) p_t += (long) ( i * pn );
	if ( ps_f ) p_t += (long) ( i * ( i * ps ));
	if ( pap_f )
	    if ( rand01() < pap )
		p_t = (long) ( p_t * pac );
        p[i] = p_t;
      }
    p[n+1] = 0;
  }


if ( s_f ) /* additional arcs from artifical source */
  {
    seed2 = 3*seed + 1;
    init_rand ( seed2 );
    sl = sl - sm + 1;

    for ( i = n; i > 1; i -- )
      {
	s = sm + nrand ( sl );
	PRINT_ARC ( n0, i, s ) 
      }

    PRINT_ARC ( n0, 1, 0 )
  }

/* initialize random number generator */
init_rand ( seed );
ll = ll - lm + 1;

/* generating connecting cycle(s) */
if (c_random)
  cl = lm + nrand ( ll );
PRINT_ARC ( 1, 2, cl )
if (c_random)
  cl = lm + nrand ( ll );
PRINT_ARC ( n, 1, cl )

for ( i = 2; i < n; i ++ )
  {
    if (c_random)
      cl = lm + nrand ( ll );

    if ( ( (i-1) % (ch-1) ) != 0 )
        PRINT_ARC ( i, i+1, cl )
    else
      { PRINT_ARC ( i,   1, cl )
        if (c_random)
          cl = lm + nrand ( ll );
	PRINT_ARC ( 1, i+1, cl )
      }
  }

/* generating random arcs */

for ( k = 1; k <= m - mc; k ++ )
  {
    i = 1 + nrand ( n );

    do
    j = 1 + nrand ( n );
    while ( j == i );

    dij = ( i > j ) ? ( i - j ) : ( j - i );
    l = lm + nrand ( ll );
    if ( ln_f ) l += (long) ( dij * ln );
    if ( ls_f ) l += (long) ( dij * ( dij * ls ) );
    PRINT_ARC ( i, j, l );
  }

/* all is done */
exit (ext);

/* ----- wrong usage ----- */

 usage:
fprintf ( stderr,
"\nusage: %s  n  m  seed  [ -ll#i -lm#i -cl#i -p -pl#i -pm#i ... ]\n\
help:  %s -h\n\n", argv[0], argv[0] );

if ( np > 0 )
  fprintf ( stderr, "error in parameter # %d\n\n", np );   
exit (4);

/* ---- help ---- */

 help:

if ( args[2] == 'h') goto hhelp;

fprintf ( stderr, 
"\n'%s' - random network generator for shortest paths problem.\n\
Generates problems in extended DIMACS format.\n\
\n\
   %s  n m seed [ -ll#i -lm#i -cl#i -p -pl#i -pm#i ... ]\n\
   %s -hh\n\
\n\
                        #i - integer number   #f - real number\n\
\n\
-ll#i  - #i is the upper bound on arc lengths          (default 10000)\n\
-lm#i  - #i is the lower bound on arc lengths          (default 0)\n\
-cl#i  - #i is length of arcs in connecting cycle(s)   (default random)\n\
-p     - generate potentials \n\
-pl#i  - #i is the upper bound on potentials           (default ll)\n\
-pm#i  - #i is the lower bound on potentials           (default lm)\n\
\n\
-hh    - extended help \n\n",
argv[0], argv[0], argv[0] );

exit (0);

/* --------- sophisticated help ------------ */
 hhelp:

if ( argc < 3 )
     fout = stderr;
else
     fout = fopen ( argv[2], "w" );

if ( fout == NULL )
{ fprintf ( stderr, "\nCan't open file  '%s' for writing help\n\n", argv[2] );
  exit ( 2 );
}

fprintf (fout, 
"\n'%s' - random network generator for shortest paths problem.\n\
Generates problems in extended DIMACS format.\n\
\n\
   %s  n m seed [ -ll#i -lm#i -ln#f -ls#f\n\
                      -p  -pl#i -pm#i -pn#f -ps#f -pap#i -pac#f\n\
                      -cl#i -ch#i\n\
                      -s -sl#i -sm#i\n\
                    ]\n\
   %s -hh file_name\n\
\n\
                        #i - integer number   #f - real number\n\
\n\
      Arc length parameters:\n\
-ll#i  - #i is the upper bound on arc lengths          (default 10000)\n\
-lm#i  - #i is the lower bound on arc lengths          (default 0)\n\
-ln#f  - multipliy l(i, j) by #f * |i-j|               (default 0)\n\
-ls#f  - multipliy l(i, j) by #f * |i-j|^2             (default 0)\n\
\n\
      Potential parameters:\n\
-p     - generate potentials \n\
-pl#i  - #i is the upper bound on potentials           (default ll)\n\
-pm#i  - #i is the lower bound on potentials           (default lm)\n\
-pn#f  - multiply p(i) by #f * i                       (default 0)\n\
-ps#f  - multiply p(i) by #f * i^2                     (default 0)\n\
-pap#i - percentage of alternative potential nodes     (default 0)\n\
-pac#f - if i is alternative, multiply  p(i) by #f     (default -1)\n\
\n\
      Connecting cycle(s) parameters:\n\
-cl#i  - #i is length of arcs in connecting cycle(s)   (default random)\n\
-ch#i  - #i is length of connecting cycles             (default n)\n\
\n\
      Artificial source parameters:\n\
-s     - generate artificial source with default connecting arc lengths\n\
-sl#i  - #i is the upper bound on art. arc lengths    (default 100000000)\n\
-sm#i  - #i is the lower bound on art. arc lengths    (default sl)\n\
\n\
-hh file_name  - save this help in the file 'file_name'\n\n",
argv[0], argv[0], argv[0] );

exit (0);
}



