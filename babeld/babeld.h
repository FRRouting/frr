/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#ifndef BABEL_BABELD_H
#define BABEL_BABELD_H

#include <zebra.h>
#include "vty.h"

#define INFINITY ((unsigned short)(~0))

#ifndef RTPROT_BABEL
#define RTPROT_BABEL 42
#endif

#define RTPROT_BABEL_LOCAL -2

#undef MAX
#undef MIN

#define MAX(x,y) ((x)<=(y)?(y):(x))
#define MIN(x,y) ((x)<=(y)?(x):(y))

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
/* nothing */
#elif defined(__GNUC__)
#define inline __inline
#if  (__GNUC__ >= 3)
#define restrict __restrict
#else
#define restrict /**/
#endif
#else
#define inline /**/
#define restrict /**/
#endif

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define ATTRIBUTE(x) __attribute__ (x)
#define LIKELY(_x) __builtin_expect(!!(_x), 1)
#define UNLIKELY(_x) __builtin_expect(!!(_x), 0)
#else
#define ATTRIBUTE(x) /**/
#define LIKELY(_x) !!(_x)
#define UNLIKELY(_x) !!(_x)
#endif

#if defined(__GNUC__) && (__GNUC__ >= 4) && (__GNUC_MINOR__ >= 3)
#define COLD __attribute__ ((cold))
#else
#define COLD /**/
#endif

#ifndef IF_NAMESIZE
#include <sys/socket.h>
#include <net/if.h>
#endif

#ifdef HAVE_VALGRIND
#include <valgrind/memcheck.h>
#else
#ifndef VALGRIND_MAKE_MEM_UNDEFINED
#define VALGRIND_MAKE_MEM_UNDEFINED(a, b) do {} while(0)
#endif
#ifndef VALGRIND_CHECK_MEM_IS_DEFINED
#define VALGRIND_CHECK_MEM_IS_DEFINED(a, b) do {} while(0)
#endif
#endif


#define BABEL_VTY_PORT 2609
#define BABEL_DEFAULT_CONFIG "babeld.conf"

/* Values in milliseconds */
#define BABEL_DEFAULT_HELLO_INTERVAL 4000
#define BABEL_DEFAULT_UPDATE_INTERVAL 16000
#define BABEL_DEFAULT_RESEND_DELAY 2000

/* In units of seconds */
#define BABEL_DEFAULT_SMOOTHING_HALF_LIFE 4

/* In units of 1/256. */
#define BABEL_DEFAULT_DIVERSITY_FACTOR 256

#define BABEL_DEFAULT_RXCOST_WIRED 96
#define BABEL_DEFAULT_RXCOST_WIRELESS 256

/* Babel structure. */
struct babel
{
    /* Babel threads. */
    struct thread *t_read;    /* on Babel protocol's socket */
    struct thread *t_update;  /* timers */
};

extern struct zebra_privs_t babeld_privs;

extern void babeld_quagga_init(void);
extern int input_filter(const unsigned char *id,
                        const unsigned char *prefix, unsigned short plen,
                        const unsigned char *neigh, unsigned int ifindex);
extern int output_filter(const unsigned char *id, const unsigned char *prefix,
                         unsigned short plen, unsigned int ifindex);
extern int redistribute_filter(const unsigned char *prefix, unsigned short plen,
                               unsigned int ifindex, int proto);
extern int resize_receive_buffer(int size);
extern void schedule_neighbours_check(int msecs, int override);


#endif /* BABEL_BABELD_H */
