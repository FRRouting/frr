// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
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

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define ATTRIBUTE(x) __attribute__ (x)
#else
#define ATTRIBUTE(x) /**/
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


#define BABEL_DEFAULT_CONFIG "babeld.conf"

/* Values in milliseconds */
#define BABEL_DEFAULT_HELLO_INTERVAL 4000
#define BABEL_DEFAULT_UPDATE_INTERVAL 16000
#define BABEL_DEFAULT_RESEND_DELAY 2000
#define BABEL_DEFAULT_RTT_DECAY 42

/* Values in microseconds */
#define BABEL_DEFAULT_RTT_MIN 10000
#define BABEL_DEFAULT_RTT_MAX 120000

/* In units of seconds */
#define BABEL_DEFAULT_SMOOTHING_HALF_LIFE 4

/* In units of 1/256. */
#define BABEL_DEFAULT_DIVERSITY_FACTOR 256

#define BABEL_DEFAULT_RXCOST_WIRED 96
#define BABEL_DEFAULT_RXCOST_WIRELESS 256
#define BABEL_DEFAULT_MAX_RTT_PENALTY 150

/* Babel structure. */
struct babel
{
    /* Babel threads. */
    struct event *t_read;   /* on Babel protocol's socket */
    struct event *t_update; /* timers */
    /* distribute_ctx */
    struct distribute_ctx *distribute_ctx;
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
extern struct babel *babel_lookup(void);

#endif /* BABEL_BABELD_H */
