// SPDX-License-Identifier: MIT
/*
Copyright (c) 2007, 2008 by Juliusz Chroboczek
Copyright 2011 by Matthieu Boutier and Juliusz Chroboczek
*/

#ifndef BABEL_UTIL_H
#define BABEL_UTIL_H

#include "babeld.h"
#include "babel_main.h"
#include "log.h"
#include "memory.h"

DECLARE_MGROUP(BABELD);

#if defined(i386) || defined(__mc68020__) || defined(__x86_64__)
#define DO_NTOHS(_d, _s) do{ _d = ntohs(*(const unsigned short*)(_s)); }while(0)
#define DO_NTOHL(_d, _s) do{ _d = ntohl(*(const unsigned*)(_s)); } while(0)
#define DO_HTONS(_d, _s) do{ *(unsigned short*)(_d) = htons(_s); } while(0)
#define DO_HTONL(_d, _s) do{ *(unsigned*)(_d) = htonl(_s); } while(0)
/* Some versions of gcc seem to be buggy, and ignore the packed attribute.
   Disable this code until the issue is clarified. */
/* #elif defined __GNUC__*/
#else
#define DO_NTOHS(_d, _s) \
    do { short _dd; \
         memcpy(&(_dd), (_s), 2); \
         _d = ntohs(_dd); } while(0)
#define DO_NTOHL(_d, _s) \
    do { int _dd; \
         memcpy(&(_dd), (_s), 4); \
         _d = ntohl(_dd); } while(0)
#define DO_HTONS(_d, _s) \
    do { unsigned short _dd; \
         _dd = htons(_s); \
         memcpy((_d), &(_dd), 2); } while(0)
#define DO_HTONL(_d, _s) \
    do { unsigned _dd; \
         _dd = htonl(_s); \
         memcpy((_d), &(_dd), 4); } while(0)
#endif

static inline int
seqno_compare(unsigned short s1, unsigned short s2)
{
    if(s1 == s2)
        return 0;
    else
        return (CHECK_FLAG((s2 - s1), 0x8000)) ? 1 : -1;
}

static inline short
seqno_minus(unsigned short s1, unsigned short s2)
{
    return (short)(CHECK_FLAG((s1 - s2), 0xFFFF));
}

static inline unsigned short
seqno_plus(unsigned short s, int plus)
{
    return CHECK_FLAG((s + plus), 0xFFFF);
}

/* Returns a time in microseconds on 32 bits (thus modulo 2^32,
   i.e. about 4295 seconds). */
static inline unsigned int
time_us(const struct timeval t)
{
    return (unsigned int) (t.tv_sec * 1000000 + t.tv_usec);
}

int roughly(int value);
void timeval_minus(struct timeval *d,
                   const struct timeval *s1, const struct timeval *s2);
unsigned timeval_minus_msec(const struct timeval *s1, const struct timeval *s2)
    ATTRIBUTE ((pure));
void timeval_add_msec(struct timeval *d, const struct timeval *s, int msecs);
void set_timeout (struct timeval *timeout, int msecs);
int timeval_compare(const struct timeval *s1, const struct timeval *s2)
    ATTRIBUTE ((pure));
void timeval_min(struct timeval *d, const struct timeval *s);
void timeval_min_sec(struct timeval *d, time_t secs);
int parse_nat(const char *string) ATTRIBUTE ((pure));
int parse_msec(const char *string) ATTRIBUTE ((pure));
unsigned char *mask_prefix(unsigned char *restrict ret,
                           const unsigned char *restrict prefix,
                           unsigned char plen);
const char *format_address(const unsigned char *address);
const char *format_prefix(const unsigned char *address, unsigned char prefix);
const char *format_eui64(const unsigned char *eui);
const char *format_thousands(unsigned int value);
int parse_address(const char *address, unsigned char *addr_r, int *af_r);
int parse_eui64(const char *eui, unsigned char *eui_r);
int wait_for_fd(int direction, int fd, int msecs);
int martian_prefix(const unsigned char *prefix, int plen) ATTRIBUTE ((pure));
int linklocal(const unsigned char *address) ATTRIBUTE ((pure));
int v4mapped(const unsigned char *address) ATTRIBUTE ((pure));
void v4tov6(unsigned char *dst, const unsigned char *src);
void inaddr_to_uchar(unsigned char *dest, const struct in_addr *src);
void uchar_to_inaddr(struct in_addr *dest, const unsigned char *src);
void in6addr_to_uchar(unsigned char *dest, const struct in6_addr *src);
void uchar_to_in6addr(struct in6_addr *dest, const unsigned char *src);
int daemonise(void);
extern const unsigned char v4prefix[16];

static inline bool
is_default(const unsigned char *prefix, int plen)
{
    return plen == 0 || (plen == 96 && v4mapped(prefix));
}

/* If debugging is disabled, we want to avoid calling format_address
   for every omitted debugging message.  So debug is a macro.  But
   vararg macros are not portable. */
#if defined NO_DEBUG

#define debugf(...) do {} while(0)

#else /* NO_DEBUG */

/* some levels */
#define BABEL_DEBUG_COMMON      (1 << 0)
#define BABEL_DEBUG_KERNEL      (1 << 1)
#define BABEL_DEBUG_FILTER      (1 << 2)
#define BABEL_DEBUG_TIMEOUT     (1 << 3)
#define BABEL_DEBUG_IF          (1 << 4)
#define BABEL_DEBUG_ROUTE       (1 << 5)
#define BABEL_DEBUG_ALL         (0xFFFF)

#define debugf(level, ...)                                                     \
	do {                                                                   \
		if (unlikely(CHECK_FLAG(debug, level)))                            \
			zlog_debug(__VA_ARGS__);                               \
	} while (0)

#endif /* NO_DEBUG */

#endif /* BABEL_UTIL_H */
