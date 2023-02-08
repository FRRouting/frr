// SPDX-License-Identifier: GPL-2.0-or-later
/* AS regular expression routine
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _FRR_BGP_REGEX_H
#define _FRR_BGP_REGEX_H

#include <zebra.h>

#ifdef HAVE_LIBPCRE2_POSIX
#ifndef _FRR_PCRE2_POSIX
#define _FRR_PCRE2_POSIX
#include <pcre2posix.h>
#endif /* _FRR_PCRE2_POSIX */
#elif defined(HAVE_LIBPCREPOSIX)
#include <pcreposix.h>
#else
#include <regex.h>
#endif /* HAVE_LIBPCRE2_POSIX */

extern void bgp_regex_free(regex_t *regex);
extern regex_t *bgp_regcomp(const char *str);
extern int bgp_regexec(regex_t *regex, struct aspath *aspath);

#endif /* _FRR_BGP_REGEX_H */
