// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2025  David Lamparter, for NetDEF, Inc.
 *
 * The point of this is to "hide" from ABI/API which specific regex library is
 * used.  Otherwise some structs end up with config-dependent layouts, which
 * is a pain.
 */

#ifndef _FRR_FRREGEX_REAL_H
#define _FRR_FRREGEX_REAL_H

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

struct frregex {
	regex_t real;
};

#endif /* _FRR_FRREGEX_REAL_H */
