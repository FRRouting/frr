/*
 * Copyright (c) 2015-2017  David Lamparter, for NetDEF, Inc.
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef _FRR_COMPILER_H
#define _FRR_COMPILER_H

/* function attributes, use like
 *   void prototype(void) __attribute__((_CONSTRUCTOR(100)));
 */
#if defined(__clang__)
#if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 5)
#  define _RET_NONNULL    , returns_nonnull
#endif
# define _CONSTRUCTOR(x)  constructor(x)
#elif defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
#  define _RET_NONNULL    , returns_nonnull
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#  define _CONSTRUCTOR(x) constructor(x)
#  define _DESTRUCTOR(x)  destructor(x)
#  define _ALLOC_SIZE(x)  alloc_size(x)
#endif
#endif

#ifdef __sun
/* Solaris doesn't do constructor priorities due to linker restrictions */
#undef _CONSTRUCTOR
#undef _DESTRUCTOR
#endif

/* fallback versions */
#ifndef _RET_NONNULL
# define _RET_NONNULL
#endif
#ifndef _CONSTRUCTOR
# define _CONSTRUCTOR(x) constructor
#endif
#ifndef _DESTRUCTOR
# define _DESTRUCTOR(x) destructor
#endif
#ifndef _ALLOC_SIZE
# define _ALLOC_SIZE(x)
#endif

/*
 * for warnings on macros, put in the macro content like this:
 *   #define MACRO BLA CPP_WARN("MACRO has been deprecated")
 */
#define CPP_STR(X) #X

#if defined(__ICC)
#define CPP_NOTICE(text) _Pragma(CPP_STR(message __FILE__ ": " text))
#define CPP_WARN(text) CPP_NOTICE(text)

#elif (defined(__GNUC__)                                                       \
       && (__GNUC__ >= 5 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 8)))           \
	|| (defined(__clang__)                                                 \
	    && (__clang_major__ >= 4                                           \
		|| (__clang_major__ == 3 && __clang_minor__ >= 5)))
#define CPP_WARN(text) _Pragma(CPP_STR(GCC warning text))
#define CPP_NOTICE(text) _Pragma(CPP_STR(message text))

#else
#define CPP_WARN(text)
#endif

#endif /* _FRR_COMPILER_H */
