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

#ifdef __cplusplus
extern "C" {
#endif

/* function attributes, use like
 *   void prototype(void) __attribute__((_CONSTRUCTOR(100)));
 */
#if defined(__clang__)
#if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 5)
#  define _RET_NONNULL    , returns_nonnull
#endif
#if __has_attribute(fallthrough)
#  define _FALLTHROUGH __attribute__((fallthrough));
#endif
# define _CONSTRUCTOR(x)  constructor(x)
# define _DEPRECATED(x) deprecated(x)
#elif defined(__GNUC__)
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 9)
#  define _RET_NONNULL    , returns_nonnull
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 3)
#  define _CONSTRUCTOR(x) constructor(x)
#  define _DESTRUCTOR(x)  destructor(x)
#  define _ALLOC_SIZE(x)  alloc_size(x)
#endif
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ >= 5)
#  define _DEPRECATED(x) deprecated(x)
#endif
#if __GNUC__ >= 7
#  define _FALLTHROUGH __attribute__((fallthrough));
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
#ifndef _FALLTHROUGH
#define _FALLTHROUGH
#endif
#ifndef _DEPRECATED
#define _DEPRECATED(x) deprecated
#endif

/* for helper functions defined inside macros */
#define macro_inline	static inline __attribute__((unused))
#define macro_pure	static inline __attribute__((unused, pure))

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
#define CPP_NOTICE(text)
#endif

/* MAX / MIN are not commonly defined, but useful */
/* note: glibc sys/param.h has #define MIN(a,b) (((a)<(b))?(a):(b)) */
#ifdef MAX
#undef MAX
#endif
#define MAX(a, b)                                                              \
	({                                                                     \
		typeof(a) _max_a = (a);                                        \
		typeof(b) _max_b = (b);                                        \
		_max_a > _max_b ? _max_a : _max_b;                             \
	})
#ifdef MIN
#undef MIN
#endif
#define MIN(a, b)                                                              \
	({                                                                     \
		typeof(a) _min_a = (a);                                        \
		typeof(b) _min_b = (b);                                        \
		_min_a < _min_b ? _min_a : _min_b;                             \
	})

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

/* this variant of container_of() retains 'const' on pointers without needing
 * to be told to do so.  The following will all work without warning:
 *
 * struct member *p;
 * const struct member *cp;
 *
 * const struct cont *x = container_of(cp, struct cont, member);
 * const struct cont *x = container_of(cp, const struct cont, member);
 * const struct cont *x = container_of(p,  struct cont, member);
 * const struct cont *x = container_of(p,  const struct cont, member);
 * struct cont *x       = container_of(p,  struct cont, member);
 *
 * but the following will generate warnings about stripping const:
 *
 * struct cont *x       = container_of(cp, struct cont, member);
 * struct cont *x       = container_of(cp, const struct cont, member);
 * struct cont *x       = container_of(p,  const struct cont, member);
 */
#ifdef container_of
#undef container_of
#endif
#define container_of(ptr, type, member)                                        \
	(__builtin_choose_expr(                                                \
		__builtin_types_compatible_p(typeof(&((type *)0)->member),     \
			typeof(ptr))                                           \
		    ||  __builtin_types_compatible_p(void *, typeof(ptr)),     \
		({                                                             \
			typeof(((type *)0)->member) *__mptr = (void *)(ptr);   \
			(type *)((char *)__mptr - offsetof(type, member));     \
		}),                                                            \
		({                                                             \
			typeof(((const type *)0)->member) *__mptr = (ptr);     \
			(const type *)((const char *)__mptr -                  \
					offsetof(type, member));               \
		})                                                             \
	))

#define container_of_null(ptr, type, member)                                   \
	({                                                                     \
		typeof(ptr) _tmp = (ptr);                                      \
		_tmp ? container_of(_tmp, type, member) : NULL;                \
	})

#define array_size(ar) (sizeof(ar) / sizeof(ar[0]))

#ifdef __cplusplus
}
#endif

#endif /* _FRR_COMPILER_H */
