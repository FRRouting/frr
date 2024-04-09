// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2015-2017  David Lamparter, for NetDEF, Inc.
 */

#ifndef _FRR_COMPILER_H
#define _FRR_COMPILER_H

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
# if __cplusplus < 201103L
#  error FRRouting headers must be compiled in C++11 mode or newer
# endif
/* C++ defines static_assert(), but not _Static_assert().  C defines
 * _Static_assert() and has static_assert() in <assert.h>.  However, we mess
 * with assert() in zassert.h so let's not include <assert.h> here.
 */
# define _Static_assert static_assert
#else
# if !defined(__STDC_VERSION__) || __STDC_VERSION__ < 201112L
#  error FRRouting must be compiled with min. -std=gnu11 (GNU ISO C11 dialect)
# endif
#endif

/* function attributes, use like
 *   void prototype(void) __attribute__((_CONSTRUCTOR(100)));
 */
#if defined(__clang__)
#if __clang_major__ > 3 || (__clang_major__ == 3 && __clang_minor__ >= 5)
#  define _RET_NONNULL    , returns_nonnull
#endif
#if __has_attribute(fallthrough) && !defined(__cplusplus)
#  define fallthrough __attribute__((fallthrough));
#endif
# define _CONSTRUCTOR(x)  constructor(x)
# define _DEPRECATED(x) deprecated(x)
# if __has_builtin(assume)
#  define assume(x) __builtin_assume(x)
# endif
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
#  define assume(x) do { if (!(x)) __builtin_unreachable(); } while (0)
#endif
#if __GNUC__ < 5
#  define __has_attribute(x) 0
#endif
#if __GNUC__ >= 7 && !defined(__cplusplus)
#  define fallthrough __attribute__((fallthrough));
#endif
#endif

#ifdef __INTELLISENSE__
/*
 * Fix Visual Studio Code error: attribute "constructor" does not take
 * arguments.
 *
 * Caused by the macro `DEFINE_MTYPE_ATTR` in `lib/memory.h`.
 */
#pragma diag_suppress 1094
#endif /* __INTELISENSE__ */

#if __has_attribute(hot)
#  define _OPTIMIZE_HOT __attribute__((hot))
#else
#  define _OPTIMIZE_HOT
#endif
#if __has_attribute(optimize)
#  define _OPTIMIZE_O3 __attribute__((optimize("3")))
#else
#  define _OPTIMIZE_O3
#endif
#define OPTIMIZE _OPTIMIZE_O3 _OPTIMIZE_HOT

#if !defined(__GNUC__)
#error module code needs GCC visibility extensions
#elif __GNUC__ < 4
#error module code needs GCC visibility extensions
#else
# define DSO_PUBLIC __attribute__ ((visibility ("default")))
# define DSO_SELF   __attribute__ ((visibility ("protected")))
# define DSO_LOCAL  __attribute__ ((visibility ("hidden")))
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
#if !defined(fallthrough) && !defined(__cplusplus)
#define fallthrough
#endif
#ifndef _DEPRECATED
#define _DEPRECATED(x) deprecated
#endif
#ifndef assume
#define assume(x)
#endif

#ifdef __COVERITY__
/* __coverity_panic__() is named a bit poorly, it's essentially the same as
 * __builtin_unreachable().  Used to eliminate false positives.
 */
#undef assume
#define assume(x) do { if (!(x)) __coverity_panic__(); } while (0)
#endif

/* for helper functions defined inside macros */
#define macro_inline	static inline __attribute__((unused))
#define macro_pure	static inline __attribute__((unused, pure))

/* if the macro ends with a function definition */
#define MACRO_REQUIRE_SEMICOLON() \
	_Static_assert(1, "please add a semicolon after this macro")

/* variadic macros, use like:
 * #define V_0()  ...
 * #define V_1(x) ...
 * #define V(...) MACRO_VARIANT(V, ##__VA_ARGS__)(__VA_ARGS__)
 */
#define _MACRO_VARIANT(A0,A1,A2,A3,A4,A5,A6,A7,A8,A9,A10, N, ...) N

#define _CONCAT2(a, b) a ## b
#define _CONCAT(a, b) _CONCAT2(a,b)

#define MACRO_VARIANT(NAME, ...) \
	_CONCAT(NAME, _MACRO_VARIANT(0, ##__VA_ARGS__, \
			_10, _9, _8, _7, _6, _5, _4, _3, _2, _1, _0))

#define NAMECTR(name) _CONCAT(name, __COUNTER__)

/* per-arg repeat macros, use like:
 * #define PERARG(n) ...n...
 * #define FOO(...) MACRO_REPEAT(PERARG, ##__VA_ARGS__)
 */

#define _MACRO_REPEAT_0(NAME)
#define _MACRO_REPEAT_1(NAME, A1) \
	NAME(A1)
#define _MACRO_REPEAT_2(NAME, A1, A2) \
	NAME(A1) NAME(A2)
#define _MACRO_REPEAT_3(NAME, A1, A2, A3) \
	NAME(A1) NAME(A2) NAME(A3)
#define _MACRO_REPEAT_4(NAME, A1, A2, A3, A4) \
	NAME(A1) NAME(A2) NAME(A3) NAME(A4)
#define _MACRO_REPEAT_5(NAME, A1, A2, A3, A4, A5) \
	NAME(A1) NAME(A2) NAME(A3) NAME(A4) NAME(A5)
#define _MACRO_REPEAT_6(NAME, A1, A2, A3, A4, A5, A6) \
	NAME(A1) NAME(A2) NAME(A3) NAME(A4) NAME(A5) NAME(A6)
#define _MACRO_REPEAT_7(NAME, A1, A2, A3, A4, A5, A6, A7) \
	NAME(A1) NAME(A2) NAME(A3) NAME(A4) NAME(A5) NAME(A6) NAME(A7)
#define _MACRO_REPEAT_8(NAME, A1, A2, A3, A4, A5, A6, A7, A8) \
	NAME(A1) NAME(A2) NAME(A3) NAME(A4) NAME(A5) NAME(A6) NAME(A7) NAME(A8)

#define MACRO_REPEAT(NAME, ...) \
	MACRO_VARIANT(_MACRO_REPEAT, ##__VA_ARGS__)(NAME, ##__VA_ARGS__)

/* per-arglist repeat macro, use like this:
 * #define foo(...) MAP_LISTS(F, ##__VA_ARGS__)
 * where F is a n-ary function where n is the number of args in each arglist.
 * e.g.: MAP_LISTS(f, (a, b), (c, d))
 * expands to: f(a, b); f(c, d)
 */

#define ESC(...) __VA_ARGS__
#define MAP_LISTS(M, ...)                                                      \
	_CONCAT(_MAP_LISTS_, PP_NARG(__VA_ARGS__))(M, ##__VA_ARGS__)
#define _MAP_LISTS_0(M)
#define _MAP_LISTS_1(M, _1) ESC(M _1)
#define _MAP_LISTS_2(M, _1, _2) ESC(M _1; M _2)
#define _MAP_LISTS_3(M, _1, _2, _3) ESC(M _1; M _2; M _3)
#define _MAP_LISTS_4(M, _1, _2, _3, _4) ESC(M _1; M _2; M _3; M _4)
#define _MAP_LISTS_5(M, _1, _2, _3, _4, _5) ESC(M _1; M _2; M _3; M _4; M _5)
#define _MAP_LISTS_6(M, _1, _2, _3, _4, _5, _6)                                \
	ESC(M _1; M _2; M _3; M _4; M _5; M _6)
#define _MAP_LISTS_7(M, _1, _2, _3, _4, _5, _6, _7)                            \
	ESC(M _1; M _2; M _3; M _4; M _5; M _6; M _7)
#define _MAP_LISTS_8(M, _1, _2, _3, _4, _5, _6, _7, _8)                        \
	ESC(M _1; M _2; M _3; M _4; M _5; M _6; M _7; M _8)

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

#define numcmp(a, b)                                                           \
	({                                                                     \
		typeof(a) _cmp_a = (a);                                        \
		typeof(b) _cmp_b = (b);                                        \
		(_cmp_a < _cmp_b) ? -1 : ((_cmp_a > _cmp_b) ? 1 : 0);          \
	})

#ifndef offsetof
#ifdef __compiler_offsetof
#define offsetof(TYPE, MEMBER) __compiler_offsetof(TYPE,MEMBER)
#else
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif
#endif

#ifdef container_of
#undef container_of
#endif

#if !(defined(__cplusplus) || defined(test__cplusplus))
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
#else
/* current C++ compilers don't have the builtins used above; so this version
 * of the macro doesn't do the const check. */
#define container_of(ptr, type, member)                                        \
		({                                                             \
			const typeof(((type *)0)->member) *__mptr = (ptr);     \
			(type *)((char *)__mptr - offsetof(type, member));     \
		})
#endif

#define container_of_null(ptr, type, member)                                   \
	({                                                                     \
		typeof(ptr) _tmp = (ptr);                                      \
		_tmp ? container_of(_tmp, type, member) : NULL;                \
	})

#define array_size(ar) (sizeof(ar) / sizeof(ar[0]))

/* Some insane macros to count number of varargs to a functionlike macro */
#define PP_ARG_N( \
          _1,  _2,  _3,  _4,  _5,  _6,  _7,  _8,  _9, _10, \
         _11, _12, _13, _14, _15, _16, _17, _18, _19, _20, \
         _21, _22, _23, _24, _25, _26, _27, _28, _29, _30, \
         _31, _32, _33, _34, _35, _36, _37, _38, _39, _40, \
         _41, _42, _43, _44, _45, _46, _47, _48, _49, _50, \
         _51, _52, _53, _54, _55, _56, _57, _58, _59, _60, \
         _61, _62, _63, N, ...) N

#define PP_RSEQ_N()                                        \
         62, 61, 60,                                       \
         59, 58, 57, 56, 55, 54, 53, 52, 51, 50,           \
         49, 48, 47, 46, 45, 44, 43, 42, 41, 40,           \
         39, 38, 37, 36, 35, 34, 33, 32, 31, 30,           \
         29, 28, 27, 26, 25, 24, 23, 22, 21, 20,           \
         19, 18, 17, 16, 15, 14, 13, 12, 11, 10,           \
          9,  8,  7,  6,  5,  4,  3,  2,  1,  0

#define PP_NARG_(...) PP_ARG_N(__VA_ARGS__)
#define PP_NARG(...)     PP_NARG_(_, ##__VA_ARGS__, PP_RSEQ_N())


/* sigh. this is so ugly, it overflows and wraps to being nice again.
 *
 * printfrr() supports "%Ld" for <int64_t>, whatever that is typedef'd to.
 * However, gcc & clang think that "%Ld" is <long long>, which doesn't quite
 * match up since int64_t is <long> on a lot of 64-bit systems.
 *
 * If we have _FRR_ATTRIBUTE_PRINTFRR, we loaded a compiler plugin that
 * replaces the whole format checking bits with a custom version that
 * understands "%Ld" (along with "%pI4" and co.), so we don't need to do
 * anything.
 *
 * If we don't have that attribute...  we still want -Wformat to work.  So,
 * this is the "f*ck it" approach and we just redefine int64_t to always be
 * <long long>.  This should work until such a time that <long long> is
 * something else (e.g. 128-bit integer)...  let's just guard against that
 * with the _Static_assert below and work with the world we have right now,
 * where <long long> is always 64-bit.
 */

/* these need to be included before any of the following, so we can
 * "overwrite" things.
 */
#include <stdint.h>
#include <inttypes.h>

#ifdef _FRR_ATTRIBUTE_PRINTFRR
#define PRINTFRR(a, b) __attribute__((frr_format("frr_printf", a, b)))

#undef PRIu64
#undef PRId64
#undef PRIx64
#define PRIu64 "Lu"
#define PRId64 "Ld"
#define PRIx64 "Lx"

#else /* !_FRR_ATTRIBUTE_PRINTFRR */
#ifdef __NetBSD__
#define PRINTFRR(a, b) __attribute__((format(gnu_syslog, a, b)))
#else
#define PRINTFRR(a, b) __attribute__((format(printf, a, b)))
#endif

/* frr-format plugin is C-only for now, so no point in doing these shenanigans
 * for C++...  (also they can break some C++ stuff...)
 */
#ifndef __cplusplus
/* these should be typedefs, but might also be #define */
#ifdef uint64_t
#undef uint64_t
#endif
#ifdef int64_t
#undef int64_t
#endif

/* can't overwrite the typedef, but we can replace int64_t with _int64_t */
typedef unsigned long long _uint64_t;
#define uint64_t _uint64_t
typedef signed long long _int64_t;
#define int64_t _int64_t

/* if this breaks, 128-bit machines may have entered reality (or <long long>
 * is something weird)
 */
_Static_assert(sizeof(_uint64_t) == 8 && sizeof(_int64_t) == 8,
	       "nobody expects the spanish intquisition");

/* since we redefined int64_t, we also need to redefine PRI*64 */
#undef PRIu64
#undef PRId64
#undef PRIx64
#define PRIu64 "llu"
#define PRId64 "lld"
#define PRIx64 "llx"

#endif /* !__cplusplus */
#endif /* !_FRR_ATTRIBUTE_PRINTFRR */

/* helper to get type safety/avoid casts on calls
 * (w/o this, functions accepting all prefix types need casts on the caller
 * side, which strips type safety since the cast will accept any pointer
 * type.)
 */
#ifndef __cplusplus
#define uniontype(uname, typename, fieldname) typename *fieldname;
#define TRANSPARENT_UNION __attribute__((transparent_union))
#else
#define uniontype(uname, typename, fieldname)                                  \
	typename *fieldname;                                                   \
	uname(typename *x)                                                     \
	{                                                                      \
		this->fieldname = x;                                           \
	}
#define TRANSPARENT_UNION
#endif

#ifdef __INTELLISENSE__
/*
 * Fix Visual Studio Code error: argument of type "struct prefix *" is
 * incompatible with parameter of type "union prefixptr".
 *
 * This is caused by all functions having the transparent unions in the
 * prototype. Example: `prefixptr` and `prefixconstptr` from `lib/prefix.h`.
 */
#pragma diag_suppress 167
#endif /* __INTELISENSE__ */

#if defined(__GNUC__) && (__GNUC__ >= 3)
#define likely(_x) __builtin_expect(!!(_x), 1)
#define unlikely(_x) __builtin_expect(!!(_x), 0)
#else
#define likely(_x) !!(_x)
#define unlikely(_x) !!(_x)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _FRR_COMPILER_H */
