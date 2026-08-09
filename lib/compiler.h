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

/* the purpose of these macros is to deal with C's macro expansion rules;
 * specifically token pasting and nesting.
 */
#define _MACRO_EXPAND(a) a
#define _CONCAT2(a, b)	 a##b
#define _CONCAT(a, b)	 _CONCAT2(a, b)

#define MACRO_APPLY(NAME, ARGS) NAME ARGS

#define NAMECTR(name) _CONCAT(name, __COUNTER__)

/* clang-format off */

/* variadic macros, use like:
 * #define V_0()  ...
 * #define V_1(x) ...
 * #define V(...) MACRO_VARIANT(V, ##__VA_ARGS__)(__VA_ARGS__)
 */
#define _MACRO_VARIANT(A0, \
		       A01, A02, A03, A04, A05, A06, A07, A08, A09, A10, \
		       A11, A12, A13, A14, A15, A16, A17, A18, A19, A20, \
		       A21, A22, A23, A24, A25, A26, A27, A28, A29, A30, \
		       A31, A32, A33, A34, A35, A36, A37, A38, A39, A40, \
		       N, ...) N

/* _XX for 11..20, _YY for 21..30, _ZZ for 31..40 - hopefully that's enough.
 * _XX, _YY and _ZZ are expected to "recurse back"
 */
#define MACRO_VARIANT(NAME, ...) \
	_CONCAT(NAME, _MACRO_VARIANT(0, ##__VA_ARGS__, \
			_ZZ, _ZZ, _ZZ, _ZZ, _ZZ, _ZZ, _ZZ, _ZZ, _ZZ, _ZZ, \
			_YY, _YY, _YY, _YY, _YY, _YY, _YY, _YY, _YY, _YY, \
			_XX, _XX, _XX, _XX, _XX, _XX, _XX, _XX, _XX, _XX, \
			_10,  _9,  _8,  _7,  _6,  _5,  _4,  _3,  _2,  _1, \
			_0))

/* per-arg repeat macros, use like:
 * #define PERARG(n) ...n...
 * #define FOO(...) MACRO_REPEAT(PERARG, ##__VA_ARGS__)
 */

#define _EMPTY()
#define _SEMICOLON() ;
#define _COMMA()     ,

/* multiple copies to get around the macro being disabled while being itself
 * expanded, for _MACRO_REPEAT_{XX,YY,ZZ} below
 */
#define _MACRO_REPEAT0(SEP, MARGS, NAME, ...)                                                     \
	MACRO_VARIANT(_MACRO_REPEAT, ##__VA_ARGS__)(SEP, MARGS, NAME, ##__VA_ARGS__)
#define _MACRO_REPEAT1(SEP, MARGS, NAME, ...)                                                     \
	MACRO_VARIANT(_MACRO_REPEAT, ##__VA_ARGS__)(SEP, MARGS, NAME, ##__VA_ARGS__)
#define _MACRO_REPEAT2(SEP, MARGS, NAME, ...)                                                     \
	MACRO_VARIANT(_MACRO_REPEAT, ##__VA_ARGS__)(SEP, MARGS, NAME, ##__VA_ARGS__)
#define _MACRO_REPEAT3(SEP, MARGS, NAME, ...)                                                     \
	MACRO_VARIANT(_MACRO_REPEAT, ##__VA_ARGS__)(SEP, MARGS, NAME, ##__VA_ARGS__)

#define _MACRO_REPEAT_0(SEP, MARGS, NAME)
#define _MACRO_REPEAT_1(SEP, MARGS, NAME, A1) \
	NAME(MARGS, A1)
#define _MACRO_REPEAT_2(SEP, MARGS, NAME, A1, A2) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2)
#define _MACRO_REPEAT_3(SEP, MARGS, NAME, A1, A2, A3) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3)
#define _MACRO_REPEAT_4(SEP, MARGS, NAME, A1, A2, A3, A4)                                         \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4)
#define _MACRO_REPEAT_5(SEP, MARGS, NAME, A1, A2, A3, A4, A5) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4) SEP() NAME(MARGS, A5)
#define _MACRO_REPEAT_6(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4) SEP() NAME(MARGS, A5) SEP() NAME(MARGS, A6)
#define _MACRO_REPEAT_7(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4) SEP() NAME(MARGS, A5) SEP() NAME(MARGS, A6) SEP() NAME(MARGS, A7)
#define _MACRO_REPEAT_8(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4) SEP() NAME(MARGS, A5) SEP() NAME(MARGS, A6) SEP() NAME(MARGS, A7) SEP() NAME(MARGS, A8)
#define _MACRO_REPEAT_9(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4) SEP() NAME(MARGS, A5) SEP() NAME(MARGS, A6) SEP() NAME(MARGS, A7) SEP() NAME(MARGS, A8) SEP() NAME(MARGS, A9)
#define _MACRO_REPEAT_10(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10) \
	NAME(MARGS, A1) SEP() NAME(MARGS, A2) SEP() NAME(MARGS, A3) SEP() NAME(MARGS, A4) SEP() NAME(MARGS, A5) SEP() NAME(MARGS, A6) SEP() NAME(MARGS, A7) SEP() NAME(MARGS, A8) SEP() NAME(MARGS, A9) SEP() NAME(MARGS, A10)

/* clang-format on */

/* note these must use a separate copy of _MACRO_REPEAT */
#define _MACRO_REPEAT_XX(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, ...)          \
	_MACRO_REPEAT_10(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10)               \
	SEP() _MACRO_REPEAT1(SEP, MARGS, NAME, __VA_ARGS__)

#define _MACRO_REPEAT_YY(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, ...)          \
	_MACRO_REPEAT_10(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10)               \
	SEP() _MACRO_REPEAT2(SEP, MARGS, NAME, __VA_ARGS__)

#define _MACRO_REPEAT_ZZ(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10, ...)          \
	_MACRO_REPEAT_10(SEP, MARGS, NAME, A1, A2, A3, A4, A5, A6, A7, A8, A9, A10)               \
	SEP() _MACRO_REPEAT3(SEP, MARGS, NAME, __VA_ARGS__)

#define _MACRO_PLAIN_ARG(NAME, ARG) NAME(ARG)
#define _MACRO_REPEAT(NAME, ...)    _MACRO_REPEAT0(_EMPTY, NAME, _MACRO_PLAIN_ARG, ##__VA_ARGS__)
#define MACRO_REPEAT(...)	    _MACRO_REPEAT(__VA_ARGS__)

#define _MACRO_REPEAT_SEMICOLON(NAME, ...)                                                        \
	_MACRO_REPEAT0(_SEMICOLON, NAME, MACRO_APPLY, ##__VA_ARGS__)
#define MACRO_REPEAT_SEMICOLON(...) _MACRO_REPEAT_SEMICOLON(__VA_ARGS__)

#define _ONE(ARG)	 +1
#define MACRO_NARGS(...) (0 MACRO_REPEAT(_ONE, ##__VA_ARGS__))

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
#ifdef __cplusplus
/* do nothing */
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
/* do nothing - "%w64u" will be used & should match the original defs */
#else
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

#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 202311L
/* whohoo, we can start moving towards getting rid of these, since
 * __STDC_VERSION__ >= 202311L also implies printf supports it
 *
 * (the issue is mainly that without C23, even though printfrr unconditionally
 * supports w64, we don't know what libc's printf supports.  And we use plain
 * printf quite a bit, since a bulk printf -> printfrr pass is rather intrusive
 * for little benefit.)
 */
#undef PRIu64
#undef PRId64
#undef PRIx64
#define PRIu64 "w64u"
#define PRId64 "w64d"
#define PRIx64 "w64x"
#endif

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

#ifdef __MACH__
#define _DATA_SECTION(name) __attribute__((section("__DATA," name)))
#else
#define _DATA_SECTION(name) __attribute__((section(".data." name)))
#endif

/* Wrapper for the 'noreturn' metadata */
#define FRR_NORETURN __attribute__((noreturn))

/* Stringify a macro's *expansion* rather than its name. */
#define _STRINGIFY(x) #x
#define STRINGIFY(x) _STRINGIFY(x)

#ifdef __cplusplus
}
#endif

#endif /* _FRR_COMPILER_H */
