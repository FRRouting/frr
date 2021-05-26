/*
 * Copyright (c) 2021  David Lamparter, for NetDEF, Inc.
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

/* WARNING: this file is "special" in that it overrides the system-provided
 * assert.h by being on the include path before it.  That means it should
 * provide the functional equivalent.
 *
 * This is intentional because FRR extends assert() to write to the log and
 * add backtraces.  Overriding the entire file is the simplest and most
 * reliable way to get this to work;  there were problems previously with the
 * system assert.h getting included afterwards and redefining assert() back to
 * the system variant.
 */

#ifndef _FRR_ASSERT_H
#define _FRR_ASSERT_H

#include "xref.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef __cplusplus
/* C++ has this built-in, but C provides it in assert.h for >=C11.  Since we
 * replace assert.h entirely, we need to provide it here too.
 */
#define static_assert _Static_assert
#endif

struct xref_assert {
	struct xref xref;

	const char *expr;
	const char *extra, *args;
};

extern void _zlog_assert_failed(const struct xref_assert *xref,
				const char *extra, ...) PRINTFRR(2, 3)
	__attribute__((noreturn));

/* the "do { } while (expr_)" is there to get a warning for assignments inside
 * the assert expression aka "assert(x = 1)".  The (necessary) braces around
 * expr_ in the if () statement would suppress these warnings.  Since
 * _zlog_assert_failed() is noreturn, the while condition will never be
 * checked.
 */
#define assert(expr_)                                                          \
	({                                                                     \
		static const struct xref_assert _xref __attribute__(           \
			(used)) = {                                            \
			.xref = XREF_INIT(XREFT_ASSERT, NULL, __func__),       \
			.expr = #expr_,                                        \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		if (__builtin_expect((expr_) ? 0 : 1, 0))                      \
			do {                                                   \
				_zlog_assert_failed(&_xref, NULL);             \
			} while (expr_);                                       \
	})

#define assertf(expr_, extra_, ...)                                            \
	({                                                                     \
		static const struct xref_assert _xref __attribute__(           \
			(used)) = {                                            \
			.xref = XREF_INIT(XREFT_ASSERT, NULL, __func__),       \
			.expr = #expr_,                                        \
			.extra = extra_,                                       \
			.args = #__VA_ARGS__,                                  \
		};                                                             \
		XREF_LINK(_xref.xref);                                         \
		if (__builtin_expect((expr_) ? 0 : 1, 0))                      \
			do {                                                   \
				_zlog_assert_failed(&_xref, extra_,            \
						    ##__VA_ARGS__);            \
			} while (expr_);                                       \
	})

#define zassert assert

#ifdef __cplusplus
}
#endif

#endif /* _FRR_ASSERT_H */
