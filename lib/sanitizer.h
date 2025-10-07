// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Sanitizer related definitions
 * Copyright (c) 2025 Network Device Education Foundation (NetDEF), Inc.
 *               David Schweizer
 */


#ifndef _FRR_SANITIZER_H
#define _FRR_SANITIZER_H


/* Leak sanitizer availability check for LLVM */
#if defined(__clang__) && defined(__has_feature)
#if __has_feature(leak_sanitizer) || __has_feature(address_sanitizer)
#define FRR_HAVE_LEAK_SANITIZER
#endif
#endif

/* Leak sanitizer availability check for GCC */
#if (defined(__GNUC__) || defined(__GNUG__)) && defined(__SANITIZE_ADDRESS__)
#define FRR_HAVE_LEAK_SANITIZER
#endif

/* Suppress known FRRouting memory leaks in leak sanitizer output */
#if defined(FRR_HAVE_LEAK_SANITIZER) && !defined(FRR_NO_KNOWN_MEMLEAK)
extern const char *__lsan_default_suppressions(void);
#endif


#endif /* _FRR_SANITIZER_H */


/* EOF */
