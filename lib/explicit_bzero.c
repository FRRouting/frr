// SPDX-License-Identifier: GPL-2.0-or-later

/*
 * Public domain.
 * Written by Matthew Dempsky.
 * Adapted for frr.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#ifndef HAVE_EXPLICIT_BZERO
#undef explicit_bzero


void explicit_bzero(void *buf, size_t len);
__attribute__((__weak__)) void
__explicit_bzero_hook(void *buf, size_t len);

__attribute__((__weak__)) void
__explicit_bzero_hook(void *buf, size_t len)
{
}

#if defined(__clang__)
#pragma clang optimize off
#else
#pragma GCC optimize("00")
#endif

void
explicit_bzero(void *buf, size_t len)
{
	memset(buf, 0, len);
	__explicit_bzero_hook(buf, len);
}

#endif
