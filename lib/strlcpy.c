// SPDX-License-Identifier: LGPL-2.1-or-later
/* Copy a null-terminated string to a fixed-size buffer, with length checking.
 * Copyright (C) 2016 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 */

/* adapted for Quagga from glibc patch submission originally from
 * Florian Weimer <fweimer@redhat.com>, 2016-05-18 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>

#ifndef HAVE_STRLCPY
#undef strlcpy

size_t strlcpy(char *__restrict dest,
	       const char *__restrict src, size_t destsize);

size_t strlcpy(char *__restrict dest,
	       const char *__restrict src, size_t destsize)
{
	size_t src_length = strlen(src);

	if (__builtin_expect(src_length >= destsize, 0)) {
		if (destsize > 0) {
			/*
			 * Copy the leading portion of the string.  The last
			 * character is subsequently overwritten with the NUL
			 * terminator, but the destination destsize is usually
			 * a multiple of a small power of two, so writing it
			 * twice should be more efficient than copying an odd
			 * number of bytes.
			 */
			memcpy(dest, src, destsize);
			dest[destsize - 1] = '\0';
		}
	} else
		/* Copy the string and its terminating NUL character.  */
		memcpy(dest, src, src_length + 1);
	return src_length;
}
#endif /* HAVE_STRLCPY */
