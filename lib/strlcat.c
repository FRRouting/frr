/* Append a null-terminated string to another string, with length checking.
 * Copyright (C) 2016 Free Software Foundation, Inc.
 * This file is part of the GNU C Library.
 *
 * The GNU C Library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * The GNU C Library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the GNU C Library; if not, see
 * <http://www.gnu.org/licenses/>.
 */

/* adapted for Quagga from glibc patch submission originally from
 * Florian Weimer <fweimer@redhat.com>, 2016-05-18 */

#include <stdint.h>
#include <string.h>

#include "config.h"

#ifndef HAVE_STRLCAT
#undef strlcat

size_t strlcat(char *__restrict dest,
	       const char *__restrict src, size_t destsize);

size_t strlcat(char *__restrict dest,
	       const char *__restrict src, size_t destsize)
{
	size_t src_length = strlen(src);

	/* Our implementation strlcat supports dest == NULL if size == 0
	   (for consistency with snprintf and strlcpy), but strnlen does
	   not, so we have to cover this case explicitly.  */
	if (destsize == 0)
		return src_length;

	size_t dest_length = strnlen(dest, destsize);
	if (dest_length != destsize) {
		/* Copy at most the remaining number of characters in the
		   destination buffer.  Leave for the NUL terminator.  */
		size_t to_copy = destsize - dest_length - 1;
		/* But not more than what is available in the source string.  */
		if (to_copy > src_length)
			to_copy = src_length;

		char *target = dest + dest_length;
		memcpy(target, src, to_copy);
		target[to_copy] = '\0';
	}

/* If the sum wraps around, we have more than SIZE_MAX + 2 bytes in
   the two input strings (including both null terminators).  If each
   byte in the address space can be assigned a unique size_t value
   (which the static_assert checks), then by the pigeonhole
   principle, the two input strings must overlap, which is
   undefined.  */
#if __STDC_VERSION__ >= 201112L
	_Static_assert(sizeof(uintptr_t) == sizeof(size_t),
		       "theoretical maximum object size covers address space");
#endif
	return dest_length + src_length;
}
#endif /* HAVE_STRLCAT */
