/*
 * FRR switchable defaults.
 * Copyright (c) 2017-2019  David Lamparter, for NetDEF, Inc.
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

#include <zebra.h>

#include "defaults.h"
#include "libfrr.h"
#include "version.h"

static int version_value(int ch)
{
	/* non-ASCII shouldn't happen */
	if (ch < 0 || ch >= 128)
		return 2;

	/* ~foo sorts older than nothing */
	if (ch == '~')
		return 0;
	if (ch == '\0')
		return 1;
	if (isalpha(ch))
		return 0x100 + tolower(ch);

	/* punctuation and digits (and everything else) */
	return 0x200 + ch;
}

int frr_version_cmp(const char *aa, const char *bb)
{
	const char *apos = aa, *bpos = bb;

	/* || is correct, we won't scan past the end of a string since that
	 * doesn't compare equal to anything else */
	while (apos[0] || bpos[0]) {
		if (isdigit((unsigned char)apos[0]) &&
		    isdigit((unsigned char)bpos[0])) {
			unsigned long av, bv;
			char *aend = NULL, *bend = NULL;

			av = strtoul(apos, &aend, 10);
			bv = strtoul(bpos, &bend, 10);
			if (av < bv)
				return -1;
			if (av > bv)
				return 1;

			apos = aend;
			bpos = bend;
			continue;
		}

		int a = version_value(*apos++);
		int b = version_value(*bpos++);

		if (a < b)
			return -1;
		if (a > b)
			return 1;
	}
	return 0;
}
