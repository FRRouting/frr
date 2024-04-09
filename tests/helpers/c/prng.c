// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Very simple prng to allow for randomized tests with reproducable
 * results.
 *
 * Copyright (C) 2012 by Open Source Routing.
 * Copyright (C) 2012 by Internet Systems Consortium, Inc. ("ISC")
 * Copyright (C) 2017 Christian Franke
 *
 * This file is part of Quagga
 */

#include <zebra.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "prng.h"

struct prng {
	uint64_t state;
};

struct prng *prng_new(unsigned long long seed)
{
	struct prng *rv = calloc(sizeof(*rv), 1);
	assert(rv);

	rv->state = seed;

	return rv;
}

/*
 * This implementation has originally been provided to musl libc by
 * Szabolcs Nagy <nsz at port70 dot net> in 2013 under the terms of
 * the MIT license.
 * It is a simple LCG which D.E. Knuth attributes to C.E. Haynes in
 * TAOCP Vol2 3.3.4
 */
int prng_rand(struct prng *prng)
{
	prng->state = 6364136223846793005ULL * prng->state + 1;
	return prng->state >> 33;
}

const char *prng_fuzz(struct prng *prng, const char *string,
		      const char *charset, unsigned int operations)
{
	static char buf[256];
	unsigned int charset_len;
	unsigned int i;
	unsigned int offset;
	unsigned int op;
	unsigned int character;

	assert(strlen(string) < sizeof(buf));

	strncpy(buf, string, sizeof(buf));
	charset_len = strlen(charset);

	for (i = 0; i < operations; i++) {
		offset = prng_rand(prng) % strlen(buf);
		op = prng_rand(prng) % 3;

		switch (op) {
		case 0:
			/* replace */
			character = prng_rand(prng) % charset_len;
			buf[offset] = charset[character];
			break;
		case 1:
			/* remove */
			memmove(buf + offset, buf + offset + 1,
				strlen(buf) - offset);
			break;
		case 2:
			/* insert */
			assert(strlen(buf) + 1 < sizeof(buf));

			memmove(buf + offset + 1, buf + offset,
				strlen(buf) + 1 - offset);
			character = prng_rand(prng) % charset_len;
			buf[offset] = charset[character];
			break;
		}
	}
	return buf;
}

void prng_free(struct prng *prng)
{
	free(prng);
}
