// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * frr_inet_ntop() unit test
 * Copyright (C) 2019  David Lamparter
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>

#include "tests/helpers/c/prng.h"

/* NB: libfrr is NOT linked for this unit test! */

#define INET_NTOP_NO_OVERRIDE
#include "lib/ntop.c"

int main(int argc, char **argv)
{
	size_t i, j, k, l;
	struct in_addr i4;
	struct in6_addr i6, i6check;
	char buf1[64], buf2[64];
	const char *rv;
	struct prng *prng;

	prng = prng_new(0);
	/* IPv4 */
	for (i = 0; i < 1000; i++) {
		i4.s_addr = prng_rand(prng);
		assert(frr_inet_ntop(AF_INET, &i4, buf1, sizeof(buf1)));
		assert(inet_ntop(AF_INET, &i4, buf2, sizeof(buf2)));
		assert(!strcmp(buf1, buf2));
	}

	/* check size limit */
	for (i = 0; i < sizeof(buf1); i++) {
		memset(buf2, 0xcc, sizeof(buf2));
		rv = frr_inet_ntop(AF_INET, &i4, buf2, i);
		if (i < strlen(buf1) + 1)
			assert(!rv);
		else
			assert(rv && !strcmp(buf1, buf2));
	}

	/* IPv6 */
	for (i = 0; i < 10000; i++) {
		uint16_t *i6w = (uint16_t *)&i6;
		for (j = 0; j < 8; j++)
			i6w[j] = prng_rand(prng);

		/* clear some words */
		l = prng_rand(prng) & 7;
		for (j = 0; j < l; j++) {
			uint32_t num = __builtin_ctz(prng_rand(prng));
			uint32_t where = prng_rand(prng) & 7;

			for (k = where; k < where + num && k < 8; k++)
				i6w[k] = 0;
		}

		assert(frr_inet_ntop(AF_INET6, &i6, buf1, sizeof(buf1)));
		assert(inet_ntop(AF_INET6, &i6, buf2, sizeof(buf2)));
		if (strcmp(buf1, buf2))
			printf("%-40s (FRR) != (SYS) %-40s\n", buf1, buf2);

		assert(inet_pton(AF_INET6, buf1, &i6check));
		assert(!memcmp(&i6, &i6check, sizeof(i6)));
	}
	return 0;
}
