/*
 * prefix2str() unit test
 * Copyright (C) 2019  David Lamparter
 * Portions:
 *     Copyright (C) 2019  Cumulus Networks, Inc
 *     Quentin Young
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "lib/prefix.h"

#include "tests/helpers/c/prng.h"

int main(int argc, char **argv)
{
	size_t i, j, k, l;
	struct in6_addr i6;
	char buf1[64], buf2[64], ntopbuf[64];
	struct prng *prng;
	struct prefix p = {};

	prng = prng_new(0);
	/* IPv4 */
	p.family = AF_INET;
	for (i = 0; i < 1000; i++) {
		p.u.prefix = prng_rand(prng);
		p.prefixlen = prng_rand(prng) >> 26;
		snprintf(buf1, sizeof(buf1), "%s/%d",
			 inet_ntop(AF_INET, &p.u.prefix4, ntopbuf,
				   sizeof(ntopbuf)),
			 p.prefixlen);
		prefix2str(&p, buf2, sizeof(buf2));
		assert(!strcmp(buf1, buf2));
		fprintf(stdout, "%s\n", buf1);
	}

	/* IPv6 */
	p.family = AF_INET6;
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

		p.prefixlen = prng_rand(prng) >> 24;
		memcpy(&p.u.prefix, &i6, sizeof(i6));
		snprintf(buf1, sizeof(buf1), "%s/%d",
			 inet_ntop(AF_INET6, &p.u.prefix6, ntopbuf,
				   sizeof(ntopbuf)),
			 p.prefixlen);
		prefix2str(&p, buf2, sizeof(buf2));
		assert(!strcmp(buf1, buf2));
		fprintf(stdout, "%s\n", buf1);
	}

	return 0;
}
