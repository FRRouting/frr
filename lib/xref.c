/*
 * Copyright (c) 2017-20  David Lamparter, for NetDEF, Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <inttypes.h>

#include "xref.h"
#include "vty.h"
#include "jhash.h"
#include "sha256.h"
#include "memory.h"
#include "hash.h"

struct xref_block *xref_blocks = NULL;
static struct xref_block **xref_block_last = &xref_blocks;

static void base32(uint8_t **inpos, int *bitpos,
		   char *out, size_t n_chars)
{
	static const char base32ch[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

	char *opos = out;
	uint8_t *in = *inpos;
	int bp = *bitpos;

	while (opos < out + n_chars) {
		uint32_t bits = in[0] | (in[1] << 8);
		if (bp == -1) {
			bits |= 0x10;
		} else
			bits >>= bp;

		*opos++ = base32ch[bits & 0x1f];

		bp += 5;
		if (bp >= 8)
			in++, bp -= 8;
	}
	*opos = '\0';
	*inpos = in;
	*bitpos = bp;
}

void xref_block_add(struct xref_block *block)
{
	const struct xref * const *xrefp;
	SHA256_CTX sha;

	*xref_block_last = block;
	xref_block_last = &block->next;

	for (xrefp = block->start; xrefp < block->stop; xrefp++) {
		const struct xref *xref = *xrefp;
		struct xrefdata *xrefdata;

		uint8_t hash[32], *h = hash;
		uint32_t be_val;
		int bitpos;

		if (!xref || !xref->xrefdata)
			continue;

		xrefdata = xref->xrefdata;
		xrefdata->xref = xref;

		if (!xrefdata->hashstr)
			continue;

		SHA256_Init(&sha);
		SHA256_Update(&sha, xref->file, strlen(xref->file));
		SHA256_Update(&sha, xrefdata->hashstr,
			      strlen(xrefdata->hashstr));
		be_val = htonl(xrefdata->hashu32[0]);
		SHA256_Update(&sha, &be_val, sizeof(be_val));
		be_val = htonl(xrefdata->hashu32[1]);
		SHA256_Update(&sha, &be_val, sizeof(be_val));
		SHA256_Final(hash, &sha);

		bitpos = -1;
		base32(&h, &bitpos, &xrefdata->prefix[0], 5);
		xrefdata->prefix[5] = '-';
		base32(&h, &bitpos, &xrefdata->prefix[6], 5);
	}
}
