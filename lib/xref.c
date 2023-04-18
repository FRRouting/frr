// SPDX-License-Identifier: ISC
/*
 * Copyright (c) 2017-20  David Lamparter, for NetDEF, Inc.
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

struct xref_block *xref_blocks;
static struct xref_block **xref_block_last = &xref_blocks;

struct xrefdata_uid_head xrefdata_uid = INIT_RBTREE_UNIQ(xrefdata_uid);

static void base32(uint8_t **inpos, int *bitpos,
		   char *out, size_t n_chars)
{
	static const char base32ch[] = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

	char *opos = out;
	uint8_t *in = *inpos;
	int bp = *bitpos;

	while (opos < out + n_chars) {
		uint32_t bits = in[0] | (in[1] << 8);

		if (bp == -1)
			bits |= 0x10;
		else
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

static void xref_add_one(const struct xref *xref)
{
	SHA256_CTX sha;
	struct xrefdata *xrefdata;

	const char *filename, *p, *q;
	uint8_t hash[32], *h = hash;
	uint32_t be_val;
	int bitpos;

	if (!xref || !xref->xrefdata)
		return;

	xrefdata = xref->xrefdata;
	xrefdata->xref = xref;

	if (!xrefdata->hashstr)
		return;

	/* as far as the unique ID is concerned, only use the last
	 * directory name + filename, e.g. "bgpd/bgp_route.c".  This
	 * gives a little leeway in moving things and avoids IDs being
	 * screwed up by out of tree builds or absolute pathnames.
	 */
	filename = xref->file;
	p = strrchr(filename, '/');
	if (p) {
		q = memrchr(filename, '/', p - filename);
		if (q)
			filename = q + 1;
	}

	SHA256_Init(&sha);
	SHA256_Update(&sha, filename, strlen(filename));
	SHA256_Update(&sha, xrefdata->hashstr,
		      strlen(xrefdata->hashstr));
	be_val = htonl(xrefdata->hashu32[0]);
	SHA256_Update(&sha, &be_val, sizeof(be_val));
	be_val = htonl(xrefdata->hashu32[1]);
	SHA256_Update(&sha, &be_val, sizeof(be_val));
	SHA256_Final(hash, &sha);

	bitpos = -1;
	base32(&h, &bitpos, &xrefdata->uid[0], 5);
	xrefdata->uid[5] = '-';
	base32(&h, &bitpos, &xrefdata->uid[6], 5);

	xrefdata_uid_add(&xrefdata_uid, xrefdata);
}

void xref_gcc_workaround(const struct xref *xref)
{
	xref_add_one(xref);
}

void xref_block_add(struct xref_block *block)
{
	const struct xref * const *xrefp;

	*xref_block_last = block;
	xref_block_last = &block->next;

	for (xrefp = block->start; xrefp < block->stop; xrefp++)
		xref_add_one(*xrefp);
}
