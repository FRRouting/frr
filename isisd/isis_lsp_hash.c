/*
 * IS-IS Rout(e)ing protocol - LSP Hash
 *
 * Copyright (C) 2017 Christian Franke
 *
 * This file is part of FreeRangeRouting (FRR)
 *
 * FRR is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * FRR is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */
#include <zebra.h>

#include "hash.h"
#include "jhash.h"

#include "isisd/isis_memory.h"
#include "isisd/isis_flags.h"
#include "dict.h"
#include "isisd/isis_circuit.h"
#include "isisd/isis_lsp.h"
#include "isisd/isis_lsp_hash.h"

DEFINE_MTYPE_STATIC(ISISD, LSP_HASH, "ISIS LSP Hash")

struct isis_lsp_hash {
	struct hash *h;
};

static unsigned lsp_hash_key(void *lp)
{
	struct isis_lsp *lsp = lp;

	return jhash(lsp->hdr.lsp_id, ISIS_SYS_ID_LEN + 2, 0x55aa5a5a);
}

static int lsp_hash_cmp(const void *a, const void *b)
{
	const struct isis_lsp *la = a, *lb = b;

	return 0 == memcmp(la->hdr.lsp_id, lb->hdr.lsp_id, ISIS_SYS_ID_LEN + 2);
}

struct isis_lsp_hash *isis_lsp_hash_new(void)
{
	struct isis_lsp_hash *rv = XCALLOC(MTYPE_LSP_HASH, sizeof(*rv));

	rv->h = hash_create(lsp_hash_key, lsp_hash_cmp, NULL);
	return rv;
}

void isis_lsp_hash_clean(struct isis_lsp_hash *ih)
{
	hash_clean(ih->h, NULL);
}

void isis_lsp_hash_free(struct isis_lsp_hash *ih)
{
	isis_lsp_hash_clean(ih);
	hash_free(ih->h);
}

struct isis_lsp *isis_lsp_hash_lookup(struct isis_lsp_hash *ih,
				      struct isis_lsp *lsp)
{
	return hash_lookup(ih->h, lsp);
}

void isis_lsp_hash_add(struct isis_lsp_hash *ih, struct isis_lsp *lsp)
{
	struct isis_lsp *inserted;
	inserted = hash_get(ih->h, lsp, hash_alloc_intern);
	assert(inserted == lsp);
}

void isis_lsp_hash_release(struct isis_lsp_hash *ih, struct isis_lsp *lsp)
{
	hash_release(ih->h, lsp);
}
